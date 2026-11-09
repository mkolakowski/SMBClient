import Foundation

/// The keys and algorithms of an authenticated SMB 3.x session ([MS-SMB2]
/// 3.2.5.3.1), shared by every `Session` copy of that session and by the
/// `Connection`, which decrypts what the server sends.
final class SecureChannel: @unchecked Sendable {
  let dialect: UInt16
  let sessionId: UInt64
  let signingAlgorithm: NegotiateContext.SigningAlgorithm
  let signingKey: Data
  let cipher: NegotiateContext.Cipher?
  let encryptionKey: Data?
  let decryptionKey: Data?

  private let lock = NSLock()
  private var nonceCounter: UInt64 = 0
  private let noncePrefix = Crypto.randomBytes(count: 4)

  enum TransformError: Error {
    case notATransform
    case unsupportedCipher
    case wrongSession
  }

  /// - Parameters:
  ///   - sessionKey: the authentication's exported session key (NTLM's random session key).
  ///   - preauthHash: the session's pre-authentication integrity hash (3.1.1 only).
  init?(
    dialect: UInt16,
    sessionId: UInt64,
    sessionKey: Data,
    preauthHash: Data?,
    negotiatedCipher: NegotiateContext.Cipher?,
    negotiatedSigning: NegotiateContext.SigningAlgorithm?,
    serverSupportsEncryption: Bool
  ) {
    guard dialect >= Negotiate.Dialects.smb300.rawValue else { return nil }
    self.dialect = dialect
    self.sessionId = sessionId

    // Session keys shorter than 16 bytes are zero-padded, longer ones cut.
    var key = sessionKey.prefix(16)
    if key.count < 16 { key += Data(count: 16 - key.count) }

    func ascii(_ s: String) -> Data { Data(s.utf8) + Data([0]) }

    if dialect == Negotiate.Dialects.smb311.rawValue {
      guard let preauthHash else { return nil }
      signingAlgorithm = negotiatedSigning ?? .aesCMAC
      signingKey = SMB3Crypto.kdf(key: key, label: ascii("SMBSigningKey"), context: preauthHash)
      switch negotiatedCipher {
      case .aes128CCM?, .aes128GCM?:
        cipher = negotiatedCipher
        encryptionKey = SMB3Crypto.kdf(key: key, label: ascii("SMBC2SCipherKey"), context: preauthHash)
        decryptionKey = SMB3Crypto.kdf(key: key, label: ascii("SMBS2CCipherKey"), context: preauthHash)
      default:
        cipher = nil
        encryptionKey = nil
        decryptionKey = nil
      }
    } else {
      signingAlgorithm = .aesCMAC
      signingKey = SMB3Crypto.kdf(key: key, label: ascii("SMB2AESCMAC"), context: ascii("SmbSign"))
      if serverSupportsEncryption {
        cipher = .aes128CCM
        encryptionKey = SMB3Crypto.kdf(key: key, label: ascii("SMB2AESCCM"), context: Data("ServerIn ".utf8) + Data([0]))
        decryptionKey = SMB3Crypto.kdf(key: key, label: ascii("SMB2AESCCM"), context: Data("ServerOut".utf8) + Data([0]))
      } else {
        cipher = nil
        encryptionKey = nil
        decryptionKey = nil
      }
    }
  }

  var canEncrypt: Bool { encryptionKey != nil }

  // MARK: - Signing ([MS-SMB2] 3.1.4.1)

  /// The 16-byte signature of `message` (header and body, signature field zeroed).
  func signature(of message: Data) -> Data {
    switch signingAlgorithm {
    case .hmacSHA256:
      return Crypto.hmacSHA256(key: signingKey, data: message).prefix(16)
    case .aesCMAC:
      return SMB3Crypto.aesCMAC(key: signingKey, data: message)
    case .aesGMAC:
      let header = Header(data: message.prefix(64))
      var nonce = Data()
      nonce += header.messageId
      var role: UInt32 = header.flags.contains(.serverToRedir) ? 1 : 0
      if header.command == Header.Command.cancel.rawValue { role |= 2 }
      nonce += role
      // GMAC can't fail with a 12-byte nonce.
      return (try? SMB3Crypto.aesGMAC(key: signingKey, nonce: nonce, data: message)) ?? Data(count: 16)
    }
  }

  // MARK: - Encryption ([MS-SMB2] 2.2.41, 3.1.4.3)

  private static let transformProtocolId: UInt32 = 0x424D53FD

  static func isTransform(_ data: Data) -> Bool {
    guard data.count >= 52 else { return false }
    let start = data.startIndex
    return data[start] == 0xFD && data[start + 1] == 0x53 && data[start + 2] == 0x4D && data[start + 3] == 0x42
  }

  private var nonceLength: Int { cipher == .aes128CCM ? 11 : 12 }

  private func nextNonce() -> Data {
    lock.lock()
    defer { lock.unlock() }
    nonceCounter &+= 1
    var nonce = Data()
    nonce += nonceCounter
    nonce += noncePrefix
    return nonce.prefix(nonceLength)
  }

  /// Wraps a whole SMB2 message (or compound chain) in a transform header.
  func encrypt(_ message: Data) throws -> Data {
    guard let encryptionKey, let cipher else { throw TransformError.unsupportedCipher }
    let nonce = nextNonce()

    var aad = Data()
    aad += nonce + Data(count: 16 - nonce.count)
    aad += UInt32(message.count)
    aad += UInt16(0)
    aad += UInt16(0x0001)
    aad += sessionId

    let sealed: (ciphertext: Data, tag: Data)
    switch cipher {
    case .aes128CCM:
      sealed = SMB3Crypto.aesCCMSeal(key: encryptionKey, nonce: nonce, plaintext: message, aad: aad)
    case .aes128GCM:
      sealed = try SMB3Crypto.aesGCMSeal(key: encryptionKey, nonce: nonce, plaintext: message, aad: aad)
    default:
      throw TransformError.unsupportedCipher
    }

    var data = Data()
    data += SecureChannel.transformProtocolId
    data += sealed.tag
    data += aad
    data += sealed.ciphertext
    return data
  }

  /// Opens a transform the server sent and returns the SMB2 message(s) inside.
  func decrypt(_ data: Data) throws -> Data {
    guard SecureChannel.isTransform(data) else { throw TransformError.notATransform }
    guard let decryptionKey, let cipher else { throw TransformError.unsupportedCipher }
    let bytes = Data(data)
    let tag = bytes[4..<20]
    let aad = bytes[20..<52]
    let nonce = bytes[20..<(20 + nonceLength)]
    func little<T: FixedWidthInteger>(_ at: Int, _: T.Type) -> T {
      bytes[at..<(at + MemoryLayout<T>.size)].reversed().reduce(T(0)) { $0 << 8 | T($1) }
    }
    let originalSize = little(36, UInt32.self)
    let session = little(44, UInt64.self)
    guard session == sessionId else { throw TransformError.wrongSession }
    let ciphertext = bytes[52...].prefix(Int(originalSize))

    switch cipher {
    case .aes128CCM:
      return try SMB3Crypto.aesCCMOpen(key: decryptionKey, nonce: Data(nonce), ciphertext: Data(ciphertext), tag: Data(tag), aad: Data(aad))
    case .aes128GCM:
      return try SMB3Crypto.aesGCMOpen(key: decryptionKey, nonce: Data(nonce), ciphertext: Data(ciphertext), tag: Data(tag), aad: Data(aad))
    default:
      throw TransformError.unsupportedCipher
    }
  }
}
