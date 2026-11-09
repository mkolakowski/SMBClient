import Foundation

/// SMB 3.1.1 negotiate contexts ([MS-SMB2] 2.2.3.1, 2.2.4.1).
public enum NegotiateContext {
  public enum ContextType: UInt16 {
    case preauthIntegrityCapabilities = 0x0001
    case encryptionCapabilities = 0x0002
    case compressionCapabilities = 0x0003
    case netnameNegotiateContextId = 0x0005
    case transportCapabilities = 0x0006
    case rdmaTransformCapabilities = 0x0007
    case signingCapabilities = 0x0008
  }

  public enum HashAlgorithm: UInt16 {
    case sha512 = 0x0001
  }

  public enum Cipher: UInt16, Sendable {
    case aes128CCM = 0x0001
    case aes128GCM = 0x0002
    case aes256CCM = 0x0003
    case aes256GCM = 0x0004
  }

  public enum SigningAlgorithm: UInt16, Sendable {
    case hmacSHA256 = 0x0000
    case aesCMAC = 0x0001
    case aesGMAC = 0x0002
  }

  /// What the client offers, in order of preference.
  public struct Offer {
    public var salt: Data
    public var ciphers: [Cipher]
    public var signingAlgorithms: [SigningAlgorithm]

    public init(
      salt: Data? = nil,
      ciphers: [Cipher] = [.aes128GCM, .aes128CCM],
      signingAlgorithms: [SigningAlgorithm] = [.aesGMAC, .aesCMAC, .hmacSHA256]
    ) {
      self.salt = salt ?? Crypto.randomBytes(count: 32)
      self.ciphers = ciphers
      self.signingAlgorithms = signingAlgorithms
    }

    /// The contexts, each starting on an 8-byte boundary (the list itself
    /// must start on one too), and how many there are.
    func encoded() -> (data: Data, count: UInt16) {
      var contexts = [(ContextType, Data)]()

      var preauth = Data()
      preauth += UInt16(1)
      preauth += UInt16(salt.count)
      preauth += HashAlgorithm.sha512.rawValue
      preauth += salt
      contexts.append((.preauthIntegrityCapabilities, preauth))

      if !ciphers.isEmpty {
        var encryption = Data()
        encryption += UInt16(ciphers.count)
        for cipher in ciphers { encryption += cipher.rawValue }
        contexts.append((.encryptionCapabilities, encryption))
      }

      if !signingAlgorithms.isEmpty {
        var signing = Data()
        signing += UInt16(signingAlgorithms.count)
        for algorithm in signingAlgorithms { signing += algorithm.rawValue }
        contexts.append((.signingCapabilities, signing))
      }

      var data = Data()
      for (index, (type, body)) in contexts.enumerated() {
        data += type.rawValue
        data += UInt16(body.count)
        data += UInt32(0)
        data += body
        if index < contexts.count - 1 {
          data += Data(count: (8 - data.count % 8) % 8)
        }
      }
      return (data, UInt16(contexts.count))
    }
  }

  /// What the server chose.
  public struct Selection: Sendable {
    public var cipher: Cipher?
    public var signingAlgorithm: SigningAlgorithm?

    /// `message` is the whole negotiate response, header included; offsets
    /// are from the start of the header.
    init(message: Data, offset: Int, count: Int) {
      let bytes = [UInt8](message)
      func u16(_ at: Int) -> UInt16? {
        guard at >= 0, at + 2 <= bytes.count else { return nil }
        return UInt16(bytes[at]) | UInt16(bytes[at + 1]) << 8
      }

      var position = offset
      for _ in 0..<count {
        position += (8 - position % 8) % 8
        guard let type = u16(position), let length = u16(position + 2) else { break }
        let body = position + 8
        guard body + Int(length) <= bytes.count else { break }

        switch ContextType(rawValue: type) {
        case .encryptionCapabilities:
          if let n = u16(body), n > 0, let raw = u16(body + 2) {
            cipher = Cipher(rawValue: raw)
          }
        case .signingCapabilities:
          if let n = u16(body), n > 0, let raw = u16(body + 2) {
            signingAlgorithm = SigningAlgorithm(rawValue: raw)
          }
        default:
          break
        }
        position = body + Int(length)
      }
    }
  }
}
