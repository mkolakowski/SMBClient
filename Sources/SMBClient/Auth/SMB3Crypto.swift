import Foundation
import CommonCrypto
import CryptoKit

/// The cryptography SMB 3.x needs ([MS-SMB2] 3.1.4): the SP800-108 key
/// derivation, AES-CMAC and AES-GMAC signing, and AES-128-CCM/GCM encryption.
enum SMB3Crypto {
  enum CryptoError: Error {
    case authenticationFailed
    case invalidLength
  }

  // MARK: - Key derivation

  /// SP800-108 counter-mode KDF with HMAC-SHA256, one iteration
  /// ([MS-SMB2] 3.1.4.2): `HMAC(Ki, [1]₃₂ || label || 0x00 || context || [L]₃₂)`.
  /// `label` and `context` are passed with any trailing NUL the spec includes.
  static func kdf(key: Data, label: Data, context: Data, bits: Int = 128) -> Data {
    var input = Data()
    input += UInt32(1).bigEndian
    input += label
    input.append(0)
    input += context
    input += UInt32(bits).bigEndian
    let mac = HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: key))
    return Data(mac).prefix(bits / 8)
  }

  static func sha512(_ data: Data) -> Data {
    Data(SHA512.hash(data: data))
  }

  // MARK: - AES primitives (CommonCrypto)

  private static func aes(_ options: CCOptions, key: Data, iv: Data?, data: Data) -> Data {
    var out = Data(count: data.count + kCCBlockSizeAES128)
    var moved = 0
    let outCount = out.count
    let status = out.withUnsafeMutableBytes { outBytes in
      data.withUnsafeBytes { inBytes in
        key.withUnsafeBytes { keyBytes in
          withOptionalBytes(iv) { ivBytes in
            CCCrypt(
              CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), options,
              keyBytes.baseAddress, key.count, ivBytes,
              inBytes.baseAddress, data.count,
              outBytes.baseAddress, outCount, &moved
            )
          }
        }
      }
    }
    precondition(status == kCCSuccess, "CCCrypt failed: \(status)")
    return out.prefix(moved)
  }

  private static func withOptionalBytes<R>(_ data: Data?, _ body: (UnsafeRawPointer?) -> R) -> R {
    guard let data else { return body(nil) }
    return data.withUnsafeBytes { body($0.baseAddress) }
  }

  /// One AES-128 block.
  static func aesBlock(key: Data, _ block: Data) -> Data {
    aes(CCOptions(kCCOptionECBMode), key: key, iv: nil, data: block)
  }

  /// The last block of AES-CBC with a zero IV over `data` (a multiple of 16 bytes).
  private static func cbcMAC(key: Data, _ data: Data) -> Data {
    aes(0, key: key, iv: Data(count: 16), data: data).suffix(16)
  }

  private static func ctr(key: Data, counter: Data, _ data: Data) -> Data {
    guard !data.isEmpty else { return Data() }
    var cryptor: CCCryptorRef?
    let created = key.withUnsafeBytes { keyBytes in
      counter.withUnsafeBytes { ivBytes in
        CCCryptorCreateWithMode(
          CCOperation(kCCEncrypt), CCMode(kCCModeCTR), CCAlgorithm(kCCAlgorithmAES),
          CCPadding(ccNoPadding), ivBytes.baseAddress, keyBytes.baseAddress, key.count,
          nil, 0, 0, CCModeOptions(kCCModeOptionCTR_BE), &cryptor
        )
      }
    }
    precondition(created == kCCSuccess, "CCCryptorCreateWithMode failed: \(created)")
    defer { CCCryptorRelease(cryptor) }
    var out = Data(count: data.count)
    var moved = 0
    let outCount = out.count
    let status = out.withUnsafeMutableBytes { outBytes in
      data.withUnsafeBytes { inBytes in
        CCCryptorUpdate(cryptor, inBytes.baseAddress, data.count, outBytes.baseAddress, outCount, &moved)
      }
    }
    precondition(status == kCCSuccess, "CCCryptorUpdate failed: \(status)")
    return out
  }

  // MARK: - AES-CMAC (RFC 4493), SMB 3.0–3.1.1 signing

  static func aesCMAC(key: Data, data: Data) -> Data {
    func double(_ block: Data) -> Data {
      var out = Data(count: 16)
      var carry: UInt8 = 0
      for i in stride(from: 15, through: 0, by: -1) {
        let byte = block[block.startIndex + i]
        out[i] = (byte << 1) | carry
        carry = byte >> 7
      }
      if carry != 0 { out[15] ^= 0x87 }
      return out
    }

    let l = aesBlock(key: key, Data(count: 16))
    let k1 = double(l)
    let k2 = double(k1)

    var message = Data(data)
    let complete = !message.isEmpty && message.count % 16 == 0
    if !complete {
      message.append(0x80)
      message.append(Data(count: (16 - message.count % 16) % 16))
    }
    let subkey = complete ? k1 : k2
    let last = message.count - 16
    for i in 0..<16 {
      message[last + i] ^= subkey[i]
    }
    return cbcMAC(key: key, message)
  }

  // MARK: - AES-GCM / GMAC (CryptoKit)

  static func aesGMAC(key: Data, nonce: Data, data: Data) throws -> Data {
    let box = try AES.GCM.seal(Data(), using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: nonce), authenticating: data)
    return Data(box.tag)
  }

  static func aesGCMSeal(key: Data, nonce: Data, plaintext: Data, aad: Data) throws -> (ciphertext: Data, tag: Data) {
    let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
    return (Data(box.ciphertext), Data(box.tag))
  }

  static func aesGCMOpen(key: Data, nonce: Data, ciphertext: Data, tag: Data, aad: Data) throws -> Data {
    let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
    do {
      return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
    } catch {
      throw CryptoError.authenticationFailed
    }
  }

  // MARK: - AES-CCM (RFC 3610 / SP800-38C), 16-byte tag, 11-byte nonce in SMB

  private static func ccmTag(key: Data, nonce: Data, plaintext: Data, aad: Data) -> Data {
    let l = 15 - nonce.count
    var b = Data()
    let flags = UInt8((aad.isEmpty ? 0 : 0x40) | (((16 - 2) / 2) << 3) | (l - 1))
    b.append(flags)
    b += nonce
    var length = UInt64(plaintext.count)
    var lengthBytes = [UInt8](repeating: 0, count: l)
    for i in stride(from: l - 1, through: 0, by: -1) {
      lengthBytes[i] = UInt8(length & 0xFF)
      length >>= 8
    }
    b += lengthBytes

    if !aad.isEmpty {
      precondition(aad.count < 0xFF00)
      b += UInt16(aad.count).bigEndian
      b += aad
      b.append(Data(count: (16 - b.count % 16) % 16))
    }
    b += plaintext
    b.append(Data(count: (16 - b.count % 16) % 16))
    return cbcMAC(key: key, b)
  }

  private static func ccmCounter(nonce: Data, _ i: UInt8) -> Data {
    let l = 15 - nonce.count
    var a = Data([UInt8(l - 1)])
    a += nonce
    a += Data(count: l - 1)
    a.append(i)
    return a
  }

  static func aesCCMSeal(key: Data, nonce: Data, plaintext: Data, aad: Data) -> (ciphertext: Data, tag: Data) {
    let t = ccmTag(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
    let s0 = aesBlock(key: key, ccmCounter(nonce: nonce, 0))
    let ciphertext = ctr(key: key, counter: ccmCounter(nonce: nonce, 1), plaintext)
    return (ciphertext, Data(zip(t, s0).map { $0 ^ $1 }))
  }

  static func aesCCMOpen(key: Data, nonce: Data, ciphertext: Data, tag: Data, aad: Data) throws -> Data {
    let plaintext = ctr(key: key, counter: ccmCounter(nonce: nonce, 1), ciphertext)
    let s0 = aesBlock(key: key, ccmCounter(nonce: nonce, 0))
    let expected = Data(zip(ccmTag(key: key, nonce: nonce, plaintext: plaintext, aad: aad), s0).map { $0 ^ $1 })
    guard tag.count == 16, constantTimeEqual(expected, tag) else {
      throw CryptoError.authenticationFailed
    }
    return plaintext
  }

  private static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for (x, y) in zip(a, b) { diff |= x ^ y }
    return diff == 0
  }
}
