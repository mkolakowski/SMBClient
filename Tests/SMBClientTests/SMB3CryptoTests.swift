import XCTest
@testable import SMBClient

/// Known answers for SMB 3's crypto. CMAC vectors are RFC 4493's; CCM, GCM,
/// GMAC and the KDF were checked against Python's `cryptography` and `hmac`.
final class SMB3CryptoTests: XCTestCase {
  private let key = Data(0..<16)
  private let nonce11 = Data(100..<111)
  private let nonce12 = Data(100..<112)
  private let plaintext = Data((0..<100).map { UInt8(($0 * 7) % 256) })
  private let aad = Data((0..<32).map { UInt8(($0 * 3) % 256) })

  func testAESCMACRFC4493() {
    let key = Data(hex: "2b7e151628aed2a6abf7158809cf4f3c")
    XCTAssertEqual(SMB3Crypto.aesCMAC(key: key, data: Data()).hex, "bb1d6929e95937287fa37d129b756746")
    XCTAssertEqual(SMB3Crypto.aesCMAC(key: key, data: Data(hex: "6bc1bee22e409f96e93d7e117393172a")).hex, "070a16b46b4d4144f79bdd9dd04a287c")
    XCTAssertEqual(
      SMB3Crypto.aesCMAC(key: key, data: Data(hex: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411")).hex,
      "dfa66747de9ae63030ca32611497c827"
    )
    XCTAssertEqual(
      SMB3Crypto.aesCMAC(key: key, data: Data(hex: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")).hex,
      "51f0bebf7e3b9d92fc49741779363cfe"
    )
  }

  func testAESCCM() throws {
    let sealed = SMB3Crypto.aesCCMSeal(key: key, nonce: nonce11, plaintext: plaintext, aad: aad)
    XCTAssertEqual(sealed.ciphertext.hex, "6c2150c74e975eeecb2726adc6e5acb74456a430f8cdec0e74038e7b51bfe51d53741da3a5b65312fe088e12ad6760403cb2b0805c73c4924c357d0f30da3f3ed0ff20f32738b7ea6798404d8c457cbb4e5d165b821515586f17f9f9c2d0118ddf518ce4")
    XCTAssertEqual(sealed.tag.hex, "95bbed2f3ab448c24dca76eeaf5bd8b9")
    let opened = try SMB3Crypto.aesCCMOpen(key: key, nonce: nonce11, ciphertext: sealed.ciphertext, tag: sealed.tag, aad: aad)
    XCTAssertEqual(opened, plaintext)

    var tampered = sealed.ciphertext
    tampered[0] ^= 1
    XCTAssertThrowsError(try SMB3Crypto.aesCCMOpen(key: key, nonce: nonce11, ciphertext: tampered, tag: sealed.tag, aad: aad))
  }

  func testAESGCMAndGMAC() throws {
    let sealed = try SMB3Crypto.aesGCMSeal(key: key, nonce: nonce12, plaintext: plaintext, aad: aad)
    XCTAssertEqual(sealed.ciphertext.hex, "1a6540b0c72192cba301115dd291498540ff067a1e3a47fb5cc0072a7839252a5a1bbcd1771b2d809247016bb9b9064e8bca4316f1753ba94b0197c06835d7d9a45ddcd87054787bdf5838df26f0135be6851c5ff8b662e5527333d661d404c3c2eecfd8")
    XCTAssertEqual(sealed.tag.hex, "3df4b54fee25e6002bba68b16e8fb8f6")
    XCTAssertEqual(try SMB3Crypto.aesGCMOpen(key: key, nonce: nonce12, ciphertext: sealed.ciphertext, tag: sealed.tag, aad: aad), plaintext)
    XCTAssertEqual(try SMB3Crypto.aesGMAC(key: key, nonce: nonce12, data: plaintext).hex, "56da51c315c7329996df293186acbfff")
  }

  func testKDF() {
    let label30 = Data("SMB2AESCMAC".utf8) + Data([0])
    let context30 = Data("SmbSign".utf8) + Data([0])
    XCTAssertEqual(SMB3Crypto.kdf(key: key, label: label30, context: context30).hex, "6234814cbb8ea9227440ebfeb5eacbe1")
    let label311 = Data("SMBSigningKey".utf8) + Data([0])
    XCTAssertEqual(SMB3Crypto.kdf(key: key, label: label311, context: Data(0..<64)).hex, "f7e5401ecc6e79ef9eab401b05004e4f")
  }

  func testTransformRoundTrip() throws {
    for (cipher, dialect) in [(NegotiateContext.Cipher.aes128GCM, Negotiate.Dialects.smb311), (.aes128CCM, .smb311), (.aes128CCM, .smb300)] {
      let channel = try XCTUnwrap(SecureChannel(
        dialect: dialect.rawValue, sessionId: 0x1122334455667788, sessionKey: key,
        preauthHash: Data(count: 64), negotiatedCipher: cipher, negotiatedSigning: .aesCMAC,
        serverSupportsEncryption: true
      ))
      let encrypted = try channel.encrypt(plaintext)
      XCTAssertTrue(SecureChannel.isTransform(encrypted))
      XCTAssertEqual(encrypted.count, 52 + plaintext.count)
      // The keys differ by direction, so the client can't open its own
      // messages: a server-side round trip is covered by SMB3Tests.
      XCTAssertThrowsError(try channel.decrypt(encrypted))
    }
  }

  func testNegotiateRequestCarriesContextsFor311() {
    let request = Negotiate.Request(messageId: 0, securityMode: [.signingEnabled], dialects: [.smb202, .smb210, .smb300, .smb302, .smb311])
    let data = request.encoded()
    // Fixed part: 64-byte header + 36; five dialects end at 110; list at 112.
    let offset = UInt32(data[92]) | UInt32(data[93]) << 8 | UInt32(data[94]) << 16 | UInt32(data[95]) << 24
    let count = UInt16(data[96]) | UInt16(data[97]) << 8
    XCTAssertEqual(offset, 112)
    XCTAssertEqual(count, 3)
    XCTAssertEqual(data[112], 0x01) // PREAUTH_INTEGRITY_CAPABILITIES
    XCTAssertTrue(request.capabilities.contains(.encryption))
  }
}

private extension Data {
  init(hex: String) {
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      data.append(UInt8(hex[index..<next], radix: 16)!)
      index = next
    }
    self = data
  }
}
