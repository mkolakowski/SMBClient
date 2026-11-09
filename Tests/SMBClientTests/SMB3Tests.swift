import XCTest
@testable import SMBClient

/// Runs against a server that only takes SMB 3.1.1 and requires encryption:
/// the `samba-smb3` service in docker-compose.yml (port 4446, share
/// "Encrypted"), or `Scripts/smb3-test-server.sh` on a Mac with Homebrew's
/// Samba. Override the account with SMB3_TEST_USER / SMB3_TEST_PASSWORD.
final class SMB3Tests: XCTestCase {
  private let host = ProcessInfo.processInfo.environment["SMB3_TEST_HOST"] ?? "localhost"
  private let port = Int(ProcessInfo.processInfo.environment["SMB3_TEST_PORT"] ?? "") ?? 4446
  private let username = ProcessInfo.processInfo.environment["SMB3_TEST_USER"] ?? "alice"
  private let password = ProcessInfo.processInfo.environment["SMB3_TEST_PASSWORD"] ?? "alipass"
  private let share = "Encrypted"

  private func connectedClient() async throws -> SMBClient {
    let client = SMBClient(host: host, port: port)
    try await client.login(username: username, password: password)
    try await client.connectShare(share)
    return client
  }

  func testNegotiatesSMB311WithEncryption() async throws {
    let client = try await connectedClient()
    XCTAssertEqual(client.session.dialect, Negotiate.Dialects.smb311.rawValue)
    XCTAssertTrue(client.session.isEncrypting)
    XCTAssertNotNil(client.session.cipher)
    try await client.disconnectShare()
    try await client.logoff()
  }

  func testEachCipherAndSigningAlgorithm() async throws {
    let offers: [(NegotiateContext.Cipher, NegotiateContext.SigningAlgorithm)] = [
      (.aes128GCM, .aesGMAC),
      (.aes128CCM, .aesCMAC),
      (.aes128GCM, .hmacSHA256),
    ]
    for (cipher, signing) in offers {
      let session = Session(host: host, port: port)
      try await session.connect()
      try await session.negotiate(contexts: NegotiateContext.Offer(ciphers: [cipher], signingAlgorithms: [signing]))
      try await session.sessionSetup(username: username, password: password)
      try await session.treeConnect(path: share)
      XCTAssertEqual(session.cipher, cipher)
      XCTAssertTrue(session.isEncrypting)
      let files = try await session.queryDirectory(path: "", pattern: "*")
      XCTAssertFalse(files.isEmpty, "\(cipher) / \(signing)")
      try await session.treeDisconnect()
      try await session.logoff()
      session.disconnect()
    }
  }

  /// SMB 3.0 and 3.0.2 (AES-CCM, the older key labels). Needs a server
  /// that still allows them: SMB3_LEGACY_TEST_PORT (default 4447).
  func testSMB30And302() async throws {
    let legacyPort = Int(ProcessInfo.processInfo.environment["SMB3_LEGACY_TEST_PORT"] ?? "") ?? 4447
    for dialect in [Negotiate.Dialects.smb300, .smb302] {
      let session = Session(host: host, port: legacyPort)
      do {
        try await session.connect()
        try await session.negotiate(dialects: [dialect])
      } catch {
        throw XCTSkip("No server allowing \(dialect) on port \(legacyPort): \(error)")
      }
      XCTAssertEqual(session.dialect, dialect.rawValue)
      try await session.sessionSetup(username: username, password: password)
      try await session.treeConnect(path: share)
      XCTAssertTrue(session.isEncrypting)
      XCTAssertEqual(session.cipher, .aes128CCM)
      let files = try await session.queryDirectory(path: "", pattern: "*")
      XCTAssertFalse(files.isEmpty)
      try await session.treeDisconnect()
      try await session.logoff()
      session.disconnect()
    }
  }

  /// Signing without encryption, every dialect and signing algorithm.
  /// Needs a server with `server signing = mandatory` and encryption off:
  /// SMB3_SIGNING_TEST_PORT (default 4448).
  func testSigningRequiredWithoutEncryption() async throws {
    let signingPort = Int(ProcessInfo.processInfo.environment["SMB3_SIGNING_TEST_PORT"] ?? "") ?? 4448
    let cases: [(Negotiate.Dialects, NegotiateContext.SigningAlgorithm?)] = [
      (.smb210, nil), (.smb300, nil), (.smb302, nil),
      (.smb311, .aesGMAC), (.smb311, .aesCMAC), (.smb311, .hmacSHA256),
    ]
    for (dialect, signing) in cases {
      let session = Session(host: host, port: signingPort)
      do {
        try await session.connect()
        try await session.negotiate(
          dialects: [dialect],
          contexts: signing.map { NegotiateContext.Offer(signingAlgorithms: [$0]) }
        )
      } catch {
        throw XCTSkip("No signing-only server on port \(signingPort): \(error)")
      }
      XCTAssertEqual(session.dialect, dialect.rawValue)
      try await session.sessionSetup(username: username, password: password)
      try await session.treeConnect(path: share)
      XCTAssertFalse(session.isEncrypting)
      XCTAssertTrue(session.isSigning)
      if let signing { XCTAssertEqual(session.signingAlgorithm, signing) }
      let files = try await session.queryDirectory(path: "", pattern: "*")
      XCTAssertFalse(files.isEmpty, "\(dialect) \(String(describing: signing))")
      try await session.treeDisconnect()
      try await session.logoff()
      session.disconnect()
    }
  }

  /// A client that asks for encryption on a server that doesn't require it.
  func testPrefersEncryptionOnSigningOnlyServer() async throws {
    let signingPort = Int(ProcessInfo.processInfo.environment["SMB3_SIGNING_TEST_PORT"] ?? "") ?? 4448
    let client = SMBClient(host: host, port: signingPort)
    do {
      try await client.login(username: username, password: password)
    } catch {
      throw XCTSkip("No signing-only server on port \(signingPort): \(error)")
    }
    client.session.prefersEncryption = true
    try await client.connectShare(share)
    XCTAssertTrue(client.session.isEncrypting)
    let data = try await client.download(path: "hello.txt")
    XCTAssertEqual(String(decoding: data, as: UTF8.self), "hello\n")
    try await client.disconnectShare()
    try await client.logoff()
  }

  func testWriteAndReadBackEncrypted() async throws {
    let client = try await connectedClient()
    let content = Data((0..<3_000_000).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) })
    let path = "smb3-roundtrip-\(UUID().uuidString).bin"

    try await client.upload(content: content, path: path)
    let downloaded = try await client.download(path: path)
    XCTAssertEqual(downloaded.count, content.count)
    XCTAssertEqual(downloaded, content)

    let reader = client.fileReader(path: path)
    let slice = try await reader.read(offset: 2_000_000, length: 100_000)
    XCTAssertEqual(slice, content[2_000_000..<2_100_000])
    try await reader.close()

    try await client.deleteFile(path: path)
    try await client.disconnectShare()
    try await client.logoff()
  }
}
