import XCTest
@testable import SMBClient

/// Server-side copy, chunked and overwriting writes, recursive delete and
/// requests from several tasks at once, against `Scripts/smb3-test-server.sh`
/// (share "Encrypted"): port 4448 (signed) and 4446 (encrypted).
final class ServerCopyTests: XCTestCase {
  private let host = ProcessInfo.processInfo.environment["SMB3_TEST_HOST"] ?? "localhost"
  private let username = ProcessInfo.processInfo.environment["SMB3_TEST_USER"] ?? "alice"
  private let password = ProcessInfo.processInfo.environment["SMB3_TEST_PASSWORD"] ?? "alipass"
  private let share = "Encrypted"

  private func tree(port: Int) async throws -> (SMBClient, TreeAccessor) {
    let client = SMBClient(host: host, port: port)
    try await client.login(username: username, password: password)
    return (client, client.treeAccessor(share: share))
  }

  private func bytes(_ count: Int) -> Data {
    Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ $0 / 7) })
  }

  private func readAll(_ tree: TreeAccessor, _ path: String) async throws -> Data {
    let reader = try await tree.fileReader(path: path)
    let size = try await reader.fileSize
    var data = Data()
    while data.count < size {
      data += try await reader.read(offset: UInt64(data.count), length: 1 << 20)
    }
    try await reader.close()
    return data
  }

  func testServerSideCopy() async throws {
    for port in [4448, 4446] {
      let (_, tree) = try await self.tree(port: port)
      let folder = "copy-\(UUID().uuidString.prefix(8))"
      try await tree.createDirectory(path: folder)
      let content = bytes(20 * 1024 * 1024 + 12345) // more than one request's 16 MiB
      try await tree.upload(content: content, path: "\(folder)/source.bin")

      var reports: [UInt64] = []
      try await tree.copyFile(from: "\(folder)/source.bin", to: "\(folder)/copy.bin") { copied, total in
        XCTAssertEqual(total, UInt64(content.count))
        reports.append(copied)
        return true
      }
      XCTAssertEqual(reports.last, UInt64(content.count), "port \(port)")
      XCTAssertGreaterThanOrEqual(reports.count, 2)
      let copied = try await readAll(tree, "\(folder)/copy.bin")
      XCTAssertEqual(copied, content, "port \(port)")

      // Onto a file that's there: fails, and leaves that file alone.
      try await tree.upload(content: Data("keep".utf8), path: "\(folder)/there.bin")
      do {
        try await tree.copyFile(from: "\(folder)/source.bin", to: "\(folder)/there.bin")
        XCTFail("copied over a file")
      } catch {}
      let kept = try await readAll(tree, "\(folder)/there.bin")
      XCTAssertEqual(kept, Data("keep".utf8))

      // Stopped: the half-made copy is removed.
      do {
        try await tree.copyFile(from: "\(folder)/source.bin", to: "\(folder)/stopped.bin") { _, _ in false }
        XCTFail("not stopped")
      } catch is CancellationError {}
      let stoppedExists = try await tree.existFile(path: "\(folder)/stopped.bin")
      XCTAssertFalse(stoppedExists)

      try await tree.deleteDirectory(path: folder)
      let folderExists = try await tree.existDirectory(path: folder)
      XCTAssertFalse(folderExists)
    }
  }

  func testChunkedAndOverwritingWrites() async throws {
    let (_, tree) = try await self.tree(port: 4446)
    let path = "write-\(UUID().uuidString.prefix(8)).bin"
    let content = bytes(3 * 1024 * 1024 + 7)
    let writer = try await tree.fileWriter(path: path)
    var offset = 0
    while offset < content.count {
      let end = min(offset + 1_000_000, content.count)
      try await writer.write(data: content.subdata(in: offset..<end), offset: UInt64(offset))
      offset = end
    }
    try await writer.close()
    let read = try await readAll(tree, path)
    XCTAssertEqual(read, content)

    // Without overwrite a second writer can't open it; with, it replaces it.
    let again = try await tree.fileWriter(path: path)
    do {
      try await again.write(data: Data("x".utf8), offset: 0)
      XCTFail("wrote over a file")
    } catch {}
    let replacing = try await tree.fileWriter(path: path, overwrite: true)
    try await replacing.write(data: Data("short".utf8), offset: 0)
    try await replacing.close()
    let replaced = try await readAll(tree, path)
    XCTAssertEqual(replaced, Data("short".utf8))
    try await tree.deleteFile(path: path)
  }

  /// Two shares' sessions share a connection and its message IDs; reads
  /// from many tasks at once mustn't give two requests the same ID.
  func testRequestsFromManyTasksAtOnce() async throws {
    let (client, tree) = try await self.tree(port: 4446)
    let other = client.treeAccessor(share: share)
    let path = "many-\(UUID().uuidString.prefix(8)).bin"
    let content = bytes(2 * 1024 * 1024)
    try await tree.upload(content: content, path: path)
    try await withThrowingTaskGroup(of: Void.self) { group in
      for index in 0..<32 {
        let accessor = index.isMultiple(of: 2) ? tree : other
        group.addTask {
          let reader = try await accessor.fileReader(path: path)
          let offset = UInt64(index * 65536)
          let data = try await reader.read(offset: offset, length: 65536)
          XCTAssertEqual(data, content.subdata(in: Int(offset)..<Int(offset) + 65536))
          try await reader.close()
        }
      }
      try await group.waitForAll()
    }
    try await tree.deleteFile(path: path)
  }
}
