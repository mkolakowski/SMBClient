import XCTest
import Network
@testable import SMBClient

/// A server that goes quiet: requests give up instead of waiting on TCP
/// (`Connection.responseTimeout`, `pendingTimeout`, `connectTimeout`).
final class ConnectionTimeoutTests: XCTestCase {
  private func smb2Message(status: UInt32) -> Data {
    var data = Header(command: .echo, messageId: 0, sessionId: 0).encoded()
    data[8]  = UInt8((status      ) & 0xFF)
    data[9]  = UInt8((status >>  8) & 0xFF)
    data[10] = UInt8((status >> 16) & 0xFF)
    data[11] = UInt8((status >> 24) & 0xFF)
    return data
  }

  /// A loopback server that accepts, reads everything, and sends `fragments`
  /// `delay` seconds apart, then keeps the connection open and says nothing
  /// more (it never closes it, as a vanished server wouldn't).
  private final class QuietServer: @unchecked Sendable {
    let listener: NWListener
    private let queue = DispatchQueue(label: "test.quiet.server")
    private var connections: [NWConnection] = []

    init(fragments: [Data], delay: Double) throws {
      let tcp = NWProtocolTCP.Options()
      tcp.noDelay = true
      listener = try NWListener(using: NWParameters(tls: nil, tcp: tcp), on: .any)
      listener.newConnectionHandler = { [unowned self] connection in
        self.connections.append(connection)
        connection.start(queue: self.queue)
        func drain() {
          connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { _, _, isComplete, error in
            if !isComplete, error == nil { drain() }
          }
        }
        drain()
        func send(_ index: Int) {
          guard index < fragments.count else { return }
          self.queue.asyncAfter(deadline: .now() + delay) {
            connection.send(content: fragments[index], completion: .contentProcessed { _ in send(index + 1) })
          }
        }
        send(0)
      }
    }

    func start() async throws -> UInt16 {
      try await withCheckedThrowingContinuation { continuation in
        var resumed = false
        listener.stateUpdateHandler = { [listener] state in
          guard !resumed else { return }
          switch state {
          case .ready:
            resumed = true
            continuation.resume(returning: listener.port!.rawValue)
          case .failed(let error):
            resumed = true
            continuation.resume(throwing: error)
          default:
            break
          }
        }
        listener.start(queue: queue)
      }
    }

    func stop() {
      listener.cancel()
      queue.sync { connections.forEach { $0.cancel() } }
    }
  }

  private final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var isSet: Bool { lock.lock(); defer { lock.unlock() }; return value }
    func set() { lock.lock(); value = true; lock.unlock() }
  }

  private func assertTimesOut(_ connection: Connection, within seconds: Double,
                              file: StaticString = #filePath, line: UInt = #line) async {
    let start = Date()
    do {
      _ = try await connection.send(smb2Message(status: 0))
      XCTFail("expected a timeout", file: file, line: line)
    } catch ConnectionError.timedOut {
      XCTAssertLessThan(Date().timeIntervalSince(start), seconds, file: file, line: line)
    } catch {
      XCTFail("expected ConnectionError.timedOut, got \(error)", file: file, line: line)
    }
  }

  func testAReplyThatNeverComesTimesOut() async throws {
    let server = try QuietServer(fragments: [], delay: 0)
    let port = try await server.start()
    defer { server.stop() }

    let connection = Connection(host: "127.0.0.1", port: Int(port))
    connection.responseTimeout = 0.5
    defer { connection.disconnect() }

    await assertTimesOut(connection, within: 3)
  }

  /// A reply that stops halfway (the header, then nothing) times out too.
  func testAReplyThatStopsHalfwayTimesOut() async throws {
    let frame = DirectTCPPacket(smb2Message: smb2Message(status: 0)).encoded()
    let server = try QuietServer(fragments: [Data(frame.prefix(10))], delay: 0)
    let port = try await server.start()
    defer { server.stop() }

    let connection = Connection(host: "127.0.0.1", port: Int(port))
    connection.responseTimeout = 0.5
    defer { connection.disconnect() }

    await assertTimesOut(connection, within: 3)
  }

  /// Bytes arriving restart the clock: a reply trickling in over longer
  /// than the timeout, but never quiet for that long, still arrives.
  func testASlowButSteadyReplyIsNotCutOff() async throws {
    let message = smb2Message(status: 0)
    let frame = DirectTCPPacket(smb2Message: message).encoded()
    let pieces = stride(from: 0, to: frame.count, by: 12).map { Data(frame[$0..<min($0 + 12, frame.count)]) }
    let server = try QuietServer(fragments: pieces, delay: 0.2)
    let port = try await server.start()
    defer { server.stop() }

    let connection = Connection(host: "127.0.0.1", port: Int(port))
    connection.responseTimeout = 0.6
    defer { connection.disconnect() }

    let start = Date()
    let reply = try await connection.send(message)
    XCTAssertGreaterThan(Date().timeIntervalSince(start), 0.6 + 0.1, "longer than the timeout in all")
    XCTAssertEqual(reply.count, message.count)
  }

  /// STATUS_PENDING: the server is working on it, so the final reply gets
  /// `pendingTimeout`, and a server gone quiet after it still times out.
  func testAfterPendingTheFinalReplyGetsLongerButNotForever() async throws {
    let pending = DirectTCPPacket(smb2Message: smb2Message(status: 0x00000103)).encoded()
    let success = DirectTCPPacket(smb2Message: smb2Message(status: 0)).encoded()

    // The final reply 0.9 s after PENDING: past responseTimeout, within pendingTimeout.
    var server = try QuietServer(fragments: [Data(pending), Data(success)], delay: 0.9)
    var port = try await server.start()
    var connection = Connection(host: "127.0.0.1", port: Int(port))
    connection.responseTimeout = 1.2
    connection.pendingTimeout = 2
    let reply = try await connection.send(smb2Message(status: 0))
    XCTAssertTrue(NTStatus(Header(data: reply).status) == ErrorCode.success)
    connection.disconnect()
    server.stop()

    // PENDING, then nothing.
    server = try QuietServer(fragments: [Data(pending)], delay: 0)
    port = try await server.start()
    defer { server.stop() }
    connection = Connection(host: "127.0.0.1", port: Int(port))
    connection.responseTimeout = 0.3
    connection.pendingTimeout = 0.8
    defer { connection.disconnect() }
    await assertTimesOut(connection, within: 3)
  }

  /// A timed-out connection stays closed: the next request fails at once.
  func testATimedOutConnectionIsClosed() async throws {
    let server = try QuietServer(fragments: [], delay: 0)
    let port = try await server.start()
    defer { server.stop() }

    let connection = Connection(host: "127.0.0.1", port: Int(port))
    connection.responseTimeout = 0.3
    defer { connection.disconnect() }
    await assertTimesOut(connection, within: 3)

    let start = Date()
    do {
      _ = try await connection.send(smb2Message(status: 0))
      XCTFail("expected the closed connection to fail")
    } catch {
      XCTAssertLessThan(Date().timeIntervalSince(start), 1)
    }
  }

  /// An address that never answers (TEST-NET-1): connecting gives up after
  /// `connectTimeout` instead of TCP's minute or more. Some networks refuse
  /// it at once instead, which is fine too: the point is it doesn't hang.
  func testConnectingToAnAddressThatNeverAnswersGivesUp() async throws {
    let connection = Connection(host: "192.0.2.1", port: 445)
    connection.connectTimeout = 1
    defer { connection.disconnect() }
    let start = Date()
    do {
      _ = try await connection.send(smb2Message(status: 0))
      XCTFail("expected connecting to fail")
    } catch {
      XCTAssertLessThan(Date().timeIntervalSince(start), 5, "\(error)")
    }
  }

  /// With no timeouts the old behaviour stands: a quiet server isn't given up on.
  func testNoTimeoutWaits() async throws {
    let server = try QuietServer(fragments: [], delay: 0)
    let port = try await server.start()
    defer { server.stop() }

    let connection = Connection(host: "127.0.0.1", port: Int(port))
    connection.responseTimeout = nil
    let finished = Flag()
    let message = smb2Message(status: 0)
    let request = Task {
      defer { finished.set() }
      return try await connection.send(message)
    }
    try await Task.sleep(nanoseconds: 1_000_000_000)
    XCTAssertFalse(finished.isSet, "still waiting after 1 s")
    connection.disconnect() // ends it
    do {
      _ = try await request.value
      XCTFail("expected the cancelled connection to fail")
    } catch ConnectionError.timedOut {
      XCTFail("no timeout was set")
    } catch {}
  }
}
