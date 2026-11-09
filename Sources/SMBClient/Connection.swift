import Foundation
import Network

public class Connection {
  let host: String
  var onDisconnected: (Error) -> Void

  private let connection: NWConnection
  private let queue: DispatchQueue
  private var buffer = Data()

  /// Set once an SMB 3.x session is set up, so encrypted responses
  /// (transform headers) can be opened.
  var secureChannel: SecureChannel?

  private func open(_ message: Data) throws -> Data {
    guard SecureChannel.isTransform(message) else { return message }
    guard let secureChannel else { throw SecureChannel.TransformError.unsupportedCipher }
    return try secureChannel.decrypt(message)
  }

  private let semaphore = Semaphore(value: 1)

  // MARK: Giving up on a server that's gone quiet

  /// How long a reply may go quiet before the request gives up: the clock
  /// restarts whenever bytes arrive, so a slow but steady reply finishes.
  /// `nil` waits as long as TCP does (a server that vanishes without closing
  /// the connection can take many minutes).
  public var responseTimeout: TimeInterval? = 30
  /// After the server answers STATUS_PENDING (it's working on it), how long
  /// the final reply may take.
  public var pendingTimeout: TimeInterval? = 300
  /// How long connecting may take.
  public var connectTimeout: TimeInterval? = 10
  /// The slowest a request may go out, in bytes a second: a send of n bytes
  /// gets n / this on top of `responseTimeout` before it's given up on.
  public var minimumSendRate: Double = 32 * 1024

  /// The running clock; when it runs out the connection is cancelled, which
  /// fails whatever is waiting on it. Only touched on `queue`.
  private var deadline: DispatchWorkItem?
  /// How long the reply may go quiet just now (`responseTimeout`, or
  /// `pendingTimeout` after STATUS_PENDING). Only touched on `queue`.
  private var quietLimit: TimeInterval?
  /// Set when a clock ran out, so the error says so. Only touched on `queue`.
  private var didTimeOut = false

  /// Starts the clock afresh. On `queue`.
  private func arm(_ seconds: TimeInterval?) {
    deadline?.cancel()
    deadline = nil
    guard let seconds else { return }
    let item = DispatchWorkItem { [weak self] in
      guard let self, self.deadline != nil else { return }
      self.deadline = nil
      self.didTimeOut = true
      self.connection.cancel()
    }
    deadline = item
    queue.asyncAfter(deadline: .now() + seconds, execute: item)
  }

  /// Bytes arrived: the reply isn't quiet. On `queue`.
  private func noteActivity() {
    if deadline != nil { arm(quietLimit) }
  }

  /// The request's over, one way or the other. On `queue`.
  private func disarm() {
    deadline?.cancel()
    deadline = nil
  }

  /// `error`, or `ConnectionError.timedOut` when a clock ran out. On `queue`.
  private func reported(_ error: Error) -> Error {
    didTimeOut ? ConnectionError.timedOut : error
  }

  public var state: NWConnection.State {
    connection.state
  }

  public init(host: String) {
    self.host = host
    
    let endpoint = NWEndpoint.hostPort(
      host: NWEndpoint.Host(host),
      port: NWEndpoint.Port(integerLiteral: 445)
    )
    connection = NWConnection(to: endpoint, using: .tcp)
    queue = DispatchQueue(label: "com.kishikawakatsumi.smbclient.connection.\(host):445", qos: .userInitiated)
    onDisconnected = { _ in }
  }

  public init(host: String, port: Int) {
    self.host = host
    let endpoint = NWEndpoint.hostPort(
      host: NWEndpoint.Host(host),
      port: NWEndpoint.Port(rawValue: UInt16(port))!
    )
    connection = NWConnection(to: endpoint, using: .tcp)
    queue = DispatchQueue(label: "com.kishikawakatsumi.smbclient.connection.\(host):\(port)", qos: .userInitiated)
    onDisconnected = { _ in }
  }

  public func connect() async throws {
    let limit = connectTimeout
    return try await withCheckedThrowingContinuation { (continuation) in
      connection.stateUpdateHandler = { [weak self] (state) in
        switch state {
        case .setup, .preparing:
          break
        case .waiting(let error):
          self?.disarm()
          continuation.resume(throwing: error)
          self?.connection.stateUpdateHandler = nil
        case .ready:
          self?.disarm()
          continuation.resume()
          // NWConnection delivers all state updates on `queue`, so assigning
          // stateUpdateHandler here is safe: it runs on the same serial queue
          // as any future state updates.
          self?.connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .waiting(let error), .failed(let error):
              self?.onDisconnected(error)
            case .setup, .preparing, .ready, .cancelled:
              break
            @unknown default:
              break
            }
          }
        case .failed(let error):
          self?.disarm()
          continuation.resume(throwing: error)
          self?.connection.stateUpdateHandler = nil
        case .cancelled:
          let timedOut = self?.didTimeOut ?? false
          self?.disarm()
          continuation.resume(throwing: timedOut ? ConnectionError.timedOut : ConnectionError.cancelled)
          self?.connection.stateUpdateHandler = nil
        @unknown default:
          break
        }
      }

      // On `queue` before the first state update can arrive.
      queue.async { self.arm(limit) }
      connection.start(queue: queue)
    }
  }

  public func disconnect() {
    // Do not nil stateUpdateHandler before cancelling: NWConnection delivers
    // the .cancelled state update asynchronously, and clearing the handler
    // first would prevent any in-flight connect() continuation from being
    // resumed, causing a hang. The retain cycle is instead broken by
    // capturing self weakly in the handler closures.
    connection.cancel()
  }

  public func send(_ data: Data) async throws -> Data {
    await semaphore.wait()
    defer { Task { await semaphore.signal() } }

    switch connection.state {
    case .setup:
      try await connect()
    case .waiting(let error), .failed(let error):
      onDisconnected(error)
      throw error
    case .preparing, .ready:
      break
    case .cancelled:
      throw ConnectionError.cancelled
    @unknown default:
      throw ConnectionError.unknown
    }

    let transportPacket = DirectTCPPacket(smb2Message: data)
    let content = transportPacket.encoded()
    let replyLimit = responseTimeout
    let sendLimit = replyLimit.map { $0 + Double(content.count) / max(minimumSendRate, 1) }
    let pendingLimit = pendingTimeout

    return try await withCheckedThrowingContinuation { (continuation) in
      // Enqueued before the send, so it runs before the send's completion.
      queue.async {
        self.quietLimit = replyLimit
        self.pendingQuietLimit = pendingLimit
        self.arm(sendLimit)
      }
      connection.send(content: content, completion: .contentProcessed() { (error) in
        if let error {
          self.disarm()
          continuation.resume(throwing: self.reported(error))
          return
        }

        // Sent: from here the reply mustn't go quiet for too long.
        if self.deadline != nil { self.arm(self.quietLimit) }
        self.receive() { (result) in
          self.disarm()
          switch result {
          case .success(let data):
            continuation.resume(returning: data)
          case .failure(let error):
            continuation.resume(throwing: self.reported(error))
          }
        }
      })
    }
  }

  /// `pendingTimeout` as it was when the request went out. Only touched on `queue`.
  private var pendingQuietLimit: TimeInterval?

  /// The server answered STATUS_PENDING: give the final reply longer. On `queue`.
  private func notePending() {
    quietLimit = pendingQuietLimit
    noteActivity()
  }

  private func receive(completion: @escaping (Result<Data, Error>) -> Void) {
    let minimumIncompleteLength = 1
    let maximumLength = 65536

    connection.receive(
      minimumIncompleteLength: minimumIncompleteLength,
      maximumLength: maximumLength)
    { (content, contentContext, isComplete, error) in
      if let error = error {
        completion(.failure(error))
        return
      }

      guard let content else {
        if isComplete {
          completion(.failure(ConnectionError.disconnected))
        } else {
          self.receive(completion: completion)
        }
        return
      }

      self.buffer.append(Data(content))
      self.noteActivity()

      self.receive(upTo: 4) { (headerResult) in
        switch headerResult {
        case .failure(let error):
          completion(.failure(error))
          return
        case .success:
          break
        }

        let transportPacket = DirectTCPPacket(response: self.buffer)
        let length = Int(transportPacket.protocolLength)
        self.buffer = Data(transportPacket.smb2Message)

        self.receive(upTo: length) { (result) in
          switch result {
          case .success:
            let data: Data
            do {
              data = try self.open(Data(self.buffer.prefix(length)))
            } catch {
              completion(.failure(error))
              return
            }
            self.buffer = Data(self.buffer.suffix(from: length))

            let reader = ByteReader(data)
            var offset = 0

            var header: Header
            var response = Data()
            repeat {
              header = reader.read()

              switch NTStatus(header.status) {
              case
                .success,
                .moreProcessingRequired,
                .noMoreFiles,
                .endOfFile:
                response += data
              case .pending:
                self.notePending()
                if self.buffer.count >= 4 {
                  let transportPacket = DirectTCPPacket(response: self.buffer)
                  let length = Int(transportPacket.protocolLength)

                  if self.buffer.count < 4 + length {
                    self.receive(completion: completion)
                    return
                  }

                  let data: Data
                  do {
                    data = try self.open(Data(transportPacket.smb2Message.prefix(length)))
                  } catch {
                    completion(.failure(error))
                    return
                  }
                  self.buffer = Data(self.buffer.suffix(from: 4 + length))

                  let reader = ByteReader(data)
                  let header: Header = reader.read()

                  switch NTStatus(header.status) {
                  case
                    .success,
                    .moreProcessingRequired,
                    .noMoreFiles,
                    .endOfFile:
                    response += data
                    break
                  default:
                    completion(.failure(ErrorResponse(data: data)))
                    return
                  }
                } else {
                  self.receive(completion: completion)
                  return
                }
              default:
                completion(.failure(ErrorResponse(data: Data(data[offset...]))))
                return
              }

              offset += Int(header.nextCommand)
              reader.seek(to: offset)
            } while header.nextCommand > 0

            completion(.success(response))
          case .failure(let error):
            completion(.failure(error))
          }
        }
      }
    }
  }

  private func receive(upTo byteCount: Int, completion: @escaping (Result<(), Error>) -> Void) {
    let minimumIncompleteLength = 1
    let maximumLength = 65536

    if self.buffer.count < byteCount {
      self.connection.receive(minimumIncompleteLength: minimumIncompleteLength, maximumLength: maximumLength) { (data, _, isComplete, error) in
        if let error = error {
          completion(.failure(error))
          return
        }

        guard let data else {
          if isComplete {
            completion(.failure(ConnectionError.disconnected))
          } else {
            self.receive(upTo: byteCount, completion: completion)
          }
          return
        }

        self.buffer.append(data)
        self.noteActivity()
        self.receive(upTo: byteCount, completion: completion)
      }
      return
    }

    completion(.success(()))
  }
}

public enum ConnectionError: Error {
  case disconnected
  case cancelled
  case unknown
  /// The server didn't answer in time (`Connection.responseTimeout`,
  /// `pendingTimeout`, `connectTimeout`, `minimumSendRate`); the connection
  /// was closed.
  case timedOut
}
