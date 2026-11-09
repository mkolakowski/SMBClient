import Foundation

public class TreeAccessor {
  public let share: String
  private let session: Session
  private let connectLock = NSLock()
  private var connecting: Task<Void, Error>?

  init(session: Session, share: String) {
    self.session = session.newSession()
    self.share = share
  }

  deinit {
    let session = self.session
    Task {
      try await session.treeDisconnect()
    }
  }

  public func listDirectory(path: String, pattern: String = "*") async throws -> [File] {
    let files = try await session().queryDirectory(path: Pathname.normalize(path), pattern: pattern)
    return files.map { File(fileInfo: $0) }
  }

  public func createDirectory(path: String) async throws {
    try await session().createDirectory(path: Pathname.normalize(path.precomposedStringWithCanonicalMapping))
  }

  public func rename(from: String, to: String) async throws {
    try await move(from: Pathname.normalize(from), to: Pathname.normalize(to))
  }

  public func move(from: String, to: String) async throws {
    try await session().move(from: Pathname.normalize(from), to: Pathname.normalize(to.precomposedStringWithCanonicalMapping))
  }

  public func deleteDirectory(path: String) async throws {
    try await session().deleteDirectory(path: Pathname.normalize(path))
  }

  public func deleteFile(path: String) async throws {
    try await session().deleteFile(path: Pathname.normalize(path))
  }

  public func fileStat(path: String) async throws -> FileStat {
    let response = try await session().fileStat(path: Pathname.normalize(path))
    return FileStat(response)
  }

  public func existFile(path: String) async throws -> Bool {
    try await session().existFile(path: Pathname.normalize(path))
  }

  public func existDirectory(path: String) async throws -> Bool {
    try await session().existDirectory(path: Pathname.normalize(path))
  }

  public func fileInfo(path: String) async throws -> FileAllInformation {
    let response = try await session().queryInfo(path: Pathname.normalize(path))
    return FileAllInformation(data: response.buffer)
  }

  public func download(path: String) async throws -> Data {
    let fileReader = try await fileReader(path: Pathname.normalize(path))

    let data = try await fileReader.download()
    try await fileReader.close()

    return data
  }

  public func upload(content: Data, path: String) async throws {
    try await upload(content: content, path: Pathname.normalize(path), progressHandler: { _ in })
  }

  public func upload(content: Data, path: String, progressHandler: (_ progress: Double) -> Void) async throws {
    let fileWriter = try await fileWriter(path: Pathname.normalize(path))

    try await fileWriter.upload(data: content, progressHandler: progressHandler)
    try await fileWriter.close()
  }

  public func upload(fileHandle: FileHandle, path: String) async throws {
    try await upload(fileHandle: fileHandle, path: path, progressHandler: { _ in })
  }

  public func upload(fileHandle: FileHandle, path: String, progressHandler: (_ progress: Double) -> Void) async throws {
    let fileWriter = try await fileWriter(path: Pathname.normalize(path))

    try await fileWriter.upload(fileHandle: fileHandle, progressHandler: progressHandler)
    try await fileWriter.close()

    await fileWriter.restoreFileAttributes(fileHandle, path)
  }

  public func upload(localPath: URL, remotePath path: String) async throws {
    try await upload(localPath: localPath, remotePath: path, progressHandler: { _, _, _ in })
  }

  public func upload(
    localPath: URL,
    remotePath path: String,
    progressHandler: (_ completedFiles: Int, _ fileBeingTransferred: URL, _ bytesSent: Int64) -> Void
  ) async throws {
    let fileWriter = try await fileWriter(path: Pathname.normalize(path))

    try await fileWriter.upload(localPath: localPath, progressHandler: progressHandler)
    try await fileWriter.close()
  }

  public func fileReader(path: String) async throws -> FileReader {
    FileReader(session: try await session(), path: Pathname.normalize(path))
  }

  public func fileWriter(path: String, overwrite: Bool = false) async throws -> FileWriter {
    FileWriter(session: try await session(), path: Pathname.normalize(path), overwrite: overwrite)
  }

  /// Copies the file `source` to `destination` (not there yet) on the
  /// server itself, with FSCTL_SRV_COPYCHUNK: nothing comes down to the
  /// device. `progressHandler` gets the bytes copied and the total, and
  /// returns whether to go on. If it fails or is stopped, the half-made
  /// `destination` is removed. Throws `ErrorResponse` with
  /// `.notSupported` or `.invalidDeviceRequest` from a server that can't.
  public func copyFile(
    from source: String,
    to destination: String,
    progressHandler: (_ bytesCopied: UInt64, _ totalBytes: UInt64) -> Bool = { _, _ in true }
  ) async throws {
    let session = try await session()
    let target = Pathname.normalize(destination.precomposedStringWithCanonicalMapping)
    let from = try await session.create(
      desiredAccess: [.readData, .readAttributes],
      fileAttributes: [],
      shareAccess: [.read],
      createDisposition: .open,
      createOptions: [.nonDirectoryFile],
      name: Pathname.normalize(source)
    )
    let to: Create.Response
    do {
      to = try await session.create(
        desiredAccess: [.readData, .writeData, .appendData, .readAttributes, .writeAttributes],
        fileAttributes: [.archive],
        shareAccess: [.read],
        createDisposition: .create,
        createOptions: [.nonDirectoryFile],
        name: target
      )
    } catch {
      _ = try? await session.close(fileId: from.fileId)
      throw error
    }
    do {
      let key = try await session.requestResumeKey(fileId: from.fileId)
      let total = from.endOfFile
      var copied: UInt64 = 0
      while copied < total {
        var chunks: [CopyChunk] = []
        var offset = copied
        while chunks.count < CopyChunk.maxChunksPerRequest && offset < total {
          let length = UInt32(min(UInt64(CopyChunk.maxChunkSize), total - offset))
          chunks.append(CopyChunk(sourceOffset: offset, targetOffset: offset, length: length))
          offset += UInt64(length)
        }
        let written = try await session.copyChunk(fileId: to.fileId, sourceKey: key, chunks: chunks)
        guard written > 0 else { throw CopyChunk.Error.noProgress }
        copied += UInt64(written)
        guard progressHandler(copied, total) else { throw CancellationError() }
      }
      _ = try? await session.close(fileId: to.fileId)
      _ = try? await session.close(fileId: from.fileId)
    } catch {
      _ = try? await session.close(fileId: to.fileId)
      _ = try? await session.close(fileId: from.fileId)
      try? await session.deleteFile(path: target)
      throw error
    }
  }

  public func availableSpace() async throws -> UInt64 {
    let response = try await session().queryInfo(path: "", infoType: .fileSystem, fileInfoClass: .fileFsSizeInformation)

    let sizeInformation = FileFsSizeInformation(data: response.buffer)
    let availableAllocationUnits = sizeInformation.availableAllocationUnits
    let sectorsPerAllocationUnit = sizeInformation.sectorsPerAllocationUnit
    let bytesPerSector = sizeInformation.bytesPerSector

    let bytesPerAllocationUnit = UInt64(sectorsPerAllocationUnit * bytesPerSector)
    let availableSpaceBytes = availableAllocationUnits * bytesPerAllocationUnit

    return availableSpaceBytes
  }

  public func keepAlive() async throws -> Echo.Response {
    try await session().echo()
  }

  /// The share connected once, however many tasks ask at the same time:
  /// two tree connects would leave files opened on the first one used on
  /// the second (STATUS_FILE_CLOSED).
  func session() async throws -> Session {
    if session.treeId != 0 { return session }
    let connecting = connectLock.withLock {
      if let task = self.connecting { return task }
      let session = self.session
      let share = self.share
      let task = Task { _ = try await session.treeConnect(path: share) }
      self.connecting = task
      return task
    }
    defer { connectLock.withLock { self.connecting = nil } }
    try await connecting.value
    return session
  }
}
