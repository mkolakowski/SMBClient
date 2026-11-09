import Foundation

/// One piece of a server-side copy (SRV_COPYCHUNK, [MS-SMB2] 2.2.31.1.1).
public struct CopyChunk: Hashable, Sendable {
  public let sourceOffset: UInt64
  public let targetOffset: UInt64
  public let length: UInt32

  public init(sourceOffset: UInt64, targetOffset: UInt64, length: UInt32) {
    self.sourceOffset = sourceOffset
    self.targetOffset = targetOffset
    self.length = length
  }

  /// Within what Windows and Samba take by default (1 MiB a chunk, 16 MiB
  /// a request), so no request comes back STATUS_INVALID_PARAMETER.
  public static let maxChunkSize: UInt32 = 1024 * 1024
  public static let maxChunksPerRequest = 16

  public enum Error: Swift.Error {
    /// The server's answer was shorter than the structure.
    case badResponse
    /// The server wrote nothing.
    case noProgress
  }
}
