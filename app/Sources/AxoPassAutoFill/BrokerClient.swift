import Foundation

/// The App Group shared with the host app. Must match
/// `com.apple.security.application-groups` in both entitlements files, and
/// `APP_GROUP_SUFFIX` in crates/core/src/core/dirs.rs.
let appGroupIdentifier = "75J48AQ5LF.com.breakfastlabs.frittata.shared"

/// One fillable item, as the broker reports it. Mirrors
/// `axo_pass_core::secrets::vaults::autofill::AutofillItem`.
struct AutofillItem: Decodable, Identifiable, Hashable {
  let vaultKey: String
  let itemKey: String
  let title: String
  let username: String?
  let passwordKey: String
  let urls: [String]

  var id: String { recordIdentifier }

  /// The identifier handed to the system with a credential identity, and handed
  /// back when the system asks us to fill it. Vault, item and credential keys
  /// are normalized to lowercase words with no slashes, so joining them is
  /// unambiguous.
  var recordIdentifier: String { "\(vaultKey)/\(itemKey)/\(passwordKey)" }

  /// The account name the system and our list show. Falls back to the item
  /// title, since a credential identity with an empty user reads as blank.
  var accountName: String {
    guard let username, !username.isEmpty else { return title }
    return username
  }

  enum CodingKeys: String, CodingKey {
    case vaultKey = "vault_key"
    case itemKey = "item_key"
    case title
    case username
    case passwordKey = "password_key"
    case urls
  }
}

/// Where a fill request points, parsed back out of a record identifier.
struct CredentialRef {
  let vaultKey: String
  let itemKey: String
  let credentialKey: String

  init?(recordIdentifier: String?) {
    let parts = (recordIdentifier ?? "").split(separator: "/", omittingEmptySubsequences: false)
    guard parts.count == 3, parts.allSatisfy({ !$0.isEmpty }) else { return nil }
    vaultKey = String(parts[0])
    itemKey = String(parts[1])
    credentialKey = String(parts[2])
  }
}

enum BrokerError: Error, LocalizedError {
  /// No app is listening. The extension cannot start it, so the UI offers to
  /// open it instead.
  case unavailable
  case cancelled
  case failed(String)

  var errorDescription: String? {
    switch self {
    case .unavailable: return "Axo Pass is not running."
    case .cancelled: return "Cancelled."
    case let .failed(message): return message
    }
  }
}

/// Speaks the app broker's protocol: connect, write one JSON line, read one
/// JSON line back, close. See crates/core/src/core/app_broker/mod.rs.
///
/// Every request may block on a Touch ID prompt in the app, so calls run off
/// the main actor and the socket carries a timeout matching the app's own.
struct BrokerClient {
  /// How long to wait for the app to answer. The app gives the user 120s to
  /// respond to a prompt, so anything shorter would give up mid-prompt.
  private static let timeout: TimeInterval = 130

  static var socketPath: String? {
    FileManager.default
      .containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier)?
      .appendingPathComponent("autofill-broker.sock")
      .path
  }

  /// Whether the app is listening right now.
  static var isAvailable: Bool {
    guard let path = socketPath else { return false }
    return FileManager.default.fileExists(atPath: path)
  }

  /// Ask the app for the items that can fill `service`. `nil` lists everything.
  static func autofillItems(service: String?) async throws -> [AutofillItem] {
    var request: [String: Any] = ["request": "list_autofill_items"]
    if let service { request["service"] = service }
    let response = try await send(request)
    guard response["status"] as? String == "autofill_items" else {
      throw error(from: response, fallback: "Unexpected response to the autofill listing.")
    }
    let items = response["items"] ?? []
    let data = try JSONSerialization.data(withJSONObject: items)
    return try JSONDecoder().decode([AutofillItem].self, from: data)
  }

  /// Ask the app for one credential's secret. Prompts every time.
  static func secret(for ref: CredentialRef) async throws -> String {
    let response = try await send([
      "request": "read_vault_secret",
      "vault_key": ref.vaultKey,
      "item_key": ref.itemKey,
      "credential_key": ref.credentialKey,
    ])
    guard response["status"] as? String == "vault_secret" else {
      throw error(from: response, fallback: "Unexpected response to the secret read.")
    }
    guard let value = response["value"] as? String else {
      throw BrokerError.failed("That credential no longer exists.")
    }
    return value
  }

  /// One registered passkey, as the broker reports it.
  struct Registration {
    let credentialID: Data
    let attestationObject: Data
  }

  /// One passkey assertion, as the broker reports it.
  struct Assertion {
    let credentialID: Data
    let userHandle: Data
    let authenticatorData: Data
    let signature: Data
  }

  /// Ask the app to register a passkey against an unlocked vault. Prompts every
  /// time.
  static func registerPasskey(
    rpID: String, rpName: String?, userHandle: Data, userName: String, userDisplayName: String,
    clientDataHash: Data, algorithms: [Int], excludedCredentials: [Data]
  ) async throws -> Registration {
    var request: [String: Any] = [
      "request": "create_passkey",
      "rp_id": rpID,
      "user_handle": userHandle.base64EncodedString(),
      "user_name": userName,
      "user_display_name": userDisplayName,
      "client_data_hash": clientDataHash.base64EncodedString(),
      "algorithms": algorithms,
      "excluded_credentials": excludedCredentials.map { $0.base64EncodedString() },
    ]
    if let rpName { request["rp_name"] = rpName }
    let response = try await send(request)
    guard response["status"] as? String == "passkey_registered" else {
      throw error(from: response, fallback: "Unexpected response to the passkey registration.")
    }
    guard let credentialID = decodeBase64(response["credential_id"]),
      let attestationObject = decodeBase64(response["attestation_object"])
    else {
      throw BrokerError.failed("The passkey registration response was incomplete.")
    }
    return Registration(credentialID: credentialID, attestationObject: attestationObject)
  }

  /// Ask the app to sign an assertion challenge with a stored passkey. Prompts
  /// every time.
  static func assertPasskey(
    rpID: String, clientDataHash: Data, allowedCredentialIDs: [Data]
  ) async throws -> Assertion {
    let response = try await send([
      "request": "assert_passkey",
      "rp_id": rpID,
      "client_data_hash": clientDataHash.base64EncodedString(),
      "allowed_credentials": allowedCredentialIDs.map { $0.base64EncodedString() },
    ])
    guard response["status"] as? String == "passkey_asserted" else {
      throw error(from: response, fallback: "Unexpected response to the passkey assertion.")
    }
    guard let credentialID = decodeBase64(response["credential_id"]),
      let authenticatorData = decodeBase64(response["authenticator_data"]),
      let signature = decodeBase64(response["signature"])
    else {
      throw BrokerError.failed("The passkey assertion response was incomplete.")
    }
    return Assertion(
      credentialID: credentialID,
      userHandle: decodeBase64(response["user_handle"]) ?? Data(),
      authenticatorData: authenticatorData,
      signature: signature)
  }

  private static func decodeBase64(_ value: Any?) -> Data? {
    guard let string = value as? String else { return nil }
    return Data(base64Encoded: string)
  }

  private static func error(from response: [String: Any], fallback: String) -> BrokerError {
    switch response["status"] as? String {
    case "cancelled": return .cancelled
    case "failed": return .failed(response["message"] as? String ?? fallback)
    default: return .failed(fallback)
    }
  }

  // MARK: - Transport

  private static func send(_ request: [String: Any]) async throws -> [String: Any] {
    let payload = try JSONSerialization.data(withJSONObject: request)
    let raw = try await Task.detached(priority: .userInitiated) {
      try exchange(payload)
    }.value
    guard let response = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
      throw BrokerError.failed("The app sent a response we could not read.")
    }
    return response
  }

  /// Write one line, read one line. Blocking, so it runs off the main actor.
  private static func exchange(_ payload: Data) throws -> Data {
    guard let path = socketPath else {
      throw BrokerError.failed("This build has no App Group container.")
    }

    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw BrokerError.unavailable }
    defer { close(fd) }

    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(path.utf8)
    // sun_path is a fixed 104-byte buffer and the path must fit with room for
    // the terminator.
    guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
      throw BrokerError.failed("The broker socket path is too long.")
    }
    withUnsafeMutableBytes(of: &address.sun_path) { buffer in
      buffer.copyBytes(from: pathBytes)
    }
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

    let connected = withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
        connect(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
      }
    }
    guard connected == 0 else { throw BrokerError.unavailable }

    var deadline = timeval(
      tv_sec: Int(timeout), tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, socklen_t(MemoryLayout<timeval>.size))

    var line = payload
    line.append(0x0A)
    try writeAll(fd, line)
    return try readLine(fd)
  }

  private static func writeAll(_ fd: Int32, _ data: Data) throws {
    try data.withUnsafeBytes { buffer in
      var offset = 0
      while offset < buffer.count {
        let written = write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
        guard written > 0 else { throw BrokerError.failed("The app closed the connection.") }
        offset += written
      }
    }
  }

  /// Read until the newline that terminates the response.
  private static func readLine(_ fd: Int32) throws -> Data {
    var out = Data()
    var chunk = [UInt8](repeating: 0, count: 4096)
    while true {
      let count = read(fd, &chunk, chunk.count)
      guard count > 0 else {
        // A short read with something buffered is a response without its
        // trailing newline, which JSON parses fine.
        if !out.isEmpty { return out }
        throw BrokerError.failed("The app closed the connection.")
      }
      if let newline = chunk[0..<count].firstIndex(of: 0x0A) {
        out.append(contentsOf: chunk[0..<newline])
        return out
      }
      out.append(contentsOf: chunk[0..<count])
    }
  }
}
