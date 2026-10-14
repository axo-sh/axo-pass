import Darwin
import Foundation

/// The App Group shared with the host app. Must match
/// `com.apple.security.application-groups` in both entitlements files, and
/// `APP_GROUP_SUFFIX` in crates/core/src/core/dirs.rs.
let appGroupIdentifier = "75J48AQ5LF.com.breakfastlabs.frittata.shared"

/// `bootstrap_look_up` from servers/bootstrap.h, which Swift's Darwin module
/// does not import.
@_silgen_name("bootstrap_look_up")
private func axo_bootstrap_look_up(
  _ bootstrapPort: mach_port_t, _ serviceName: UnsafePointer<CChar>,
  _ servicePort: UnsafeMutablePointer<mach_port_t>
) -> kern_return_t

/// One login offered for a page, as the broker reports it. Mirrors
/// `axo_pass_core::secrets::vaults::autofill::LoginSummary` for a login that
/// matches the page, and `OtherLogin` for one that does not. It carries no
/// password and no vault, item, or credential key.
struct Login: Decodable, Identifiable, Hashable {
  /// `<vault uuid>/<item uuid>/<password credential uuid>`. Handed back to the
  /// broker to fill, and stored in the system's credential identity.
  let recordID: String
  let title: String
  let username: String?
  /// The stored website that made the login match. `nil` for a login that does
  /// not match the page. The app asks the user to confirm before filling one.
  let matched: Matched?
  /// The login has a one-time code.
  let hasTotp: Bool

  /// The stored website that made the login match, and how.
  struct Matched: Decodable, Hashable {
    let host: String
    /// `domain`, `host`, or `starts-with`.
    let kind: String

    init(host: String, kind: String = "domain") {
      self.host = host
      self.kind = kind
    }
  }

  init(
    recordID: String, title: String, username: String?, matched: Matched?,
    hasTotp: Bool = false
  ) {
    self.recordID = recordID
    self.title = title
    self.username = username
    self.matched = matched
    self.hasTotp = hasTotp
  }

  init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    recordID = try values.decode(String.self, forKey: .recordID)
    title = try values.decode(String.self, forKey: .title)
    username = try values.decodeIfPresent(String.self, forKey: .username)
    matched = try values.decodeIfPresent(Matched.self, forKey: .matched)
    hasTotp = try values.decodeIfPresent(Bool.self, forKey: .hasTotp) ?? false
  }

  var id: String { recordID }

  /// The account name the system and our list show. Falls back to the item
  /// title, since a credential identity with an empty user reads as blank.
  var accountName: String {
    guard let username, !username.isEmpty else { return title }
    return username
  }

  /// Why the login is listed, in words for the list.
  var reason: String {
    guard let matched else { return "Saved for another site" }
    switch matched.kind {
    case "host": return "Saved for \(matched.host) only"
    case "starts-with": return "Saved for pages on \(matched.host)"
    default: return "Matched \(matched.host)"
    }
  }

  enum CodingKeys: String, CodingKey {
    case recordID = "record_id"
    case title
    case username
    case matched
    case hasTotp = "has_totp"
  }
}

/// The logins for a page: the ones that match it, and the rest of the vaults
/// when the request asked for them.
struct LoginList {
  var matches: [Login]
  var others: [Login]
}

/// The values to fill, as the broker reports them.
struct LoginFill {
  let username: String?
  let password: String
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
    case .failed(let message): return message
    }
  }
}

/// Speaks the app broker's protocol over its Mach service: one request message
/// carrying the request JSON, one reply message carrying the response JSON. See
/// crates/core/src/core/app_broker/mach.rs for the message layout.
///
/// The service is named under the App Group, which is what lets a sandboxed
/// extension look it up. The lookup touches no files.
///
/// Every request may block on a Touch ID prompt in the app, so calls run off
/// the main actor and the reply wait carries a timeout matching the app's own.
struct BrokerClient {
  /// How long to wait for the app to answer. The app gives the user 120s to
  /// respond to a prompt, so anything shorter would give up mid-prompt.
  private static let timeout: TimeInterval = 130

  /// The app's Mach service. Matches `autofill_service_name` in
  /// crates/core/src/core/app_broker/mod.rs.
  static let serviceName = "\(appGroupIdentifier).broker"

  /// Whether the app is serving the broker right now.
  static var isAvailable: Bool {
    guard let service = lookUpService() else { return false }
    mach_port_deallocate(mach_task_self_, service)
    return true
  }

  /// Ask the app for the logins that match `service`, the domain or URL the
  /// system gave us. The system supplies no separate top-level page, so the
  /// service stands for both. `requester` names the app that asked, and is
  /// `nil` for a browser. With `all`, the other logins in the vaults come back
  /// too, so a login that failed to match can still be picked.
  static func logins(
    service: String, requester: String? = nil, all: Bool = false
  ) async throws -> LoginList {
    var request: [String: Any] = [
      "request": "list_logins", "url": service, "frame_url": service, "all": all,
    ]
    if let requester { request["requester"] = requester }
    let response = try await send(request)
    guard response["status"] as? String == "logins" else {
      throw error(from: response, fallback: "Unexpected response to the login listing.")
    }
    let decoder = JSONDecoder()
    func decode(_ key: String) throws -> [Login] {
      let data = try JSONSerialization.data(withJSONObject: response[key] ?? [])
      return try decoder.decode([Login].self, from: data)
    }
    return LoginList(matches: try decode("logins"), others: try decode("others"))
  }

  /// Ask the app for one login's username and password. The app checks the
  /// record against `service` again and prompts every time. `account` is only
  /// the label the prompt shows. `unmatched` says the login came from the list
  /// of logins that do not match the page, which the app asks the user to
  /// confirm.
  static func fill(
    service: String, recordID: String, account: String, unmatched: Bool = false,
    requester: String? = nil
  ) async throws -> LoginFill {
    var request: [String: Any] = [
      "request": "fill_login", "url": service, "frame_url": service, "record_id": recordID,
      "account": account, "unmatched": unmatched,
    ]
    if let requester { request["requester"] = requester }
    let response = try await send(request)
    guard response["status"] as? String == "login_fill" else {
      throw error(from: response, fallback: "Unexpected response to the fill.")
    }
    guard let password = response["password"] as? String else {
      throw BrokerError.failed("That login no longer has a password.")
    }
    return LoginFill(username: response["username"] as? String, password: password)
  }

  /// Ask the app for the current one-time code of one login. The app checks the
  /// record against `service` again and prompts every time.
  static func totp(
    service: String, recordID: String, requester: String? = nil
  ) async throws -> String {
    var request: [String: Any] = [
      "request": "generate_totp", "url": service, "frame_url": service, "record_id": recordID,
    ]
    if let requester { request["requester"] = requester }
    let response = try await send(request)
    guard response["status"] as? String == "totp_code" else {
      throw error(from: response, fallback: "Unexpected response to the code request.")
    }
    guard let code = (response["code"] as? [String: Any])?["code"] as? String else {
      throw BrokerError.failed("That login has no one-time code.")
    }
    return code
  }

  /// One or two PRF values. As input these are the page values, which the app
  /// hashes. As output they are the 32-byte PRF results.
  struct PRFValues {
    let first: Data
    let second: Data?
  }

  /// PRF input of a passkey registration. Its presence asks whether PRF is
  /// supported. `values` also asks for results.
  struct PRFRegistrationInput {
    let values: PRFValues?
  }

  /// PRF input of a passkey assertion. A per-credential entry for the signing
  /// passkey takes precedence over `values`.
  struct PRFAssertionInput {
    let values: PRFValues?
    let perCredential: [Data: PRFValues]
  }

  /// PRF output of a passkey registration.
  struct PRFRegistrationOutput {
    let enabled: Bool
    let results: PRFValues?
  }

  /// One registered passkey, as the broker reports it.
  struct Registration {
    let credentialID: Data
    let attestationObject: Data
    /// Present when the request carried PRF input.
    let prf: PRFRegistrationOutput?
  }

  /// One passkey assertion, as the broker reports it.
  struct Assertion {
    let credentialID: Data
    let userHandle: Data
    let authenticatorData: Data
    let signature: Data
    /// Present when the request carried PRF input and the passkey supports
    /// PRF.
    let prf: PRFValues?
  }

  /// Ask the app to register a passkey against an unlocked vault. Prompts every
  /// time.
  static func registerPasskey(
    rpID: String, rpName: String?, userHandle: Data, userName: String, userDisplayName: String,
    clientDataHash: Data, algorithms: [Int], excludedCredentials: [Data],
    prf: PRFRegistrationInput? = nil
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
    if let prf {
      var input: [String: Any] = [:]
      if let values = prf.values { input["eval"] = encode(values) }
      request["prf"] = input
    }
    let response = try await send(request)
    guard response["status"] as? String == "passkey_registered" else {
      throw error(from: response, fallback: "Unexpected response to the passkey registration.")
    }
    guard let credentialID = decodeBase64(response["credential_id"]),
      let attestationObject = decodeBase64(response["attestation_object"])
    else {
      throw BrokerError.failed("The passkey registration response was incomplete.")
    }
    let prfOutput = (response["prf"] as? [String: Any]).map { output in
      PRFRegistrationOutput(
        enabled: output["enabled"] as? Bool ?? false,
        results: decodePRF(output["results"]))
    }
    return Registration(
      credentialID: credentialID, attestationObject: attestationObject, prf: prfOutput)
  }

  /// Ask the app to sign an assertion challenge with a stored passkey. Prompts
  /// every time. With `chooseAccount`, the app asks the user to pick an account
  /// after the vaults unlock, if several passkeys match.
  static func assertPasskey(
    rpID: String, clientDataHash: Data, allowedCredentialIDs: [Data],
    chooseAccount: Bool = false, prf: PRFAssertionInput? = nil
  ) async throws -> Assertion {
    var request: [String: Any] = [
      "request": "assert_passkey",
      "rp_id": rpID,
      "client_data_hash": clientDataHash.base64EncodedString(),
      "allowed_credentials": allowedCredentialIDs.map { $0.base64EncodedString() },
      "choose_account": chooseAccount,
    ]
    if let prf {
      var input: [String: Any] = [:]
      if let values = prf.values { input["eval"] = encode(values) }
      input["eval_by_credential"] = prf.perCredential.map { credentialID, values in
        var entry = encode(values)
        entry["credential_id"] = credentialID.base64EncodedString()
        return entry
      }
      request["prf"] = input
    }
    let response = try await send(request)
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
      signature: signature,
      prf: decodePRF(response["prf"]))
  }

  /// Ask the app for the passkeys of `rpID` from its index. Raises no prompt.
  /// `nil` means the app has not indexed since it started.
  static func passkeys(rpID: String) async throws -> [PasskeyAccount]? {
    let response = try await send(["request": "list_passkeys", "rp_id": rpID])
    guard response["status"] as? String == "passkeys" else {
      throw error(from: response, fallback: "Unexpected response to the passkey listing.")
    }
    guard response["indexed"] as? Bool == true else { return nil }
    let entries = response["passkeys"] as? [[String: Any]] ?? []
    return entries.compactMap { entry in
      guard let credentialID = decodeBase64(entry["credential_id"]) else { return nil }
      return PasskeyAccount(
        credentialID: credentialID, userName: entry["user_name"] as? String ?? "")
    }
  }

  // MARK: - Site reports

  /// Relay a site report that it does not know a passkey. Raises no prompt.
  static func reportUnknownPasskey(rpID: String, credentialID: Data) async throws {
    try await report([
      "request": "report_unknown_passkey",
      "rp_id": rpID,
      "credential_id": credentialID.base64EncodedString(),
    ])
  }

  /// Relay the passkeys a site accepts for one account. Raises no prompt.
  static func reportAcceptedPasskeys(
    rpID: String, userHandle: Data, credentialIDs: [Data]
  ) async throws {
    try await report([
      "request": "report_accepted_passkeys",
      "rp_id": rpID,
      "user_handle": userHandle.base64EncodedString(),
      "credential_ids": credentialIDs.map { $0.base64EncodedString() },
    ])
  }

  /// Relay a new account name a site reported. Raises no prompt.
  static func reportPasskeyName(rpID: String, userHandle: Data, name: String) async throws {
    try await report([
      "request": "report_passkey_name",
      "rp_id": rpID,
      "user_handle": userHandle.base64EncodedString(),
      "name": name,
    ])
  }

  private static func report(_ request: [String: Any]) async throws {
    let response = try await send(request)
    guard response["status"] as? String == "acknowledged" else {
      throw error(from: response, fallback: "Unexpected response to the passkey report.")
    }
  }

  private static func encode(_ values: PRFValues) -> [String: Any] {
    var encoded: [String: Any] = ["first": values.first.base64EncodedString()]
    if let second = values.second { encoded["second"] = second.base64EncodedString() }
    return encoded
  }

  private static func decodePRF(_ value: Any?) -> PRFValues? {
    guard let values = value as? [String: Any], let first = decodeBase64(values["first"]) else {
      return nil
    }
    return PRFValues(first: first, second: decodeBase64(values["second"]))
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

  // Message layout and constants. Must match crates/core/src/core/app_broker/mach.rs
  // and the kernel's mach/message.h.
  private static let requestID: Int32 = 0x4158_5001
  private static let replyID: Int32 = 0x4158_5002
  /// Header (24 bytes), descriptor count (4), one out-of-line descriptor (16).
  private static let messageSize = 44
  /// Room for a reply and its trailer, or a send-once notification.
  private static let receiveBufferSize = 256
  private static let msgTypeCopySend: UInt32 = 19
  private static let msgTypeMakeSendOnce: UInt32 = 21
  private static let msghBitsComplex: UInt32 = 0x8000_0000
  private static let oolDescriptor: UInt8 = 1
  private static let virtualCopy: UInt8 = 1
  private static let sendMsg: mach_msg_option_t = 0x1
  private static let rcvMsg: mach_msg_option_t = 0x2
  private static let sendTimeout: mach_msg_option_t = 0x10
  private static let rcvTimeout: mach_msg_option_t = 0x100
  private static let rcvTimedOut: mach_msg_return_t = 0x1000_4003
  private static let portRightReceive: mach_port_right_t = 1

  /// `TASK_BOOTSTRAP_PORT` from mach/task_special_ports.h.
  private static let taskBootstrapPort: Int32 = 4

  private static func lookUpService() -> mach_port_t? {
    var bootstrap: mach_port_t = 0
    guard task_get_special_port(mach_task_self_, taskBootstrapPort, &bootstrap) == KERN_SUCCESS
    else { return nil }
    defer { mach_port_deallocate(mach_task_self_, bootstrap) }

    var service: mach_port_t = 0
    let kr = serviceName.withCString { name in
      axo_bootstrap_look_up(bootstrap, name, &service)
    }
    return kr == KERN_SUCCESS ? service : nil
  }

  /// Send one request and wait for its reply. Blocking, so it runs off the main
  /// actor.
  private static func exchange(_ payload: Data) throws -> Data {
    guard let service = lookUpService() else { throw BrokerError.unavailable }
    defer { mach_port_deallocate(mach_task_self_, service) }

    var reply: mach_port_t = 0
    guard mach_port_allocate(mach_task_self_, portRightReceive, &reply) == KERN_SUCCESS else {
      throw BrokerError.failed("Could not create a reply port.")
    }
    // Destroying the reply port is also how the app learns we gave up: its
    // right to the port turns into a dead name, which ends the prompt.
    defer { mach_port_mod_refs(mach_task_self_, reply, portRightReceive, -1) }

    try send(payload, to: service, replyTo: reply)
    return try receiveReply(on: reply)
  }

  private static func send(_ payload: Data, to service: mach_port_t, replyTo reply: mach_port_t)
    throws
  {
    let message = UnsafeMutableRawPointer.allocate(byteCount: messageSize, alignment: 8)
    defer { message.deallocate() }
    message.initializeMemory(as: UInt8.self, repeating: 0, count: messageSize)

    let kr = payload.withUnsafeBytes { bytes -> kern_return_t in
      let bits = msgTypeCopySend | (msgTypeMakeSendOnce << 8) | msghBitsComplex
      message.storeBytes(of: bits, toByteOffset: 0, as: UInt32.self)
      message.storeBytes(of: UInt32(messageSize), toByteOffset: 4, as: UInt32.self)
      message.storeBytes(of: service, toByteOffset: 8, as: UInt32.self)
      message.storeBytes(of: reply, toByteOffset: 12, as: UInt32.self)
      message.storeBytes(of: requestID, toByteOffset: 20, as: Int32.self)
      message.storeBytes(of: UInt32(1), toByteOffset: 24, as: UInt32.self)
      let address = UInt64(UInt(bitPattern: bytes.baseAddress))
      message.storeBytes(of: address, toByteOffset: 28, as: UInt64.self)
      message.storeBytes(of: virtualCopy, toByteOffset: 37, as: UInt8.self)
      message.storeBytes(of: oolDescriptor, toByteOffset: 39, as: UInt8.self)
      message.storeBytes(of: UInt32(bytes.count), toByteOffset: 40, as: UInt32.self)
      return mach_msg(
        message.assumingMemoryBound(to: mach_msg_header_t.self), sendMsg | sendTimeout,
        mach_msg_size_t(messageSize), 0, mach_port_name_t(MACH_PORT_NULL), 5000,
        mach_port_name_t(MACH_PORT_NULL))
    }
    guard kr == KERN_SUCCESS else { throw BrokerError.unavailable }
  }

  private static func receiveReply(on reply: mach_port_t) throws -> Data {
    let buffer = UnsafeMutableRawPointer.allocate(byteCount: receiveBufferSize, alignment: 8)
    defer { buffer.deallocate() }
    buffer.initializeMemory(as: UInt8.self, repeating: 0, count: receiveBufferSize)
    let header = buffer.assumingMemoryBound(to: mach_msg_header_t.self)

    let kr = mach_msg(
      header, rcvMsg | rcvTimeout, 0, mach_msg_size_t(receiveBufferSize), reply,
      mach_msg_timeout_t(timeout * 1000), mach_port_name_t(MACH_PORT_NULL))
    if kr == rcvTimedOut { throw BrokerError.failed("Axo Pass did not answer in time.") }
    guard kr == KERN_SUCCESS else { throw BrokerError.failed("The app closed the connection.") }

    let bits = buffer.loadUnaligned(fromByteOffset: 0, as: UInt32.self)
    let id = buffer.loadUnaligned(fromByteOffset: 20, as: Int32.self)
    let count = buffer.loadUnaligned(fromByteOffset: 24, as: UInt32.self)
    let kind = buffer.loadUnaligned(fromByteOffset: 39, as: UInt8.self)
    guard id == replyID, bits & msghBitsComplex != 0, count == 1, kind == oolDescriptor else {
      // A send-once notification in place of the reply: the app dropped the
      // request, because it refused this extension or could not read it.
      mach_msg_destroy(header)
      throw BrokerError.failed("Axo Pass refused the request.")
    }

    let address = buffer.loadUnaligned(fromByteOffset: 28, as: UInt64.self)
    let size = buffer.loadUnaligned(fromByteOffset: 40, as: UInt32.self)
    guard size > 0, let bytes = UnsafeRawPointer(bitPattern: UInt(address)) else {
      throw BrokerError.failed("The app sent an empty response.")
    }
    let data = Data(bytes: bytes, count: Int(size))
    vm_deallocate(mach_task_self_, vm_address_t(address), vm_size_t(size))
    return data
  }
}
