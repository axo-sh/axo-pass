import AxoPassFFI
import Foundation
import Observation

/// Backs the Keychain window. The window is only opened while the app is
/// unlocked, but the core does not gate these reads on vault state, so this owns
/// its own `AxoPass` handle like `AuditLogModel` does.
@Observable
@MainActor
final class KeychainModel {
  private let core = AxoPass()

  var passwords: [SavedPasswordRow] = []
  var managedKeys: [ManagedKeyRow] = []
  var isLoading = false
  var loadError: String? = nil

  func reload() async {
    guard !isLoading else { return }
    isLoading = true
    defer { isLoading = false }
    do {
      async let passwordsResult = core.listPasswords()
      async let keysResult = core.listSshKeys()
      passwords = try await passwordsResult.map(SavedPasswordRow.init)
      managedKeys = try await keysResult.filter { $0.isManaged }.map(ManagedKeyRow.init)
      loadError = nil
    } catch {
      loadError = String(describing: error)
    }
  }
}

/// One saved generic password, with a stable identity for `Table`.
struct SavedPasswordRow: Identifiable, Hashable {
  let entry: PasswordEntryInfo

  init(_ entry: PasswordEntryInfo) { self.entry = entry }

  static func == (lhs: SavedPasswordRow, rhs: SavedPasswordRow) -> Bool { lhs.id == rhs.id }
  func hash(into hasher: inout Hasher) { hasher.combine(id) }

  var id: String { "\(typeText):\(entry.keyId)" }

  var keyId: String { entry.keyId }

  var typeText: String {
    switch entry.passwordType {
    case .gpgKey: return "GPG key"
    case .sshKey: return "SSH key"
    case .ageKey: return "age key"
    case .other: return "Other"
    }
  }

  var account: String {
    switch entry.passwordType {
    case .gpgKey: return "gpg-key-\(entry.keyId)"
    case .sshKey: return "ssh-key-\(entry.keyId)"
    case .ageKey: return "age-key-\(entry.keyId)"
    case .other: return entry.keyId
    }
  }
}

/// One managed Secure Enclave key, with a stable identity for `Table`.
struct ManagedKeyRow: Identifiable, Hashable {
  let entry: SshKeyEntry

  init(_ entry: SshKeyEntry) { self.entry = entry }

  static func == (lhs: ManagedKeyRow, rhs: ManagedKeyRow) -> Bool { lhs.id == rhs.id }
  func hash(into hasher: inout Hasher) { hasher.combine(id) }

  var id: String { entry.fingerprintSha256 }

  var label: String { entry.comment ?? entry.name }

  var fingerprintSha256: String { entry.fingerprintSha256 }

  var fingerprintMd5: String { entry.fingerprintMd5 }

  var publicKeyOpenssh: String? { entry.publicKeyOpenssh }
}
