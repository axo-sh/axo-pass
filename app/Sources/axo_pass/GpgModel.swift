import AxoPassFFI
import Foundation
import Observation

@Observable
@MainActor
final class GpgModel {
  // Doesn't touch vault state, so this can be an independent AxoPass
  // instance rather than sharing VaultsModel's.
  private let core = AxoPass()

  enum TestResult {
    case success
    case failure(String)
  }

  var keys: [GpgKeyEntry] = []
  /// Fingerprint of the key shown in the detail pane.
  var selectedFingerprint: String? = nil
  var passwords: [PasswordEntryInfo] = []
  var loadError: String? = nil
  var isLoading = false
  var isTesting = false
  var testResult: TestResult? = nil

  /// State of the `pinentry-program` line in `gpg-agent.conf`.
  var confStatus: GpgAgentConfStatus? = nil
  var isConfiguring = false
  var configureError: String? = nil

  var selectedKey: GpgKeyEntry? {
    guard let selectedFingerprint else { return nil }
    return keys.first { $0.fingerprint == selectedFingerprint }
  }

  var secretKeys: [GpgKeyEntry] { keys.filter { $0.secretState != .none } }
  var publicOnlyKeys: [GpgKeyEntry] { keys.filter { $0.secretState == .none } }

  /// Saved GPG passphrases whose keygrip belongs to no key in the keyring.
  var orphanedPasswords: [PasswordEntryInfo] {
    let knownKeygrips = Set(keys.flatMap(keygrips(of:)))
    return passwords.filter { $0.passwordType == .gpgKey && !knownKeygrips.contains($0.keyId) }
  }

  func reload() async {
    isLoading = true
    refreshConfStatus()
    do {
      keys = try await core.listGpgKeys()
      loadError = nil
    } catch {
      keys = []
      loadError = String(describing: error)
    }
    passwords = (try? await core.listPasswords()) ?? []
    if let selectedFingerprint, !keys.contains(where: { $0.fingerprint == selectedFingerprint }) {
      self.selectedFingerprint = nil
    }
    isLoading = false
  }

  /// Pick up edits made in the terminal, cheap enough to run whenever the pane appears or the app
  /// is reactivated.
  func refreshConfStatus() {
    confStatus = core.checkGpgAgentConf()
  }

  func configureAgentConf() async {
    isConfiguring = true
    configureError = nil
    testResult = nil
    do {
      confStatus = try await core.configureGpgAgentConf()
    } catch {
      configureError = String(describing: error)
    }
    isConfiguring = false
  }

  func testIntegration() async {
    isTesting = true
    testResult = nil
    do {
      try await core.gpgTestIntegration()
      testResult = .success
    } catch {
      testResult = .failure(String(describing: error))
    }
    isTesting = false
  }

  /// The key's public half in ASCII armor. Returns nil and sets `loadError`
  /// when gpg cannot export it.
  func exportPublicKey(fingerprint: String) async -> String? {
    do {
      return try await core.exportGpgPublicKey(fingerprint: fingerprint)
    } catch {
      loadError = String(describing: error)
      return nil
    }
  }

  /// The keygrips a key is known by: the primary key's and each subkey's.
  /// gpg-agent names a key by keygrip, so keychain entries and audit events
  /// use them rather than the fingerprint.
  func keygrips(of key: GpgKeyEntry) -> [String] {
    var grips: [String] = []
    if let keygrip = key.keygrip { grips.append(keygrip) }
    grips.append(contentsOf: key.subkeys.compactMap(\.keygrip))
    return grips
  }

  /// Save the passphrase for one keygrip, after gpg has checked it. Returns
  /// nil on success, or a message describing why gpg would not take it.
  func savePassphrase(keyId: String, keygrip: String, passphrase: String) async -> String? {
    do {
      try await core.saveGpgKeyPassword(keyId: keyId, keygrip: keygrip, password: passphrase)
      await reload()
      return nil
    } catch {
      return Self.message(for: error)
    }
  }

  /// Delete one keygrip's saved passphrase.
  @discardableResult
  func forgetPassphrase(keygrip: String) async -> Bool {
    do {
      try await core.deletePassword(passwordType: .gpgKey, keyId: keygrip)
      await reload()
      return true
    } catch {
      loadError = Self.message(for: error)
      return false
    }
  }

  /// An error's text without the case name wrapped around it: this one is read
  /// by the user, who typed the passphrase gpg just refused.
  private static func message(for error: Error) -> String {
    switch error {
    case let error as FfiError:
      switch error {
      case .NotFound(let message), .InvalidInput(let message), .Internal(let message):
        return message
      default:
        return error.localizedDescription
      }
    default:
      return String(describing: error)
    }
  }

  @discardableResult
  func delete(_ entry: PasswordEntryInfo) async -> Bool {
    do {
      try await core.deletePassword(passwordType: entry.passwordType, keyId: entry.keyId)
      await reload()
      return true
    } catch {
      loadError = String(describing: error)
      return false
    }
  }

  /// The most recent GPG audit events for one key, newest first. Events name
  /// their key by keygrip, and the reader matches the query against the
  /// subject id, so this runs one query per keygrip and merges the results.
  func recentEvents(for key: GpgKeyEntry, limit: UInt32) async -> [AuditLogRow] {
    var rows: [AuditLogRow] = []
    for keygrip in keygrips(of: key) {
      let filter = AuditFilterInput(
        sinceRfc3339: nil,
        untilRfc3339: nil,
        actions: AuditActionGroup.gpg.actions,
        sources: [],
        outcomes: [],
        query: keygrip,
        limit: limit,
        offset: 0
      )
      guard let events = try? await core.listAuditEvents(filter: filter) else { continue }
      rows.append(contentsOf: events.map(AuditLogRow.init))
    }
    rows.sort { $0.record.at > $1.record.at }
    return Array(rows.prefix(Int(limit)))
  }
}
