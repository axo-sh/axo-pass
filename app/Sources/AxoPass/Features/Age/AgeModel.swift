import AxoPassFFI
import Foundation
import Observation

@Observable
@MainActor
final class AgeModel {
  // age keys don't touch vault state, so this can be an independent AxoPass
  // instance rather than sharing VaultsModel's.
  private let core = AxoPass()

  var keys: [AgeKeyEntry] = []
  /// Recipient of the key shown in the detail pane.
  var selectedRecipient: String? = nil
  var loadError: String? = nil
  var isLoading = false
  /// Set if a reload found the app authentication expired. The main view locks
  /// the app in response.
  private(set) var authExpired = false

  var selectedKey: AgeKeyEntry? {
    guard let selectedRecipient else { return nil }
    return keys.first { $0.recipient == selectedRecipient }
  }

  func reload() async {
    isLoading = true
    do {
      keys = try await core.listAgeKeys()
      loadError = nil
    } catch FfiError.AuthExpired {
      keys = []
      authExpired = true
    } catch {
      keys = []
      loadError = String(describing: error)
    }
    if let selectedRecipient, !keys.contains(where: { $0.recipient == selectedRecipient }) {
      self.selectedRecipient = nil
    }
    isLoading = false
  }

  @discardableResult
  func generateKey(name: String) async -> Bool {
    do {
      let key = try await core.generateAgeKey(name: name)
      await reload()
      selectedRecipient = key.recipient
      return true
    } catch {
      loadError = String(describing: error)
      return false
    }
  }

  @discardableResult
  func deleteKey(name: String) async -> Bool {
    do {
      try await core.deleteAgeKey(name: name)
      await reload()
      return true
    } catch {
      loadError = String(describing: error)
      return false
    }
  }

  /// Read a key's secret identity back from the keychain on the app unlock.
  /// Does not prompt. Returns nil and sets `loadError` on failure.
  func revealSecret(name: String) async -> String? {
    do {
      return try await core.revealKeyPassword(passwordType: .ageKey, keyId: name)
    } catch {
      loadError = String(describing: error)
      return nil
    }
  }

  /// The most recent age audit events for one key, newest first. Events name
  /// their key by the identity name or recipient, matched against the subject
  /// id by the reader's query.
  func recentEvents(name: String, limit: UInt32) async -> [AuditLogRow] {
    let filter = AuditFilterInput(
      sinceRfc3339: nil,
      untilRfc3339: nil,
      actions: [],
      categories: [.age],
      kind: nil,
      requesters: [],
      outcomes: [],
      query: name,
      detailId: nil,
      limit: limit,
      offset: 0
    )
    guard let events = try? await core.listAuditEvents(filter: filter) else { return [] }
    return events.map(AuditLogRow.init)
  }
}
