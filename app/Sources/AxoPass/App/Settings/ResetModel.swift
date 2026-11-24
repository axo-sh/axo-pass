import AppKit
import AxoPassFFI
import Observation
import SwiftUI

/// Runs the resets of Settings. Each asks for user presence, deletes state in
/// the core, clears the preferences, and quits, so the next launch starts from
/// what is left.
@Observable
@MainActor
final class ResetModel {
  enum Kind {
    /// Preferences, approvals, and protected settings. Sync and first run are
    /// kept.
    case settings
    /// Everything on this Mac: vault files, device keys, Secure Enclave SSH
    /// keys, keychain passphrases, and the app configuration, as well as the
    /// settings.
    case eraseThisMac

    fileprivate var reason: String {
      switch self {
      case .settings: "reset the settings of Axo Pass"
      case .eraseThisMac: "erase all data from this Mac"
      }
    }
  }

  private(set) var isWorking = false
  private(set) var error: String? = nil
  /// True once the reset is done and the app is about to quit. The erase sheet
  /// dismisses itself, since AppKit does not terminate while a sheet is open.
  private(set) var isFinished = false

  /// Run the reset `kind`. An erase with `sync` first turns off sync of every
  /// synced vault, so other devices list this Mac as left.
  func run(_ kind: Kind, core: AxoPass, sync: SyncModel? = nil) async {
    guard !isWorking else { return }
    isWorking = true
    error = nil
    defer { isWorking = false }

    do {
      guard try await UserPresence.confirm(core: core, reason: kind.reason) else { return }
    } catch {
      self.error = error.userMessage
      return
    }

    // Best effort. A vault whose turn-off fails, for example because the
    // synced folder is unreachable, stays listed on other devices until one
    // of them removes this Mac.
    if kind == .eraseThisMac, let sync {
      do {
        for failure in try await sync.leaveAll() {
          NSLog("Erase did not turn off sync: %@", failure)
        }
      } catch {
        NSLog("Erase did not turn off sync: %@", String(describing: error))
      }
    }

    // The launchd service restarts a stopped agent, so unregister it first.
    if kind == .eraseThisMac { await AgentService.shared.shutDownForErase() }
    do {
      try await Task.detached {
        switch kind {
        case .settings:
          try AxoPassFFI.resetSettings()
        case .eraseThisMac:
          // Stop sync first. A sync pass during the erase can write the open
          // vaults back to disk.
          AxoPassFFI.syncShutdown()
          try AxoPassFFI.eraseThisMac()
        }
      }.value
      switch kind {
      case .settings: Preferences.resetSettings()
      case .eraseThisMac: Preferences.resetAll()
      }
      quit()
    } catch {
      switch kind {
      case .settings:
        self.error = error.userMessage
      case .eraseThisMac:
        quitAfterFailedErase(error)
      }
    }
  }

  /// Report a failed erase and quit. Part of the state may already be
  /// deleted, and sync and the SSH agent are stopped, so the app does not
  /// keep running.
  private func quitAfterFailedErase(_ error: Error) {
    let alert = NSAlert()
    alert.alertStyle = .critical
    alert.messageText = "Erase Did Not Finish"
    alert.informativeText =
      "\(error.userMessage)\n\nSome data on this Mac may already be deleted. Axo Pass quits now. Open it again and choose Erase This Mac to finish."
    alert.addButton(withTitle: "Quit")
    alert.runModal()
    quit()
  }

  /// Quit after a reset. AppKit aborts a terminate request while a window has
  /// an attached sheet, and the erase sheet is still open here. End the
  /// sheets and terminate once they are gone. Exit the process directly if
  /// that has not happened after a few seconds. The reset leaves nothing to
  /// save.
  private func quit() {
    isFinished = true
    DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
      NSLog("Quit after reset did not finish, exiting")
      exit(0)
    }
    Self.terminateWhenSheetsAreGone()
  }

  private static func terminateWhenSheetsAreGone() {
    if NSApp.windows.contains(where: { $0.attachedSheet != nil }) {
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { terminateWhenSheetsAreGone() }
    } else {
      NSApp.terminate(nil)
    }
  }
}

/// Confirmation of "Erase This Mac". Lists the data that the erase deletes,
/// warns about data that nothing restores, and asks for a typed phrase.
struct EraseThisMacSheet: View {
  let reset: ResetModel
  @Environment(VaultsModel.self) private var model
  @Environment(SyncModel.self) private var sync
  @Environment(\.dismiss) private var dismiss
  @State private var typed = ""
  @State private var sshKeys: [SshKeyEntry] = []
  @State private var gpgKeys: [GpgKeyEntry] = []
  @State private var ageKeys: [AgeKeyEntry] = []
  @State private var expanded: Set<EraseGroup.Kind> = []

  /// Phrase the user types to confirm. Case and surrounding spaces are
  /// ignored.
  private static let phrase = "I understand my data cannot be recovered"

  private var isConfirmed: Bool {
    typed.trimmingCharacters(in: .whitespaces).lowercased() == Self.phrase.lowercased()
  }

  private func isSynced(_ vault: VaultInfo) -> Bool {
    sync.state(vault.key)?.isOn == true
  }

  private var hasUnsynced: Bool {
    model.vaults.contains { !isSynced($0) }
  }

  private var enclaveKeys: [SshKeyEntry] {
    sshKeys.filter(\.isManaged)
  }

  private var sshPassphrases: [SshKeyEntry] {
    sshKeys.filter { !$0.isManaged && $0.hasSavedPassword }
  }

  private var gpgPassphrases: [GpgKeyEntry] {
    gpgKeys.filter { key in key.hasSavedPassword || key.subkeys.contains(where: \.hasSavedPassword)
    }
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Erase This Mac?")
        .font(.headline)
      Text(
        """
        Delete all Axo Pass settings and data from this Mac. Sync turns off first, so your other \
        devices list this Mac as left. Synced vaults can be restored by pairing or with a \
        recovery kit. Axo Pass will quit after erase.
        """
      )
      Text(
        """
        The erase does not edit your config files. Remove the Axo Pass lines from \
        ~/.ssh/config, ~/.gnupg/gpg-agent.conf, and ~/.zshrc yourself if you added them.
        """
      )
      if hasUnsynced {
        Text(
          """
          Some vaults are not synced, and cannot be restored after the erase. If you want to \
          keep these vaults, you'll have to export them first.
          """
        )
        .foregroundStyle(.red)
      }
      groups
      // The phrase is a label, since a placeholder is hidden while typing.
      VStack(alignment: .leading, spacing: 6) {
        Text("To confirm, type \"\(Self.phrase)\":")
        TextField("", text: $typed)
          .textFieldStyle(.roundedBorder)
          .autocorrectionDisabled()
          .disabled(reset.isWorking)
      }
      if let error = reset.error {
        Text(error)
          .foregroundStyle(.red)
      }
      HStack {
        if reset.isWorking {
          ProgressView()
            .controlSize(.small)
          Text("Deleting data…")
            .foregroundStyle(.secondary)
        }
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }
          .keyboardShortcut(.cancelAction)
          .disabled(reset.isWorking)
        Button("Erase This Mac", role: .destructive) {
          Task { await reset.run(.eraseThisMac, core: model.core, sync: sync) }
        }
        .disabled(!isConfirmed || reset.isWorking)
      }
    }
    .fixedSize(horizontal: false, vertical: true)
    .padding(20)
    .frame(width: 440)
    .task { await load() }
    .onChange(of: reset.isFinished) {
      if reset.isFinished { dismiss() }
    }
  }

  /// Groups of the data that the erase deletes. Empty groups are hidden.
  @ViewBuilder
  private var groups: some View {
    let rows: [(EraseGroup.Kind, [EraseGroup.Row])] = [
      (
        .vaults,
        model.vaults.map {
          EraseGroup.Row(
            id: $0.key, title: $0.name ?? $0.key,
            detail: isSynced($0) ? "Synced" : "Not synced",
            detailColor: isSynced($0) ? .secondary : .red)
        }
      ),
      (
        .sshKeys,
        enclaveKeys.map {
          EraseGroup.Row(
            id: $0.fingerprintSha256, title: Self.enclaveKeyTitle($0),
            tag: Self.sshTag($0), detail: sshKeyTypeLabel($0.keyType))
        }
      ),
      (
        .sshPassphrases,
        sshPassphrases.map {
          EraseGroup.Row(id: $0.fingerprintSha256, title: $0.name, tag: Self.sshTag($0))
        }
      ),
      (
        .gpgPassphrases,
        gpgPassphrases.map {
          EraseGroup.Row(
            id: $0.fingerprint, title: $0.name, tag: String($0.fingerprint.prefix(6)),
            detail: $0.email)
        }
      ),
      (.ageKeys, ageKeys.map { EraseGroup.Row(id: $0.name, title: $0.name) }),
    ]
    let shown = rows.filter { !$0.1.isEmpty }
    if !shown.isEmpty {
      TodayCard {
        ForEach(Array(shown.enumerated()), id: \.element.0) { index, group in
          if index > 0 {
            Divider()
          }
          EraseGroup(
            kind: group.0, rows: group.1,
            isExpanded: expanded.contains(group.0),
            onToggle: {
              if !expanded.insert(group.0).inserted { expanded.remove(group.0) }
            })
        }
      }
    }
  }

  /// Title of a Secure Enclave key. Comment if set, otherwise the start of the
  /// key id, which is a UUID.
  private static func enclaveKeyTitle(_ key: SshKeyEntry) -> String {
    if let comment = key.comment, !comment.isEmpty, comment != key.name { return comment }
    return "Key \(key.name.prefix(8))"
  }

  /// First characters of the SHA256 fingerprint. Matches the key tags of the
  /// Activity pane.
  private static func sshTag(_ key: SshKeyEntry) -> String {
    let prefix = "SHA256:"
    let id = key.fingerprintSha256
    return String((id.hasPrefix(prefix) ? id.dropFirst(prefix.count) : id[...]).prefix(6))
  }

  /// Load sync states and the keys to list. A list that fails to load is
  /// left empty. Age keys fail to load if the app is locked.
  private func load() async {
    await sync.reloadAll()
    async let ssh = try? model.core.listSshKeys()
    async let gpg = try? model.core.listGpgKeys()
    async let age = try? model.core.listAgeKeys()
    sshKeys = await ssh ?? []
    gpgKeys = await gpg ?? []
    ageKeys = await age ?? []
  }
}

/// Expandable group of the Erase This Mac sheet. Matches the merged rows of
/// the Activity pane.
private struct EraseGroup: View {
  enum Kind: Hashable {
    case vaults, sshKeys, sshPassphrases, gpgPassphrases, ageKeys

    var title: String {
      switch self {
      case .vaults: "Vaults"
      case .sshKeys: "Secure Enclave SSH Keys"
      case .sshPassphrases: "SSH Passphrases"
      case .gpgPassphrases: "GPG Passphrases"
      case .ageKeys: "Age Keys"
      }
    }

    /// Consequence of the erase for this group, shown above the expanded rows.
    var note: String? {
      switch self {
      case .vaults: nil
      case .sshKeys:
        "These keys cannot be restored. Servers that use them will need a new key."
      case .sshPassphrases: "SSH will ask for these passphrases again."
      case .gpgPassphrases: "GPG will ask for these passphrases again."
      case .ageKeys:
        "Files encrypted using these keys will no longer be decryptable unless you have a copy of the key elsewhere."
      }
    }

    var style: UsedTodayKind {
      switch self {
      case .vaults: .vault
      case .sshKeys, .sshPassphrases: .sshKey
      case .gpgPassphrases: .gpgKey
      case .ageKeys: .ageIdentity
      }
    }
  }

  struct Row: Identifiable {
    let id: String
    let title: String
    /// Short key id, shown as a `KeyIdTag`.
    var tag: String? = nil
    var detail: String? = nil
    var detailColor: Color = .secondary
  }

  let kind: Kind
  let rows: [Row]
  let isExpanded: Bool
  let onToggle: () -> Void

  var body: some View {
    Button(action: onToggle) {
      HStack(spacing: 12) {
        TodayIcon(
          symbol: UsedTodayStyle.symbol(kind.style), color: UsedTodayStyle.color(kind.style))
        Text(kind.title)
        Text("\(rows.count)")
          .font(.caption)
          .monospacedDigit()
          .foregroundStyle(.secondary)
          .padding(.horizontal, 6)
          .padding(.vertical, 1)
          .background(.quaternary, in: Capsule())
          .fixedSize()
        Spacer(minLength: 12)
        Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
          .font(.caption)
          .foregroundStyle(.secondary)
          .frame(width: 12)
      }
      .padding(.horizontal, 14)
      .padding(.vertical, 10)
      .contentShape(.rect)
    }
    .buttonStyle(.plain)
    .help(isExpanded ? "Hide details" : "Show details")

    if isExpanded {
      VStack(alignment: .leading, spacing: 0) {
        if let note = kind.note {
          Text(note)
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.leading, 14 + 28 + 12)
            .padding(.trailing, 14)
            .padding(.bottom, 6)
        }
        ForEach(rows) { row in
          HStack(spacing: 12) {
            HStack(spacing: 6) {
              Text(row.title)
                .lineLimit(1)
                .truncationMode(.tail)
              if let tag = row.tag {
                KeyIdTag(text: tag)
              }
            }
            Spacer(minLength: 12)
            if let detail = row.detail {
              Text(detail)
                .foregroundStyle(row.detailColor)
            }
            // Chevron width of the group row, so details line up.
            Color.clear.frame(width: 12, height: 1)
          }
          .font(.callout)
          .foregroundStyle(.secondary)
          .padding(.leading, 14 + 28 + 12)
          .padding(.trailing, 14)
          .padding(.vertical, 3)
        }
      }
      .padding(.top, -4)
      .padding(.bottom, 6)
    }
  }
}
