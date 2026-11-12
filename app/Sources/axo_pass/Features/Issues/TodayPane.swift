import AppKit
import AuthenticationServices
import AxoPassFFI
import SwiftUI

/// Home page of the app. Lists the issues with one fix button for each, then
/// the keys and credentials used today. Counted issues are listed under "Needs
/// you" and setup issues under "Not set up". Info issues are left out. If no
/// counted issue exists, a summary line lists the checks that pass.
struct TodayPane: View {
  let sshModel: SshModel
  let gpgModel: GpgModel

  @Environment(VaultsModel.self) private var vaults
  @Environment(SyncModel.self) private var sync
  @Environment(IssuesModel.self) private var issues
  @Environment(\.openSettings) private var openSettings
  @State private var shellModel = ShellIntegrationModel()
  @State private var usedToday = UsedTodayModel()
  @State private var sheet: TodaySheet? = nil

  var body: some View {
    let counted = issues.countedIssues
    let setup = issues.issues.filter { $0.severity == .setup }
    ScrollView {
      VStack(alignment: .leading, spacing: 0) {
        header
        if counted.isEmpty {
          TodaySectionHeader("Status")
          TodayCard { healthRow }
        } else {
          TodaySectionHeader(
            "Needs you", count: counted.count,
            tint: issues.worstSeverity == .broken ? .red : .orange)
          issueCard(counted)
        }
        if !setup.isEmpty {
          TodaySectionHeader("Not set up")
          issueCard(setup)
        }
        TodaySectionHeader("Used today")
        usedTodayCard
      }
      .padding(.horizontal, 32)
      .padding(.bottom, 32)
    }
    .paneBackground()
    .navigationTitle("Today")
    .task { await usedToday.reload() }
    // Uses happen while the app is in the background, so read them again on
    // each activation.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      Task { await usedToday.reload() }
    }
    .sheet(item: $sheet, onDismiss: refresh) { sheet in
      switch sheet {
      case .duplicateVaults:
        DuplicateVaultsSheet(
          duplicates: vaults.duplicateVaults, duplicateKeys: vaults.duplicateVaultKeys)
      case .sshSetup: SshSetupSheet(model: sshModel)
      case .shellSetup: ShellIntegrationSetupSheet(model: shellModel)
      case .gpgSetup: GpgSetupSheet(model: gpgModel)
      }
    }
    // Sync sheets are presented by the sidebar. Refresh after one closes.
    .onChange(of: sync.sheet?.id) { old, new in
      if old != nil && new == nil { refresh() }
    }
  }

  /// Page title with the date.
  private var header: some View {
    VStack(alignment: .leading, spacing: 2) {
      Text("Today")
        .font(.largeTitle)
        .fontWeight(.bold)
      Text(Date.now.formatted(.dateTime.weekday(.wide).month(.wide).day()))
        .foregroundStyle(.secondary)
    }
    .padding(.top, 24)
  }

  // MARK: - Status

  /// Summary of the checks that pass. Shown if no counted issue exists.
  private var healthRow: some View {
    let checks = passingChecks
    return HStack(spacing: 12) {
      TodayIcon(symbol: "checkmark", color: .green)
      VStack(alignment: .leading, spacing: 2) {
        Text("Nothing needs you")
          .fontWeight(.medium)
        if !checks.isEmpty {
          Text(checks.joined(separator: " · "))
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
      }
      Spacer(minLength: 0)
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
  }

  /// Checks that pass, in sidebar order. A check that has not run is left out.
  private var passingChecks: [String] {
    var list: [String] = []
    let synced = vaults.vaults.filter { sync.state($0.key)?.isOn == true }.count
    if synced > 0 {
      list.append(synced == 1 ? "1 vault synced" : "\(synced) vaults synced")
    }
    if issues.agentStatus == .running { list.append("SSH agent running") }
    if issues.sshConf?.state == .configured { list.append("ssh uses Axo Pass") }
    if issues.shell?.configured == true { list.append("ap set up in zsh") }
    if issues.gpgConf?.state == .configured { list.append("gpg uses Axo Pass") }
    if issues.autofillEnabled == true { list.append("AutoFill on") }
    return list
  }

  // MARK: - Used today

  @ViewBuilder
  private var usedTodayCard: some View {
    if let error = usedToday.loadError {
      TodayCard { TodayNoteRow(error, color: .red) }
    } else if usedToday.entries.isEmpty {
      TodayCard { TodayNoteRow("No keys or credentials used yet today.") }
    } else {
      TodayCard {
        ForEach(Array(usedToday.entries.enumerated()), id: \.element.id) { index, entry in
          if index > 0 {
            Divider()
          }
          usedRow(entry)
        }
      }
    }
  }

  @ViewBuilder
  private func usedRow(_ entry: UsedTodayEntry) -> some View {
    let content = HStack(spacing: 12) {
      TodayIcon(
        symbol: UsedTodayStyle.symbol(entry.displayKind),
        color: UsedTodayStyle.color(entry.displayKind))
      VStack(alignment: .leading, spacing: 2) {
        Text(entry.label)
          .fontWeight(.medium)
          .lineLimit(1)
          .truncationMode(.middle)
        Text(UsedTodayStyle.summary(entry))
          .font(.callout)
          .foregroundStyle(.secondary)
          .lineLimit(1)
      }
      Spacer(minLength: 12)
      VStack(alignment: .trailing, spacing: 2) {
        Text(entry.count == 1 ? "1 time" : "\(entry.count) times")
          .monospacedDigit()
        if let lastUsed = entry.lastUsed {
          Text(lastUsed.formatted(date: .omitted, time: .shortened))
            .font(.callout)
            .foregroundStyle(.secondary)
            .monospacedDigit()
        }
      }
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
    .contentShape(.rect)

    if canOpen(entry) {
      Button {
        open(entry)
      } label: {
        content
      }
      .buttonStyle(.plain)
      .help(entry.kind == .sshKey || entry.kind == .gpgKey ? "Show this key" : "Show this item")
    } else {
      content
    }
  }

  /// Whether the row opens a key or an item. SSH keys open by SHA256
  /// fingerprint and GPG keys by keygrip. Other entries open the item of the
  /// last use if the audit event recorded it.
  private func canOpen(_ entry: UsedTodayEntry) -> Bool {
    switch entry.kind {
    case .sshKey: return true
    case .gpgKey: return gpgFingerprint(keygrip: entry.subjectId) != nil
    default: return itemLocation(entry) != nil
    }
  }

  private func open(_ entry: UsedTodayEntry) {
    switch entry.kind {
    case .sshKey:
      // Audit events name the key as `SHA256:<hash>`. Key entries hold the
      // hash only.
      let prefix = "SHA256:"
      let id = entry.subjectId
      sshModel.selectedFingerprint = id.hasPrefix(prefix) ? String(id.dropFirst(prefix.count)) : id
      vaults.selectSidebarDestination(.ssh)
    case .gpgKey:
      gpgModel.selectedFingerprint = gpgFingerprint(keygrip: entry.subjectId)
      vaults.selectSidebarDestination(.gpg)
    default:
      guard let location = itemLocation(entry) else { return }
      Task { await vaults.showItem(vaultKey: location.vaultKey, itemId: location.itemId) }
    }
  }

  /// Vault key and short item id of the last use of `entry`. The vault is
  /// looked up by short id first, then by the recorded vault key.
  private func itemLocation(_ entry: UsedTodayEntry) -> (vaultKey: String, itemId: String)? {
    guard let itemId = entry.itemId else { return nil }
    let byId = entry.vaultId.flatMap { vaults.vaultKey(id: $0) }
    let byKey = entry.vaultKey.flatMap { key in vaults.vaults.contains { $0.key == key } ? key : nil
    }
    guard let vaultKey = byId ?? byKey else { return nil }
    return (vaultKey, itemId)
  }

  /// Fingerprint of the GPG key that holds `keygrip` as its primary key or a
  /// subkey.
  private func gpgFingerprint(keygrip: String) -> String? {
    issues.gpgKeys?.first { key in
      key.keygrip == keygrip || key.subkeys.contains { $0.keygrip == keygrip }
    }?.fingerprint
  }

  // MARK: - Issues

  /// Card of issue rows with dividers between rows.
  private func issueCard(_ list: [Issue]) -> some View {
    TodayCard {
      ForEach(Array(list.enumerated()), id: \.element.id) { index, issue in
        if index > 0 {
          Divider()
        }
        row(issue)
      }
    }
  }

  private func row(_ issue: Issue) -> some View {
    HStack(spacing: 12) {
      IssueSeverityIcon(severity: issue.severity)
      VStack(alignment: .leading, spacing: 2) {
        Text(issue.title)
          .fontWeight(.medium)
          .fixedSize(horizontal: false, vertical: true)
        if let detail = detail(issue) {
          Text(detail)
            .font(.callout)
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
        }
      }
      Spacer(minLength: 12)
      if let label = fixLabel(issue) {
        Button(label) { fix(issue) }
          .disabled(isFixing(issue))
      }
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
  }

  /// Second line of an issue row: an error message or the file to change. Nil
  /// if the title says enough.
  private func detail(_ issue: Issue) -> String? {
    switch issue {
    case .vaultLoadFailed(let message): return message
    case .syncUnreadable(_, let message): return message
    case .agentNotRunning: return sshModel.agentError
    case .identityAgentMissing(let configPath): return configPath
    case .shellIntegrationMissing(let zshrcPath): return zshrcPath
    case .pinentryMissing(let confPath): return confPath
    default: return nil
    }
  }

  /// Fix button label. Nil if the issue has no fix in the app.
  private func fixLabel(_ issue: Issue) -> String? {
    switch issue {
    case .vaultKeyState, .syncedVaultsMissing, .vaultFilesHidden: return "Show…"
    case .syncFolderNeeded, .syncStopped, .syncPaused, .syncUnreadable: return "Sync Status…"
    case .recoveryKitMissing: return "New Recovery Kit…"
    case .pairingRequests: return "Review…"
    case .agentNotRunning: return "Start"
    case .agentNeedsApproval: return "Open Login Items"
    case .identityAgentMissing, .shellIntegrationMissing, .pinentryMissing: return "Set Up…"
    case .gpgKeyExpiring, .gpgKeyExpired: return "Show Key"
    case .gpgOrphanedPassphrases: return "Show"
    case .autofillOff: return "Open System Settings"
    case .browserManifestMissing, .browserManifestBroken: return "Open Settings"
    case .vaultLoadFailed, .identityAgentOther, .pinentryOther, .browserManifestForeign: return nil
    }
  }

  private func isFixing(_ issue: Issue) -> Bool {
    if case .agentNotRunning = issue { return sshModel.isTogglingAgent }
    return false
  }

  private func fix(_ issue: Issue) {
    switch issue {
    case .vaultKeyState:
      sync.sheet = .keyState
    case .syncedVaultsMissing:
      sync.sheet = .missingVaults
    case .vaultFilesHidden:
      sheet = .duplicateVaults
    case .syncFolderNeeded(let vault), .syncStopped(let vault, _), .syncPaused(let vault, _),
      .syncUnreadable(let vault, _):
      sync.sheet = .status(vault)
    case .recoveryKitMissing(let vault):
      sync.sheet = .newKit(vault)
    case .pairingRequests(let root, _):
      sync.sheet = .pairingPrompt(root: root)
    case .agentNotRunning:
      Task {
        await sshModel.startAgent()
        await issues.refreshAll()
      }
    case .agentNeedsApproval:
      AgentService.shared.openLoginItemsSettings()
    case .identityAgentMissing:
      sshModel.refreshConfStatus()
      sheet = .sshSetup
    case .shellIntegrationMissing:
      shellModel.refreshStatus()
      sheet = .shellSetup
    case .pinentryMissing:
      gpgModel.refreshConfStatus()
      sheet = .gpgSetup
    case .gpgKeyExpiring(let key, _), .gpgKeyExpired(let key):
      gpgModel.selectedFingerprint = key.fingerprint
      vaults.selectSidebarDestination(.gpg)
    case .gpgOrphanedPassphrases:
      vaults.selectSidebarDestination(.gpg)
    case .autofillOff:
      ASSettingsHelper.openCredentialProviderAppSettings { _ in }
    case .browserManifestMissing, .browserManifestBroken:
      NSApp.activate(ignoringOtherApps: true)
      openSettings()
    case .vaultLoadFailed, .identityAgentOther, .pinentryOther, .browserManifestForeign:
      break
    }
  }

  private func refresh() {
    Task { await issues.refreshAll() }
  }
}

/// Fix sheet that the Today pane presents itself.
private enum TodaySheet: String, Identifiable {
  case duplicateVaults
  case sshSetup
  case shellSetup
  case gpgSetup

  var id: String { rawValue }
}

/// Uppercase section title of the Today page, with an optional count badge.
private struct TodaySectionHeader: View {
  let title: String
  let count: Int?
  let tint: Color

  init(_ title: String, count: Int? = nil, tint: Color = .secondary) {
    self.title = title
    self.count = count
    self.tint = tint
  }

  var body: some View {
    HStack(spacing: 8) {
      Text(title)
        .textCase(.uppercase)
        .kerning(0.6)
        .foregroundStyle(.secondary)
      if let count {
        Text("\(count)")
          .monospacedDigit()
          .foregroundStyle(tint)
          .padding(.horizontal, 6)
          .background(tint.opacity(0.18), in: Capsule())
      }
    }
    .font(.caption)
    .fontWeight(.semibold)
    .padding(.top, 24)
    .padding(.bottom, 8)
  }
}

/// Rounded card of the Today page.
private struct TodayCard<Content: View>: View {
  let content: Content

  init(@ViewBuilder content: () -> Content) {
    self.content = content()
  }

  var body: some View {
    VStack(spacing: 0) {
      content
    }
    .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    .overlay {
      RoundedRectangle(cornerRadius: 10)
        .strokeBorder(.separator)
    }
  }
}

/// One line of secondary text in a card.
private struct TodayNoteRow: View {
  let text: String
  let color: Color

  init(_ text: String, color: Color = .secondary) {
    self.text = text
    self.color = color
  }

  var body: some View {
    Text(text)
      .font(.callout)
      .foregroundStyle(color)
      .textSelection(.enabled)
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(.horizontal, 14)
      .padding(.vertical, 12)
  }
}

/// White symbol on a rounded square of `color`.
private struct TodayIcon: View {
  let symbol: String
  let color: Color

  var body: some View {
    Image(systemName: symbol)
      .font(.system(size: 13, weight: .semibold))
      .foregroundStyle(.white)
      .frame(width: 28, height: 28)
      .background(color, in: RoundedRectangle(cornerRadius: 7))
  }
}

/// Presentation of a used-today entry.
private enum UsedTodayStyle {
  static func symbol(_ kind: UsedTodayKind) -> String {
    switch kind {
    case .sshKey: return "key.horizontal.fill"
    case .gpgKey: return "signature"
    case .login: return "globe"
    case .passkey: return "person.badge.key.fill"
    case .credential: return "terminal.fill"
    case .item: return "doc.text.fill"
    case .vault: return "archivebox.fill"
    case .ageIdentity: return "lock.rectangle.stack.fill"
    }
  }

  static func color(_ kind: UsedTodayKind) -> Color {
    switch kind {
    case .sshKey: return .teal
    case .gpgKey: return .purple
    case .login, .passkey: return .green
    case .credential, .item: return .blue
    case .vault: return .gray
    case .ageIdentity: return .indigo
    }
  }

  static func kindLabel(_ kind: UsedTodayKind) -> String {
    switch kind {
    case .sshKey: return "SSH key"
    case .gpgKey: return "GPG key"
    case .login: return "Login"
    case .passkey: return "Passkey"
    case .credential: return "Credential"
    case .item: return "Item"
    case .vault: return "Vault"
    case .ageIdentity: return "age identity"
    }
  }

  /// Past-tense verb of an access action.
  static func verb(_ action: String) -> String {
    switch action {
    case "ssh.sign": return "Signed"
    case "ssh.passphrase", "gpg.passphrase": return "Passphrase supplied"
    case "gpg.confirm": return "Confirmed"
    case "age.decrypt": return "Decrypted"
    case "age.encrypt": return "Encrypted"
    case "vault.exported": return "Exported"
    case "credential.read": return "Read"
    case "credential.exec": return "Used by ap exec"
    case "credential.inject": return "Injected"
    case "passkey.asserted": return "Signed in with a passkey"
    case "login.fill": return "Filled"
    case "login.totp": return "One-time code filled"
    default: return action
    }
  }

  /// Kind, actions, and up to three callers, such as "SSH key · Signed by git,
  /// ssh".
  static func summary(_ entry: UsedTodayEntry) -> String {
    var parts = [kindLabel(entry.displayKind)]
    var action = entry.actions.map(verb).joined(separator: ", ")
    if !entry.callers.isEmpty {
      let shown = entry.callers.prefix(3).joined(separator: ", ")
      let more = entry.callers.count > 3 ? " and \(entry.callers.count - 3) more" : ""
      action += " by \(shown)\(more)"
    }
    parts.append(action)
    return parts.joined(separator: " · ")
  }
}

/// Severity symbol of an issue row, white on a rounded square of the severity
/// color.
private struct IssueSeverityIcon: View {
  let severity: IssueSeverity

  var body: some View {
    TodayIcon(symbol: symbol, color: severity.color)
  }

  private var symbol: String {
    switch severity {
    case .broken: return "exclamationmark"
    case .request: return "bell.fill"
    case .advice: return "exclamationmark.triangle.fill"
    case .setup: return "wrench.and.screwdriver.fill"
    case .info: return "info"
    }
  }
}

extension IssueSeverity {
  /// Severity color for icons and status dots.
  var color: Color {
    switch self {
    case .broken: return .red
    case .request: return .accentColor
    case .advice: return .orange
    case .setup, .info: return .gray
    }
  }
}
