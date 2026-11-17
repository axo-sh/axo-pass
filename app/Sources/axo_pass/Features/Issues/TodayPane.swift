import AppKit
import AuthenticationServices
import AxoPassFFI
import SwiftUI

/// Home page of the app. Lists the issues with one fix button for each, then
/// the keys and credentials used today. The "Status" section lists chips of
/// the status checks, then the counted issues. Setup issues are listed under
/// "Not set up". Info issues are left out. Advice issues can be snoozed or
/// dismissed, and are then listed under "Dismissed".
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
    let dismissed = issues.dismissedIssues
    ScrollView {
      VStack(alignment: .leading, spacing: 0) {
        header
        let checks = statusChecks
        if !checks.isEmpty || !counted.isEmpty {
          TodaySectionHeader("Status")
          if !checks.isEmpty {
            checkChips(checks)
              .padding(.bottom, counted.isEmpty ? 0 : 10)
          }
          if !counted.isEmpty {
            issueCard(counted)
          }
        }
        if !setup.isEmpty {
          TodaySectionHeader("Not set up")
          issueCard(setup)
        }
        if !dismissed.isEmpty {
          TodaySectionHeader("Dismissed")
          issueCard(dismissed, dismissed: true)
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
    .padding(.top, 4)
  }

  // MARK: - Status

  /// Chips of the status checks. Shown above the counted issues.
  private func checkChips(_ checks: [StatusCheck]) -> some View {
    TodayFlowLayout(spacing: 6) {
      ForEach(checks, id: \.label) { check in
        TodayCheckChip(label: check.label, passing: check.passing)
          .help(check.help)
      }
    }
  }

  /// Status checks, in sidebar order. Checks that pass are listed. The SSH
  /// agent check is also listed if it fails. A check that has not run is left
  /// out. Labels are short. Help text gives the full check.
  private var statusChecks: [StatusCheck] {
    var list: [StatusCheck] = []
    let synced = vaults.vaults.filter { sync.state($0.key)?.isOn == true }.count
    if synced > 0 {
      list.append(
        StatusCheck("Sync", synced == 1 ? "1 vault synced" : "\(synced) vaults synced"))
    }
    switch issues.agentStatus {
    case .running: list.append(StatusCheck("SSH agent", "SSH agent running"))
    case .notRunning, .staleSocket:
      list.append(StatusCheck("SSH agent", "SSH agent not running", passing: false))
    case nil: break
    }
    if issues.sshConf?.state == .configured { list.append(StatusCheck("SSH", "ssh uses Axo Pass")) }
    if issues.shell?.configured == true { list.append(StatusCheck("Shell", "ap set up in zsh")) }
    if issues.gpgConf?.state == .configured { list.append(StatusCheck("GPG", "gpg uses Axo Pass")) }
    if issues.autofillEnabled == true { list.append(StatusCheck("AutoFill", "AutoFill on")) }
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
    let opener = SubjectOpener(
      vaults: vaults, issues: issues, sshModel: sshModel, gpgModel: gpgModel)
    let content = HStack(spacing: 12) {
      TodayIcon(
        symbol: UsedTodayStyle.symbol(entry.displayKind),
        color: UsedTodayStyle.color(entry.displayKind))
      VStack(alignment: .leading, spacing: 2) {
        HStack(spacing: 6) {
          Text(opener.title(entry.ref, label: entry.label))
            .fontWeight(.medium)
            .lineLimit(1)
            .truncationMode(.middle)
          if let tag = opener.keyTag(entry.ref) {
            KeyIdTag(text: tag)
          }
        }
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

    if opener.canOpen(entry.ref) {
      Button {
        opener.open(entry.ref)
      } label: {
        content
      }
      .buttonStyle(.plain)
      .help(opener.help(entry.ref))
    } else {
      content
    }
  }

  // MARK: - Issues

  /// Card of issue rows with dividers between rows. Rows of dismissed issues
  /// have a Restore button in place of the fix.
  private func issueCard(_ list: [Issue], dismissed: Bool = false) -> some View {
    TodayCard {
      ForEach(Array(list.enumerated()), id: \.element.id) { index, issue in
        if index > 0 {
          Divider()
        }
        row(issue, dismissed: dismissed)
      }
    }
  }

  private func row(_ issue: Issue, dismissed: Bool) -> some View {
    HStack(spacing: 12) {
      IssueSeverityIcon(severity: issue.severity)
      VStack(alignment: .leading, spacing: 2) {
        Text(issue.title)
          .fontWeight(.medium)
          .fixedSize(horizontal: false, vertical: true)
        if let detail = dismissed ? Optional(snoozeDetail(issue)) : detail(issue) {
          Text(detail)
            .font(.callout)
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
        }
      }
      Spacer(minLength: 12)
      if dismissed {
        Button("Restore") { issues.restore(issue) }
      } else {
        if let label = fixLabel(issue) {
          Button(label) { fix(issue) }
            .disabled(isFixing(issue))
        }
        if issue.isDismissible {
          dismissMenu(issue)
        }
      }
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
    .opacity(dismissed ? 0.6 : 1)
  }

  /// Snooze and dismiss choices of an advice issue.
  private func dismissMenu(_ issue: Issue) -> some View {
    Menu {
      Button("Snooze for 1 Day") { snooze(issue, days: 1) }
      Button("Snooze for 1 Week") { snooze(issue, days: 7) }
      Divider()
      Button("Dismiss") { issues.dismiss(issue) }
    } label: {
      Image(systemName: "ellipsis")
    }
    .menuStyle(.borderlessButton)
    .menuIndicator(.hidden)
    .fixedSize()
    .help("Snooze or dismiss")
  }

  private func snooze(_ issue: Issue, days: Int) {
    let until = Calendar.current.date(byAdding: .day, value: days, to: Date())
    issues.dismiss(issue, until: until ?? Date().addingTimeInterval(Double(days) * 86_400))
  }

  /// Second line of a dismissed issue row: the end of the snooze.
  private func snoozeDetail(_ issue: Issue) -> String {
    guard let until = issues.snoozedUntil(issue) else { return "Dismissed" }
    return "Snoozed until \(until.formatted(date: .abbreviated, time: .shortened))"
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

/// Status check of the Today pane.
private struct StatusCheck {
  let label: String
  let help: String
  let passing: Bool

  init(_ label: String, _ help: String, passing: Bool = true) {
    self.label = label
    self.help = help
    self.passing = passing
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

/// Opens the key or item named by an audit event.
@MainActor
struct SubjectOpener {
  let vaults: VaultsModel
  let issues: IssuesModel
  let sshModel: SshModel
  let gpgModel: GpgModel

  /// Whether `ref` opens a key or an item. SSH keys open by SHA256
  /// fingerprint and GPG keys by keygrip. Other subjects open the item if the
  /// audit event recorded it.
  func canOpen(_ ref: AuditSubjectRef) -> Bool {
    switch ref.kind {
    case .sshKey: return true
    case .gpgKey: return gpgFingerprint(keygrip: ref.subjectId) != nil
    default: return itemLocation(ref) != nil
    }
  }

  func help(_ ref: AuditSubjectRef) -> String {
    ref.kind == .sshKey || ref.kind == .gpgKey ? "Show this key" : "Show this item"
  }

  func open(_ ref: AuditSubjectRef) {
    switch ref.kind {
    case .sshKey:
      // Audit events name the key as `SHA256:<hash>`. Key entries hold the
      // hash only.
      let prefix = "SHA256:"
      let id = ref.subjectId
      sshModel.selectedFingerprint = id.hasPrefix(prefix) ? String(id.dropFirst(prefix.count)) : id
      vaults.selectSidebarDestination(.ssh)
    case .gpgKey:
      gpgModel.selectedFingerprint = gpgFingerprint(keygrip: ref.subjectId)
      vaults.selectSidebarDestination(.gpg)
    default:
      guard let location = itemLocation(ref) else { return }
      Task { await vaults.showItem(vaultKey: location.vaultKey, itemId: location.itemId) }
    }
  }

  /// Vault key and short item id of `ref`. The vault is looked up by short id
  /// first, then by the recorded vault key.
  private func itemLocation(_ ref: AuditSubjectRef) -> (vaultKey: String, itemId: String)? {
    guard let itemId = ref.itemId else { return nil }
    let byId = ref.vaultId.flatMap { vaults.vaultKey(id: $0) }
    let byKey = ref.vaultKey.flatMap { key in vaults.vaults.contains { $0.key == key } ? key : nil }
    guard let vaultKey = byId ?? byKey else { return nil }
    return (vaultKey, itemId)
  }

  /// Username of the login item `ref` points to, if its vault is loaded.
  func username(_ ref: AuditSubjectRef) -> String? {
    guard let location = itemLocation(ref) else { return nil }
    return vaults.cachedUsername(vaultKey: location.vaultKey, itemId: location.itemId)
  }

  /// Display title of a subject. GPG keys are named by the key name in place
  /// of the keygrip. SSH keys labeled by fingerprint show as "SSH key", since
  /// the id tag already shows the fingerprint. If the event was recorded
  /// without account details, the title is looked up from the loaded keys,
  /// items, and vaults, and is `label` if none matches.
  func title(_ ref: AuditSubjectRef, label: String) -> String {
    switch ref.kind {
    case .sshKey:
      if !ref.hasName { return sshKeyComment(ref) ?? label }
      return label.hasPrefix("SHA256:") ? "SSH key" : label
    case .gpgKey:
      guard let key = gpgKey(keygrip: ref.subjectId) else {
        return "Keygrip …\(ref.subjectId.suffix(8))"
      }
      if !key.name.isEmpty { return key.name }
      return key.email ?? key.fingerprint
    default:
      return ref.hasName ? label : storedName(ref) ?? label
    }
  }

  /// Comment of the loaded SSH key with the fingerprint of `ref`.
  private func sshKeyComment(_ ref: AuditSubjectRef) -> String? {
    let prefix = "SHA256:"
    let id = ref.subjectId
    let hash = id.hasPrefix(prefix) ? String(id.dropFirst(prefix.count)) : id
    let comment = sshModel.keys.first { $0.fingerprintSha256 == hash }?.comment
    return comment?.isEmpty == false ? comment : nil
  }

  /// Item title or vault name of `ref`, if the vault is loaded.
  private func storedName(_ ref: AuditSubjectRef) -> String? {
    switch ref.kind {
    case .vault:
      return ref.vaultId.flatMap { vaults.vaultName(id: $0) }
    case .item, .credential, .login, .passkey:
      guard let location = itemLocation(ref) else { return nil }
      return vaults.cachedTitle(vaultKey: location.vaultKey, itemId: location.itemId)
    default:
      return nil
    }
  }

  /// First six characters of the key id, shown after the title. SSH keys use
  /// the SHA256 fingerprint hash and GPG keys the fingerprint. Nil for other
  /// kinds and for GPG keys not in the keyring.
  func keyTag(_ ref: AuditSubjectRef) -> String? {
    switch ref.kind {
    case .sshKey:
      let prefix = "SHA256:"
      let id = ref.subjectId
      return String((id.hasPrefix(prefix) ? id.dropFirst(prefix.count) : id[...]).prefix(6))
    case .gpgKey:
      return gpgKey(keygrip: ref.subjectId).map { String($0.fingerprint.prefix(6)) }
    default:
      return nil
    }
  }

  /// GPG key that holds `keygrip` as its primary key or a subkey.
  func gpgKey(keygrip: String) -> GpgKeyEntry? {
    issues.gpgKeys?.first { key in
      key.keygrip == keygrip || key.subkeys.contains { $0.keygrip == keygrip }
    }
  }

  private func gpgFingerprint(keygrip: String) -> String? {
    gpgKey(keygrip: keygrip)?.fingerprint
  }
}

/// Uppercase section title of the Today page, with an optional count badge.
struct TodaySectionHeader: View {
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
struct TodayCard<Content: View>: View {
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
struct TodayNoteRow: View {
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

/// Monospaced capsule of a shortened key id.
struct KeyIdTag: View {
  let text: String

  var body: some View {
    KeyBadge(text: text)
      .monospaced()
      .fixedSize()
  }
}

/// Status check with a green checkmark if it passes, or a red cross if it
/// fails.
private struct TodayCheckChip: View {
  let label: String
  let passing: Bool

  var body: some View {
    HStack(spacing: 4) {
      Image(systemName: passing ? "checkmark" : "xmark")
        .font(.system(size: 9, weight: .bold))
        .foregroundStyle(passing ? .green : .red)
      Text(label)
        .font(.callout)
        .foregroundStyle(.secondary)
    }
    .padding(.horizontal, 8)
    .padding(.vertical, 2)
    .background(.quaternary.opacity(0.6), in: Capsule())
  }
}

/// Layout that places subviews left to right and wraps to a new line if the
/// width runs out.
private struct TodayFlowLayout: Layout {
  var spacing: CGFloat

  func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
    let rows = arrange(width: proposal.width ?? .infinity, subviews: subviews)
    let width = rows.map(\.width).max() ?? 0
    let height = rows.map(\.height).reduce(0, +) + spacing * CGFloat(max(rows.count - 1, 0))
    return CGSize(width: width, height: height)
  }

  func placeSubviews(
    in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()
  ) {
    var y = bounds.minY
    for row in arrange(width: bounds.width, subviews: subviews) {
      var x = bounds.minX
      for index in row.indices {
        let size = subviews[index].sizeThatFits(.unspecified)
        subviews[index].place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
        x += size.width + spacing
      }
      y += row.height + spacing
    }
  }

  /// Subview indices of each line, with line width and height.
  private func arrange(
    width: CGFloat, subviews: Subviews
  ) -> [(indices: [Int], width: CGFloat, height: CGFloat)] {
    var rows: [(indices: [Int], width: CGFloat, height: CGFloat)] = []
    var current: (indices: [Int], width: CGFloat, height: CGFloat) = ([], 0, 0)
    for (index, subview) in subviews.enumerated() {
      let size = subview.sizeThatFits(.unspecified)
      let added = current.indices.isEmpty ? size.width : current.width + spacing + size.width
      if !current.indices.isEmpty && added > width {
        rows.append(current)
        current = ([index], size.width, size.height)
      } else {
        current = (current.indices + [index], added, max(current.height, size.height))
      }
    }
    if !current.indices.isEmpty { rows.append(current) }
    return rows
  }
}

/// White symbol on a rounded square of `color`.
struct TodayIcon: View {
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
enum UsedTodayStyle {
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
    case .login: return Color(red: 66 / 255, green: 96 / 255, blue: 119 / 255)
    case .passkey: return .green
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
    case "ssh.passphrase", "gpg.passphrase": return "Unlocked"
    case "gpg.confirm": return "Confirmed"
    case "age.decrypt": return "Decrypted"
    case "age.encrypt": return "Encrypted"
    case "vault.exported": return "Exported"
    case "credential.read": return "Read"
    case "credential.file_read": return "Saved to disk"
    case "credential.exec": return "Used by ap exec"
    case "credential.inject": return "Injected"
    case "credential.env": return "Used by ap env"
    case "passkey.asserted": return "Signed in with a passkey"
    case "login.fill": return "Filled"
    case "login.totp": return "One-time code filled"
    default: return action
    }
  }

  /// Whether a caller is shown. gpg-agent is left out of GPG key callers,
  /// since it makes every pinentry request.
  static func showsCaller(_ caller: String, kind: UsedTodayKind) -> Bool {
    !(kind == .gpgKey && caller == "gpg-agent")
  }

  /// Kind, actions, and up to three callers, such as "SSH key · Signed by git,
  /// ssh".
  static func summary(_ entry: UsedTodayEntry) -> String {
    var parts = [kindLabel(entry.displayKind)]
    var action = entry.actions.map(verb).joined(separator: ", ")
    let callers = entry.callers.filter { showsCaller($0, kind: entry.kind) }
    if !callers.isEmpty {
      let shown = callers.prefix(3).joined(separator: ", ")
      let more = callers.count > 3 ? " and \(callers.count - 3) more" : ""
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
