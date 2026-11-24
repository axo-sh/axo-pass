import AppKit
import AxoPassFFI
import SwiftUI
import UniformTypeIdentifiers

/// Text of a vault paused by a separate key.
let syncSeparateKeyMessage =
  "Another device also enabled sync for this vault. Pair the devices to merge them."

/// Text of a vault that is cut off by a declined sync key.
let syncRotationDeclinedMessage =
  "You declined a new sync key from another device, so this device no longer syncs with the devices that accepted it. Pair this device again to rejoin, or remove the device that made the key."

/// Notice of a synced vault that needs the user, read from its sync report.
/// Nil if sync runs with nothing to do.
func syncNotice(_ report: SyncReportInfo) -> String? {
  if report.needsFolder { return "Choose the synced folder of this vault again." }
  if !report.rotations.isEmpty {
    return "The sync key for this vault was updated by another device. Review it in Sync Status."
  }
  switch report.status {
  case .stopped(let cause)?: return stopText(cause)
  case .paused(let causes)?:
    if causes.contains(where: { if case .separateKey = $0 { return true } else { return false } }) {
      return syncSeparateKeyMessage
    }
    if causes.contains(where: {
      if case .rotationDeclined = $0 { return true } else { return false }
    }) {
      return syncRotationDeclinedMessage
    }
    return "Sync is paused."
  case .active?, nil: break
  }
  return nil
}

/// Short status line of a synced vault and the color of its status dot, read
/// from its sync report in the order of `syncNotice`. The help text holds the
/// full notice or the causes of a pause.
func syncStatusSummary(_ report: SyncReportInfo) -> (line: String, color: Color, help: String) {
  let notice = syncNotice(report)
  if report.needsFolder { return ("Choose the synced folder again", .orange, notice ?? "") }
  if !report.rotations.isEmpty { return ("New sync key to review", .orange, notice ?? "") }
  switch report.status {
  case .stopped(let cause)?:
    return ("Stopped", .red, stopText(cause))
  case .paused(let causes)?:
    return ("Paused", .orange, causes.map { pausedText($0).text }.joined(separator: "\n"))
  case nil:
    return ("Unavailable", .secondary, "")
  case .active?:
    break
  }
  if report.recoveryKitMissing {
    return (
      "Needs a new recovery kit", .orange,
      "This vault does not open with any recovery kit. Save a new kit."
    )
  }
  if report.conflicts > 0 {
    let count = report.conflicts == 1 ? "1 conflict" : "\(report.conflicts) conflicts"
    return ("Syncing, \(count)", .green, "Conflicts to resolve: \(report.conflicts)")
  }
  return ("Syncing", .green, "")
}

/// Reason of a stopped sync.
func stopText(_ cause: StopCauseInfo) -> String {
  switch cause {
  case .drift(let build, _):
    return
      "Sync stopped because this vault was edited without syncing, on Axo Pass build \(build)."
  case .signatureFailed(let reason):
    return
      "Sync stopped because the sync state of this vault failed its check: \(signatureText(reason))."
  case .stateMissing:
    return "Sync stopped because the sync state of this vault is missing."
  }
}

private func signatureText(_ reason: SignatureFailureInfo) -> String {
  switch reason {
  case .envelope: return "the file is damaged"
  case .signature: return "the signature does not match"
  case .malformed: return "the contents cannot be read"
  case .keyring: return "the sync keys cannot be opened"
  case .body: return "the contents cannot be decrypted"
  case .ownKey: return "it does not hold the keys of this Mac"
  }
}

/// Reason of a paused sync, with the error detail if any.
func pausedText(_ cause: PausedCauseInfo) -> (text: String, detail: String?) {
  switch cause {
  case .unreachable(let error):
    return ("Synced folder cannot be reached.", error)
  case .publishFailed(let error):
    return ("Changes on this Mac could not be copied to the synced folder.", error)
  case .quarantined(let files):
    return (
      files == 1
        ? "1 file from another device cannot be read and is set aside."
        : "\(files) files from other devices cannot be read and are set aside.", nil
    )
  case .versionSkew(let files):
    return (
      files == 1
        ? "1 file is from a newer version of Axo Pass. Update Axo Pass to read it."
        : "\(files) files are from a newer version of Axo Pass. Update Axo Pass to read them.",
      nil
    )
  case .applyFailed(let error):
    return ("Changes from other devices could not be applied to this vault.", error)
  case .diffFailed(let error):
    return ("Changes on this Mac could not be compared with the synced copy.", error)
  case .keyMissing:
    return (
      "This Mac lacks the current sync key of this vault. Pair with another device or use a newer recovery kit.",
      nil
    )
  case .separateKey:
    return (syncSeparateKeyMessage, nil)
  case .rotationDeclined:
    return (syncRotationDeclinedMessage, nil)
  }
}

/// Notice of the selected synced vault at the top of the items pane, with a
/// button that opens its sync status.
struct SyncNoticeBanner: View {
  @Environment(SyncModel.self) private var sync
  let vault: VaultInfo

  var body: some View {
    if let report = sync.report(vault.key), let notice = syncNotice(report),
      !sync.hiddenNoticeVaults.contains(vault.key)
    {
      let ref = SyncVaultRef(key: vault.key, name: vault.name ?? vault.key)
      VStack(alignment: .leading, spacing: 8) {
        Label("Sync needs attention", systemImage: "exclamationmark.arrow.triangle.2.circlepath")
          .font(.headline)
        Text(notice)
          .font(.body)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        HStack {
          if !report.rotations.isEmpty {
            Button("Review…") { sync.sheet = .rotation(ref) }
          }
          Button("Sync Status…") { sync.sheet = .status(ref) }
          Button("Hide") { sync.hideNotice(vault.key) }
            .help("Hide this notice until Axo Pass restarts")
        }
      }
      .padding(12)
      .frame(maxWidth: .infinity, alignment: .leading)
      .opaqueBannerBackground()
    }
  }
}

extension View {
  /// Banner background that list rows do not show through.
  func opaqueBannerBackground() -> some View {
    background {
      Color(nsColor: .windowBackgroundColor).overlay(.quaternary)
    }
    .overlay(alignment: .bottom) { Divider() }
  }
}

/// Sync status of one vault: the status, folder, and conflict count, the
/// causes and actions, the quarantined files, the recovery kits, and the sync
/// key. The synced folder, devices, and pairing of all vaults are in
/// Settings > Sync.
struct SyncStatusSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(WindowRequests.self) private var windows
  @Environment(\.dismiss) private var dismiss

  let vault: SyncVaultRef
  /// Window that presents the sheet. In Settings, "Sync Settings…" only
  /// dismisses the sheet.
  var host: SyncSheetHost = .main

  @State private var isWorking = false
  @State private var error: String? = nil
  @State private var overrideCount: UInt32? = nil
  @State private var confirmingTurnOff = false
  @State private var folderCopied = false
  @State private var kitCopied = false
  @State private var isSyncing = false

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      VaultSheetTitle(name: vault.name, key: vault.key, section: "Sync Status")
        .padding([.horizontal, .top], 20)

      if let report = sync.report(vault.key) {
        Form {
          overviewSection(report)
          devicesSection(report)
          rotationsSection(report)
          causesSection(report)
          quarantinedSection(report)
          syncActionsSection(report)
        }
        .formStyle(.grouped)
        .scrollBounceBehavior(.basedOnSize)
        .frame(minHeight: 200, maxHeight: 560)
      } else if case .unknown(let message)? = sync.state(vault.key) {
        SyncErrorLabel(message: "Could not read sync status: \(message)")
          .padding(20)
      } else {
        HStack(spacing: 8) {
          ProgressView().controlSize(.small)
          Text("Reading sync status…").foregroundStyle(.secondary)
        }
        .padding(20)
      }

      if let error {
        SyncErrorLabel(message: error)
          .padding(.horizontal, 20)
      }

      HStack {
        Button("Sync Settings…") {
          dismiss()
          if host == .main { windows.requestSettings(tab: .sync) }
        }
        .help("Synced folder, devices, and pairing of all synced vaults")
        if isWorking { ProgressView().controlSize(.small) }
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
      .padding([.horizontal, .bottom], 20)
      .padding(.top, 8)
    }
    .frame(width: 520)
    .task { await sync.reload(vault.key) }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .confirmationDialog(
      "Resume sync and show \(overrideCount.map(differences) ?? "the differences") as conflicts?",
      isPresented: Binding(
        get: { overrideCount != nil }, set: { if !$0 { overrideCount = nil } })
    ) {
      Button("Resume Sync") { resume() }
    } message: {
      Text(
        "The edits on this Mac stay. Each value that differs from the synced copy shows as a conflict on every device."
      )
    }
    .confirmationDialog(
      "Turn off sync for \(vault.name)?", isPresented: $confirmingTurnOff
    ) {
      Button("Turn Off Sync", role: .destructive) { turnOff() }
    } message: {
      Text(syncDisableMessage)
    }
  }

  // MARK: - Sections

  /// Key rotations of other devices that wait for an answer.
  @ViewBuilder
  private func rotationsSection(_ report: SyncReportInfo) -> some View {
    if !report.rotations.isEmpty {
      Section("New Sync Key") {
        Text(
          report.rotations.count == 1
            ? "Another device made a new sync key for this vault and waits for your answer."
            : "Other devices made new sync keys for this vault and wait for your answer."
        )
        .fixedSize(horizontal: false, vertical: true)
        Button("Review…") { sync.sheet = .rotation(vault) }
      }
    }
  }

  /// Status, folder, and conflict count. Conflicts show only if there are any.
  private func overviewSection(_ report: SyncReportInfo) -> some View {
    Section {
      LabeledContent("Status") { statusLabel(report.status) }

      if report.needsFolder || report.root == nil {
        LabeledContent("Folder") {
          Button("Choose Folder…") { chooseFolder() }
            .disabled(isWorking)
        }
      } else if let root = report.root {
        LabeledContent("Folder") {
          Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(rootHelp(root), forType: .string)
            folderCopied = true
            Task {
              try? await Task.sleep(for: .seconds(1.5))
              folderCopied = false
            }
          } label: {
            Text(folderCopied ? "Copied" : rootDescription(root))
              .lineLimit(1)
              .truncationMode(.middle)
          }
          .buttonStyle(.plain)
          .help("Copy \(rootHelp(root))")
        }
      }

      if report.status != nil, report.root != nil, !report.needsFolder {
        LabeledContent("Last Sync") {
          HStack(spacing: 8) {
            if isSyncing {
              ProgressView().controlSize(.small)
            } else {
              scanLabel(report.scan)
            }
            Button("Sync Now") { syncNow() }
              .controlSize(.small)
              .disabled(isWorking || isSyncing)
          }
        }
      }

      if report.conflicts > 0 {
        LabeledContent("Conflicts") {
          HStack {
            Text(report.conflicts == 1 ? "1 value" : "\(report.conflicts) values")
            Button("Resolve…") { sync.sheet = .conflicts(vault, itemKey: nil) }
              .controlSize(.small)
          }
        }
      }

      if report.status != nil || report.recoveryKitMissing { kitRow(report) }
    } footer: {
      if report.needsFolder || report.root == nil {
        Text("Choose the folder that holds this vault on this Mac.")
      }
    }
  }

  /// Devices connected to this vault, this device first. Devices that left or
  /// were removed are not listed.
  @ViewBuilder
  private func devicesSection(_ report: SyncReportInfo) -> some View {
    let macs = report.knownMacs
      .filter { $0.thisMac || !($0.left || $0.removed) }
      .sorted { ($0.thisMac ? 0 : 1, $0.name) < ($1.thisMac ? 0 : 1, $1.name) }
    if report.status != nil, !macs.isEmpty {
      Section("Devices") {
        ForEach(macs, id: \.replicaId) { deviceRow($0) }
      }
    }
  }

  private func deviceRow(_ mac: KnownMacInfo) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      HStack(spacing: 6) {
        Text(mac.name)
          .lineLimit(1)
          .truncationMode(.middle)
        if mac.keysFlagged {
          Image(systemName: "exclamationmark.circle.fill")
            .foregroundStyle(.orange)
            .help(
              "This device published keys that differ from the keys pinned for it. The pinned keys are used."
            )
        }
      }
      Text(deviceDetail(mac))
        .font(.caption)
        .foregroundStyle(.secondary)
    }
  }

  private func deviceDetail(_ mac: KnownMacInfo) -> String {
    if mac.thisMac { return "This device" }
    if let receivedAt = mac.receivedAt {
      return "Changes received \(relativeTime(receivedAt))"
    }
    return "No changes received"
  }

  /// Result of the latest scan of the synced folder since the app started.
  @ViewBuilder
  private func scanLabel(_ scan: ScanStatusInfo?) -> some View {
    if let scan {
      switch scan.outcome {
      case .synced:
        Text(relativeTime(scan.at))
      case .waiting(let files):
        Label(
          files == 1
            ? "Waiting for 1 file to download"
            : "Waiting for \(files) files to download",
          systemImage: "icloud.and.arrow.down"
        )
        .foregroundStyle(.orange)
        .help("Checked \(relativeTime(scan.at)). The files download in the background.")
      case .failed(let message):
        Label(message, systemImage: "exclamationmark.circle.fill")
          .foregroundStyle(.red)
          .lineLimit(2)
          .help("Checked \(relativeTime(scan.at)).")
      }
    } else {
      Text("Not yet")
        .foregroundStyle(.secondary)
    }
  }

  private func relativeTime(_ seconds: Int64) -> String {
    Date(timeIntervalSince1970: TimeInterval(seconds))
      .formatted(.relative(presentation: .named))
  }

  @ViewBuilder
  private func statusLabel(_ status: SyncStatusInfo?) -> some View {
    switch status {
    case .active?:
      Label("Syncing", systemImage: "checkmark.circle.fill")
        .foregroundStyle(.green)
    case .paused?:
      Label("Paused", systemImage: "pause.circle.fill")
        .foregroundStyle(.orange)
    case .stopped?:
      Label("Stopped", systemImage: "stop.circle.fill")
        .foregroundStyle(.red)
    case nil:
      Text("Unavailable")
    }
  }

  /// Causes of a paused or stopped sync, with the actions of a stop.
  @ViewBuilder
  private func causesSection(_ report: SyncReportInfo) -> some View {
    switch report.status {
    case .paused(let causes)?:
      Section {
        ForEach(Array(causes.enumerated()), id: \.offset) { _, cause in
          causeRow(pausedText(cause))
          pausedActions(cause, report)
        }
      } footer: {
        Text("Edits on this Mac are kept and sync once resolved.")
      }
    case .stopped(let cause)?:
      Section {
        causeRow((stopText(cause), nil))
        stopActions(cause, report)
      }
    case .active?, nil:
      EmptyView()
    }
  }

  private func causeRow(_ cause: (text: String, detail: String?)) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(cause.text)
        .fixedSize(horizontal: false, vertical: true)
      if let detail = cause.detail {
        Text(detail)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(3)
          .textSelection(.enabled)
      }
    }
  }

  /// Actions of a paused cause. A separate enable and a declined rotation
  /// are resolved by pairing with a device that syncs the vault.
  @ViewBuilder
  private func pausedActions(_ cause: PausedCauseInfo, _ report: SyncReportInfo) -> some View {
    switch cause {
    case .separateKey:
      Button("Pair with Another Device…") {
        sync.sheet = .pair(root: report.root ?? sync.folder, join: vault)
      }
    case .rotationDeclined(let signerId):
      HStack {
        Button("Pair with Another Device…") {
          sync.sheet = .pair(root: report.root ?? sync.folder, join: vault)
        }
        if let signer = report.knownMacs.first(where: { $0.replicaId == signerId }),
          let signingKey = signer.signingKey
        {
          Button("Remove \(signer.name)…") {
            sync.sheet = .removeMac(preselect: signingKey)
          }
        }
      }
    default:
      EmptyView()
    }
  }

  @ViewBuilder
  private func stopActions(_ cause: StopCauseInfo, _ report: SyncReportInfo) -> some View {
    switch cause {
    case .drift(_, let overrideOffered):
      if overrideOffered, let count = report.overridePreview {
        Button("Resume and show differences as conflicts (\(count))…") { confirmResume() }
          .disabled(isWorking)
      } else {
        Text(
          "Sync cannot resume on this Mac. Turn off sync, then turn it on again to join the synced copy."
        )
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
        turnOffButton
      }
    case .signatureFailed, .stateMissing:
      Text(
        "Link this vault again by pairing with a device that syncs it or with its recovery kit, or turn off sync. Values that differ show as conflicts."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
      HStack {
        Button("Pair with Another Device…") {
          sync.sheet = .pair(root: report.root ?? sync.folder, join: vault)
        }
        Button("Use a Recovery Kit…") {
          sync.sheet = .kitImport(root: report.root ?? sync.folder, join: vault)
        }
        turnOffButton
      }
    }
  }

  private var turnOffButton: some View {
    Button("Turn Off Sync…") { confirmingTurnOff = true }
      .disabled(isWorking)
  }

  /// Turn off sync with the turn-off text of 10.8. A failure shows in this
  /// sheet.
  private func turnOff() {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      await sync.disable(vaultKey: vault.key)
      if let failed = sync.disableError, failed.vaultKey == vault.key {
        error = failed.message
        sync.clearDisableError()
      }
    }
  }

  /// Recovery kit of the vault. The vault holds one kit, so a new kit
  /// replaces it. A missing kit for the current key shows as a warning.
  private func kitRow(_ report: SyncReportInfo) -> some View {
    let kit = report.recoveryKits.last
    return LabeledContent("Recovery Kit") {
      VStack(alignment: .trailing, spacing: 4) {
        HStack(spacing: 8) {
          if report.recoveryKitMissing {
            HStack(spacing: 4) {
              Image(systemName: "exclamationmark.circle.fill")
              Text(kit == nil ? "None saved" : "Needs a new kit")
            }
            .foregroundStyle(.orange)
            .help("No recovery kit opens the current sync key of this vault.")
            Button("Save New Kit…") { sync.sheet = .newKit(vault) }
              .controlSize(.small)
              .disabled(isWorking)
          } else if let kit {
            kitName(kit)
          }
          kitMenu(kit, stale: report.recoveryKitMissing)
        }
        if let kit {
          if report.recoveryKitMissing {
            kitSummary(kit)
          } else {
            Text(kitDetail(kit))
              .font(.caption)
              .foregroundStyle(.secondary)
              .lineLimit(1)
          }
        }
      }
    }
  }

  /// Menu of kit actions. A stale row has an inline button for a new kit, so
  /// the menu omits it.
  private func kitMenu(_ kit: RecoveryKitInfo?, stale: Bool) -> some View {
    Menu {
      if !stale {
        Button(kit == nil ? "New Kit…" : "Replace Kit…") { sync.sheet = .newKit(vault) }
      }
      Button("Check a Kit…") { sync.sheet = .checkKit }
      if let kit {
        Button("Revoke Kit…") { sync.sheet = .revokeKit(vault, kit) }
      }
    } label: {
      Image(systemName: "ellipsis.circle")
    }
    .menuStyle(.borderlessButton)
    .menuIndicator(.hidden)
    .fixedSize()
    .help("Kit actions")
  }

  /// Label of a kit, or its short recipient if it has no label. A click
  /// copies the full recipient.
  private func kitName(_ kit: RecoveryKitInfo) -> some View {
    Button {
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(kit.recipient, forType: .string)
      kitCopied = true
      Task {
        try? await Task.sleep(for: .seconds(1.5))
        kitCopied = false
      }
    } label: {
      Text(kitCopied ? "Copied" : (kit.label ?? kit.shortRecipient))
        .font(kit.label == nil ? .caption.monospaced() : .body)
        .lineLimit(1)
        .truncationMode(.tail)
    }
    .buttonStyle(.plain)
    .help("Copy \(kit.recipient)\nKey id: \(kit.keyId)")
  }

  /// Kit name and detail on one line, or on two lines if the row is narrow.
  private func kitSummary(_ kit: RecoveryKitInfo) -> some View {
    ViewThatFits(in: .horizontal) {
      HStack(alignment: .firstTextBaseline, spacing: 6) {
        kitName(kit)
        Text("·").font(.caption)
        Text(kitDetail(kit)).font(.caption)
      }
      VStack(alignment: .trailing, spacing: 2) {
        kitName(kit)
        Text(kitDetail(kit)).font(.caption)
      }
    }
    .foregroundStyle(.secondary)
    .lineLimit(1)
  }

  /// Date a kit was added, and the device that added it if known.
  private func kitDetail(_ kit: RecoveryKitInfo) -> String {
    let date = Date(timeIntervalSince1970: TimeInterval(kit.writtenAt))
      .formatted(date: .abbreviated, time: .omitted)
    guard let device = kit.addedBy else { return "Added \(date)" }
    return "Added \(date) on \(device)"
  }

  /// Sync key replacement and turn off of this vault. A stopped sync offers
  /// the turn off button with its causes.
  @ViewBuilder
  private func syncActionsSection(_ report: SyncReportInfo) -> some View {
    let stopped: Bool = if case .stopped? = report.status { true } else { false }
    let showsKey = report.status != nil
    let showsTurnOff = !stopped
    if showsKey || showsTurnOff {
      Section("Sync") {
        if showsKey {
          actionRow(
            "Sync Key",
            help:
              "Replaces the sync key of this vault. Other devices switch to the new key automatically. This invalidates the existing recovery kit. Save a new one."
          ) {
            Button("Replace Sync Key…") { sync.sheet = .rotateKey(vault) }
              .disabled(isWorking)
          }
        }
        if showsTurnOff {
          actionRow(
            "This Mac",
            help:
              "Stop syncing \(vault.name) on this Mac. You can still open the vault, but changes will no longer sync. Other devices are not affected."
          ) {
            turnOffButton
          }
        }
      }
    }
  }

  /// Label with a button inline and help text below.
  private func actionRow<Control: View>(
    _ title: String,
    help: String,
    @ViewBuilder control: () -> Control
  ) -> some View {
    VStack(alignment: .leading, spacing: 6) {
      LabeledContent(title) { control() }
      Text(help)
        .font(.callout)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }
  }

  @ViewBuilder
  private func quarantinedSection(_ report: SyncReportInfo) -> some View {
    if !report.quarantined.isEmpty {
      Section("Files Set Aside") {
        ForEach(report.quarantined, id: \.name) { file in
          VStack(alignment: .leading, spacing: 2) {
            Text("From \(file.macName ?? "another device"): \(file.reason)")
              .fixedSize(horizontal: false, vertical: true)
            Text(file.name)
              .font(.caption.monospaced())
              .foregroundStyle(.secondary)
              .lineLimit(1)
              .truncationMode(.middle)
              .textSelection(.enabled)
          }
        }
      }
    }
  }

  // MARK: - Actions

  /// Scan the synced folder for changes of other devices now. The report
  /// reloads after the scan had time to run.
  private func syncNow() {
    error = nil
    isSyncing = true
    Task {
      defer { isSyncing = false }
      do {
        try await sync.syncNow(vaultKey: vault.key)
      } catch {
        self.error = error.userMessage
      }
    }
  }

  private func differences(_ count: UInt32) -> String {
    count == 1 ? "1 difference" : "\(count) differences"
  }

  /// Read the override count again, then confirm.
  private func confirmResume() {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        overrideCount = try await sync.overridePreview(vaultKey: vault.key)
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = error.userMessage
      }
    }
  }

  private func resume() {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        try await sync.resumeWithConflicts(vaultKey: vault.key)
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = error.userMessage
      }
    }
  }

  private func chooseFolder() {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.canCreateDirectories = false
    panel.allowsMultipleSelection = false
    if case .folder(let path)? = sync.folder {
      panel.directoryURL = URL(fileURLWithPath: path)
    }
    panel.prompt = "Choose"
    panel.message = "Choose the synced folder that holds \(vault.name)."
    guard panel.runModal() == .OK, let url = panel.url else { return }
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        try await sync.setRoot(vaultKey: vault.key, url: url)
      } catch {
        self.error = error.userMessage
      }
    }
  }
}

/// New recovery kit for the current sync key of a synced vault, saved before
/// it is added.
struct NewRecoveryKitSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let vault: SyncVaultRef

  @State private var text: String? = nil
  @State private var label = ""
  @State private var kitSaved = false
  @State private var isWorking = false
  @State private var done = false
  @State private var error: String? = nil

  /// The vault has a kit that the new kit replaces.
  private var replaces: Bool { !(sync.report(vault.key)?.recoveryKits.isEmpty ?? true) }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Recovery Kit for \(vault.name)").font(.headline)

      if done {
        Text(
          replaces
            ? "The new recovery kit replaces the earlier kit. It opens the vault from the synced folder."
            : "The recovery kit is added. It opens the vault from the synced folder."
        )
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
        HStack {
          Spacer()
          Button("Done") { dismiss() }
            .keyboardShortcut(.defaultAction)
        }
      } else if let text {
        Text(
          recoveryKitMessage
        )
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)

        RecoveryKitPanel(text: text, vaultName: vault.name, kitSaved: $kitSaved) {
          error = $0
        }

        KitLabelField(label: $label)

        if let error { SyncErrorLabel(message: error) }

        HStack {
          if isWorking { ProgressView().controlSize(.small) }
          Spacer()
          Button("Cancel") { dismiss() }
            .keyboardShortcut(.cancelAction)
          Button("Add Kit") { confirm(text) }
            .keyboardShortcut(.defaultAction)
            .disabled(!kitSaved || isWorking)
        }
      } else if let error {
        SyncErrorLabel(message: error)
        HStack {
          Spacer()
          Button("Close") { dismiss() }
            .keyboardShortcut(.cancelAction)
        }
      } else {
        HStack(spacing: 8) {
          ProgressView().controlSize(.small)
          Text("Preparing recovery kit…").foregroundStyle(.secondary)
        }
      }
    }
    .padding(20)
    .frame(width: 520)
    .task { await create() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
  }

  private func create() async {
    guard text == nil else { return }
    do {
      text = try await sync.createKit(vaultKey: vault.key)
    } catch FfiError.AuthExpired {
      // The app locked, which closes the sheet.
    } catch {
      self.error = error.userMessage
    }
  }

  private func confirm(_ text: String) {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        try await sync.confirmKit(
          vaultKey: vault.key, kitText: text,
          label: label.trimmingCharacters(in: .whitespacesAndNewlines))
        done = true
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = error.userMessage
      }
    }
  }
}

/// Check of a recovery kit that the user chooses or pastes. Reports whether
/// the kit opens the current sync key of its vault. Writes nothing other than
/// download requests.
struct CheckKitSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  /// Result of a check.
  private enum Outcome {
    /// The kit opens the current sync key.
    case current
    /// The kit is for an earlier sync key.
    case earlier
    /// No file of the synced folder opens with the kit.
    case noKey
    /// Files of these devices are downloading.
    case waiting([String])
  }

  @State private var kitText = ""
  @State private var outcome: Outcome? = nil
  @State private var isWorking = false
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Check a Recovery Kit").font(.headline)

      Text(
        "Choose a kit file or paste its text. Axo Pass checks whether the kit opens the current sync key of its vault. The check does not change the vault."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      TextEditor(text: $kitText)
        .font(.caption.monospaced())
        .scrollContentBackground(.hidden)
        .padding(4)
        .frame(height: 120)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        .onChange(of: kitText) {
          outcome = nil
          error = nil
        }

      if let outcome { outcomeView(outcome) }
      if let error { SyncErrorLabel(message: error) }

      HStack {
        Button("Choose File…") { chooseFile() }
        if isWorking { ProgressView().controlSize(.small) }
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Check") { check() }
          .keyboardShortcut(.defaultAction)
          .disabled(trimmedText.isEmpty || isWorking)
      }
    }
    .padding(20)
    .frame(width: 520)
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
  }

  private var trimmedText: String {
    kitText.trimmingCharacters(in: .whitespacesAndNewlines)
  }

  /// Vault of this Mac named by the "Vault:" line of the kit. Nil if the line
  /// is missing or no listed vault has the id.
  private var kitVault: SyncVaultRef? {
    let line = trimmedText.split(whereSeparator: \.isNewline)
      .map { $0.trimmingCharacters(in: .whitespaces) }
      .first { $0.hasPrefix("Vault:") }
    guard let line else { return nil }
    let uuid = line.dropFirst("Vault:".count).trimmingCharacters(in: .whitespaces)
    guard let id = shortId(id: uuid), let key = model.vaultKey(id: id) else { return nil }
    return SyncVaultRef(key: key, name: sync.vaultName(key))
  }

  @ViewBuilder
  private func outcomeView(_ outcome: Outcome) -> some View {
    let vault = kitVault
    let name = vault?.name ?? "its vault"
    switch outcome {
    case .current:
      Label(
        "This kit opens the current sync key of \(name).", systemImage: "checkmark.circle.fill"
      )
      .foregroundStyle(.green)
      .fixedSize(horizontal: false, vertical: true)
    case .earlier:
      VStack(alignment: .leading, spacing: 8) {
        Label(
          "This kit is for an earlier sync key of \(name). It does not open the vault.",
          systemImage: "exclamationmark.circle.fill"
        )
        .foregroundStyle(.orange)
        .fixedSize(horizontal: false, vertical: true)
        if let vault {
          Button("New Kit for \(vault.name)…") { sync.sheet = .newKit(vault) }
        }
      }
    case .noKey:
      Label(
        "The files in the synced folder do not open with this kit. The kit was not added, or its vault syncs with another folder.",
        systemImage: "xmark.circle.fill"
      )
      .foregroundStyle(.red)
      .fixedSize(horizontal: false, vertical: true)
    case .waiting(let names):
      Label(
        "Files from \(nameList(names)) are downloading. Check again in a few seconds.",
        systemImage: "icloud.and.arrow.down"
      )
      .foregroundStyle(.orange)
      .fixedSize(horizontal: false, vertical: true)
    }
  }

  // MARK: - Actions

  private func chooseFile() {
    let panel = NSOpenPanel()
    panel.canChooseFiles = true
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    panel.allowedContentTypes = [.plainText]
    panel.prompt = "Choose"
    panel.message = "Choose the recovery kit file."
    guard panel.runModal() == .OK, let url = panel.url else { return }
    do {
      kitText = try String(contentsOf: url, encoding: .utf8)
    } catch {
      self.error = error.userMessage
    }
  }

  /// Check the kit against the synced folder of its vault, or the synced
  /// folder of the app if this Mac does not list the vault.
  private func check() {
    let vault = kitVault
    guard let root = vault.flatMap({ sync.report($0.key)?.root }) ?? sync.folder else {
      error = syncNoFolderMessage
      return
    }
    let text = trimmedText
    error = nil
    outcome = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        switch try await sync.checkKit(root: root, kitText: text) {
        case .recovered: outcome = .current
        case .kitOutdated: outcome = .earlier
        case .noKey: outcome = .noKey
        case .waiting(let macs): outcome = .waiting(macs.map { $0.name ?? "another device" })
        }
      } catch {
        self.error = error.userMessage
      }
    }
  }
}

/// Synced vaults whose vault file is missing on this Mac, each with Rebuild
/// and Turn Off Sync.
struct MissingVaultsSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  @State private var working: String? = nil
  @State private var turningOff: MissingVaultInfo? = nil
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Missing Vaults").font(.headline)

      Text(
        "This Mac syncs these vaults, but their vault files are missing. Rebuild a vault from its sync state, or turn off sync for it."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      if sync.missingVaults.isEmpty {
        Text("All vaults are present.")
          .foregroundStyle(.secondary)
      } else {
        VStack(alignment: .leading, spacing: 10) {
          ForEach(sync.missingVaults, id: \.vaultId) { missing in
            row(missing)
          }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      }

      if let error { SyncErrorLabel(message: error) }

      HStack {
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(20)
    .frame(width: 520)
    .onAppear { sync.reloadMissingVaults() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .confirmationDialog(
      "Turn off sync for vault \(turningOff?.vaultId ?? "")?",
      isPresented: Binding(
        get: { turningOff != nil }, set: { if !$0 { turningOff = nil } }),
      presenting: turningOff
    ) { missing in
      Button("Turn Off Sync", role: .destructive) { turnOff(missing) }
    } message: { _ in
      Text("This Mac stops syncing the vault. The vault stays on your other devices.")
    }
  }

  private func row(_ missing: MissingVaultInfo) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 8) {
      VStack(alignment: .leading, spacing: 2) {
        Text("Vault \(missing.vaultId)")
        Text(missing.path)
          .font(.caption.monospaced())
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
          .help(missing.path)
          .textSelection(.enabled)
      }
      Spacer(minLength: 8)
      if working == missing.vaultId { ProgressView().controlSize(.small) }
      Button("Rebuild") { rebuild(missing) }
      Button("Turn Off Sync…") { turningOff = missing }
    }
    .disabled(working != nil)
  }

  private func rebuild(_ missing: MissingVaultInfo) {
    run(missing) { try await sync.rebuildMissingVault(missing.vaultId) }
  }

  private func turnOff(_ missing: MissingVaultInfo) {
    run(missing) { try await sync.disableMissingVault(missing.vaultId) }
  }

  private func run(_ missing: MissingVaultInfo, _ action: @escaping () async throws -> Void) {
    error = nil
    working = missing.vaultId
    Task {
      defer { working = nil }
      do {
        try await action()
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = error.userMessage
      }
    }
  }
}
