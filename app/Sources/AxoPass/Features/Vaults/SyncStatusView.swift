import AppKit
import AxoPassFFI
import SwiftUI

/// Text of a vault paused by a separate key.
let syncSeparateKeyMessage =
  "Another Mac enabled sync for this vault separately. Turn off sync for this vault on one Mac, then turn it on again there to join the other Mac's copy."

/// Notice of a synced vault that needs the user, read from its sync report.
/// Nil if sync runs with nothing to do.
func syncNotice(_ report: SyncReportInfo) -> String? {
  if report.needsFolder { return "Choose the synced folder of this vault again." }
  switch report.status {
  case .stopped(let cause)?: return stopText(cause)
  case .paused(let causes)?:
    if causes.contains(where: { if case .separateKey = $0 { return true } else { return false } }) {
      return syncSeparateKeyMessage
    }
    return "Sync is paused."
  case .active?, nil: break
  }
  if report.recoveryKitMissing {
    return "This vault does not open with any recovery kit. Save a new kit."
  }
  return nil
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
private func pausedText(_ cause: PausedCauseInfo) -> (text: String, detail: String?) {
  switch cause {
  case .unreachable(let error):
    return ("Synced folder cannot be reached.", error)
  case .publishFailed(let error):
    return ("Changes on this Mac could not be copied to the synced folder.", error)
  case .quarantined(let files):
    return (
      files == 1
        ? "1 file from another Mac cannot be read and is set aside."
        : "\(files) files from other Macs cannot be read and are set aside.", nil
    )
  case .versionSkew(let files):
    return (
      files == 1
        ? "1 file is from a newer version of Axo Pass. Update Axo Pass to read it."
        : "\(files) files are from a newer version of Axo Pass. Update Axo Pass to read them.",
      nil
    )
  case .applyFailed(let error):
    return ("Changes from other Macs could not be applied to this vault.", error)
  case .diffFailed(let error):
    return ("Changes on this Mac could not be compared with the synced copy.", error)
  case .keyMissing:
    return (
      "This Mac lacks the current sync key of this vault. Pair with another Mac or use a newer recovery kit.",
      nil
    )
  case .separateKey:
    return (syncSeparateKeyMessage, nil)
  }
}

/// Notice of the selected synced vault at the top of the items pane, with a
/// button that opens its sync status.
struct SyncNoticeBanner: View {
  @Environment(SyncModel.self) private var sync
  let vault: VaultInfo

  var body: some View {
    if let report = sync.report(vault.key), let notice = syncNotice(report) {
      VStack(alignment: .leading, spacing: 6) {
        Label("Sync needs attention", systemImage: "exclamationmark.arrow.triangle.2.circlepath")
          .font(.subheadline.weight(.semibold))
        Text(notice)
          .font(.caption)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        Button("Sync Status…") {
          sync.sheet = .status(SyncVaultRef(key: vault.key, name: vault.name ?? vault.key))
        }
        .controlSize(.small)
      }
      .padding(10)
      .frame(maxWidth: .infinity, alignment: .leading)
      .background(.quaternary)
    }
  }
}

/// Sync status of one vault: the folder, the status with its causes and
/// actions, the kit prompt, the conflicts, the quarantined files, and the
/// known Macs.
struct SyncStatusSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let vault: SyncVaultRef

  @State private var isWorking = false
  @State private var error: String? = nil
  @State private var overrideCount: UInt32? = nil
  @State private var confirmingTurnOff = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Sync Status of \(vault.name)").font(.headline)

      if let report = sync.report(vault.key) {
        ScrollView {
          VStack(alignment: .leading, spacing: 16) {
            folderSection(report)
            statusSection(report)
            if report.recoveryKitMissing { kitSection }
            detailsSection(report)
          }
          .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxHeight: 440)
      } else if case .unknown(let message)? = sync.state(vault.key) {
        SyncErrorLabel(message: "Could not read sync status: \(message)")
      } else {
        HStack(spacing: 8) {
          ProgressView().controlSize(.small)
          Text("Reading sync status…").foregroundStyle(.secondary)
        }
      }

      if let error { SyncErrorLabel(message: error) }

      HStack {
        if isWorking { ProgressView().controlSize(.small) }
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(20)
    .frame(width: 560)
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
        "The edits on this Mac stay. Each value that differs from the synced copy shows as a conflict, on every Mac."
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

  private func folderSection(_ report: SyncReportInfo) -> some View {
    VStack(alignment: .leading, spacing: 6) {
      Text("Synced Folder").font(.subheadline.weight(.semibold))
      if report.needsFolder || report.root == nil {
        Text(
          "This vault does not have a synced folder on this Mac. Choose the folder that holds it again."
        )
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
        Button("Choose Folder…") { chooseFolder() }
          .disabled(isWorking)
      } else if let root = report.root {
        Text(rootDescription(root))
          .font(.callout.monospaced())
          .lineLimit(1)
          .truncationMode(.middle)
          .help(rootDescription(root))
          .textSelection(.enabled)
      }
    }
  }

  @ViewBuilder
  private func statusSection(_ report: SyncReportInfo) -> some View {
    VStack(alignment: .leading, spacing: 6) {
      Text("Status").font(.subheadline.weight(.semibold))
      switch report.status {
      case .active?:
        Label("Syncing", systemImage: "checkmark.circle.fill")
          .foregroundStyle(.green)
      case .paused(let causes)?:
        Label("Paused", systemImage: "pause.circle.fill")
          .foregroundStyle(.orange)
        Text("Edits on this Mac are kept and sync once the cause is resolved.")
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        ForEach(Array(causes.enumerated()), id: \.offset) { _, cause in
          causeRow(pausedText(cause))
        }
      case .stopped(let cause)?:
        Label("Stopped", systemImage: "stop.circle.fill")
          .foregroundStyle(.red)
        causeRow((stopText(cause), nil))
        stopActions(cause, report)
      case nil:
        Text("Sync status unavailable.")
          .foregroundStyle(.secondary)
      }
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
        "Link this vault again by pairing with a Mac that syncs it or with its recovery kit. Entries are merged, and values that differ show as conflicts. Or turn off sync."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
      HStack {
        Button("Pair with Another Mac…") {
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

  private var kitSection: some View {
    VStack(alignment: .leading, spacing: 6) {
      Text("Recovery Kit").font(.subheadline.weight(.semibold))
      Text(
        "The current sync key of this vault does not open with any recovery kit. If no other Mac is available, a kit is the only way to open the synced vault."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
      Button("Save a New Recovery Kit…") { sync.sheet = .newKit(vault) }
    }
  }

  private func detailsSection(_ report: SyncReportInfo) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      if report.status != nil {
        VStack(alignment: .leading, spacing: 6) {
          Text("Conflicts").font(.subheadline.weight(.semibold))
          Text(
            report.conflicts == 0
              ? "Values do not show as conflicts."
              : report.conflicts == 1
                ? "1 value shows as a conflict." : "\(report.conflicts) values show as conflicts."
          )
          .foregroundStyle(.secondary)
        }
      }

      if !report.quarantined.isEmpty {
        VStack(alignment: .leading, spacing: 6) {
          Text("Files Set Aside").font(.subheadline.weight(.semibold))
          ForEach(report.quarantined, id: \.name) { file in
            VStack(alignment: .leading, spacing: 2) {
              Text("From \(file.macName ?? "another Mac"): \(file.reason)")
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

      if !report.knownMacs.isEmpty {
        VStack(alignment: .leading, spacing: 6) {
          Text("Macs").font(.subheadline.weight(.semibold))
          ForEach(report.knownMacs, id: \.replicaId) { mac in
            HStack(alignment: .firstTextBaseline, spacing: 8) {
              Text(mac.thisMac ? "\(mac.name) (this Mac)" : mac.name)
              if mac.left {
                Text("Left")
                  .font(.caption)
                  .foregroundStyle(.secondary)
                  .padding(.horizontal, 4)
                  .background(.quaternary, in: RoundedRectangle(cornerRadius: 3))
              }
              Spacer(minLength: 8)
              if let lastActive = mac.lastActive {
                Text(
                  "Last active \(Date(timeIntervalSince1970: TimeInterval(lastActive)).formatted(date: .abbreviated, time: .shortened))"
                )
                .font(.callout)
                .foregroundStyle(.secondary)
              }
            }
          }
        }
      }
    }
  }

  // MARK: - Actions

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
        self.error = String(describing: error)
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
        self.error = String(describing: error)
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
        self.error = String(describing: error)
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
  @State private var kitSaved = false
  @State private var isWorking = false
  @State private var done = false
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Recovery Kit for \(vault.name)").font(.headline)

      if done {
        Text("The recovery kit is added. It opens the vault from the synced folder.")
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        HStack {
          Spacer()
          Button("Done") { dismiss() }
            .keyboardShortcut(.defaultAction)
        }
      } else if let text {
        Text(
          "Save this recovery kit. If no other Mac is available, the kit opens the synced vault. Anyone with the kit and the folder can read the vault, so store it somewhere else."
        )
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)

        RecoveryKitPanel(text: text, vaultName: vault.name, kitSaved: $kitSaved) {
          error = $0
        }

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
      self.error = String(describing: error)
    }
  }

  private func confirm(_ text: String) {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        try await sync.confirmKit(vaultKey: vault.key, kitText: text)
        done = true
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = String(describing: error)
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
      Text("This Mac stops syncing the vault. The vault stays on your other Macs.")
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
        self.error = String(describing: error)
      }
    }
  }
}
