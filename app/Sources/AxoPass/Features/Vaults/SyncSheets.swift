import AppKit
import AxoPassFFI
import SwiftUI
import UniformTypeIdentifiers

extension View {
  /// Present the sync sheets that `SyncModel` requests: the enable sheet, the
  /// pairing sheets, the kit import, the status sheets, the conflicts sheet,
  /// the key state sheet, and the turn-off confirmation. Attach in the main window and in the
  /// welcome window. Only one of the two is open at a time, so a shared
  /// `sync.sheet` never presents twice. Do not attach it to a third window.
  func syncSheets() -> some View {
    modifier(SyncSheetsModifier())
  }
}

extension SyncModel {
  /// Ask for the synced folder of the app if none is chosen. Returns whether a
  /// folder is set. The pairing and kit sheets refuse to start without one,
  /// and a new Mac has not been to Settings.
  @MainActor
  func ensureFolder() -> Bool {
    if folder != nil { return true }
    let panel = NSOpenPanel()
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.canCreateDirectories = true
    panel.allowsMultipleSelection = false
    panel.prompt = "Choose"
    panel.message = "Choose the synced folder for your vaults."
    guard panel.runModal() == .OK, let url = panel.url else { return false }
    setFolder(url)
    return true
  }
}

private struct SyncSheetsModifier: ViewModifier {
  @Environment(SyncModel.self) private var sync

  func body(content: Content) -> some View {
    @Bindable var sync = sync
    content
      .sheet(item: $sync.sheet) { sheet in
        switch sheet {
        case .enable(let vault): SyncEnableSheet(vault: vault)
        case .pair(let root, let join): PairingSheet(root: root, join: join)
        case .kitImport(let root, let join): KitImportSheet(root: root, join: join)
        case .pairingPrompt(let root): PairingPromptSheet(root: root)
        case .pendingPairings(let root): PendingPairingsSheet(root: root)
        case .status(let vault): SyncStatusSheet(vault: vault)
        case .conflicts(let vault, let itemKey): ConflictsSheet(vault: vault, itemKey: itemKey)
        case .newKit(let vault): NewRecoveryKitSheet(vault: vault)
        case .missingVaults: MissingVaultsSheet()
        case .keyState: KeyStateSheet()
        }
      }
      .confirmationDialog(
        "Turn off sync for \(sync.disableRequest?.name ?? "this vault")?",
        isPresented: Binding(
          get: { sync.disableRequest != nil }, set: { if !$0 { sync.disableRequest = nil } }),
        presenting: sync.disableRequest
      ) { vault in
        Button("Turn Off Sync", role: .destructive) {
          Task { await sync.disable(vaultKey: vault.key) }
        }
      } message: { _ in
        Text(syncDisableMessage)
      }
      .alert(
        "Could not turn off sync",
        isPresented: Binding(
          get: { sync.disableError != nil }, set: { if !$0 { sync.clearDisableError() } }),
        presenting: sync.disableError
      ) { _ in
        Button("OK") { sync.clearDisableError() }
      } message: { error in
        Text(error.message)
      }
  }
}

/// Text of the turn-off confirmation.
let syncDisableMessage =
  "This Mac stops syncing the vault. The vault stays here and on your other devices. This Mac still has the vault's sync key until key rotation arrives in a later version."

/// Text of the delete confirmation of a synced vault.
let syncedVaultDeleteMessage =
  "This deletes the vault on this Mac only. Your other devices still have it. Sync turns off first, so Axo Pass must be unlocked."

/// Text of the delete confirmation of a vault that is not synced.
let vaultDeleteMessage =
  "This moves the vault and all of its items to the Trash. They do not go to Recently Deleted. To restore the vault, move its file out of the Trash in Finder."

/// Text for a vault whose earlier turn-off waits for the synced folder.
let syncDisableInProgressMessage =
  "Sync is still turning off for this vault. You can turn it on again once the change reaches the synced folder."

/// Text above a new recovery kit.
let recoveryKitMessage =
  "The kit opens the vault if no other device is available. Store it away from the synced folder, since anyone with both can read the vault."

/// Text for a sync sheet if no synced folder is chosen.
let syncNoFolderMessage = "Choose a synced folder in Settings › Vaults first."

/// Error of a sync sheet.
struct SyncErrorLabel: View {
  let message: String

  var body: some View {
    Label(message, systemImage: "xmark.circle.fill")
      .font(.caption)
      .foregroundStyle(.red)
      .lineLimit(4)
      .fixedSize(horizontal: false, vertical: true)
      .textSelection(.enabled)
  }
}

/// Recovery kit text of a vault with Save and Print, and the checkbox that the
/// user saved it.
struct RecoveryKitPanel: View {
  let text: String
  let vaultName: String
  @Binding var kitSaved: Bool
  /// Called with the message of a failed save.
  let onError: (String) -> Void

  var body: some View {
    ScrollView {
      Text(text)
        .font(.caption.monospaced())
        .textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
    }
    .frame(height: 160)
    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))

    HStack {
      Button("Save…") { save() }
      Button("Print…") { printKit() }
    }

    Toggle("I saved the recovery kit", isOn: $kitSaved)
  }

  private func save() {
    let panel = NSSavePanel()
    panel.nameFieldStringValue = "Axo Pass Recovery Kit - \(vaultName).txt"
    panel.allowedContentTypes = [.plainText]
    panel.isExtensionHidden = false
    guard panel.runModal() == .OK, let url = panel.url else { return }
    do {
      try text.write(to: url, atomically: true, encoding: .utf8)
    } catch {
      onError(error.userMessage)
    }
  }

  private func printKit() {
    let info = NSPrintInfo.shared.copy() as? NSPrintInfo ?? NSPrintInfo()
    info.horizontalPagination = .fit
    info.isVerticallyCentered = false
    let width = info.paperSize.width - info.leftMargin - info.rightMargin
    let view = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: 0))
    view.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
    view.string = text
    view.sizeToFit()
    let operation = NSPrintOperation(view: view, printInfo: info)
    operation.jobTitle = "Axo Pass Recovery Kit - \(vaultName)"
    operation.run()
  }
}

/// Sync symbol of a vault row in the sidebar. Shows nothing for a vault that
/// does not sync. The help text gives the notice of the report, the synced
/// folder, the turn-off that waits, or the error of the report. A click on the
/// symbol of a synced vault opens its sync status.
struct VaultSyncSymbol: View {
  @Environment(SyncModel.self) private var sync
  let vault: SyncVaultRef

  var body: some View {
    switch sync.state(vault.key) {
    case .none, .off:
      EmptyView()
    case .on:
      Button {
        sync.sheet = .status(vault)
      } label: {
        onSymbol
      }
      .buttonStyle(.plain)
    case .turningOff:
      symbol("clock.arrow.circlepath", .tertiary, syncDisableInProgressMessage)
    case .unknown(let message):
      symbol("exclamationmark.circle", .secondary, "Could not read sync status: \(message)")
    }
  }

  @ViewBuilder
  private var onSymbol: some View {
    if let notice = sync.report(vault.key).flatMap(syncNotice) {
      symbol("exclamationmark.arrow.triangle.2.circlepath", .orange, notice)
    } else {
      folderSymbol
    }
  }

  @ViewBuilder
  private var folderSymbol: some View {
    switch sync.state(vault.key) {
    case .on(let root?) where sync.folder != nil && sync.folder != root:
      symbol(
        "arrow.triangle.2.circlepath", .secondary,
        "Syncs with \(rootDescription(root)), not the folder in Settings")
    case .on(let root?):
      symbol("arrow.triangle.2.circlepath", .secondary, "Syncs with \(rootDescription(root))")
    case .on(nil):
      symbol(
        "arrow.triangle.2.circlepath", .orange, "Choose the synced folder again")
    default:
      EmptyView()
    }
  }

  private func symbol(_ name: String, _ style: some ShapeStyle, _ help: String) -> some View {
    Image(systemName: name)
      .font(.caption)
      .foregroundStyle(style)
      .help(help)
      .accessibilityLabel(help)
  }
}

/// Folder of `root`, for display. A folder in iCloud Drive shows as
/// "iCloud Drive/…" and a folder in the home folder starts with "~".
func rootDescription(_ root: SyncRootInfo) -> String {
  switch root {
  case .folder(let path):
    let iCloudDrive = NSHomeDirectory() + "/Library/Mobile Documents/com~apple~CloudDocs"
    if path == iCloudDrive { return "iCloud Drive" }
    if path.hasPrefix(iCloudDrive + "/") {
      return "iCloud Drive" + path.dropFirst(iCloudDrive.count)
    }
    return (path as NSString).abbreviatingWithTildeInPath
  case .iCloud: return "iCloud Drive"
  case .s3(let name): return "S3 location \(name)"
  }
}

/// Full path of `root` for help text, or its description if it has no path.
func rootHelp(_ root: SyncRootInfo) -> String {
  if case .folder(let path) = root { return path }
  return rootDescription(root)
}

/// Turn on sync for one vault with the synced folder of the app: save the
/// recovery kit and confirm, or see the join offer if the folder already holds
/// the vault.
struct SyncEnableSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let vault: SyncVaultRef

  private enum Step {
    case preparing
    case noFolder
    case kit(SyncSetupHandle, text: String)
    case join(SyncRootInfo)
    case disableInProgress
    case done(deduplicated: [String])
  }

  @State private var step: Step = .preparing
  /// Folder the setup was prepared with.
  @State private var root: SyncRootInfo? = nil
  @State private var kitSaved = false
  @State private var isWorking = false
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Turn On Sync for \(vault.name)").font(.headline)

      switch step {
      case .preparing: preparingStep
      case .noFolder: noFolderStep
      case .kit(let setup, let text): kitStep(setup, text: text)
      case .join(let root): joinStep(root)
      case .disableInProgress: disableInProgressStep
      case .done(let titles): doneStep(titles)
      }
    }
    .padding(20)
    .frame(width: 520)
    .task { await start() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
  }

  // MARK: - Start

  private var preparingStep: some View {
    VStack(alignment: .leading, spacing: 12) {
      if error != nil {
        errorLabel
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
  }

  private var noFolderStep: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(syncNoFolderMessage)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
      HStack {
        Spacer()
        Button("OK") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  /// Show the turn-off that waits, or prepare the setup with the synced folder
  /// of the app.
  private func start() async {
    await sync.reload(vault.key)
    if sync.state(vault.key) == .turningOff {
      step = .disableInProgress
      return
    }
    guard let root = sync.folder else {
      step = .noFolder
      return
    }
    self.root = root
    do {
      switch try await sync.prepare(vaultKey: vault.key, root: root) {
      case .kit(let setup):
        step = .kit(setup, text: setup.kitText())
      case .join(let root):
        step = .join(root)
      }
    } catch FfiError.InvalidInput(let message) {
      await showRefusal(message, root: root)
    } catch {
      self.error = error.userMessage
    }
  }

  /// Show the refusal of the setup, read from the state again.
  private func showRefusal(_ message: String, root: SyncRootInfo) async {
    switch await sync.refusal(vaultKey: vault.key, root: root) {
    case .disableInProgress: step = .disableInProgress
    case .folderHasVault(let root): step = .join(root)
    case .alreadyEnabled, nil: error = message
    }
  }

  // MARK: - Kit

  private func kitStep(_ setup: SyncSetupHandle, text: String) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(recoveryKitMessage)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)

      RecoveryKitPanel(text: text, vaultName: vault.name, kitSaved: $kitSaved) {
        error = $0
      }

      errorLabel

      HStack {
        if isWorking { ProgressView().controlSize(.small) }
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Turn On") { confirm(setup) }
          .keyboardShortcut(.defaultAction)
          .disabled(!kitSaved || isWorking)
      }
    }
  }

  private func confirm(_ setup: SyncSetupHandle) {
    error = nil
    isWorking = true
    let root = self.root
    Task {
      defer { isWorking = false }
      do {
        step = .done(deduplicated: try await sync.confirm(setup))
      } catch FfiError.InvalidInput(let message) {
        if let root {
          await showRefusal(message, root: root)
        } else {
          self.error = message
        }
      } catch {
        self.error = error.userMessage
      }
    }
  }

  // MARK: - Join offer

  private func joinStep(_ root: SyncRootInfo) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(
        "\(rootDescription(root)) already has this vault. Join it by pairing with a device that syncs it or with its recovery kit. Values that differ show as conflicts."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
      .help(rootHelp(root))

      HStack {
        Button("Pair with Another Device…") { join(.pair, root) }
        Button("Use a Recovery Kit…") { join(.recoveryKit, root) }
      }
      .disabled(sync.onJoin == nil)

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
      }
    }
  }

  /// Hand the choice to `onJoin`, which replaces this sheet with the pairing or
  /// kit sheet.
  private func join(_ choice: SyncJoinChoice, _ root: SyncRootInfo) {
    guard let onJoin = sync.onJoin else { return }
    onJoin(choice, vault, root)
  }

  // MARK: - Other steps

  private var disableInProgressStep: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(syncDisableInProgressMessage)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
      HStack {
        Spacer()
        Button("OK") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  private func doneStep(_ titles: [String]) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Sync is on.")
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)

      if !titles.isEmpty {
        Text(
          "Duplicate websites were removed from these items:"
        )
        .fixedSize(horizontal: false, vertical: true)
        ScrollView {
          VStack(alignment: .leading, spacing: 4) {
            ForEach(Array(titles.enumerated()), id: \.offset) { _, title in
              Text(title)
            }
          }
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(8)
        }
        .frame(maxHeight: 140)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      }

      HStack {
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  @ViewBuilder
  private var errorLabel: some View {
    if let error {
      SyncErrorLabel(message: error)
    }
  }
}
