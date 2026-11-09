import AppKit
import AxoPassFFI
import SwiftUI
import UniformTypeIdentifiers

extension View {
  /// Present the sync sheets that `SyncModel` requests: the enable sheet and
  /// the turn-off confirmation. Attach once, in the main window.
  func syncSheets() -> some View {
    modifier(SyncSheetsModifier())
  }
}

private struct SyncSheetsModifier: ViewModifier {
  @Environment(SyncModel.self) private var sync

  func body(content: Content) -> some View {
    @Bindable var sync = sync
    content
      .sheet(item: $sync.enableRequest) { vault in
        SyncEnableSheet(vault: vault)
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
  "This Mac stops syncing the vault. The vault stays here and on your other Macs. This Mac still has the vault's sync key until key rotation arrives in a later version."

/// Text of the delete confirmation of a synced vault.
let syncedVaultDeleteMessage =
  "This deletes the vault on this Mac only. Your other Macs still have it. Sync turns off first, so Axo Pass must be unlocked."

/// Text for a vault whose earlier turn-off waits for the synced folder.
let syncDisableInProgressMessage =
  "Sync is still turning off for this vault. You can turn it on again once the change reaches the synced folder."

/// Sync symbol of a vault row in the sidebar. Shows nothing for a vault that
/// does not sync. The help text gives the synced folder, the turn-off that
/// waits, or the error of the report.
struct VaultSyncSymbol: View {
  @Environment(SyncModel.self) private var sync
  let vaultKey: String

  var body: some View {
    switch sync.state(vaultKey) {
    case .none, .off:
      EmptyView()
    case .on(let root?) where sync.folder != nil && sync.folder != root:
      symbol(
        "arrow.triangle.2.circlepath", .secondary,
        "Syncs with \(rootDescription(root)), not the folder in Settings")
    case .on(let root?):
      symbol("arrow.triangle.2.circlepath", .secondary, "Syncs with \(rootDescription(root))")
    case .on(nil):
      symbol(
        "arrow.triangle.2.circlepath", .orange, "Choose the synced folder again")
    case .turningOff:
      symbol("clock.arrow.circlepath", .tertiary, syncDisableInProgressMessage)
    case .unknown(let message):
      symbol("exclamationmark.circle", .secondary, "Could not read sync status: \(message)")
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

/// Folder of `root`, for display.
func rootDescription(_ root: SyncRootInfo) -> String {
  switch root {
  case .folder(let path): return path
  case .iCloud: return "iCloud Drive"
  }
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
      if let error {
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
      Text(
        "Choose a synced folder in Settings › Vaults first."
      )
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
      self.error = String(describing: error)
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
      Text(
        "Save this recovery kit before turning on sync. If no other Mac is available, the kit opens the synced vault. Anyone with the kit and the folder can read the vault, so store it somewhere else."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

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
        Button("Save…") { saveKit(text) }
        Button("Print…") { printKit(text) }
      }

      Toggle("I saved the recovery kit", isOn: $kitSaved)

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

  private func saveKit(_ text: String) {
    let panel = NSSavePanel()
    panel.nameFieldStringValue = "Axo Pass Recovery Kit - \(vault.name).txt"
    panel.allowedContentTypes = [.plainText]
    panel.isExtensionHidden = false
    guard panel.runModal() == .OK, let url = panel.url else { return }
    do {
      try text.write(to: url, atomically: true, encoding: .utf8)
    } catch {
      self.error = String(describing: error)
    }
  }

  private func printKit(_ text: String) {
    let info = NSPrintInfo.shared.copy() as? NSPrintInfo ?? NSPrintInfo()
    info.horizontalPagination = .fit
    info.isVerticallyCentered = false
    let width = info.paperSize.width - info.leftMargin - info.rightMargin
    let view = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: 0))
    view.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
    view.string = text
    view.sizeToFit()
    let operation = NSPrintOperation(view: view, printInfo: info)
    operation.jobTitle = "Axo Pass Recovery Kit - \(vault.name)"
    operation.run()
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
        self.error = String(describing: error)
      }
    }
  }

  // MARK: - Join offer

  private func joinStep(_ root: SyncRootInfo) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(
        "The synced folder already has this vault. To join it, pair with a Mac that syncs it or use its recovery kit. Entries are merged, and values that differ show as conflicts."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      Text(rootDescription(root))
        .font(.callout.monospaced())
        .lineLimit(1)
        .truncationMode(.middle)
        .help(rootDescription(root))

      HStack {
        Button("Pair with Another Mac…") { join(.pair, root) }
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

  private func join(_ choice: SyncJoinChoice, _ root: SyncRootInfo) {
    guard let onJoin = sync.onJoin else { return }
    dismiss()
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
      Label(error, systemImage: "xmark.circle.fill")
        .font(.caption)
        .foregroundStyle(.red)
        .lineLimit(4)
        .fixedSize(horizontal: false, vertical: true)
        .textSelection(.enabled)
    }
  }
}
