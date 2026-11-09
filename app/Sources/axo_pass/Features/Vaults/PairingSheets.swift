import AppKit
import AxoPassFFI
import SwiftUI
import UniformTypeIdentifiers

/// Pairing of this Mac as the new Mac: the code to type on a Mac that syncs
/// the vaults, and the vaults as they are received, waiting, and imported.
/// Closing the sheet finishes the pairing. Imports of vaults already received
/// continue.
struct PairingSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  /// Synced folder. Nil if none is chosen in Settings.
  let root: SyncRootInfo?
  /// Vault of the join offer, if the pairing started from it.
  let join: SyncVaultRef?

  @State private var handle: PairingHandle? = nil
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(join.map { "Pair to Join \($0.name)" } ?? "Pair with Another Mac").font(.headline)

      if root == nil {
        Text(syncNoFolderMessage)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        HStack {
          Spacer()
          Button("OK") { dismiss() }
            .keyboardShortcut(.defaultAction)
        }
      } else if let handle {
        codeStep(handle)
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
          Text("Starting pairing…").foregroundStyle(.secondary)
        }
      }
    }
    .padding(20)
    .frame(width: 520)
    .task { await start() }
    .onDisappear { try? handle?.finish() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
  }

  private func start() async {
    guard let root, handle == nil else { return }
    do {
      handle = try await sync.startPairing(root: root)
    } catch FfiError.AuthExpired {
      // The app locked, which closes the sheet.
    } catch {
      self.error = String(describing: error)
    }
  }

  private func codeStep(_ handle: PairingHandle) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(
        "On a Mac that syncs your vaults, open Axo Pass, click the pairing request in the sidebar, and enter this code. Then choose the vaults to share."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      Text(handle.code())
        .font(.title2.monospaced())
        .textSelection(.enabled)
        .frame(maxWidth: .infinity)
        .padding(10)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))

      let received = handle.vaultIds().filter { sync.imports[$0] != nil }
      if received.isEmpty {
        Text("No vaults received yet.")
          .foregroundStyle(.secondary)
      } else {
        VStack(alignment: .leading, spacing: 6) {
          ForEach(received, id: \.self) { vaultId in
            if let progress = sync.imports[vaultId] {
              importRow(vaultId, progress)
            }
          }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      }

      Text(
        "Keep this open until the other Mac shares the vaults. Vaults already received continue to download after you finish."
      )
      .font(.callout)
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      HStack {
        Spacer()
        Button("Finish") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  private func importRow(_ vaultId: String, _ progress: VaultImportProgress) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 8) {
      switch progress {
      case .paired, .waiting:
        ProgressView().controlSize(.mini)
      case .imported:
        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
      case .failed:
        Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
      }
      Text(vaultName(vaultId, progress))
      Spacer(minLength: 8)
      Text(progressText(progress))
        .font(.callout)
        .foregroundStyle(.secondary)
        .lineLimit(3)
        .multilineTextAlignment(.trailing)
        .textSelection(.enabled)
    }
  }

  /// Name of a received vault: the listed vault of its id, or its short id
  /// before the import.
  private func vaultName(_ vaultId: String, _ progress: VaultImportProgress) -> String {
    let key: String?
    if case .imported(let vaultKey) = progress {
      key = vaultKey
    } else {
      key = model.vaultKey(id: vaultId)
    }
    if let key, let vault = model.vaults.first(where: { $0.key == key }) {
      return vault.name ?? vault.key
    }
    return key ?? "Vault \(vaultId)"
  }

  private func progressText(_ progress: VaultImportProgress) -> String {
    switch progress {
    case .paired: return "Received"
    case .waiting: return "Waiting for files from the other Mac"
    case .imported: return "Ready"
    case .failed(let message): return "Failed: \(message)"
    }
  }
}

/// Pairing prompt of the requests under one synced folder. Shows the number of
/// requests and no computer name until a code matches. Then lists the vaults
/// the request asks for, and shares the picked vaults once.
struct PairingPromptSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let root: SyncRootInfo

  private enum Step {
    case code
    case share(name: String, vaults: [PairingVaultInfo])
    case shared(vaults: [PairingVaultInfo], results: [PairingGrantInfo])
  }

  @State private var step: Step = .code
  @State private var code = ""
  @State private var noMatch = false
  @State private var picked: Set<String> = []
  @State private var isWorking = false
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Pairing Request").font(.headline)

      switch step {
      case .code: codeStep
      case .share(let name, let vaults): shareStep(name, vaults)
      case .shared(let vaults, let results): sharedStep(vaults, results)
      }
    }
    .padding(20)
    .frame(width: 520)
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
  }

  // MARK: - Code

  /// Code typed, without hyphens and spaces, has the 16 characters of a code.
  private var codeComplete: Bool {
    code.filter { $0 != "-" && $0 != " " }.count == 16
  }

  private var requestText: String {
    switch sync.pairingCounts[root] ?? 0 {
    case 0: return "A Mac asked to pair with the vaults in this synced folder."
    case 1: return "A Mac asks to pair with the vaults in this synced folder."
    case let count: return "\(count) Macs ask to pair with the vaults in this synced folder."
    }
  }

  private var codeStep: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(
        "\(requestText) Enter the code shown on the new Mac. Pair only with a Mac you set up yourself."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      Text(rootDescription(root))
        .font(.callout.monospaced())
        .lineLimit(1)
        .truncationMode(.middle)
        .help(rootDescription(root))

      TextField("XXXX-XXXX-XXXX-XXXX", text: $code)
        .font(.title3.monospaced())
        .textFieldStyle(.roundedBorder)
        .onSubmit { if codeComplete { enterCode() } }
        .onChange(of: code) { noMatch = false }

      if noMatch {
        Text("This code matches no request. Check the code on the new Mac.")
          .font(.caption)
          .foregroundStyle(.red)
      }
      if let error { SyncErrorLabel(message: error) }

      HStack {
        Button("Dismiss") { dismissRequests() }
          .help("Stop showing these requests. Only a new request shows again.")
          .disabled(isWorking)
        if isWorking { ProgressView().controlSize(.small) }
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Enter Code") { enterCode() }
          .keyboardShortcut(.defaultAction)
          .disabled(!codeComplete || isWorking)
      }
    }
  }

  private func enterCode() {
    error = nil
    noMatch = false
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        guard let name = try await sync.matchCode(root: root, code: code) else {
          noMatch = true
          return
        }
        let vaults = try await sync.pairingVaults(root: root, code: code)
        picked = []
        step = .share(name: name, vaults: vaults)
      } catch {
        self.error = String(describing: error)
      }
    }
  }

  private func dismissRequests() {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        try await sync.dismissPairing(root: root)
        dismiss()
      } catch {
        self.error = String(describing: error)
      }
    }
  }

  // MARK: - Share

  private func shareStep(_ name: String, _ vaults: [PairingVaultInfo]) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("The code matches the request of “\(name)”.")
        .fixedSize(horizontal: false, vertical: true)

      if vaults.isEmpty {
        Text("This Mac syncs none of the vaults that the new Mac asks for.")
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
      } else {
        Text("Choose the vaults to share. The new Mac receives their sync keys.")
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        VStack(alignment: .leading, spacing: 6) {
          ForEach(vaults, id: \.vaultId) { vault in
            Toggle(
              vault.name ?? vault.vaultKey,
              isOn: Binding(
                get: { picked.contains(vault.vaultId) },
                set: { on in
                  if on { picked.insert(vault.vaultId) } else { picked.remove(vault.vaultId) }
                }))
          }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      }

      if let error { SyncErrorLabel(message: error) }

      HStack {
        if isWorking { ProgressView().controlSize(.small) }
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Share") { share(vaults) }
          .keyboardShortcut(.defaultAction)
          .disabled(picked.isEmpty || isWorking)
      }
    }
  }

  /// Grant the picked vaults once.
  private func share(_ vaults: [PairingVaultInfo]) {
    error = nil
    isWorking = true
    let ids = vaults.map(\.vaultId).filter { picked.contains($0) }
    Task {
      defer { isWorking = false }
      do {
        let results = try await sync.grant(root: root, code: code, vaultIds: ids)
        step = .shared(vaults: vaults, results: results)
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = String(describing: error)
      }
    }
  }

  private func sharedStep(_ vaults: [PairingVaultInfo], _ results: [PairingGrantInfo])
    -> some View
  {
    VStack(alignment: .leading, spacing: 12) {
      VStack(alignment: .leading, spacing: 6) {
        ForEach(results, id: \.vaultId) { result in
          let vault = vaults.first { $0.vaultId == result.vaultId }
          HStack(alignment: .firstTextBaseline, spacing: 8) {
            if case .granted = result.outcome {
              Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            } else {
              Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
            }
            Text(vault.map { $0.name ?? $0.vaultKey } ?? result.vaultId)
            Spacer(minLength: 8)
            Text(outcomeText(result.outcome))
              .font(.callout)
              .foregroundStyle(.secondary)
              .lineLimit(3)
              .multilineTextAlignment(.trailing)
              .textSelection(.enabled)
          }
        }
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(8)
      .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))

      Text("The new Mac adds each shared vault once its files download.")
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)

      HStack {
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  private func outcomeText(_ outcome: GrantOutcomeInfo) -> String {
    switch outcome {
    case .granted: return "Shared"
    case .conflict: return "Not shared. This vault knows the new Mac with other keys."
    case .notTrusted(let reason): return "Not shared. \(reason)"
    case .failed(let message): return "Failed: \(message)"
    }
  }
}

/// Import of a synced vault with its recovery kit, or join of a local vault
/// with it. Checks the kit every 5 seconds while files of the folder download,
/// for one minute at a time, then imports once the kit opens the key.
struct KitImportSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  /// Synced folder. Nil if none is chosen in Settings.
  let root: SyncRootInfo?
  /// Vault of the join offer, which the kit joins.
  let join: SyncVaultRef?

  private enum Step {
    case choose
    case checking
    case waiting([WaitingMacInfo])
    /// Checks stopped after a round. The user waits for another round or cancels.
    case paused([WaitingMacInfo])
    case refused(String)
    case importing
    case done(vaultKey: String, titles: [String])
  }

  /// Checks of one round of waiting, 5 seconds apart.
  private static let checksPerRound = 12

  @State private var step: Step = .choose
  @State private var kitText: String? = nil
  /// Round of checks. A change starts a new round.
  @State private var round = 0
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(join.map { "Join \($0.name) with a Recovery Kit" } ?? "Use a Recovery Kit")
        .font(.headline)

      if root == nil {
        Text(syncNoFolderMessage)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        HStack {
          Spacer()
          Button("OK") { dismiss() }
            .keyboardShortcut(.defaultAction)
        }
      } else {
        switch step {
        case .choose: chooseStep
        case .checking, .importing: progressStep
        case .waiting(let macs): waitingStep(macs, paused: false)
        case .paused(let macs): waitingStep(macs, paused: true)
        case .refused(let reason): refusedStep(reason)
        case .done(let vaultKey, let titles): doneStep(vaultKey, titles)
        }
      }
    }
    .padding(20)
    .frame(width: 520)
    .task(id: round) { await checkRound() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
  }

  // MARK: - Kit file

  private var chooseStep: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(
        join == nil
          ? "Choose the recovery kit file of a vault in the synced folder. The vault is added to this Mac."
          : "Choose the recovery kit file of this vault. Entries are merged, and values that differ show as conflicts."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      if let error { SyncErrorLabel(message: error) }

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Choose Kit…") { chooseKit() }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  private func chooseKit() {
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
      error = nil
      step = .checking
      round += 1
    } catch {
      self.error = String(describing: error)
    }
  }

  // MARK: - Checks

  /// Check the kit every 5 seconds for one round, and import once it opens
  /// the key. Stops if the sheet closes.
  private func checkRound() async {
    guard let root, let kitText, round > 0 else { return }
    for check in 0..<Self.checksPerRound {
      if check > 0 {
        try? await Task.sleep(for: .seconds(5))
      }
      if Task.isCancelled { return }
      do {
        let result = try await sync.checkKit(root: root, kitText: kitText)
        if Task.isCancelled { return }
        if case .recovered = result {
          await runImport(root: root, kitText: kitText)
          return
        }
        if !show(result) { return }
      } catch {
        fail(error)
        return
      }
    }
    if case .waiting(let macs) = step { step = .paused(macs) }
  }

  /// Show the check `result`. Returns whether the checks continue.
  private func show(_ result: RecoveryCheckInfo) -> Bool {
    switch result {
    case .recovered:
      return true
    case .waiting(let macs):
      step = .waiting(macs)
      return true
    case .kitOutdated:
      step = .refused(
        "This recovery kit is for an older sync key of the vault, so it cannot open the vault. Use a newer kit, or pair with a Mac that syncs the vault."
      )
      return false
    case .noKey:
      step = .refused(
        "No file in the synced folder opens with this recovery kit. Check that the kit is for a vault in this folder."
      )
      return false
    }
  }

  private func runImport(root: SyncRootInfo, kitText: String) async {
    step = .importing
    do {
      switch try await sync.importKit(root: root, kitText: kitText, join: join) {
      case .imported(let vaultKey, let deduplicated):
        let titles = await model.itemTitles(ids: deduplicated, vaultKey: vaultKey)
        step = .done(vaultKey: vaultKey, titles: titles)
      case .notImported(let check):
        // Files changed between the check and the import. Check again.
        if show(check) { round += 1 }
      }
    } catch {
      fail(error)
    }
  }

  private func fail(_ error: Error) {
    if case FfiError.AuthExpired = error { return }
    self.error = String(describing: error)
    step = .choose
  }

  private var progressStep: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack(spacing: 8) {
        ProgressView().controlSize(.small)
        if case .importing = step {
          Text(join == nil ? "Adding the vault…" : "Joining the vault…")
            .foregroundStyle(.secondary)
        } else {
          Text("Checking the recovery kit…").foregroundStyle(.secondary)
        }
      }
      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
          .disabled(isImporting)
      }
    }
  }

  private var isImporting: Bool {
    if case .importing = step { return true }
    return false
  }

  private func waitingStep(_ macs: [WaitingMacInfo], paused: Bool) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(
        "Files in the synced folder are still downloading. The kit is checked once every file is on this Mac. Waiting for files from:"
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      VStack(alignment: .leading, spacing: 4) {
        ForEach(macs, id: \.replicaId) { mac in
          Text(mac.name ?? "Another Mac")
        }
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(8)
      .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))

      HStack {
        if !paused {
          ProgressView().controlSize(.small)
          Text("Checking again every 5 seconds.")
            .font(.callout)
            .foregroundStyle(.secondary)
        }
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        if paused {
          Button("Keep Waiting") {
            step = .waiting(macs)
            round += 1
          }
          .keyboardShortcut(.defaultAction)
        }
      }
    }
  }

  private func refusedStep(_ reason: String) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Label(reason, systemImage: "exclamationmark.triangle.fill")
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
      HStack {
        Spacer()
        Button("Close") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Choose Another Kit…") { chooseKit() }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  private func doneStep(_ vaultKey: String, _ titles: [String]) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      let vault = model.vaults.first { $0.key == vaultKey }
      Text(
        join == nil
          ? "\(vault?.name ?? vaultKey) is on this Mac and syncs."
          : "\(vault?.name ?? vaultKey) syncs. Values that differ show as conflicts."
      )
      .fixedSize(horizontal: false, vertical: true)

      if !titles.isEmpty {
        Text("Duplicate websites were removed from these items:")
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
}
