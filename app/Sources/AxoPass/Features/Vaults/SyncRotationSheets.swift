import AxoPassFFI
import SwiftUI

extension RotationInfo {
  /// Name that the answer to the core uses for the rotation.
  var idInfo: RotationIdInfo {
    RotationIdInfo(signerId: signer.replicaId, keyId: keyId, fingerprint: fingerprint)
  }

  /// Name of the device that made the rotation.
  var signerName: String { signer.name ?? "Another device" }
}

/// Names joined as a list with commas and "and". "no other device" if empty.
func nameList(_ names: [String]) -> String {
  switch names.count {
  case 0: return "no other device"
  case 1: return names[0]
  case 2: return "\(names[0]) and \(names[1])"
  default: return names.dropLast().joined(separator: ", ") + ", and \(names[names.count - 1])"
  }
}

/// Names of `macs`, with "an unknown device" for a device the sync state does
/// not name.
private func rotationNames(_ macs: [RotationMacInfo]) -> [String] {
  macs.map { $0.name ?? "an unknown device" }
}

/// Keys of the vaults that `outcomes` rotated, in order.
private func rotatedVaults(_ outcomes: [VaultRotationInfo]) -> [String] {
  outcomes.compactMap { outcome in
    if case .rotated = outcome.outcome { outcome.vaultKey } else { nil }
  }
}

/// Outcome of a rotation of each vault.
struct RotationResultsView: View {
  @Environment(SyncModel.self) private var sync

  let outcomes: [VaultRotationInfo]

  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      if outcomes.isEmpty {
        Text("No vault needed a new sync key.")
          .foregroundStyle(.secondary)
      }
      ForEach(outcomes, id: \.vaultKey) { outcome in
        row(outcome)
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  @ViewBuilder
  private func row(_ outcome: VaultRotationInfo) -> some View {
    let name = sync.vaultName(outcome.vaultKey)
    switch outcome.outcome {
    case .rotated(let keyId, _, let unpinned, let kept):
      VStack(alignment: .leading, spacing: 2) {
        Label("\(name): sync key replaced", systemImage: "checkmark.circle.fill")
          .foregroundStyle(.green)
          .help("Key id: \(keyId)")
        if !unpinned.isEmpty {
          Text(
            unpinned.count == 1
              ? "1 device has no pinned keys and received no key. Pair it again to rejoin."
              : "\(unpinned.count) devices have no pinned keys and received no key. Pair them again to rejoin."
          )
          .font(.caption)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        }
        if !kept.isEmpty {
          Text(
            kept.count == 1
              ? "The files of 1 removed device stay in the synced folder until cleanup."
              : "The files of \(kept.count) removed devices stay in the synced folder until cleanup."
          )
          .font(.caption)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        }
      }
    case .waiting(let replicaIds):
      Label(
        "\(name): waiting for the files of \(replicaIds.count == 1 ? "1 retired device" : "\(replicaIds.count) retired devices") to download",
        systemImage: "arrow.down.circle"
      )
      .foregroundStyle(.orange)
    case .failed(let message):
      VStack(alignment: .leading, spacing: 2) {
        Label("\(name): the sync key was not changed", systemImage: "xmark.circle.fill")
          .foregroundStyle(.red)
        Text("The removed devices still have access to this vault. \(message)")
          .font(.caption)
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
          .fixedSize(horizontal: false, vertical: true)
      }
    }
  }
}

/// Whether any outcome waits for files that are downloading.
private func anyWaiting(_ outcomes: [VaultRotationInfo]) -> Bool {
  outcomes.contains { if case .waiting = $0.outcome { true } else { false } }
}

/// Outcome of a finished rotation, then a step that saves a new recovery kit
/// for each vault that rotated, then a summary of the kits. Each kit step
/// offers Skip. The summary offers a new kit again for each skipped vault.
struct RotationKitFlow: View {
  @Environment(SyncModel.self) private var sync
  @Environment(\.dismiss) private var dismiss

  let outcomes: [VaultRotationInfo]
  /// Whether the flow asks the user to save a new kit after the results.
  var savesKit = true

  private enum Step: Equatable {
    case results
    /// Kit of the vault at this index of `rotated`.
    case kit(Int)
    case summary
  }

  @State private var step: Step = .results
  /// Keys of the vaults whose new kit was added.
  @State private var saved: Set<String> = []
  /// Kit text of the current kit step. Nil while it is prepared.
  @State private var kitText: String? = nil
  @State private var label = ""
  @State private var kitSaved = false
  @State private var isWorking = false
  @State private var error: String? = nil

  private var rotated: [String] { savesKit ? rotatedVaults(outcomes) : [] }

  var body: some View {
    switch step {
    case .results: resultsStep
    case .kit(let index): kitStep(index)
    case .summary: summaryStep
    }
  }

  // MARK: - Steps

  private var resultsStep: some View {
    VStack(alignment: .leading, spacing: 12) {
      RotationResultsView(outcomes: outcomes)
      if !rotated.isEmpty {
        Text(
          rotated.count == 1
            ? "Recovery kits made before the change do not open this vault. Save a new kit in the next step."
            : "Recovery kits made before the change do not open these vaults. Save a new kit for each in the next steps."
        )
        .font(.caption)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
      }
      HStack {
        Spacer()
        if rotated.isEmpty {
          Button("Done") { dismiss() }
            .keyboardShortcut(.defaultAction)
        } else {
          Button("Continue") { step = .kit(0) }
            .keyboardShortcut(.defaultAction)
        }
      }
    }
  }

  private func kitStep(_ index: Int) -> some View {
    let vaultKey = rotated[index]
    let name = sync.vaultName(vaultKey)
    return VStack(alignment: .leading, spacing: 12) {
      Text(
        rotated.count == 1
          ? "New Recovery Kit for \(name)"
          : "New Recovery Kit for \(name) (\(index + 1) of \(rotated.count))"
      )
      .font(.subheadline.weight(.semibold))
      Text(recoveryKitMessage)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)

      if let kitText {
        RecoveryKitPanel(text: kitText, vaultName: name, kitSaved: $kitSaved) {
          error = $0
        }
        KitLabelField(label: $label)
      } else if error == nil {
        HStack(spacing: 8) {
          ProgressView().controlSize(.small)
          Text("Preparing recovery kit…").foregroundStyle(.secondary)
        }
      }

      if let error { SyncErrorLabel(message: error) }

      HStack {
        if isWorking { ProgressView().controlSize(.small) }
        Spacer()
        Button("Skip") { advance(from: index) }
          .disabled(isWorking)
        Button("Add Kit") {
          if let kitText { add(kitText, vaultKey: vaultKey, index: index) }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(kitText == nil || !kitSaved || isWorking)
      }
    }
    .task(id: index) { await create(vaultKey) }
  }

  private var summaryStep: some View {
    VStack(alignment: .leading, spacing: 12) {
      GroupedTable(rotated, id: \.self) { vaultKey in
        HStack(spacing: 8) {
          Text(sync.vaultName(vaultKey))
          Spacer(minLength: 8)
          if saved.contains(vaultKey) {
            Text("New kit added")
              .foregroundStyle(.secondary)
          } else {
            Label("Skipped", systemImage: "exclamationmark.circle.fill")
              .foregroundStyle(.orange)
            Button("New Kit…") {
              sync.sheet = .newKit(SyncVaultRef(key: vaultKey, name: sync.vaultName(vaultKey)))
            }
            .controlSize(.small)
          }
        }
      }
      if saved.count < rotated.count {
        Text(
          "A skipped vault does not open with any recovery kit until you save a new one. Its sync status shows it as needing a new kit."
        )
        .font(.caption)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
      }
      HStack {
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  // MARK: - Actions

  /// Prepare the kit of vault `vaultKey` for a new kit step.
  private func create(_ vaultKey: String) async {
    kitText = nil
    label = ""
    kitSaved = false
    error = nil
    do {
      kitText = try await sync.createKit(vaultKey: vaultKey)
    } catch FfiError.AuthExpired {
      // The app locked, which closes the sheet.
    } catch {
      self.error = error.userMessage
    }
  }

  private func add(_ text: String, vaultKey: String, index: Int) {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        try await sync.confirmKit(
          vaultKey: vaultKey, kitText: text,
          label: label.trimmingCharacters(in: .whitespacesAndNewlines))
        saved.insert(vaultKey)
        advance(from: index)
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = error.userMessage
      }
    }
  }

  private func advance(from index: Int) {
    step = index + 1 < rotated.count ? .kit(index + 1) : .summary
  }
}

/// Remove devices from every vault they belong to, with a new sync key for
/// each of those vaults. Each device is retired, so its last files are joined
/// first, or lost or stolen, so they are not waited for.
struct RemoveMacSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let preselect: String?

  /// Signing keys of the selected devices.
  @State private var selection: Set<String> = []
  @State private var reasons: [String: MacRemovalReason] = [:]
  @State private var started = false
  @State private var confirming = false
  @State private var isWorking = false
  @State private var outcomes: [VaultRotationInfo]? = nil
  @State private var error: String? = nil

  private var macs: [RemovableMac] { sync.removableMacs() }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Remove Device").font(.headline)

      if let outcomes, !anyWaiting(outcomes) {
        RotationKitFlow(outcomes: outcomes)
      } else if let outcomes {
        RotationResultsView(outcomes: outcomes)
        if let error { SyncErrorLabel(message: error) }
        waitingButtons
      } else {
        chooseView
      }
    }
    .padding(20)
    .frame(width: 520)
    .onAppear { select() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .confirmationDialog(
      selection.count == 1 ? "Remove 1 device?" : "Remove \(selection.count) devices?",
      isPresented: $confirming
    ) {
      Button("Remove", role: .destructive) { run() }
    } message: {
      Text(confirmMessage)
    }
  }

  // MARK: - Choose

  @ViewBuilder
  private var chooseView: some View {
    Text(
      "Axo Pass makes a new sync key for every vault the device belongs to, and gives it only to the devices that stay. The removed device keeps a copy of the old key and of everything it already synced."
    )
    .foregroundStyle(.secondary)
    .fixedSize(horizontal: false, vertical: true)

    if macs.isEmpty {
      Text("No other device syncs these vaults.")
        .foregroundStyle(.secondary)
    } else {
      VStack(alignment: .leading, spacing: 10) {
        ForEach(macs) { mac in
          macRow(mac)
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
      Button("Remove…") { confirming = true }
        .keyboardShortcut(.defaultAction)
        .disabled(selection.isEmpty || isWorking)
    }
  }

  /// Device toggle with the reason picker of a selected device, and the text
  /// on what happens to its files.
  private func macRow(_ mac: RemovableMac) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      macToggle(mac)
      if selection.contains(mac.signingKey) {
        Text((reasons[mac.signingKey] ?? .retired).filesText)
          .font(.caption)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
          .padding(.leading, 20)
      }
    }
    .disabled(isWorking)
  }

  private func macToggle(_ mac: RemovableMac) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 8) {
      Toggle(
        isOn: Binding(
          get: { selection.contains(mac.signingKey) },
          set: { on in
            if on { selection.insert(mac.signingKey) } else { selection.remove(mac.signingKey) }
          })
      ) {
        VStack(alignment: .leading, spacing: 2) {
          Text(mac.left ? "\(mac.name) (turned sync off)" : mac.name)
          Text(nameList(mac.vaultNames))
            .font(.caption)
            .foregroundStyle(.secondary)
          if mac.preselected {
            Text("Not paired. Its keys came from the synced folder.")
              .font(.caption)
              .foregroundStyle(.orange)
          }
        }
      }
      Spacer(minLength: 8)
      if selection.contains(mac.signingKey) {
        Picker(
          "Reason",
          selection: Binding(
            get: { reasons[mac.signingKey] ?? .retired },
            set: { reasons[mac.signingKey] = $0 })
        ) {
          ForEach(MacRemovalReason.allCases) { Text($0.rawValue).tag($0) }
        }
        .labelsHidden()
        .pickerStyle(.segmented)
        .fixedSize()
      }
    }
  }

  /// Select the preselected device and the devices Remove Mac selects at
  /// first, once.
  private func select() {
    guard !started else { return }
    started = true
    if let preselect {
      selection = [preselect]
    } else {
      selection = Set(macs.filter(\.preselected).map(\.signingKey))
    }
  }

  private var confirmMessage: String {
    let removed = macs.filter { selection.contains($0.signingKey) }.map(\.name)
    let remaining = sync.remainingMacNames(removing: selection)
    let keep =
      remaining.isEmpty
      ? "No other device keeps access, so only this device syncs these vaults."
      : "These devices keep access: \(nameList(remaining + ["this device"]))."
    return
      "\(nameList(removed)) loses access to every vault it shares with this device. \(keep) This cannot be undone."
  }

  // MARK: - Run

  private func removals() -> [MacRemovalInfo] {
    selection.sorted().map { key in
      MacRemovalInfo(signingKey: key, retired: (reasons[key] ?? .retired) == .retired)
    }
  }

  private func run() {
    error = nil
    isWorking = true
    let removals = removals()
    Task {
      defer { isWorking = false }
      do {
        outcomes = merged(outcomes, try await sync.removeMacs(removals))
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = error.userMessage
      }
    }
  }

  private var waitingButtons: some View {
    HStack {
      if isWorking { ProgressView().controlSize(.small) }
      Spacer()
      Button("Cancel") { dismiss() }
        .keyboardShortcut(.cancelAction)
      Button("Keep Waiting") { run() }
        .keyboardShortcut(.defaultAction)
        .disabled(isWorking)
    }
  }
}

/// Outcomes of `earlier` replaced by the outcomes of `later` for the same
/// vault, followed by the other outcomes of `later`. A run that keeps waiting
/// can omit vaults that an earlier run rotated, so their kit steps still run.
private func merged(_ earlier: [VaultRotationInfo]?, _ later: [VaultRotationInfo])
  -> [VaultRotationInfo]
{
  var result = earlier ?? []
  for outcome in later {
    if let index = result.firstIndex(where: { $0.vaultKey == outcome.vaultKey }) {
      result[index] = outcome
    } else {
      result.append(outcome)
    }
  }
  return result
}

extension MacRemovalReason {
  /// What happens to the files of a device removed for this reason.
  var filesText: String {
    switch self {
    case .retired:
      return
        "Axo Pass waits for the last files of this device to download, so its edits are kept. Its files are then deleted from the synced folder. Files that were not all joined stay there until Clean Up."
    case .lost:
      return
        "Axo Pass does not wait for the files of this device. Its files are deleted from the synced folder after the new key is published. Edits that only those files hold are lost."
    }
  }
}

/// Replace the sync key of one vault, or of every synced vault, and remove no
/// device, then save a new recovery kit for each vault.
struct RotateKeySheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  /// Vault whose key is replaced. If nil, every synced vault.
  let vault: SyncVaultRef?

  @State private var confirming = false
  @State private var isWorking = false
  @State private var outcomes: [VaultRotationInfo]? = nil
  @State private var error: String? = nil

  /// Names of the devices that keep access, this device last.
  private var keepAccess: [String] {
    let others: [String]
    if let vault {
      others = (sync.report(vault.key)?.knownMacs ?? [])
        .filter { !$0.thisMac && !$0.removed && !$0.left }
        .map(\.name)
        .sorted()
    } else {
      others = sync.remainingMacNames(removing: [])
    }
    return others + ["this device"]
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(vault.map { "Replace Sync Key of \($0.name)" } ?? "Replace All Sync Keys")
        .font(.headline)

      if let outcomes {
        RotationKitFlow(outcomes: outcomes)
      } else {
        Text(
          vault.map {
            "Use this if someone else has access to your synced folder or the recovery kit for \($0.name). Axo Pass will sync future changes with a new key to prevent reads using the old key."
          }
            ?? "Use this if someone else has access to your synced folder or a recovery kit. Axo Pass will sync future changes with new keys to prevent reads using the old key."
        )
        .fixedSize(horizontal: false, vertical: true)

        Text(
          "Your devices will switch to the new key the next time they sync. Existing recovery kits will no longer work and have to be recreated."
        )
        .fixedSize(horizontal: false, vertical: true)

        Text("These devices are synced: \(nameList(keepAccess)).")
          .fixedSize(horizontal: false, vertical: true)

        if let error { SyncErrorLabel(message: error) }

        HStack {
          if isWorking { ProgressView().controlSize(.small) }
          Spacer()
          Button("Cancel") { dismiss() }
            .keyboardShortcut(.cancelAction)
          Button("Replace…") { confirming = true }
            .keyboardShortcut(.defaultAction)
            .disabled(isWorking)
        }
      }
    }
    .padding(20)
    .frame(width: 520)
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .confirmationDialog(
      vault.map { "Replace the sync key of \($0.name)?" }
        ?? "Replace the sync key of every synced vault?",
      isPresented: $confirming
    ) {
      Button("Replace Sync Key") { run() }
    } message: {
      Text(
        "Devices that are offline will pick up the new key when they come back online."
      )
    }
  }

  private func run() {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        outcomes = try await sync.rotateKey(vaultKey: vault?.key)
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = error.userMessage
      }
    }
  }
}

/// Revoke one recovery kit of a vault and replace the sync key of that vault
/// only, then save a new kit for it.
struct RevokeKitSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let vault: SyncVaultRef
  let kit: RecoveryKitInfo

  @State private var isWorking = false
  @State private var outcomes: [VaultRotationInfo]? = nil
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Revoke Recovery Kit").font(.headline)

      if let outcomes {
        RotationKitFlow(outcomes: outcomes, savesKit: false)
      } else {
        InsetGroupedSection {
          Text("\(kit.displayName)")
        }
        Text(
          "Use this if the recovery kit is lost or stolen. Anyone who has it can open \(vault.name) from the synced folder. Revoking the kit will disable it."
        )
        .fixedSize(horizontal: false, vertical: true)

        Text(
          "Revoking the recovery kit will create a new sync key for \(vault.name). Devices that are offline will pick up the new key when they come back online."
        )
        .fixedSize(horizontal: false, vertical: true)

        Text("Please make a new recovery kit for \(vault.name) afterwards.")
          .fixedSize(horizontal: false, vertical: true)

        if let error { SyncErrorLabel(message: error) }

        HStack {
          if isWorking { ProgressView().controlSize(.small) }
          Spacer()
          Button("Cancel") { dismiss() }
            .keyboardShortcut(.cancelAction)
          Button("Revoke Kit", role: .destructive) { run() }
            .keyboardShortcut(.defaultAction)
            .disabled(isWorking)
        }
      }
    }
    .padding(20)
    .frame(width: 520)
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
  }

  private func run() {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        outcomes = try await sync.revokeKit(vaultKey: vault.key, recipient: kit.recipient)
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = error.userMessage
      }
    }
  }
}

/// Key rotations of other devices that wait for an answer in one vault.
struct RotationPromptSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let vault: SyncVaultRef

  /// Rotations of the decline in the confirmation.
  @State private var declining: [RotationInfo]? = nil
  @State private var isWorking = false
  @State private var error: String? = nil
  /// Removals that the accepted rotation did not make, to run again.
  @State private var repeatRemovals: [MacRemovalInfo] = []
  @State private var outcomes: [VaultRotationInfo]? = nil

  private var prompts: [RotationPromptInfo] { sync.report(vault.key)?.rotations ?? [] }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Sync Key for \(vault.name)").font(.headline)

      if let outcomes {
        RotationKitFlow(outcomes: outcomes)
      } else if !repeatRemovals.isEmpty {
        repeatView
      } else if prompts.isEmpty {
        Text("No device is waiting for an answer.")
          .foregroundStyle(.secondary)
        HStack {
          Spacer()
          Button("Done") { dismiss() }
            .keyboardShortcut(.defaultAction)
        }
      } else {
        ForEach(Array(prompts.enumerated()), id: \.offset) { _, prompt in
          promptView(prompt)
        }
        if let error { SyncErrorLabel(message: error) }
        HStack {
          if isWorking { ProgressView().controlSize(.small) }
          Spacer()
          Button("Later") { dismiss() }
            .keyboardShortcut(.cancelAction)
        }
      }
    }
    .padding(20)
    .frame(width: 520)
    .task { await sync.reload(vault.key) }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .confirmationDialog(
      "Decline the new sync key?",
      isPresented: Binding(
        get: { declining != nil }, set: { if !$0 { declining = nil } }),
      presenting: declining
    ) { rotations in
      Button("Decline", role: .destructive) { decline(rotations) }
    } message: { _ in
      Text(
        "This device keeps the old key and stops syncing this vault with the devices that accepted the new one. Pair it again to rejoin them, or remove the device that made the new key."
      )
    }
  }

  // MARK: - Prompts

  @ViewBuilder
  private func promptView(_ prompt: RotationPromptInfo) -> some View {
    switch prompt {
    case .confirm(let rotation, let replaces):
      VStack(alignment: .leading, spacing: 8) {
        Text(
          replaces
            ? "\(rotation.signerName) made a new sync key that replaces the key this device uses."
            : "\(rotation.signerName) made a new sync key."
        )
        .fixedSize(horizontal: false, vertical: true)
        details(rotation)
        HStack {
          Spacer()
          Button("Decline…") { declining = [rotation] }
            .disabled(isWorking)
          Button("Accept") { accept(rotation) }
            .keyboardShortcut(.defaultAction)
            .disabled(isWorking)
        }
      }
      .padding(10)
      .frame(maxWidth: .infinity, alignment: .leading)
      .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    case .choose(let first, let second, let current):
      VStack(alignment: .leading, spacing: 8) {
        Text(
          "\(first.signerName) and \(second.signerName) each made a new sync key and removed the other. Choose the one you trust, or decline both."
        )
        .fixedSize(horizontal: false, vertical: true)
        if current {
          Text("This device uses the key of \(first.signerName).")
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        ForEach([first, second], id: \.fingerprint) { rotation in
          VStack(alignment: .leading, spacing: 6) {
            Text("Key of \(rotation.signerName)").font(.subheadline.weight(.semibold))
            details(rotation)
            Button("Accept the Key of \(rotation.signerName)") { accept(rotation) }
              .disabled(isWorking)
          }
        }
        HStack {
          Spacer()
          Button("Decline Both…") { declining = [first, second] }
            .disabled(isWorking)
        }
      }
      .padding(10)
      .frame(maxWidth: .infinity, alignment: .leading)
      .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }
  }

  /// The devices that lose access and the devices that keep it.
  private func details(_ rotation: RotationInfo) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(
        rotation.removed.isEmpty
          ? "No device is removed."
          : "Removed: \(nameList(rotationNames(rotation.removed)))."
      )
      Text("Keep access: \(nameList(rotationNames(rotation.remaining) + ["this device"])).")
    }
    .font(.caption)
    .foregroundStyle(.secondary)
    .fixedSize(horizontal: false, vertical: true)
  }

  private var repeatView: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(
        "The key you accepted does not remove \(repeatRemovals.count == 1 ? "a device" : "\(repeatRemovals.count) devices") that your own rotation removed. Remove \(repeatRemovals.count == 1 ? "it" : "them") again with the new key?"
      )
      .fixedSize(horizontal: false, vertical: true)
      if let error { SyncErrorLabel(message: error) }
      HStack {
        if isWorking { ProgressView().controlSize(.small) }
        Spacer()
        Button("Not Now") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Remove Again") { removeAgain() }
          .keyboardShortcut(.defaultAction)
          .disabled(isWorking)
      }
    }
  }

  // MARK: - Actions

  private func accept(_ rotation: RotationInfo) {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        let repeated = try await sync.acceptRotation(vaultKey: vault.key, rotation: rotation)
        if repeated.isEmpty {
          dismiss()
        } else {
          repeatRemovals = repeated
        }
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = error.userMessage
      }
    }
  }

  private func decline(_ rotations: [RotationInfo]) {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        try await sync.declineRotations(vaultKey: vault.key, rotations: rotations)
        dismiss()
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = error.userMessage
      }
    }
  }

  private func removeAgain() {
    error = nil
    isWorking = true
    let removals = repeatRemovals
    Task {
      defer { isWorking = false }
      do {
        outcomes = try await sync.removeMacs(removals)
      } catch FfiError.AuthExpired {
        // The app locked, which closes the sheet.
      } catch {
        self.error = error.userMessage
      }
    }
  }
}
