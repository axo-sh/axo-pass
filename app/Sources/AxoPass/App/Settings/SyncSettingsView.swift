import AxoPassFFI
import SwiftUI

/// Sync settings that apply to every synced vault: the synced folder, the
/// devices, the vault status list, and the pairing requests.
/// Recovery kits and the key of one vault are in its status sheet. Sheets opened here show in the Settings window.
struct SyncSettingsView: View {
  @Environment(VaultsModel.self) private var model
  @Environment(SyncModel.self) private var sync
  @State private var showingLocation = false
  /// Device whose cleanup is confirmed.
  @State private var cleaning: SyncDevice? = nil
  /// Id of the device whose cleanup runs.
  @State private var cleaningId: String? = nil
  /// Whether the removal of this device is confirmed.
  @State private var confirmingLeave = false
  /// Whether the removal of this device runs.
  @State private var leaving = false
  @State private var error: String? = nil
  /// Measured height of the vault list content.
  @State private var vaultListHeight: CGFloat = 0

  var body: some View {
    SettingsForm {
      folderRow
      SettingsDivider()
      devicesRow
      SettingsDivider()
      vaultsRow
      SettingsDivider()
      pairingsRow
    }
    .sheet(isPresented: $showingLocation) {
      SyncLocationSheet()
    }
    .syncSheets(in: .settings)
    .confirmationDialog(
      "Clean up \(cleaning?.name ?? "this device")?",
      isPresented: Binding(get: { cleaning != nil }, set: { if !$0 { cleaning = nil } }),
      presenting: cleaning
    ) { device in
      Button("Clean Up", role: .destructive) { cleanUp(device) }
    } message: { _ in
      Text(
        "This deletes the files of the device from the synced folder. Its edits that other devices already joined stay in the vaults."
      )
    }
    .confirmationDialog("Remove this device?", isPresented: $confirmingLeave) {
      Button("Remove", role: .destructive) { leave() }
    } message: {
      Text(
        "This device stops syncing every vault, and your other devices list it as left. The vaults stay here and on your other devices. To sync again, pair this device again."
      )
    }
    .task(id: model.vaults) { await sync.reloadAll() }
    .task(id: sync.folder) { await sync.reloadRemoteVaults() }
  }

  // MARK: - Vaults

  /// Synced vaults with a status dot and a short status line. A click opens
  /// the sync status of the vault. Vaults with sync turned off and vaults in
  /// the synced folder follow under section headings, each unsynced vault with
  /// a Turn On Sync button. The list scrolls if it is taller than a fixed
  /// height. Reset Sync Keys is last.
  private var vaultsRow: some View {
    SettingsRow("Vaults:") {
      let vaults = sync.syncedVaults
      let unsynced = sync.unsyncedVaults
      ScrollView {
        VStack(alignment: .leading, spacing: 12) {
          if vaults.isEmpty {
            Text(syncOffText)
              .foregroundStyle(.secondary)
          } else {
            GroupedTable(vaults, id: \.vault.key) { entry in
              vaultRow(entry.vault, entry.report)
            }
          }
          if !unsynced.isEmpty {
            vaultSection("Sync off (\(unsynced.count))") {
              GroupedTable(unsynced, id: \.key) { unsyncedVaultRow($0) }
            }
          }
          if sync.folder != nil {
            remoteVaultsSection
          }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onGeometryChange(for: CGFloat.self) {
          $0.size.height
        } action: {
          vaultListHeight = $0
        }
      }
      .frame(height: min(vaultListHeight, Self.vaultListMaxHeight))
      .scrollBounceBehavior(.basedOnSize)
      // A scroll view has no text baseline. Align the row label with the
      // text of the first row, which is inset by the table row padding.
      .alignmentGuide(.firstTextBaseline) { $0[.top] + 20 }
      if !vaults.isEmpty {
        Button("Reset Sync Keys…") { sync.showInSettings(.rotateKey(nil)) }
        Text(
          "Use this if someone else may have a copy of your synced folder or a recovery kit. Your devices keep access."
        )
        .captionStyle()
      }
    }
  }

  /// Vaults in the synced folder. A vault on this device shows its name, and
  /// any other vault shows its id, since the folder does not hold names.
  @ViewBuilder
  private var remoteVaultsSection: some View {
    if let message = sync.remoteVaultsError {
      Text("Cannot read the synced folder: \(message)")
        .foregroundStyle(.red)
        .captionStyle()
    } else if let ids = sync.remoteVaultIds {
      let remote = sync.remoteVaults
      vaultSection("In synced folder (\(ids.count))") {
        if remote.isEmpty {
          Text("The synced folder has no vaults.")
            .foregroundStyle(.secondary)
        } else {
          GroupedTable(remote, id: \.id) { remoteVaultRow($0) }
        }
      }
    }
  }

  /// Maximum height of the vault list before it scrolls.
  private static let vaultListMaxHeight: CGFloat = 200

  /// Section heading above a group of vault rows.
  private func vaultSection<Content: View>(
    _ title: String, @ViewBuilder content: () -> Content
  ) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(title)
        .font(.subheadline.weight(.medium))
        .foregroundStyle(.secondary)
      content()
    }
  }

  /// Row of a vault in the synced folder.
  private func remoteVaultRow(_ vault: RemoteVaultRef) -> some View {
    HStack(spacing: 8) {
      // Placeholder for the status dot, so names line up with the rows above.
      Color.clear
        .frame(width: 8, height: 8)
      Text(vault.localName ?? vault.id)
        .lineLimit(1)
        .truncationMode(.middle)
        .help("Vault id: \(vault.id)")
      Spacer(minLength: 8)
      Text(vault.localName == nil ? "Not on this device" : "On this device")
        .foregroundStyle(.secondary)
    }
  }

  /// Row of a vault with sync turned off.
  private func unsyncedVaultRow(_ vault: SyncVaultRef) -> some View {
    HStack(spacing: 8) {
      Circle()
        .fill(.secondary)
        .frame(width: 8, height: 8)
      Text(vault.name)
        .lineLimit(1)
        .truncationMode(.middle)
      Spacer(minLength: 8)
      Button("Sync…") { sync.showInSettings(.enable(vault)) }
    }
  }

  private func vaultRow(_ vault: SyncVaultRef, _ report: SyncReportInfo) -> some View {
    let summary = syncStatusSummary(report)
    return Button {
      sync.showInSettings(.status(vault))
    } label: {
      HStack(spacing: 8) {
        Circle()
          .fill(summary.color)
          .frame(width: 8, height: 8)
        Text(vault.name)
          .lineLimit(1)
          .truncationMode(.middle)
        Spacer(minLength: 8)
        Text(summary.line)
          .foregroundStyle(.secondary)
          .lineLimit(1)
        Image(systemName: "chevron.right")
          .font(.caption)
          .foregroundStyle(.tertiary)
      }
      .contentShape(.rect)
    }
    .buttonStyle(.plain)
    .help(summary.help.isEmpty ? "Show the sync status of \(vault.name)" : summary.help)
  }

  // MARK: - Folder

  private var folderRow: some View {
    SettingsRow("Synced folder:") {
      HStack(spacing: 8) {
        Text(sync.folder.map(rootDescription) ?? "None")
          .foregroundStyle(sync.folder == nil ? .secondary : .primary)
          .lineLimit(1)
          .truncationMode(.middle)
          .help(sync.folder.map(rootHelp) ?? "")
        Button(sync.folder == nil ? "Choose…" : "Change…") { showingLocation = true }
      }
      .help(
        "A change applies only to vaults turned on later. The path can differ on each device.")
      Text(
        "Use a folder that a sync service or shared drive copies to your other devices, or an S3-compatible bucket."
      )
      .captionStyle()
    }
  }

  // MARK: - Devices

  /// Devices of the synced vaults, this device first. Devices that left or
  /// were removed from every vault they belong to are listed under Former
  /// devices.
  private var devicesRow: some View {
    SettingsRow("Devices:") {
      let devices = sync.syncDevices()
      let current = devices.filter { $0.thisMac || !$0.left }
      let former = devices.filter { !$0.thisMac && $0.left }
      if devices.isEmpty {
        Text(syncOffText)
          .foregroundStyle(.secondary)
      } else {
        GroupedTable(current, id: \.id) { deviceRow($0) }
      }
      if !former.isEmpty {
        DisclosureGroup("Former devices (\(former.count))") {
          VStack(alignment: .leading, spacing: 6) {
            GroupedTable(former, id: \.id) { deviceRow($0) }
            Text("Clean Up deletes the files of a former device from the synced folder.")
              .captionStyle()
          }
          .padding(.top, 4)
        }
      }
      if let error {
        Text(error)
          .foregroundStyle(.red)
          .captionStyle()
      }
      Text(
        "If a device is lost, stolen, or sold, remove it. Each vault it belongs to gets a new sync key that the device does not receive."
      )
      .captionStyle()
    }
  }

  /// Text of a list that is empty because every vault has sync turned off.
  private let syncOffText = "No synced vaults on this device."

  /// Device row with the name and the status on the leading side, and the
  /// actions on the trailing side.
  private func deviceRow(_ device: SyncDevice) -> some View {
    HStack(spacing: 8) {
      VStack(alignment: .leading, spacing: 2) {
        HStack(spacing: 6) {
          Text(device.name)
            .lineLimit(1)
            .truncationMode(.middle)
          if device.keysFlagged {
            Image(systemName: "exclamationmark.circle.fill")
              .foregroundStyle(.orange)
              .help(
                "This device published keys that differ from the keys pinned for it. The pinned keys are used."
              )
          }
          if !device.paired && !device.thisMac && !device.left {
            notPairedBadge
          }
        }
        Text(deviceDetail(device))
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
      }
      .help(deviceHelp(device))
      Spacer(minLength: 8)
      if cleaningId == device.id {
        ProgressView().controlSize(.small)
      }
      if !device.retired.isEmpty {
        Button("Clean Up…") { cleaning = device }
          .controlSize(.small)
          .disabled(cleaningId != nil)
      }
      if device.thisMac {
        if leaving {
          ProgressView().controlSize(.small)
        }
        Button("Remove…") { confirmingLeave = true }
          .controlSize(.small)
          .disabled(leaving)
      } else if !device.removed, let signingKey = device.signingKey {
        Button("Remove…") { sync.showInSettings(.removeMac(preselect: signingKey)) }
          .controlSize(.small)
      }
    }
  }

  private var notPairedBadge: some View {
    HStack(spacing: 4) {
      Circle()
        .fill(.orange)
        .frame(width: 6, height: 6)
      Text("Not paired")
    }
    .font(.caption)
    .foregroundStyle(.secondary)
    .help(
      "The keys of this device came from the synced folder, and it did not pair with this device. Remove it if you do not recognize it."
    )
  }

  // MARK: - Pairing

  /// Pairing of this Mac and the pairing requests that wait for a code.
  private var pairingsRow: some View {
    SettingsRow("Pairing:") {
      HStack(spacing: 8) {
        Button(sync.isPairing ? "Show Pairing Code" : "Pair with Another Device") {
          sync.showInSettings(.pair(root: sync.folder, join: nil))
        }
        .disabled(sync.folder == nil)
        if sync.activePairing != nil {
          Button("Cancel Pairing", role: .destructive) { sync.cancelPairing() }
        }
      }
      if let status = sync.pairingStatus {
        HStack(spacing: 6) {
          ProgressView().controlSize(.mini)
          Text(status).foregroundStyle(.secondary)
        }
      }
      let requests = sync.pairingCounts.sorted { rootDescription($0.key) < rootDescription($1.key) }
      if !requests.isEmpty {
        ForEach(requests, id: \.key) { request in
          Button("Review Pairing Requests…") {
            sync.showInSettings(.pairingPrompt(root: request.key))
          }
        }
        Text(
          "Requests from new devices show here. To add a device, choose Pair with Another Device on that device."
        )
        .captionStyle()
      }
      if let folder = sync.folder {
        Button("View pending pairing requests…") {
          sync.showInSettings(.pendingPairings(root: folder))
        }
        .buttonStyle(.link)
        .font(.callout)
      }
    }
  }

  // MARK: - Text

  /// Second line of a device row: the status and the vault count.
  private func deviceDetail(_ device: SyncDevice) -> String {
    let count = device.vaultNames.count
    let vaults = count == 1 ? "1 vault" : "\(count) vaults"
    return "\(deviceStatus(device)) · \(vaults)"
  }

  private func deviceStatus(_ device: SyncDevice) -> String {
    if device.thisMac { return "This device" }
    if device.removed { return "Removed" }
    if device.left { return "Left" }
    if let receivedAt = device.receivedAt {
      let date = Date(timeIntervalSince1970: TimeInterval(receivedAt))
      return "Changes received \(date.formatted(.relative(presentation: .named)))"
    }
    return "No changes received"
  }

  /// Vaults, received changes, key origin, and signing key of a device.
  private func deviceHelp(_ device: SyncDevice) -> String {
    var lines = ["Vaults: \(device.vaultNames.joined(separator: ", "))"]
    if !device.thisMac, !device.left {
      lines.append(
        "Changes received: when this device last received changes from that device, on this device's clock. A device with no edits since this was recorded shows no changes."
      )
    }
    if !device.thisMac {
      lines.append(
        device.paired ? "Keys: paired with this device" : "Keys: learned from the synced folder")
    }
    if let signingKey = device.signingKey {
      lines.append("Signing key: \(signingKey)")
    }
    return lines.joined(separator: "\n")
  }

  // MARK: - Actions

  /// Turn off sync of every synced vault on this device. Lists the vaults
  /// that failed.
  private func leave() {
    error = nil
    leaving = true
    Task {
      defer { leaving = false }
      do {
        let failures = try await sync.leaveAll()
        if !failures.isEmpty {
          error = "Sync did not turn off for:\n\(failures.joined(separator: "\n"))"
        }
      } catch FfiError.AuthExpired {
        // The app locked, which closes the window.
      } catch FfiError.AuthCancelled {
      } catch {
        self.error = error.userMessage
      }
    }
  }

  /// Delete the files of the retired device `device` from the synced folder
  /// of each vault it left. A vault whose device files still download shows a
  /// message to try again.
  private func cleanUp(_ device: SyncDevice) {
    error = nil
    cleaningId = device.id
    Task {
      defer { cleaningId = nil }
      var waiting: [String] = []
      for (vaultKey, replicaId) in device.retired {
        do {
          if try await sync.cleanReplica(vaultKey: vaultKey, replicaId: replicaId) == false {
            waiting.append(sync.vaultName(vaultKey))
          }
        } catch FfiError.AuthExpired {
          // The app locked, which closes the window.
          return
        } catch {
          self.error = error.userMessage
          return
        }
      }
      if !waiting.isEmpty {
        error =
          "The files of \(device.name) stay in the synced folder of \(nameList(waiting.sorted())) until they are all joined."
      }
    }
  }
}
