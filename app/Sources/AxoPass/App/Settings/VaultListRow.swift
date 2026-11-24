import AxoPassFFI
import SwiftUI

/// Vaults of this device with a status dot and a short sync line. A click opens
/// the vault sheet. Vaults in the synced folder follow under a heading. The list
/// scrolls if it is taller than a fixed height.
struct VaultListRow: View {
  @Environment(VaultsModel.self) private var model
  @Environment(SyncModel.self) private var sync
  /// Measured height of the vault list content.
  @State private var listHeight: CGFloat = 0

  /// Maximum height of the vault list before it scrolls.
  private static let maxHeight: CGFloat = 240

  var body: some View {
    SettingsRow("Vaults:") {
      ScrollView {
        VStack(alignment: .leading, spacing: 12) {
          if model.vaults.isEmpty {
            Text("No vaults on this device.")
              .foregroundStyle(.secondary)
          } else {
            GroupedTable(vaultRefs, id: \.key) { vaultRow($0) }
          }
          if sync.folder != nil {
            remoteVaultsSection
          }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onGeometryChange(for: CGFloat.self) {
          $0.size.height
        } action: {
          listHeight = $0
        }
      }
      .frame(height: min(listHeight, Self.maxHeight))
      .scrollBounceBehavior(.basedOnSize)
      // A scroll view has no text baseline. Align the row label with the
      // text of the first row, which is inset by the table row padding.
      .alignmentGuide(.firstTextBaseline) { $0[.top] + 20 }
      Text("Choose a vault to see its details, sync status, and actions.")
        .captionStyle()
    }
    .task(id: model.vaults) { await sync.reloadAll() }
    .task(id: sync.folder) { await sync.reloadRemoteVaults() }
  }

  /// Vaults with sync on first, then the others, each group by name.
  private var vaultRefs: [SyncVaultRef] {
    model.vaults
      .map { SyncVaultRef(key: $0.key, name: $0.name ?? $0.key) }
      .sorted {
        (sync.state($0.key)?.isOn == true ? 0 : 1, $0.name, $0.key)
          < (sync.state($1.key)?.isOn == true ? 0 : 1, $1.name, $1.key)
      }
  }

  /// Row of a vault on this device.
  private func vaultRow(_ vault: SyncVaultRef) -> some View {
    let status = syncStatus(vault)
    return Button {
      sync.showInSettings(.vault(vault))
    } label: {
      HStack(spacing: 8) {
        Circle()
          .fill(status.color)
          .frame(width: 8, height: 8)
        VStack(alignment: .leading, spacing: 0) {
          Text(vault.name)
            .lineLimit(1)
            .truncationMode(.middle)
          if model.autofillExcludedVaults.contains(vault.key) {
            Text("AutoFill disabled")
              .font(.caption)
              .foregroundStyle(.secondary)
          }
        }
        Spacer(minLength: 8)
        Text(status.line)
          .foregroundStyle(.secondary)
          .lineLimit(1)
        Image(systemName: "chevron.right")
          .font(.caption)
          .foregroundStyle(.tertiary)
      }
      .contentShape(.rect)
    }
    .buttonStyle(.plain)
    .help(status.help.isEmpty ? "Show \(vault.name)" : status.help)
  }

  /// Dot color, status line, and help text of the sync state of `vault`.
  private func syncStatus(_ vault: SyncVaultRef) -> (line: String, color: Color, help: String) {
    switch sync.state(vault.key) {
    case .on:
      if let report = sync.report(vault.key) { return syncStatusSummary(report) }
      return ("Sync on", .secondary, "")
    case .off:
      return ("Local", .secondary, "Not synced")
    case .turningOff:
      return ("Turning off sync", .secondary, syncDisableInProgressMessage)
    case .unknown(let message):
      return ("Sync unknown", .secondary, "Could not read sync status: \(message)")
    case .none:
      return ("", .secondary, "")
    }
  }

  /// Vaults in the synced folder that are not on this device. Each shows its
  /// id, since the folder does not hold names. Hidden if there are none.
  @ViewBuilder
  private var remoteVaultsSection: some View {
    if let message = sync.remoteVaultsError {
      Text("Cannot read the synced folder: \(message)")
        .foregroundStyle(.red)
        .captionStyle()
    } else {
      let remote = sync.remoteVaults.filter { $0.localName == nil }
      if !remote.isEmpty {
        VStack(alignment: .leading, spacing: 4) {
          Text("Not on this device (\(remote.count))")
            .font(.subheadline.weight(.medium))
            .foregroundStyle(.secondary)
          GroupedTable(remote, id: \.id) { remoteVaultRow($0) }
        }
      }
    }
  }

  /// Row of a vault in the synced folder.
  private func remoteVaultRow(_ vault: RemoteVaultRef) -> some View {
    HStack(spacing: 8) {
      Text(vault.id)
        .lineLimit(1)
        .truncationMode(.middle)
      Spacer(minLength: 8)
    }
  }
}
