import AppKit
import AuthenticationServices
import AxoPassFFI
import SwiftUI

/// Issues of the app with one fix button for each. Counted issues are listed
/// under "Needs you" and setup issues under "Not set up". Info issues are left
/// out.
struct TodayPane: View {
  let sshModel: SshModel
  let gpgModel: GpgModel

  @Environment(VaultsModel.self) private var vaults
  @Environment(SyncModel.self) private var sync
  @Environment(IssuesModel.self) private var issues
  @Environment(\.openSettings) private var openSettings
  @State private var shellModel = ShellIntegrationModel()
  @State private var sheet: TodaySheet? = nil

  var body: some View {
    let counted = issues.countedIssues
    let setup = issues.issues.filter { $0.severity == .setup }
    Group {
      if counted.isEmpty && setup.isEmpty {
        ContentUnavailableView(
          "Nothing needs you", systemImage: "checkmark.circle",
          description: Text("Problems with vaults, sync, SSH, GPG, and AutoFill show here."))
      } else {
        List {
          if !counted.isEmpty {
            Section("Needs you") {
              ForEach(counted) { row($0) }
            }
          }
          if !setup.isEmpty {
            Section("Not set up") {
              ForEach(setup) { row($0) }
            }
          }
        }
      }
    }
    .paneBackground()
    .navigationSplitViewColumnWidth(min: 260, ideal: 340)
    .navigationTitle("Today")
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

  private func row(_ issue: Issue) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 8) {
      IssueSeverityIcon(severity: issue.severity)
      VStack(alignment: .leading, spacing: 2) {
        Text(issue.title)
          .fixedSize(horizontal: false, vertical: true)
        if let detail = detail(issue) {
          Text(detail)
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
        }
      }
      Spacer(minLength: 8)
      if let label = fixLabel(issue) {
        Button(label) { fix(issue) }
          .controlSize(.small)
          .disabled(isFixing(issue))
      }
    }
    .padding(.vertical, 4)
  }

  /// Second line of an issue row. Nil for most issues.
  private func detail(_ issue: Issue) -> String? {
    switch issue {
    case .vaultLoadFailed(let message): return message
    case .agentNotRunning: return sshModel.agentError
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

/// Severity symbol of an issue row.
private struct IssueSeverityIcon: View {
  let severity: IssueSeverity

  var body: some View {
    Image(systemName: symbol)
      .foregroundStyle(color)
      .frame(width: 18)
  }

  private var symbol: String {
    switch severity {
    case .broken: return "exclamationmark.circle.fill"
    case .request: return "bell.badge.fill"
    case .advice: return "exclamationmark.triangle.fill"
    case .setup: return "circle.dashed"
    case .info: return "info.circle"
    }
  }

  private var color: Color {
    switch severity {
    case .broken: return .red
    case .request: return .accentColor
    case .advice: return .orange
    case .setup, .info: return .secondary
    }
  }
}
