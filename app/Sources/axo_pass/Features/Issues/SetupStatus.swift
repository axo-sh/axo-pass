import AxoPassFFI
import Observation

/// SSH agent, `~/.ssh/config`, zsh, and `gpg-agent.conf` state. One instance
/// for the app.
///
/// `SshModel`, `GpgModel`, `ShellIntegrationModel`, and `IssuesModel` read
/// this state, so the panes, Settings, and Today show the same values.
/// Configure calls write their result here.
@Observable
@MainActor
final class SetupStatus {
  static let shared = SetupStatus()

  private let core = AxoPass()

  private(set) var axoAgent: SshAgentStatusResponse? = nil
  private(set) var systemAgent: SshAgentStatusResponse? = nil
  /// State of the `IdentityAgent` directive in `~/.ssh/config`.
  private(set) var sshConf: SshAgentConfStatus? = nil
  /// State of the `ap` lines in `~/.zshrc`.
  private(set) var shell: ShellIntegrationStatus? = nil
  /// State of the `pinentry-program` line in `gpg-agent.conf`.
  private(set) var gpgConf: GpgAgentConfStatus? = nil

  private init() {}

  /// Re-read all state. Cheap enough for a timer.
  func refresh() {
    refreshAgents()
    refreshSshConf()
    refreshShell()
    refreshGpgConf()
  }

  /// Re-read agent state, which the CLI can change (`ap ssh-agent stop`)
  /// without the app knowing.
  func refreshAgents() {
    axoAgent = core.getSshAgentStatus(agentType: .axo)
    systemAgent = core.getSshAgentStatus(agentType: .system)
    AgentService.shared.refreshStatus()
  }

  func refreshSshConf() {
    sshConf = core.checkSshAgentConf()
  }

  func refreshShell() {
    shell = core.checkShellIntegration()
  }

  func refreshGpgConf() {
    gpgConf = core.checkGpgAgentConf()
  }

  func configureSshConf() async throws {
    sshConf = try await core.configureSshAgentConf()
  }

  func configureShell() async throws {
    shell = try await core.writeShellIntegration()
  }

  func configureGpgConf() async throws {
    gpgConf = try await core.configureGpgAgentConf()
  }
}
