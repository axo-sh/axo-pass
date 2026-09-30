import AxoPassFFI
import Foundation
import Observation
import ServiceManagement

struct AgentServiceError: Error, CustomStringConvertible {
  let description: String
}

/// Owns how the Axo Pass agent is run.
///
/// With the background item allowed, the agent is a launchd service
/// (`com.breakfastlabs.frittata.agent.plist` in the bundle) that launchd
/// restarts if it dies. If the user has not allowed the item, or the app runs
/// outside a bundle, the agent is started detached with `ap agent start`, and
/// nothing restarts it.
@Observable
@MainActor
final class AgentService {
  static let shared = AgentService()

  private static let plistName = "com.breakfastlabs.frittata.agent.plist"

  private let service = SMAppService.agent(plistName: AgentService.plistName)
  private let core = AxoPass()
  private var isSyncing = false

  private(set) var status: SMAppService.Status

  /// Whether the user wants the agent running. Cleared by Stop, set by Start.
  var isEnabled: Bool {
    UserDefaults.standard.bool(forKey: Preferences.Key.sshAgentEnabled)
  }

  private init() {
    status = service.status
  }

  func refreshStatus() {
    status = service.status
  }

  /// Start the agent and remember that the user wants it running.
  func start() async throws {
    UserDefaults.standard.set(true, forKey: Preferences.Key.sshAgentEnabled)
    try await launch()
  }

  /// Stop the agent, remove the launchd service so it does not start at the
  /// next login, and remember that the user wants it off.
  func stop() async throws {
    UserDefaults.standard.set(false, forKey: Preferences.Key.sshAgentEnabled)
    refreshStatus()

    var failure: Error?
    do {
      try await core.stopSshAgent()
    } catch {
      failure = error
    }
    if isRegistered {
      do {
        try await service.unregister()
      } catch {
        failure = failure ?? error
      }
    }
    refreshStatus()
    if let failure { throw failure }
  }

  /// Bring the agent in line with the setting and the bundled `ap`. Runs on
  /// launch and whenever the app becomes active.
  ///
  /// - Registers the launchd service if the user wants the agent and it is not
  ///   registered.
  /// - Starts a detached agent if the service cannot run it.
  /// - Restarts an agent whose version differs from the bundled `ap`, or a
  ///   detached agent that the service can now replace.
  func sync() async {
    refreshStatus()
    NSLog("agent service sync: enabled=\(isEnabled) syncing=\(isSyncing) status=\(status.rawValue)")
    guard isEnabled, !isSyncing else { return }
    isSyncing = true
    defer { isSyncing = false }

    if canRegister {
      registerService()
    }

    guard isAgentRunning else {
      // With the service enabled, launchd starts the agent itself.
      if status != .enabled {
        try? await core.startSshAgent()
      }
      return
    }

    guard let info = await core.getSshAgentInfo() else {
      // An agent that predates `agent-info` also predates `restart`, so
      // replace it with a shutdown.
      try? await core.stopSshAgent()
      try? await launch()
      return
    }

    let detached = info.launcher == .detached
    guard !info.isCurrent || (detached && status == .enabled) else { return }

    try? await core.restartSshAgent()
    // launchd starts a service agent again. A detached agent stays down.
    if detached && status != .enabled {
      try? await core.startSshAgent()
    }
  }

  /// Whether the launchd service exists, whether or not the user has allowed
  /// it.
  private var isRegistered: Bool {
    status == .enabled || status == .requiresApproval
  }

  /// Whether `register()` is worth calling. `.notFound` is included because
  /// the status can report it for a plist that `register()` accepts, and when
  /// the plist is really missing (a run outside the bundle), `register()`
  /// fails and the failure is logged.
  private var canRegister: Bool {
    status == .notRegistered || status == .notFound
  }

  private var isAgentRunning: Bool {
    core.getSshAgentStatus(agentType: .axo).status == .running
  }

  private func registerService() {
    do {
      try service.register()
      NSLog("agent service register succeeded")
    } catch {
      NSLog("agent service register failed: \(error)")
    }
    refreshStatus()
    NSLog("agent service status after register: \(status.rawValue)")
  }

  /// Start the agent through launchd if the service is allowed, otherwise
  /// detached.
  private func launch() async throws {
    refreshStatus()
    if status == .enabled {
      // The service is registered but its agent is not running, for example
      // after `ap ssh-agent stop`, which exits 0 and is not restarted. Register
      // again so RunAtLoad starts it.
      try? await service.unregister()
      refreshStatus()
    }
    if canRegister {
      registerService()
    }

    guard status == .enabled else {
      try await core.startSshAgent()
      return
    }
    guard await waitForAgent() else {
      throw AgentServiceError(description: "The agent did not start")
    }
  }

  private func waitForAgent() async -> Bool {
    for _ in 0..<100 {
      if isAgentRunning { return true }
      try? await Task.sleep(for: .milliseconds(50))
    }
    return false
  }

  /// Open System Settings at Login Items, where the user allows the agent to
  /// run in the background.
  func openLoginItemsSettings() {
    SMAppService.openSystemSettingsLoginItems()
  }
}
