import AxoPassFFI
import Foundation
import Observation
import ServiceManagement

struct AgentServiceError: Error, CustomStringConvertible {
  let description: String
}

/// Owns how the Axo Pass agent is run.
///
/// With "start on login" on and the background item allowed, the agent is a
/// launchd service (`com.breakfastlabs.frittata.agent.plist` in the bundle)
/// that launchd starts at login and restarts if it dies. Otherwise the agent is
/// started detached with `ap agent start`, and nothing restarts it.
///
/// Start and Stop act on the running agent only, like `ap agent start` and
/// `ap ssh-agent stop`. Whether the service is registered follows "start on
/// login".
@Observable
@MainActor
final class AgentService {
  static let shared = AgentService()

  private static let plistName = "com.breakfastlabs.frittata.agent.plist"

  private let service = SMAppService.agent(plistName: AgentService.plistName)
  private let core = AxoPass()
  private var isSyncing = false

  private(set) var status: SMAppService.Status

  /// Whether the agent starts at login. Changed through `setStartsOnLogin`.
  private(set) var startsOnLogin: Bool

  private init() {
    status = service.status
    startsOnLogin = UserDefaults.standard.bool(forKey: Preferences.Key.sshStartOnLogin)
  }

  func refreshStatus() {
    status = service.status
  }

  /// Start the agent. Under launchd if the service is registered and allowed,
  /// otherwise detached.
  func start() async throws {
    try await launch()
  }

  /// Stop the running agent. The service stays registered, so launchd starts
  /// the agent again at the next login if "start on login" is on.
  func stop() async throws {
    try await core.stopSshAgent()
  }

  /// Turn "start on login" on or off. On registers the service, which starts
  /// the agent now if the user has allowed the item. Off unregisters it; a
  /// running agent is kept alive as a detached one.
  func setStartsOnLogin(_ on: Bool) async throws {
    startsOnLogin = on
    UserDefaults.standard.set(on, forKey: Preferences.Key.sshStartOnLogin)
    refreshStatus()

    if on {
      if canRegister {
        registerService()
      }
      await restartIfStale()
      return
    }

    let wasRunning = isAgentRunning
    if isRegistered {
      try await service.unregister()
    }
    refreshStatus()
    // Unregistering ends an agent that launchd runs. Start a detached one
    // once it is gone, since a detached agent exits if the old one still holds
    // the lock.
    if wasRunning {
      _ = await waitForAgent(running: false)
      try await core.startSshAgent()
    }
  }

  /// Bring the running agent in line with the bundled `ap`, and on launch
  /// start it if "start on login" is on. Runs on launch and whenever the app
  /// becomes active.
  ///
  /// - On launch, registers the launchd service if "start on login" is on and
  ///   it is not registered.
  /// - On launch, starts a detached agent if the service cannot run it.
  ///   `startIfStopped` is false for a launch by the broker, which must not
  ///   bring back an agent the user stopped.
  /// - Restarts an agent whose version differs from the bundled `ap`, or a
  ///   detached agent that the service can now replace.
  func sync(launch: Bool, startIfStopped: Bool = true) async {
    refreshStatus()
    guard !isSyncing else { return }
    isSyncing = true
    defer { isSyncing = false }

    if launch && startsOnLogin && canRegister {
      registerService()
    }

    guard isAgentRunning else {
      // With the service enabled, launchd starts the agent itself.
      if launch && startsOnLogin && startIfStopped && status != .enabled {
        try? await core.startSshAgent()
      }
      return
    }
    await restartIfStale()
  }

  /// Restart the running agent if it does not match the bundled `ap`.
  private func restartIfStale() async {
    guard isAgentRunning else { return }
    guard let info = await core.getSshAgentInfo() else {
      // An agent that predates `agent-info` also predates `restart`, so
      // replace it with a shutdown.
      try? await core.stopSshAgent()
      _ = await waitForAgent(running: false)
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
  /// the status reports it for a plist that `register()` accepts, and when the
  /// plist is really missing (a run outside the bundle), `register()` fails
  /// and the failure is logged.
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

  /// Start the agent through launchd if "start on login" is on and the service
  /// is allowed, otherwise detached.
  private func launch() async throws {
    refreshStatus()
    if startsOnLogin {
      if status == .enabled {
        // The service is registered but its agent is not running, for example
        // after `ap ssh-agent stop`, which exits 0 and is not restarted.
        // Register again so RunAtLoad starts it.
        try? await service.unregister()
        refreshStatus()
      }
      if canRegister {
        registerService()
      }
    }

    guard startsOnLogin, status == .enabled else {
      try await core.startSshAgent()
      return
    }
    guard await waitForAgent(running: true) else {
      throw AgentServiceError(description: "The agent did not start")
    }
  }

  /// Wait up to five seconds for the agent to be running or not running.
  private func waitForAgent(running: Bool) async -> Bool {
    for _ in 0..<100 {
      if isAgentRunning == running { return true }
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
