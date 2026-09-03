import AppKit
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI
import UserNotifications
import AxoPassFFI

/// How long an approval is reused before the next signature prompts again.
///
/// Reuse keeps every git push from asking for a fingerprint. It is bounded on
/// two clocks because an approval that never expires permits signing
/// indefinitely: the agent socket is reachable by anything running as this
/// user, and signing is served with the vault locked.
enum SigningGrantPolicy {
  /// Prompt for every signature.
  case everyUse

  /// Reuse an approval until it has gone `idle` without use, or `absolute` has
  /// passed since the user gave it, whichever comes first. The absolute bound
  /// is the necessary one: an idle timer alone never expires under continuous
  /// use, so a process signing on a timer would hold an approval open
  /// indefinitely.
  case cache(idle: TimeInterval, absolute: TimeInterval)

  #if DEBUG
    /// Short enough to exercise expiry by hand.
    static let standard = SigningGrantPolicy.cache(idle: 5, absolute: 15)
  #else
    /// 300s is `LATouchIDAuthenticationMaximumAllowableReuseDuration`, the
    /// system's own ceiling on reusing a biometric match.
    static let standard = SigningGrantPolicy.cache(idle: 60, absolute: 300)
  #endif
}

/// Identifies a cached approval.
///
/// Currently the key label alone. The identified peer will join it, so that one
/// process cannot reuse an approval another process was given.
struct GrantKey: Hashable {
  let keyLabel: String
}

/// An approval the user has given, and the context that carries it.
private final class Grant {
  let context: LAContext
  let view: LAAuthenticationView

  /// When the user approved. Set once and never refreshed: a reused approval
  /// reports success too, so refreshing this would turn the absolute bound into
  /// a second idle timer. Nil until the first approval, so a context is not
  /// expired before it has ever been used.
  var approvedAt: Date?
  var lastUsedAt: Date?

  /// Shown in the notification for a signature that raised no prompt.
  var lastCaller: String?

  /// Requests evaluating on this context right now. Expiry must not run while
  /// one is in flight: invalidating the context is how a cancellation is
  /// delivered, so expiring mid-request would report a cancellation the user
  /// never made.
  var inFlight = 0

  var expiry: Timer?

  init(context: LAContext, view: LAAuthenticationView) {
    self.context = context
    self.view = view
  }
}

/// Draws the authorization prompt for SSH signatures the agent delegates here.
///
/// The agent is headless, so on its own it can only raise the system dialog. It
/// hands the request to the core's signing broker instead, which calls in here
/// for a context to sign on. This process owns that context, so
/// `LAAuthenticationView` draws the biometric prompt in our panel, and the
/// broker's evaluation on that same context drives the icon.
@MainActor
final class SigningPromptModel {
  private let policy: SigningGrantPolicy
  private var grants: [GrantKey: Grant] = [:]
  private var panel: NSPanel?
  private var showTask: Task<Void, Never>?
  private var observers: [(NotificationCenter, NSObjectProtocol)] = []

  init(policy: SigningGrantPolicy = .standard) {
    self.policy = policy
  }

  // MARK: - Lifetime

  /// Start watching for the events that drop every approval, and ask for the
  /// notification permission used to report a signature.
  ///
  /// These belong to the broker's lifetime, not the vault's. Signing is served
  /// with the vault locked, and `AutoLock` only runs while it is unlocked, so
  /// without these an approval given to a locked app would never expire.
  func start() {
    stop()
    observe(NSWorkspace.shared.notificationCenter, NSWorkspace.willSleepNotification)
    observe(
      DistributedNotificationCenter.default(),
      Notification.Name("com.apple.screenIsLocked"))

    UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { _, error in
      if let error {
        NSLog("SigningPrompt: notification permission failed: %@", String(describing: error))
      }
    }
  }

  func stop() {
    for (center, observer) in observers { center.removeObserver(observer) }
    observers = []
  }

  private func observe(_ center: NotificationCenter, _ name: Notification.Name) {
    let observer = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
      MainActor.assumeIsolated { self?.forgetAll() }
    }
    observers.append((center, observer))
  }

  // MARK: - Broker delegate

  /// Prepare a context for `keyLabel` and return its address for the broker.
  /// The context stays referenced here, so it outlives the signing attempt.
  func begin(keyLabel: String, caller: String?) -> UInt64 {
    let key = GrantKey(keyLabel: keyLabel)

    // Check the clocks here as well as on the timer. A timer cannot fire while
    // a request is in flight, and none run while the machine is asleep, so an
    // approval can be past its deadline with its timer still pending.
    if let grant = grants[key], grant.inFlight == 0, hasExpired(grant) {
      log("approval for \(keyLabel) expired, prompting again")
      forget(key)
    }

    let grant = grants[key] ?? newGrant(for: key)
    grant.lastCaller = caller
    // Incremented before the pointer leaves this method: the broker retains the
    // context and evaluates it, and expiry in that gap fails the evaluation.
    grant.inFlight += 1
    grant.expiry?.invalidate()
    grant.expiry = nil

    // A context that is still authenticated signs with no prompt at all. Delay
    // the panel briefly so that case does not flash a window on screen.
    showTask?.cancel()
    showTask = Task { [weak self] in
      try? await Task.sleep(for: .milliseconds(250))
      guard !Task.isCancelled else { return }
      self?.showPanel(keyLabel: keyLabel, caller: caller, view: grant.view)
    }

    return UInt64(UInt(bitPattern: Unmanaged.passUnretained(grant.context).toOpaque()))
  }

  /// The signing attempt finished, successfully or not.
  func end(keyLabel: String, outcome: SignOutcome) {
    let key = GrantKey(keyLabel: keyLabel)
    showTask?.cancel()
    showTask = nil
    hidePanel()

    // Cancelling through our own button forgets the grant before the evaluation
    // fails, so there may be nothing left to settle.
    guard let grant = grants[key] else {
      report(keyLabel: keyLabel, caller: nil, outcome: outcome)
      return
    }
    grant.inFlight = max(0, grant.inFlight - 1)

    switch outcome {
    case .succeeded:
      let now = Date()
      if grant.approvedAt == nil { grant.approvedAt = now }
      grant.lastUsedAt = now
    case .cancelled:
      // Nothing was authorized. Leave the clocks alone; the context is left
      // unauthenticated, so the next request prompts.
      break
    case .failed(let message):
      // The context may be invalid or expired; start the next attempt clean.
      log("signing failed for \(keyLabel): \(message)")
      forget(key)
    }

    armExpiry(key)
    report(keyLabel: keyLabel, caller: grant.lastCaller, outcome: outcome)
  }

  /// Dismiss the prompt on the user's behalf. Invalidating the context fails
  /// the evaluation in flight, which the broker reports as a cancellation.
  func cancel(keyLabel: String) {
    forget(GrantKey(keyLabel: keyLabel))
  }

  /// Drop every signing authorization, so the next signature prompts again.
  /// Called when the app locks, and when the machine sleeps or the screen
  /// locks.
  func forgetAll() {
    // Snapshot the keys: `forget` mutates the dictionary.
    for key in Array(grants.keys) {
      forget(key)
    }
  }

  private func newGrant(for key: GrantKey) -> Grant {
    let context = LAContext()
    // Creating the view is what suppresses the system dialog for this context,
    // so it has to exist before the broker evaluates rather than when the panel
    // appears.
    let grant = Grant(context: context, view: LAAuthenticationView(context: context))
    grants[key] = grant
    return grant
  }

  private func forget(_ key: GrantKey) {
    guard let grant = grants.removeValue(forKey: key) else { return }
    grant.expiry?.invalidate()
    grant.context.invalidate()
  }

  // MARK: - Expiry

  /// Schedule the next expiry for `key`, or drop the approval if it has already
  /// run out. Only ever called with nothing in flight.
  private func armExpiry(_ key: GrantKey) {
    guard let grant = grants[key] else { return }
    grant.expiry?.invalidate()
    grant.expiry = nil
    // Nothing to expire until the user has actually approved something.
    guard grant.inFlight == 0, grant.approvedAt != nil else { return }

    guard let remaining = timeUntilExpiry(grant) else {
      // This policy reuses nothing.
      forget(key)
      return
    }
    guard remaining > 0 else {
      // The window closed while the request was in flight.
      log("approval for \(key.keyLabel) expired during signing")
      forget(key)
      return
    }

    grant.expiry = Timer.scheduledTimer(withTimeInterval: remaining, repeats: false) {
      [weak self] _ in
      MainActor.assumeIsolated { self?.expire(key) }
    }
  }

  private func expire(_ key: GrantKey) {
    guard let grant = grants[key] else { return }
    // A request arrived after the timer was armed. Leave the approval alone:
    // `end` re-arms, and `begin` re-checks the clocks.
    guard grant.inFlight == 0 else { return }
    log("approval for \(key.keyLabel) expired")
    forget(key)
  }

  /// Seconds until the approval on `grant` runs out, or nil if this policy
  /// reuses nothing.
  private func timeUntilExpiry(_ grant: Grant) -> TimeInterval? {
    guard case let .cache(idle, absolute) = policy, let approvedAt = grant.approvedAt else {
      return nil
    }
    let idleDeadline = (grant.lastUsedAt ?? approvedAt).addingTimeInterval(idle)
    let absoluteDeadline = approvedAt.addingTimeInterval(absolute)
    return min(idleDeadline, absoluteDeadline).timeIntervalSinceNow
  }

  private func hasExpired(_ grant: Grant) -> Bool {
    guard grant.approvedAt != nil else { return false }
    guard let remaining = timeUntilExpiry(grant) else { return true }
    return remaining <= 0
  }

  // MARK: - Reporting

  /// Tell the user a key was used. A signature served from a still-valid
  /// approval raises no prompt and shows no window, so this notification is the
  /// only indication it happened.
  private func report(keyLabel: String, caller: String?, outcome: SignOutcome) {
    guard case .succeeded = outcome else { return }

    let content = UNMutableNotificationContent()
    content.title = "SSH key used"
    let name = Self.shortKeyName(keyLabel)
    if let caller, !caller.isEmpty {
      content.body = "Signed with Secure Enclave key \(name) for \(caller)."
    } else {
      content.body = "Signed with Secure Enclave key \(name)."
    }

    let request = UNNotificationRequest(
      identifier: UUID().uuidString, content: content, trigger: nil)
    UNUserNotificationCenter.current().add(request) { error in
      if let error {
        NSLog("SigningPrompt: could not post notification: %@", String(describing: error))
      }
    }
  }

  // MARK: - Panel

  private func showPanel(keyLabel: String, caller: String?, view: LAAuthenticationView) {
    hidePanel()

    let content = SigningPromptView(
      caller: caller,
      keyName: Self.shortKeyName(keyLabel),
      icon: AuthenticationIcon(view: view),
      onCancel: { [weak self] in self?.cancel(keyLabel: keyLabel) }
    )

    // Non-activating: signing is triggered from another app (a terminal, an
    // editor), which keeps focus while this panel is on screen.
    let panel = NSPanel(
      contentRect: NSRect(x: 0, y: 0, width: 320, height: 240),
      styleMask: [.titled, .fullSizeContentView, .nonactivatingPanel],
      backing: .buffered,
      defer: false
    )
    panel.titleVisibility = .hidden
    panel.titlebarAppearsTransparent = true
    panel.isMovableByWindowBackground = true
    panel.isFloatingPanel = true
    panel.level = .floating
    panel.hidesOnDeactivate = false
    panel.contentView = NSHostingView(rootView: content)
    panel.center()
    panel.orderFrontRegardless()
    self.panel = panel
  }

  private func hidePanel() {
    panel?.orderOut(nil)
    panel = nil
  }

  /// Shorten `ssh-key-<uuid>` for display. The leading characters are enough to
  /// tell two keys apart.
  private static func shortKeyName(_ keyLabel: String) -> String {
    let id = keyLabel.hasPrefix("ssh-key-") ? String(keyLabel.dropFirst("ssh-key-".count)) : keyLabel
    return String(id.prefix(6))
  }

  private func log(_ message: String) {
    NSLog("SigningPrompt: %@", message)
  }
}

private struct SigningPromptView: View {
  let caller: String?
  let keyName: String
  let icon: AuthenticationIcon
  let onCancel: () -> Void

  var body: some View {
    VStack(spacing: 14) {
      icon
        .frame(width: 64, height: 64)

      VStack(spacing: 4) {
        Text(title)
          .font(.headline)
          .multilineTextAlignment(.center)

        Text("Secure Enclave key \(keyName)")
          .font(.subheadline)
          .foregroundStyle(.secondary)
      }

      Button("Cancel", action: onCancel)
        .keyboardShortcut(.cancelAction)
    }
    .padding(24)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private var title: String {
    if let caller, !caller.isEmpty {
      return "\(caller) wants to sign with an SSH key"
    }
    return "Authorize an SSH signature"
  }
}

/// Bridges the core's delegate calls, which arrive off the main thread, onto
/// the main-actor model.
final class SigningPromptBridge: SignPromptDelegate {
  private let model: SigningPromptModel

  init(model: SigningPromptModel) {
    self.model = model
  }

  func beginAuthorization(keyLabel: String, caller: String?) async throws -> UInt64 {
    await model.begin(keyLabel: keyLabel, caller: caller)
  }

  func endAuthorization(keyLabel: String, outcome: SignOutcome) async {
    await model.end(keyLabel: keyLabel, outcome: outcome)
  }
}
