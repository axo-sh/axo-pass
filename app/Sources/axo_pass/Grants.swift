import AxoPassFFI
import Foundation
import LocalAuthentication
import LocalAuthenticationEmbeddedUI

/// How long an approval is reused before the next request prompts again.
///
/// Reuse keeps every git push from asking for a fingerprint. It is bounded on
/// two clocks because an approval that never expires permits use indefinitely:
/// the broker socket is reachable by our own CLI, and it is served with the
/// vault locked.
enum GrantPolicy {
  /// Prompt every time.
  case everyUse

  /// Reuse an approval until it has gone `idle` without use, or `absolute` has
  /// passed since the user gave it, whichever comes first. The absolute bound
  /// is the necessary one: an idle timer alone never expires under continuous
  /// use, so a process asking on a timer would hold an approval open
  /// indefinitely.
  case cache(idle: TimeInterval, absolute: TimeInterval)

  #if DEBUG
    /// Short enough to exercise expiry by hand.
    static let standard = GrantPolicy.cache(idle: 5, absolute: 15)
  #else
    /// 300s is `LATouchIDAuthenticationMaximumAllowableReuseDuration`, the
    /// system's own ceiling on reusing a biometric match.
    static let standard = GrantPolicy.cache(idle: 60, absolute: 300)
  #endif
}

/// An approval the user has given, and the context that carries it.
@MainActor
final class Grant {
  let context: LAContext
  let view: LAAuthenticationView

  /// When the user approved. Set once and never refreshed: a reused approval
  /// reports success too, so refreshing this would turn the absolute bound into
  /// a second idle timer. Nil until the first approval, so a context is not
  /// expired before it has ever been used.
  var approvedAt: Date?
  var lastUsedAt: Date?

  /// Shown in the notification for a use that raised no prompt.
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

/// The approvals one prompt has outstanding, and the clocks that end them.
///
/// Keyed by whatever identifies a grant to its caller: an SSH key label, a GPG
/// key grip. The identified peer will join that key, so that one process cannot
/// reuse an approval another process was given.
@MainActor
final class AuthorizationGrants<Key: Hashable & CustomStringConvertible & Sendable> {
  private let policy: GrantPolicy
  private let label: String
  private var grants: [Key: Grant] = [:]

  init(label: String, policy: GrantPolicy = .standard) {
    self.label = label
    self.policy = policy
  }

  /// The grant to evaluate on, created if there is none and dropped first if
  /// its window has closed. The caller owns the returned context until it calls
  /// `end`.
  func begin(_ key: Key) -> Grant {
    // Check the clocks here as well as on the timer. A timer cannot fire while
    // a request is in flight, and none run while the machine is asleep, so an
    // approval can be past its deadline with its timer still pending.
    if let grant = grants[key], grant.inFlight == 0, hasExpired(grant) {
      log("approval for \(key) expired, prompting again")
      forget(key)
    }

    let grant = grants[key] ?? newGrant(for: key)
    // Incremented before the context leaves this method: the broker retains it
    // and evaluates it, and expiry in that gap fails the evaluation.
    grant.inFlight += 1
    grant.expiry?.invalidate()
    grant.expiry = nil
    return grant
  }

  /// Settle the clocks for a finished request and schedule the next expiry.
  /// Returns the grant, or nil if it was already forgotten, which is what
  /// cancelling through our own button does.
  @discardableResult
  func end(_ key: Key, outcome: PromptOutcome) -> Grant? {
    guard let grant = grants[key] else { return nil }
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
      log("request failed for \(key): \(message)")
      forget(key)
    }

    armExpiry(key)
    return grants[key] ?? grant
  }

  /// Drop one approval. Invalidating the context fails any evaluation in
  /// flight, which is how a prompt on screen gets dismissed.
  func forget(_ key: Key) {
    guard let grant = grants.removeValue(forKey: key) else { return }
    grant.expiry?.invalidate()
    grant.context.invalidate()
  }

  /// Drop every approval, so the next request prompts again. Called when the
  /// app locks, and when the machine sleeps or the screen locks.
  func forgetAll() {
    // Snapshot the keys: `forget` mutates the dictionary.
    for key in Array(grants.keys) {
      forget(key)
    }
  }

  private func newGrant(for key: Key) -> Grant {
    let context = LAContext()
    // Creating the view is what suppresses the system dialog for this context,
    // so it has to exist before the broker evaluates rather than when the panel
    // appears.
    let grant = Grant(
      context: context, view: LAAuthenticationView(context: context, controlSize: .regular))
    grants[key] = grant
    return grant
  }

  // MARK: - Expiry

  /// Schedule the next expiry for `key`, or drop the approval if it has already
  /// run out. Only ever called with nothing in flight.
  private func armExpiry(_ key: Key) {
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
      log("approval for \(key) expired during use")
      forget(key)
      return
    }

    grant.expiry = Timer.scheduledTimer(withTimeInterval: remaining, repeats: false) {
      [weak self] _ in
      MainActor.assumeIsolated { self?.expire(key) }
    }
  }

  private func expire(_ key: Key) {
    guard let grant = grants[key] else { return }
    // A request arrived after the timer was armed. Leave the approval alone:
    // `end` re-arms, and `begin` re-checks the clocks.
    guard grant.inFlight == 0 else { return }
    log("approval for \(key) expired")
    forget(key)
  }

  /// Seconds until the approval on `grant` runs out, or nil if this policy
  /// reuses nothing.
  private func timeUntilExpiry(_ grant: Grant) -> TimeInterval? {
    guard case .cache(let idle, let absolute) = policy, let approvedAt = grant.approvedAt else {
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

  private func log(_ message: String) {
    NSLog("%@: %@", label, message)
  }
}

/// The address of a live `LAContext`, as the broker expects it. The caller
/// keeps its own reference; the core takes another.
func contextPointer(_ context: LAContext) -> UInt64 {
  UInt64(UInt(bitPattern: Unmanaged.passUnretained(context).toOpaque()))
}
