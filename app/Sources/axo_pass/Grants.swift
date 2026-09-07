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
    static let reuseWindow = (idle: TimeInterval(5), absolute: TimeInterval(15))
  #else
    /// 300s is `LATouchIDAuthenticationMaximumAllowableReuseDuration`, the
    /// system's own ceiling on reusing a biometric match.
    static let reuseWindow = (idle: TimeInterval(60), absolute: TimeInterval(300))
  #endif

  /// The policy for a request that permits reuse at all. Settings turns reuse
  /// off, which makes every request prompt.
  static var standard: GrantPolicy {
    guard Preferences.reuseApprovals else { return .everyUse }
    return .cache(idle: reuseWindow.idle, absolute: reuseWindow.absolute)
  }
}

/// Identifies the key an approval is for, in the form the audit log records.
///
/// `id` is the canonical `SHA256:...` fingerprint for an SSH key and the
/// keygrip for a GPG key, matching how the agent's `ssh.sign` and the
/// pinentry's own events name the same key.
struct GrantSubject: Hashable, Sendable {
  enum Kind: Hashable, Sendable {
    case ssh
    case gpg
    case vault
  }

  let kind: Kind
  let id: String
  var label: String?

  /// Equality and hashing are on `kind` and `id` alone: `label` is derived from
  /// the key and only carries display detail.
  static func == (lhs: GrantSubject, rhs: GrantSubject) -> Bool {
    lhs.kind == rhs.kind && lhs.id == rhs.id
  }

  func hash(into hasher: inout Hasher) {
    hasher.combine(kind)
    hasher.combine(id)
  }

  var ffiInput: GrantSubjectInput {
    let ffiKind: GrantSubjectKind =
      switch kind {
      case .ssh: .sshKey
      case .gpg: .gpgKey
      case .vault: .vault
      }
    return GrantSubjectInput(kind: ffiKind, id: id, label: label)
  }
}

/// Identifies an approval. Reuse is scoped to the requesting process as well as
/// the key, so approving a request for one caller does not silently authorize a
/// different caller's request on the same key inside the reuse window.
///
/// A nil caller is its own bucket. It means the caller could not be resolved,
/// which happens on an unsigned local build.
///
/// `scope` narrows a key further when one subject covers operations of
/// different weight. A vault uses it to keep a listing's approval from
/// authorizing a read of the same vault.
///
/// `description` is the key alone. It names the subject in the process log; the
/// caller is recorded separately as the event's actor.
struct GrantKey: Hashable, CustomStringConvertible, Sendable {
  let subject: GrantSubject
  let caller: String?
  var scope: String? = nil

  var description: String {
    guard let scope else { return subject.id }
    return "\(subject.id) (\(scope))"
  }
}

/// An approval the user has given, and the context that carries it.
@MainActor
final class Grant {
  let context: LAContext
  let view: LAAuthenticationView

  /// How long this approval is reused. Fixed for the life of the grant: it is
  /// a property of the key, and a key's constraints do not change between
  /// requests.
  let policy: GrantPolicy

  /// When the user approved. Set once and never refreshed: a reused approval
  /// reports success too, so refreshing this would turn the absolute bound into
  /// a second idle timer. Nil until the first approval, so a context is not
  /// expired before it has ever been used.
  var approvedAt: Date?
  var lastUsedAt: Date?

  /// Requests evaluating on this context right now. Expiry must not run while
  /// one is in flight: invalidating the context is how a cancellation is
  /// delivered, so expiring mid-request would report a cancellation the user
  /// never made.
  var inFlight = 0

  var expiry: Timer?

  /// The process behind the most recent request on this grant, as the broker
  /// verified it. Expiry events carry it because nothing is in flight when a
  /// clock runs out, so the last requester is the only one there is to name.
  var lastPeer: RequestActor?

  init(context: LAContext, view: LAAuthenticationView, policy: GrantPolicy) {
    self.context = context
    self.view = view
    self.policy = policy
  }
}

/// The approvals one prompt has outstanding, and the clocks that end them.
///
/// Keyed by the key and the requesting process, so one process cannot reuse an
/// approval another process was given.
@MainActor
final class AuthorizationGrants {
  typealias Key = GrantKey

  private let label: String
  private var grants: [Key: Grant] = [:]

  init(label: String) {
    self.label = label
  }

  /// The grant to evaluate on, created if there is none and dropped first if
  /// its window has closed. The caller owns the returned context until it calls
  /// `end`.
  ///
  /// `policy` applies to a grant this call creates. An existing grant keeps the
  /// policy it was created with.
  ///
  /// `peer` is the process the broker verified for this request. It is recorded
  /// on the grant event, and kept on the grant so a later expiry can name the
  /// last process to use it.
  func begin(_ key: Key, policy: GrantPolicy = .standard, peer: RequestActor) -> Grant {
    // Check the clocks here as well as on the timer. A timer cannot fire while
    // a request is in flight, and none run while the machine is asleep, so an
    // approval can be past its deadline with its timer still pending.
    if let grant = grants[key], grant.inFlight == 0, hasExpired(grant) {
      log("approval for \(key) expired, prompting again")
      AuditBridge.recordGrant(key, .expired, peer: grant.lastPeer)
      forget(key)
    }

    let existing = grants[key]
    let grant = existing ?? newGrant(for: key, policy: policy)
    grant.lastPeer = peer

    if existing == nil {
      AuditBridge.recordGrant(key, .created, peer: peer)
    } else if existing?.approvedAt != nil {
      // A still-valid approval, reused without a prompt. The agent or pinentry
      // records the key use; this explains why no prompt appeared.
      AuditBridge.recordGrant(key, .reused, peer: peer)
    }

    // Incremented before the context leaves this method: the broker retains it
    // and evaluates it, and expiry in that gap fails the evaluation.
    grant.inFlight += 1
    grant.expiry?.invalidate()
    grant.expiry = nil
    return grant
  }

  /// Settle the clocks for a finished request and schedule the next expiry.
  /// Does nothing if the grant was already forgotten, which is what cancelling
  /// through our own button does.
  func end(_ key: Key, outcome: PromptOutcome) {
    guard let grant = grants[key] else { return }
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

  private func newGrant(for key: Key, policy: GrantPolicy) -> Grant {
    let context = LAContext()
    // Creating the view is what suppresses the system dialog for this context,
    // so it has to exist before the broker evaluates rather than when the panel
    // appears.
    let grant = Grant(
      context: context, view: LAAuthenticationView(context: context, controlSize: .regular),
      policy: policy)
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
    AuditBridge.recordGrant(key, .expired, peer: grant.lastPeer)
    forget(key)
  }

  /// Seconds until the approval on `grant` runs out, or nil if this policy
  /// reuses nothing.
  private func timeUntilExpiry(_ grant: Grant) -> TimeInterval? {
    guard case .cache(let idle, let absolute) = grant.policy, let approvedAt = grant.approvedAt
    else {
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
