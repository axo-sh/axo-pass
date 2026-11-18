import AxoArtwork
import SwiftUI

/// The Axo Pass mark: a shell with a gear inside it. The gear turns slowly while
/// `spins` is true and both parts fade in when the view appears.
struct AxoLogo: View {
  /// Turns the gear continuously. If this becomes false, the gear eases to the
  /// next rest position.
  var spins: Bool = true
  /// Seconds for the gear to advance a quarter turn.
  var period: Double = 9

  @State private var appeared = false
  @State private var motion = GearMotion.resting(-55)

  // The gear is four-fold symmetric, so a quarter turn returns it to its
  // starting shape. Rest positions are multiples of a quarter turn.
  private static let quarter = 90.0
  private static let entranceDelay = 0.25
  private static let entranceDuration = 0.9
  private static let settleDuration = 0.8

  var body: some View {
    ZStack {
      // Both shapes carry an inner subpath that has to read as a hole.
      AxoShellShape()
        .fill(Color.primary, style: FillStyle(eoFill: true))
        .opacity(appeared ? 1 : 0)
        .scaleEffect(appeared ? 1 : 0.92)

      TimelineView(.animation(paused: !motion.isMoving)) { context in
        AxoGearShape()
          .fill(Color.primary, style: FillStyle(eoFill: true))
          .rotationEffect(
            .degrees(motion.angle(at: context.date, period: period)),
            anchor: AxoGearShape.center
          )
      }
      .opacity(appeared ? 1 : 0)
      .scaleEffect(appeared ? 1 : 0.7, anchor: AxoGearShape.center)
    }
    .aspectRatio(1, contentMode: .fit)
    .onAppear(perform: start)
    .onChange(of: spins) { _, spins in
      if spins { startSpinning(after: 0) } else { settle() }
    }
    // Stops the timeline once a settling motion has finished.
    .task(id: motion.settleEnd) {
      guard let end = motion.settleEnd, case .settling(_, let to, _, _) = motion else { return }
      try? await Task.sleep(for: .seconds(max(0, end.timeIntervalSinceNow)))
      guard !Task.isCancelled else { return }
      motion = .resting(to)
    }
  }

  private func start() {
    guard !appeared else { return }
    withAnimation(.spring(response: 0.7, dampingFraction: 0.8)) { appeared = true }
    motion = .settling(
      from: -55, to: 0, begin: .now.addingTimeInterval(Self.entranceDelay),
      duration: Self.entranceDuration)
    if spins { startSpinning(after: Self.entranceDelay + Self.entranceDuration) }
  }

  private func startSpinning(after delay: Double) {
    let from = delay > 0 ? 0 : motion.angle(at: .now, period: period)
    motion = .spinning(from: from, begin: .now.addingTimeInterval(delay))
  }

  /// Ease the gear forward to the next quarter turn.
  private func settle() {
    let now = Date.now
    let current = motion.angle(at: now, period: period)
    let target = (current / Self.quarter).rounded(.up) * Self.quarter
    motion = .settling(from: current, to: target, begin: now, duration: Self.settleDuration)
  }
}

/// Gear rotation in degrees as a function of time.
private enum GearMotion {
  case resting(Double)
  case spinning(from: Double, begin: Date)
  case settling(from: Double, to: Double, begin: Date, duration: Double)

  var isMoving: Bool {
    if case .resting = self { return false }
    return true
  }

  /// End time of a settling motion.
  var settleEnd: Date? {
    guard case .settling(_, _, let begin, let duration) = self else { return nil }
    return begin.addingTimeInterval(duration)
  }

  func angle(at date: Date, period: Double) -> Double {
    switch self {
    case .resting(let angle):
      return angle
    case .spinning(let from, let begin):
      return from + max(0, date.timeIntervalSince(begin)) / period * 90
    case .settling(let from, let to, let begin, let duration):
      let progress = min(1, max(0, date.timeIntervalSince(begin) / duration))
      let eased = 1 - pow(1 - progress, 3)
      return from + (to - from) * eased
    }
  }
}
