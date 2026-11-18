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

/// The outer shell of the mark.
struct AxoShellShape: Shape {
  func path(in rect: CGRect) -> Path {
    SVGPath.path(AxoArtwork.shell, viewBox: AxoArtwork.viewBox, in: rect)
  }
}

/// The gear that sits inside the shell.
struct AxoGearShape: Shape {
  /// The gear's axis, as a fraction of the artwork's bounds.
  static let center = UnitPoint(x: 512.586 / 1025, y: 578.879 / 1025)

  func path(in rect: CGRect) -> Path {
    SVGPath.path(AxoArtwork.gear, viewBox: AxoArtwork.viewBox, in: rect)
  }
}

/// Path data lifted from the app icon.
private enum AxoArtwork {
  static let viewBox = CGSize(width: 1025, height: 1025)

  static let shell = """
    M257.857,837.235l-13.46,40.987c164.214,53.925 371.976,53.925 536.189,-0l0.014,-0.005c96.162,\
    -31.652 153.947,-133.92 131.886,-234.601c-36.449,-171.537 -140.274,-354.643 -267.943,-472.623c\
    -74.59,-68.929 -189.513,-68.929 -264.103,0c-127.703,118.012 -231.551,301.186 -267.982,472.807c\
    -21.397,100.444 36.031,202.148 131.64,234.322l13.759,-40.887Zm13.647,-40.926c147.681,48.449 \
    334.483,48.431 482.146,-0.055c54.856,-18.062 87.163,-76.792 74.508,-134.387l-0.031,-0.15c\
    -32.927,-155.112 -126.723,-320.699 -242.141,-427.358c-41.514,-38.363 -105.475,-38.363 -146.989,\
    0c-115.418,106.659 -209.213,272.246 -242.144,427.373l-0.003,0.015c-12.252,57.514 19.953,116.089 \
    74.654,134.562Z
    """

  static let gear = """
    M372.519,522.469l-22.367,-22.367c-11.543,-11.543 -11.543,-30.286 -0,-41.828l41.829,-41.829c\
    11.542,-11.543 30.285,-11.543 41.828,-0l22.367,22.367c17.428,-7.035 36.47,-10.909 56.41,-10.909c\
    19.94,0 38.982,3.874 56.41,10.909l22.343,-22.343c11.543,-11.543 30.286,-11.543 41.829,-0l41.829,\
    41.828c11.542,11.543 11.542,30.286 -0,41.829l-22.343,22.343c7.034,17.428 10.908,36.47 10.908,\
    56.41c0,19.94 -3.874,38.982 -10.908,56.41l22.366,22.367c11.543,11.543 11.543,30.286 0,41.829l\
    -41.828,41.828c-11.543,11.543 -30.286,11.543 -41.829,0l-22.367,-22.366c-17.428,7.034 -36.47,\
    10.908 -56.41,10.908c-19.94,0 -38.982,-3.874 -56.41,-10.908l-22.343,22.343c-11.543,11.542 \
    -30.286,11.542 -41.829,-0l-41.828,-41.829c-11.543,-11.543 -11.543,-30.286 -0,-41.829l22.343,\
    -22.343c-7.035,-17.428 -10.909,-36.47 -10.909,-56.41c0,-19.94 3.874,-38.982 10.909,-56.41Zm\
    140.067,-25.411c45.158,0 81.821,36.663 81.821,81.821c0,45.158 -36.663,81.821 -81.821,81.821c\
    -45.158,0 -81.821,-36.663 -81.821,-81.821c0,-45.158 36.663,-81.821 81.821,-81.821Z
    """
}

/// Builds a `Path` from SVG path data. Supports the move, line, cubic and
/// quadratic commands; elliptical arcs (`A`/`a`) are not implemented.
enum SVGPath {
  /// Parses `data` in `viewBox` coordinates and scales it to fit `rect`,
  /// preserving the aspect ratio.
  static func path(_ data: String, viewBox: CGSize, in rect: CGRect) -> Path {
    let raw = parse(data)
    let scale = min(rect.width / viewBox.width, rect.height / viewBox.height)
    let offsetX = rect.minX + (rect.width - viewBox.width * scale) / 2
    let offsetY = rect.minY + (rect.height - viewBox.height * scale) / 2
    let transform = CGAffineTransform(translationX: offsetX, y: offsetY)
      .scaledBy(x: scale, y: scale)
    return raw.applying(transform)
  }

  static func parse(_ data: String) -> Path {
    var path = Path()
    var scanner = Scanner(data)
    var current = CGPoint.zero
    var subpathStart = CGPoint.zero
    // The reflected control point for smooth curves, in absolute coordinates.
    var lastCubicControl: CGPoint?
    var lastQuadControl: CGPoint?
    var command: Character?

    func point(_ x: CGFloat, _ y: CGFloat, relative: Bool) -> CGPoint {
      relative ? CGPoint(x: current.x + x, y: current.y + y) : CGPoint(x: x, y: y)
    }

    while !scanner.isAtEnd {
      if scanner.isAtCommand { command = scanner.takeCommand() }
      guard let cmd = command else { break }
      let relative = cmd.isLowercase
      var consumedCubic: CGPoint?
      var consumedQuad: CGPoint?

      switch Character(cmd.lowercased()) {
      case "m":
        guard let x = scanner.number(), let y = scanner.number() else { return path }
        current = point(x, y, relative: relative)
        subpathStart = current
        path.move(to: current)
        // Further coordinate pairs after a move are implicit line commands.
        command = relative ? "l" : "L"
      case "l":
        guard let x = scanner.number(), let y = scanner.number() else { return path }
        current = point(x, y, relative: relative)
        path.addLine(to: current)
      case "h":
        guard let x = scanner.number() else { return path }
        current = relative ? CGPoint(x: current.x + x, y: current.y) : CGPoint(x: x, y: current.y)
        path.addLine(to: current)
      case "v":
        guard let y = scanner.number() else { return path }
        current = relative ? CGPoint(x: current.x, y: current.y + y) : CGPoint(x: current.x, y: y)
        path.addLine(to: current)
      case "c":
        guard let x1 = scanner.number(), let y1 = scanner.number(),
          let x2 = scanner.number(), let y2 = scanner.number(),
          let x = scanner.number(), let y = scanner.number()
        else { return path }
        let c1 = point(x1, y1, relative: relative)
        let c2 = point(x2, y2, relative: relative)
        current = point(x, y, relative: relative)
        path.addCurve(to: current, control1: c1, control2: c2)
        consumedCubic = c2
      case "s":
        guard let x2 = scanner.number(), let y2 = scanner.number(),
          let x = scanner.number(), let y = scanner.number()
        else { return path }
        let c1 = reflect(lastCubicControl, about: current)
        let c2 = point(x2, y2, relative: relative)
        current = point(x, y, relative: relative)
        path.addCurve(to: current, control1: c1, control2: c2)
        consumedCubic = c2
      case "q":
        guard let x1 = scanner.number(), let y1 = scanner.number(),
          let x = scanner.number(), let y = scanner.number()
        else { return path }
        let c = point(x1, y1, relative: relative)
        current = point(x, y, relative: relative)
        path.addQuadCurve(to: current, control: c)
        consumedQuad = c
      case "t":
        guard let x = scanner.number(), let y = scanner.number() else { return path }
        let c = reflect(lastQuadControl, about: current)
        current = point(x, y, relative: relative)
        path.addQuadCurve(to: current, control: c)
        consumedQuad = c
      case "z":
        path.closeSubpath()
        current = subpathStart
      default:
        // An unsupported command leaves the rest of the data unparseable.
        return path
      }

      lastCubicControl = consumedCubic
      lastQuadControl = consumedQuad
    }
    return path
  }

  private static func reflect(_ control: CGPoint?, about point: CGPoint) -> CGPoint {
    guard let control else { return point }
    return CGPoint(x: 2 * point.x - control.x, y: 2 * point.y - control.y)
  }

  /// Reads numbers and command letters out of SVG path data.
  private struct Scanner {
    private let chars: [Character]
    private var index = 0

    init(_ data: String) { chars = Array(data) }

    var isAtEnd: Bool {
      mutating get {
        skipSeparators()
        return index >= chars.count
      }
    }

    var isAtCommand: Bool {
      mutating get {
        skipSeparators()
        return index < chars.count && chars[index].isLetter
      }
    }

    mutating func takeCommand() -> Character? {
      guard isAtCommand else { return nil }
      defer { index += 1 }
      return chars[index]
    }

    mutating func number() -> CGFloat? {
      skipSeparators()
      let start = index
      if index < chars.count, chars[index] == "+" || chars[index] == "-" { index += 1 }
      var sawDigit = takeDigits()
      if index < chars.count, chars[index] == "." {
        index += 1
        sawDigit = takeDigits() || sawDigit
      }
      guard sawDigit else {
        index = start
        return nil
      }
      if index < chars.count, chars[index] == "e" || chars[index] == "E" {
        let beforeExponent = index
        index += 1
        if index < chars.count, chars[index] == "+" || chars[index] == "-" { index += 1 }
        if !takeDigits() { index = beforeExponent }
      }
      guard let value = Double(String(chars[start..<index])) else {
        index = start
        return nil
      }
      return CGFloat(value)
    }

    @discardableResult
    private mutating func takeDigits() -> Bool {
      let start = index
      while index < chars.count, chars[index].isASCII, chars[index].isNumber { index += 1 }
      return index > start
    }

    private mutating func skipSeparators() {
      while index < chars.count, chars[index] == "," || chars[index].isWhitespace {
        index += 1
      }
    }
  }
}
