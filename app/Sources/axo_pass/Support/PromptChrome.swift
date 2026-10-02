import AxoPassFFI
import LocalAuthentication
import SwiftUI

/// Helpers for naming the caller and checking Touch ID in authorization
/// prompts.
enum PromptCaller {
  /// Returns the name of the outermost verified app in the chain, such as the
  /// terminal. Returns the raw caller string when no node is a verified app.
  /// The caller string names both ends of the chain.
  static func appName(caller: String?, chain: [ProcessNode]) -> String? {
    if let name = CallerAppIcon.name(for: chain) { return name }
    guard let caller, !caller.isEmpty else { return nil }
    return caller
  }

  /// Returns the executable file name of the innermost process, such as
  /// `ssh-keygen`. Uses the command when the executable path is unknown.
  static func requesterName(chain: [ProcessNode]) -> String {
    guard let node = chain.first else { return "Unknown process" }
    let name =
      node.executable.map { URL(fileURLWithPath: $0).lastPathComponent } ?? node.command
    return name.isEmpty ? "Unknown process" : name
  }

  /// Returns whether Touch ID is available. `biometryType` is only set after
  /// `canEvaluatePolicy` runs.
  @MainActor
  static func hasTouchID() -> Bool {
    let context = LAContext()
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
      return false
    }
    return context.biometryType == .touchID
  }
}

/// Shows the requesting app's icon, or `fallbackSystemImage` when no verified
/// app is in the chain.
struct PromptAppIcon: View {
  let callerChain: [ProcessNode]
  var fallbackSystemImage = "key.fill"

  var body: some View {
    if let appIcon = CallerAppIcon.icon(for: callerChain) {
      Image(nsImage: appIcon)
        .resizable()
        .frame(width: 64, height: 64)
    } else {
      Image(systemName: fallbackSystemImage)
        .font(.system(size: 36))
        .foregroundStyle(.secondary)
        .frame(width: 64, height: 64)
    }
  }
}

/// Prompt header showing the requesting app's icon and the Axo Pass logo,
/// connected by dashed lines with a checkmark between them.
struct PromptConnection: View {
  let callerChain: [ProcessNode]
  var fallbackSystemImage = "key.fill"

  var body: some View {
    HStack(spacing: 0) {
      PromptAppIcon(callerChain: callerChain, fallbackSystemImage: fallbackSystemImage)
      connector
      Image(systemName: "checkmark.circle")
        .font(.system(size: 22))
        .foregroundStyle(.secondary)
      connector
      AxoLogo(spins: false)
        .padding(14)
        .frame(width: 64, height: 64)
        .background(Circle().fill(.quaternary))
    }
  }

  private var connector: some View {
    Line()
      .stroke(.tertiary, style: StrokeStyle(lineWidth: 1.5, dash: [4, 3]))
      .frame(width: 28, height: 1.5)
      .padding(.horizontal, 4)
  }

  private struct Line: Shape {
    func path(in rect: CGRect) -> Path {
      var path = Path()
      path.move(to: CGPoint(x: rect.minX, y: rect.midY))
      path.addLine(to: CGPoint(x: rect.maxX, y: rect.midY))
      return path
    }
  }
}

/// A run of headline text. Bold runs hold the app name and the requested item.
/// Plain runs hold the words between them.
enum HeadlinePart {
  case plain(String)
  case bold(String)
}

/// Prompt headline built from plain and bold runs.
struct PromptHeadline: View {
  let parts: [HeadlinePart]

  init(_ parts: HeadlinePart...) {
    self.parts = parts
  }

  init(parts: [HeadlinePart]) {
    self.parts = parts
  }

  var body: some View {
    Text(attributed)
      .font(.title3)
      .multilineTextAlignment(.center)
      .lineSpacing(3)
  }

  private var attributed: AttributedString {
    parts.reduce(into: AttributedString()) { result, part in
      switch part {
      case .plain(let text):
        result += AttributedString(text)
      case .bold(let text):
        var run = AttributedString(text)
        run.inlinePresentationIntent = .stronglyEmphasized
        result += run
      }
    }
  }
}

/// Rounded card showing the symbol, title, and detail of what a prompt grants
/// access to. When `items` is non-empty, clicking the card expands a list of
/// them, such as the secrets requested by a vault read.
struct PromptSubjectCard: View {
  let systemImage: String
  let title: String
  let detail: String?
  var items: [String] = []

  @State private var expanded = false

  /// Number of items shown before the list scrolls.
  private static let visibleItems = 6

  /// Approximate height of one item, used to set the scroll area height.
  private static let itemHeight: CGFloat = 22

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      if items.isEmpty {
        header
      } else {
        Button {
          expanded.toggle()
        } label: {
          header.contentShape(Rectangle())
        }
        .buttonStyle(.plain)

        if expanded {
          Divider()
          list
        }
      }
    }
    .promptCard()
  }

  private var header: some View {
    HStack(spacing: 10) {
      Image(systemName: systemImage)
        .font(.body)
        .foregroundStyle(.secondary)
        .frame(width: 20)
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
          .font(.body.weight(.medium))
        if let detail {
          Text(detail)
            .font(.subheadline)
            .foregroundStyle(.secondary)
        }
      }
      Spacer()
      if !items.isEmpty {
        Image(systemName: "chevron.right")
          .font(.caption.weight(.semibold))
          .foregroundStyle(.secondary)
          .rotationEffect(.degrees(expanded ? 90 : 0))
          .frame(width: 10, height: 10)
      }
    }
    .padding(12)
  }

  @ViewBuilder
  private var list: some View {
    let stack = VStack(alignment: .leading, spacing: 4) {
      ForEach(Array(items.enumerated()), id: \.offset) { _, item in
        Text(item)
          .font(.system(.body, design: .monospaced))
      }
    }
    .padding(12)
    .frame(maxWidth: .infinity, alignment: .leading)
    .textSelection(.enabled)

    if items.count > Self.visibleItems {
      ScrollView { stack }
        .frame(height: CGFloat(Self.visibleItems) * Self.itemHeight + 24)
    } else {
      stack
    }
  }
}

/// Prompt footer with a Cancel button on the left and the biometric icon on
/// the right. The icon runs the biometric evaluation.
struct BiometricFooter: View {
  let icon: AuthenticationIcon
  let touchID: Bool
  let onCancel: () -> Void

  var body: some View {
    HStack(spacing: 8) {
      Button("Cancel", action: onCancel)
        .keyboardShortcut(.cancelAction)
      Spacer()
      Text(touchID ? LocalizedStringKey("Authorize with **Touch ID**") : "Authorize")
        .foregroundStyle(.primary)
      icon
        .frame(width: 32, height: 32)
    }
    .padding(.top, 4)
  }
}

extension View {
  /// Applies the rounded, tinted background used by prompt cards.
  func promptCard() -> some View {
    frame(maxWidth: .infinity, alignment: .leading)
      .background(
        RoundedRectangle(cornerRadius: 10, style: .continuous)
          .fill(.quaternary.opacity(0.5))
      )
  }
}
