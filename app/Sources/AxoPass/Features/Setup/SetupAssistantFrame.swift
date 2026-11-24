import AppKit
import SwiftUI

/// Step state of a setup assistant. `go` slides to another step.
@MainActor
@Observable
final class SetupNavigator<Step: Hashable> {
  var step: Step
  /// Direction of the last step change. Sets the slide direction.
  var forward = true

  init(start: Step) {
    step = start
  }

  /// Slide to `next`. Direction is set one update before the step changes, so
  /// the outgoing step slides the same way as the incoming one.
  func go(to next: Step, forward: Bool = true) {
    self.forward = forward
    DispatchQueue.main.async {
      withAnimation(.smooth(duration: 0.35)) {
        self.step = next
      }
    }
  }
}

/// Window frame of a setup assistant. Matches the item import flow in size,
/// padding, and step transition.
struct SetupAssistantFrame<Step: Hashable, Content: View>: View {
  let navigator: SetupNavigator<Step>
  var error: String? = nil
  @ViewBuilder let content: (Step) -> Content

  /// Minimum height of the flow. Steps of different lengths resize the window
  /// less.
  private static var minHeight: CGFloat { 360 }

  private var stepTransition: AnyTransition {
    .asymmetric(
      insertion: .move(edge: navigator.forward ? .trailing : .leading),
      removal: .move(edge: navigator.forward ? .leading : .trailing))
  }

  var body: some View {
    ZStack(alignment: .topLeading) {
      page
        .id(navigator.step)
        .transition(stepTransition)
    }
    .frame(width: 460)
    .frame(minHeight: Self.minHeight, alignment: .topLeading)
    .clipped()
  }

  private var page: some View {
    VStack(alignment: .leading, spacing: 16) {
      content(navigator.step)
        .frame(maxHeight: .infinity)

      if let error {
        Label(error, systemImage: "xmark.circle.fill")
          .font(.caption)
          .foregroundStyle(.red)
          .lineLimit(4)
          .fixedSize(horizontal: false, vertical: true)
      }
    }
    .padding(28)
    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
  }
}

/// Title and detail line at the top of a setup step.
struct SetupHeader: View {
  let title: String
  let detail: LocalizedStringKey
  var detailLineSpacing: CGFloat = 0

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(title)
        .font(.title2)
        .fontWeight(.semibold)
      Text(detail)
        .font(.callout)
        .lineSpacing(detailLineSpacing)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }
  }
}

/// Monospaced text with a copy button.
struct SetupCodeBlock: View {
  let text: String

  var body: some View {
    HStack(alignment: .top, spacing: 8) {
      Text(text)
        .font(.system(size: 12, design: .monospaced))
        .lineSpacing(3)
        .textSelection(.enabled)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
      Button {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
      } label: {
        Image(systemName: "document.on.document")
      }
      .buttonStyle(.borderless)
      .help("Copy to clipboard")
    }
    .padding(10)
    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
  }
}

/// Warning that another program is configured and will be commented out.
struct SetupReplaceWarning: View {
  let message: String
  let current: String

  var body: some View {
    Label {
      VStack(alignment: .leading, spacing: 2) {
        Text(message)
        Text(current)
          .font(.caption.monospaced())
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
      }
    } icon: {
      Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.orange)
    }
    .fixedSize(horizontal: false, vertical: true)
  }
}

/// Final step card. The first row is a checkmark with a summary and, if
/// `code` is set, a toggle that shows the configured code. `rows` adds
/// further rows below, each preceded by a divider.
struct SetupDoneCard<Rows: View>: View {
  let summary: String
  var code: String? = nil
  @ViewBuilder var rows: () -> Rows

  @State private var showsCode = false

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      Button {
        withAnimation(.easeOut(duration: 0.15)) { showsCode.toggle() }
      } label: {
        HStack {
          Label {
            Text(summary).textSelection(.enabled)
          } icon: {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
          }
          Spacer(minLength: 0)
          if code != nil {
            Image(systemName: "chevron.right")
              .font(.caption.weight(.semibold))
              .foregroundStyle(.secondary)
              .rotationEffect(.degrees(showsCode ? 90 : 0))
          }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
      .disabled(code == nil)
      .accessibilityHint("Shows the configured code")
      if showsCode, let code {
        SetupCodeBlock(text: code)
          .padding(.horizontal, 10)
          .padding(.bottom, 10)
      }
      rows()
    }
    .font(.callout)
    .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    .overlay {
      RoundedRectangle(cornerRadius: 10)
        .strokeBorder(.separator)
    }
  }
}

extension SetupDoneCard where Rows == EmptyView {
  init(summary: String, code: String? = nil) {
    self.init(summary: summary, code: code) { EmptyView() }
  }
}

/// Row of a `SetupDoneCard`, preceded by a divider.
struct SetupCardRow<Content: View>: View {
  let symbol: String
  let tint: Color
  @ViewBuilder let content: () -> Content

  var body: some View {
    Divider()
    Label {
      content().textSelection(.enabled)
    } icon: {
      Image(systemName: symbol).foregroundStyle(tint)
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .fixedSize(horizontal: false, vertical: true)
  }
}

/// Card row that reports the value that was commented out.
struct SetupReplacedRow: View {
  let replaced: String

  var body: some View {
    SetupCardRow(symbol: "minus.circle.fill", tint: .secondary) {
      VStack(alignment: .leading, spacing: 2) {
        Text("Previously configured, now commented out:")
        Text(replaced)
          .font(.caption.monospaced())
          .foregroundStyle(.secondary)
      }
    }
  }
}
