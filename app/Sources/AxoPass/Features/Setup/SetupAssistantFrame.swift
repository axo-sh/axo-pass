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
  let detail: String

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(title)
        .font(.title2)
        .fontWeight(.semibold)
      Text(detail)
        .font(.callout)
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
        .font(.caption.monospaced())
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
      Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
    }
    .fixedSize(horizontal: false, vertical: true)
  }
}

/// Final step content: a checkmark with the config path, the active line, and
/// the value that was commented out, if any.
struct SetupDoneSummary: View {
  let path: String
  let activeLine: String?
  var replaced: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      Label {
        Text("Configured in \(path).")
          .textSelection(.enabled)
      } icon: {
        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
      }
      .font(.callout)
      if let activeLine {
        SetupCodeBlock(text: activeLine)
      }
      if let replaced {
        VStack(alignment: .leading, spacing: 4) {
          Text("Previously configured, now commented out:")
            .font(.caption)
            .foregroundStyle(.secondary)
          Text(replaced)
            .font(.caption.monospaced())
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
        }
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}
