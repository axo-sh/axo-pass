import AxoPassFFI
import SwiftUI

/// A card in an authorization prompt whose header names the requesting
/// process, e.g. `ssh-keygen`. Clicking it expands the full caller chain inside
/// the card: one row per process, innermost first, with the detail needed to
/// recognize an unexpected caller.
struct CallerChainView: View {
  let chain: [ProcessNode]

  /// The header text, usually `PromptCaller.requesterName(chain:)`.
  let summary: String

  @State private var expanded = false

  /// Rows past this many scroll inside the panel instead of stretching it down
  /// the screen.
  private static let visibleRows = 3

  /// Rough height of one row, used to cap the scroll area. An estimate is
  /// enough: the content scrolls if it is off.
  private static let rowHeight: CGFloat = 66

  var body: some View {
    if !chain.isEmpty {
      card
    }
  }

  private var card: some View {
    VStack(alignment: .leading, spacing: 0) {
      Button {
        expanded.toggle()
      } label: {
        HStack(spacing: 10) {
          Image(systemName: "terminal")
            .font(.body)
            .foregroundStyle(.secondary)
            .frame(width: 20)
          Text(summary)
            .font(.body.weight(.medium))
          Spacer()
          Image(systemName: "chevron.right")
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .rotationEffect(.degrees(expanded ? 90 : 0))
            .frame(width: 10, height: 10)
        }
        .padding(12)
        .contentShape(Rectangle())
      }
      .buttonStyle(.plain)

      if expanded {
        Divider()
        rows
          .textSelection(.enabled)
      }
    }
    .promptCard()
  }

  /// The process rows. A chain longer than `visibleRows` scrolls inside a
  /// capped area; a shorter one sizes to its content.
  @ViewBuilder
  private var rows: some View {
    let stack = VStack(alignment: .leading, spacing: 10) {
      ForEach(Array(chain.enumerated()), id: \.offset) { index, node in
        ProcessRow(node: node, isLast: index == chain.count - 1)
      }
    }
    .padding(12)
    .frame(maxWidth: .infinity, alignment: .leading)

    if chain.count > Self.visibleRows {
      ScrollView { stack }
        .frame(height: CGFloat(Self.visibleRows) * Self.rowHeight)
    } else {
      stack
    }
  }
}

/// One process in the chain.
private struct ProcessRow: View {
  let node: ProcessNode
  let isLast: Bool

  var body: some View {
    HStack(alignment: .top, spacing: 8) {
      Text(isLast ? "└" : "├")
        .font(monoFont)
        .foregroundStyle(.secondary)

      VStack(alignment: .leading, spacing: 2) {
        HStack(spacing: 6) {
          command
            .font(.body.weight(.medium))
          if !node.verified {
            Label("Unverified", systemImage: "exclamationmark.triangle.fill")
              .font(.caption.weight(.semibold))
              .foregroundStyle(.orange)
              .help(
                "This process's code signature could not be verified. Its name and bundle ID may be forged."
              )
          }
        }
        Text(metadata)
          .font(.system(.subheadline, design: .monospaced))
          .lineSpacing(3)
          .foregroundStyle(.secondary)
      }
    }
  }

  private var command: Text {
    if node.command.isEmpty {
      return Text("unknown")
    }
    if let bundleId = node.bundleId, !bundleId.isEmpty {
      let bundle = Text(" · \(bundleId)").foregroundStyle(.secondary)
      return Text("\(node.command) \(bundle)")
    }
    return Text(node.command)
  }

  private var metadata: String {
    if let executable = node.executable, !executable.isEmpty {
      return "\(executable) [\(node.pid)]"
    } else {
      return "pid \(node.pid)"
    }
  }

  private var monoFont: Font { .system(.body, design: .monospaced) }
}
