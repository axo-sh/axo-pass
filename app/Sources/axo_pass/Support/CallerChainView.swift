import AxoPassFFI
import SwiftUI

/// An expander under an authorization prompt that shows the full caller chain:
/// one row per process, innermost first, with the detail needed to recognize an
/// unexpected caller.
///
/// Collapsed by default. The prompt's one-line `caller` already names the ends
/// of the chain, so this only earns its place when there is more than one
/// process or a single process carries detail worth seeing.
struct CallerChainView: View {
  let chain: [ProcessNode]

  @State private var expanded = false

  /// Rows past this many scroll inside the panel instead of stretching it down
  /// the screen.
  private static let visibleRows = 3

  /// Rough height of one row, used to cap the scroll area. An estimate is
  /// enough: the content scrolls if it is off.
  private static let rowHeight: CGFloat = 66

  var body: some View {
    if !chain.isEmpty {
      VStack(alignment: .leading, spacing: 8) {
        Button {
          expanded.toggle()
        } label: {
          HStack(spacing: 6) {
            Image(systemName: "chevron.right")
              .font(.caption.weight(.semibold))
              .rotationEffect(.degrees(expanded ? 90 : 0))
              .frame(width: 10, height: 10)
            Text("Caller details")
              .font(.body)
            Spacer()
          }
          .foregroundStyle(.secondary)
          .padding(.vertical, 2)
          .padding(.horizontal, 8)
          .contentShape(Rectangle())
        }
        .buttonStyle(.plain)

        if expanded {
          rows
            .background(
              RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(.quaternary.opacity(0.5))
            )
            .textSelection(.enabled)
        }
      }
      .frame(maxWidth: .infinity, alignment: .leading)
    }
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
        command
          .font(.body.weight(.medium))
        Text(metadata)
          .font(monoFont)
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
