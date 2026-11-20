import SwiftUI

/// Status bar at the foot of a source list. Shows the most severe issue of the
/// source from `IssuesModel`, with a count of the others. Shows `healthyLabel`
/// if the source has no issues.
struct SourceStatusBar: View {
  @Environment(IssuesModel.self) private var issues

  let source: IssueSource
  let healthyLabel: String
  let healthyColor: Color
  let help: String
  let action: () -> Void

  var body: some View {
    let sourceIssues = issues.issues.filter { $0.source == source }
    Button(action: action) {
      HStack(spacing: 6) {
        Circle()
          .fill(sourceIssues.first?.severity.color ?? healthyColor)
          .frame(width: 7, height: 7)
        Text(sourceIssues.first?.title ?? healthyLabel)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.tail)
        if sourceIssues.count > 1 {
          Text("+\(sourceIssues.count - 1)")
            .font(.caption)
            .foregroundStyle(.tertiary)
            .monospacedDigit()
        }
        Spacer()
        Image(systemName: "chevron.right")
          .font(.caption2)
          .foregroundStyle(.tertiary)
      }
      .contentShape(Rectangle())
      .padding(.horizontal, 12)
      .padding(.vertical, 8)
    }
    .buttonStyle(.plain)
    .background(.bar)
    .overlay(alignment: .top) { Divider() }
    .help(help)
  }
}
