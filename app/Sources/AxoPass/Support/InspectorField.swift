import SwiftUI

/// A left-aligned label/value row with a fixed-width label column. Values stay
/// flush left and wrap onto multiple lines unless the caller limits them,
/// unlike the default centered `LabeledContent` layout in a narrow pane.
///
/// Apply with `.labeledContentStyle(.inspectorField)` on a container; the rows
/// themselves are plain `LabeledContent`, usually via `InspectorRow`.
struct InspectorFieldStyle: LabeledContentStyle {
  var labelWidth: CGFloat = 100

  func makeBody(configuration: Configuration) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 8) {
      configuration.label
        .foregroundStyle(.secondary)
        .frame(width: labelWidth, alignment: .leading)
      configuration.content
        .frame(maxWidth: .infinity, alignment: .leading)
        .multilineTextAlignment(.leading)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

extension LabeledContentStyle where Self == InspectorFieldStyle {
  static var inspectorField: InspectorFieldStyle { InspectorFieldStyle() }

  static func inspectorField(labelWidth: CGFloat) -> InspectorFieldStyle {
    InspectorFieldStyle(labelWidth: labelWidth)
  }
}

/// A label/value row for inspector and detail panes. Renders as `LabeledContent`
/// so it picks up `.inspectorField` styling and accessibility grouping. The
/// value is selectable; pass `truncatesMiddle` for ids that should stay on one
/// line.
struct InspectorRow: View {
  let label: String
  let value: String
  var monospaced: Bool = false
  var truncatesMiddle: Bool = false

  init(
    _ label: String, value: String, monospaced: Bool = false,
    truncatesMiddle: Bool = false
  ) {
    self.label = label
    self.value = value
    self.monospaced = monospaced
    self.truncatesMiddle = truncatesMiddle
  }

  var body: some View {
    LabeledContent(label) {
      Text(value)
        .font(monospaced ? .system(.body, design: .monospaced) : .body)
        .textSelection(.enabled)
        .lineLimit(truncatesMiddle ? 1 : nil)
        .truncationMode(truncatesMiddle ? .middle : .tail)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
  }
}
