import AppKit
import SwiftUI

/// A text editor with no chrome of its own, so it can sit inside an existing
/// value box. It grows with its content between `minLines` and `maxLines`, then
/// scrolls.
///
/// The text is not masked. Callers show this only for values the user has
/// already revealed, or is typing in for the first time.
struct ValueTextEditor: View {
  @Binding var text: String
  var placeholder: String = ""
  /// Return inserts a newline. When false, newlines are stripped as they arrive
  /// and the editor stays one line tall.
  var multiline: Bool = false
  /// Lines the editor occupies before it grows. Ignored when single line.
  var minLines: Int = 3
  var maxLines: Int = 12
  /// Draw a background and border, for an editor standing on its own in a form.
  /// The default is chromeless, for one inside a box that already draws them.
  var bordered: Bool = false
  var font: NSFont = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
  /// Extra space between wrapped lines. Matches the read view, so a value keeps
  /// its shape when the row enters and leaves editing.
  var lineSpacing: CGFloat = 8

  /// Horizontal inset TextEditor puts around its text. The measuring mirror
  /// matches it so both wrap at the same width.
  private static let textInset: CGFloat = 5

  /// The inset the text ends up with. A chromeless editor cancels TextEditor's
  /// own inset so its text sits where the read view's text sat, rather than
  /// shifting right when the row enters editing. A bordered editor keeps the
  /// inset to stand off its own border.
  private var inset: CGFloat { bordered ? Self.textInset : 0 }

  @State private var contentHeight: CGFloat = 0

  var body: some View {
    ZStack(alignment: .topLeading) {
      if text.isEmpty, !placeholder.isEmpty {
        Text(placeholder)
          .foregroundStyle(.tertiary)
          .padding(.horizontal, inset)
          .allowsHitTesting(false)
      }
      TextEditor(text: $text)
        .textEditorStyle(.plain)
        .scrollContentBackground(.hidden)
        .padding(.horizontal, inset - Self.textInset)
    }
    .font(Font(font))
    .lineSpacing(lineSpacing)
    .frame(height: height)
    .background { mirror }
    .background {
      if bordered {
        RoundedRectangle(cornerRadius: 5)
          .fill(Color(nsColor: .textBackgroundColor))
          .overlay(RoundedRectangle(cornerRadius: 5).strokeBorder(.separator, lineWidth: 1))
      }
    }
    .onChange(of: text) { _, new in
      if !multiline, new.contains("\n") {
        text = new.replacingOccurrences(of: "\n", with: "")
      }
    }
  }

  /// A hidden copy of the text laid out at the editor's width, used to measure
  /// how tall the content wants to be.
  private var mirror: some View {
    Text(text.isEmpty ? " " : text)
      .font(Font(font))
      .lineSpacing(lineSpacing)
      .padding(.horizontal, inset)
      .frame(maxWidth: .infinity, alignment: .leading)
      .fixedSize(horizontal: false, vertical: true)
      .hidden()
      .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { contentHeight = $0 }
  }

  private var lineHeight: CGFloat {
    NSLayoutManager().defaultLineHeight(for: font)
  }

  /// Height of `lines` lines, with spacing in the gaps between them.
  private func height(lines: Int) -> CGFloat {
    CGFloat(lines) * lineHeight + CGFloat(max(0, lines - 1)) * lineSpacing
  }

  private var height: CGFloat {
    guard multiline else { return ceil(height(lines: 1)) }
    let low = height(lines: max(1, minLines))
    let high = height(lines: max(max(1, minLines), maxLines))
    return ceil(min(max(contentHeight, low), high))
  }
}
