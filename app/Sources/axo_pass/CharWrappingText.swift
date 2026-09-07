import AppKit
import SwiftUI

/// A selectable, multi-line label that wraps on any character. SwiftUI's `Text`
/// only breaks on word boundaries, so one long unbroken token like the base64
/// body of an SSH public key overflows the pane or truncates instead of
/// filling the available width.
///
/// Backed by a read-only `NSTextView`. An `NSTextField` label drops its
/// attributed color and paragraph style as soon as the text is selected.
struct CharWrappingText: NSViewRepresentable {
  let text: String
  var font: NSFont = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
  var lineSpacing: CGFloat = 4
  /// When set, the leading token and everything after the second field are
  /// drawn in the secondary color, leaving the key body in the label color.
  /// Matches the `algorithm base64 comment` shape of an SSH public key.
  var dimsOuterFields = false

  private func attributedString() -> NSAttributedString {
    let paragraph = NSMutableParagraphStyle()
    paragraph.lineBreakMode = .byCharWrapping
    paragraph.lineSpacing = lineSpacing
    let result = NSMutableAttributedString(
      string: text,
      attributes: [
        .font: font,
        .paragraphStyle: paragraph,
        .foregroundColor: NSColor.labelColor,
      ])
    if dimsOuterFields {
      let ns = text as NSString
      let firstSpace = ns.range(of: " ")
      if firstSpace.location != NSNotFound {
        result.addAttribute(
          .foregroundColor, value: NSColor.secondaryLabelColor,
          range: NSRange(location: 0, length: firstSpace.location))
        let afterFirst = firstSpace.location + firstSpace.length
        let secondSpace = ns.range(
          of: " ", options: [], range: NSRange(location: afterFirst, length: ns.length - afterFirst))
        if secondSpace.location != NSNotFound {
          result.addAttribute(
            .foregroundColor, value: NSColor.secondaryLabelColor,
            range: NSRange(
              location: secondSpace.location, length: ns.length - secondSpace.location))
        }
      }
    }
    return result
  }

  func makeNSView(context: Context) -> NSTextView {
    let view = NSTextView()
    view.isEditable = false
    view.isSelectable = true
    view.isRichText = false
    view.drawsBackground = false
    view.textContainerInset = .zero
    view.textContainer?.lineFragmentPadding = 0
    view.textContainer?.widthTracksTextView = true
    view.isVerticallyResizable = true
    view.isHorizontallyResizable = false
    // A selection keeps the stored attributes; only the insertion point styling
    // would differ, and this view has none.
    view.selectedTextAttributes = [.backgroundColor: NSColor.selectedTextBackgroundColor]
    view.setContentHuggingPriority(.required, for: .vertical)
    view.setContentCompressionResistancePriority(.required, for: .vertical)
    return view
  }

  func updateNSView(_ view: NSTextView, context: Context) {
    view.textStorage?.setAttributedString(attributedString())
  }

  func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSTextView, context: Context) -> CGSize? {
    guard let width = proposal.width, width.isFinite, width > 0 else { return nil }
    nsView.frame = NSRect(x: 0, y: 0, width: width, height: 10_000)
    nsView.textContainer?.containerSize = NSSize(width: width, height: .greatestFiniteMagnitude)
    let bounds = attributedString().boundingRect(
      with: NSSize(width: width, height: .greatestFiniteMagnitude),
      options: [.usesLineFragmentOrigin])
    return CGSize(width: width, height: ceil(bounds.height))
  }
}
