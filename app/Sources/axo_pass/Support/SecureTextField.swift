import AppKit
import SwiftUI

/// A secure text field with no chrome of its own, so it can sit inside an
/// existing value box. SwiftUI's `SecureField` keeps NSTextField's opaque
/// background even under `.textFieldStyle(.plain)`, which covers the box with
/// the system text background colour.
///
/// In multiline mode Return inserts a newline instead of ending editing, and
/// the field grows between `minLines` and `maxLines`. The secure field editor
/// masks every character, newlines included, so masked text stays on one visual
/// line; the line breaks are present in the bound string and show once the
/// value is revealed elsewhere.
struct SecureTextField: NSViewRepresentable {
  @Binding var text: String
  var placeholder: String = ""
  /// Return inserts a newline rather than submitting.
  var multiline: Bool = false
  /// Lines the field occupies in multiline mode. Ignored when single line.
  var minLines: Int = 3
  var maxLines: Int = 12
  /// Draw the system bezel, background and focus ring, for a field standing on
  /// its own in a form. The default is chromeless, for a field inside a box
  /// that already draws them.
  var bordered: Bool = false
  var font: NSFont = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
  /// Called when Return is pressed in single-line mode.
  var onSubmit: (() -> Void)? = nil
  /// Called when Escape is pressed.
  var onCancel: (() -> Void)? = nil

  func makeNSView(context: Context) -> NSSecureTextField {
    let field = NSSecureTextField()
    field.delegate = context.coordinator
    field.setContentHuggingPriority(.defaultLow, for: .horizontal)
    apply(to: field, context: context)
    return field
  }

  func updateNSView(_ field: NSSecureTextField, context: Context) {
    apply(to: field, context: context)
    if field.stringValue != text {
      field.stringValue = text
    }
  }

  func makeCoordinator() -> Coordinator {
    Coordinator(parent: self)
  }

  func sizeThatFits(
    _ proposal: ProposedViewSize, nsView field: NSSecureTextField, context: Context
  ) -> CGSize? {
    let width = proposal.width ?? 100
    let lineHeight = NSLayoutManager().defaultLineHeight(for: font)
    guard let cell = field.cell as? NSTextFieldCell else {
      return CGSize(width: width, height: ceil(lineHeight))
    }
    // What the bezel adds around the text, measured against a probe bounds so
    // the bordered and chromeless cases share one height calculation.
    let probe = NSRect(x: 0, y: 0, width: width, height: 100)
    let chrome = max(0, 100 - cell.titleRect(forBounds: probe).height)
    let fitted = cell.cellSize(forBounds: NSRect(
      x: 0, y: 0, width: width, height: .greatestFiniteMagnitude)).height
    guard multiline else {
      return CGSize(width: width, height: ceil(max(fitted, lineHeight + chrome)))
    }
    let minHeight = lineHeight * CGFloat(max(1, minLines)) + chrome
    let maxHeight = lineHeight * CGFloat(max(minLines, maxLines)) + chrome
    return CGSize(width: width, height: ceil(min(max(fitted, minHeight), maxHeight)))
  }

  private func apply(to field: NSSecureTextField, context: Context) {
    context.coordinator.parent = self
    field.placeholderString = placeholder
    field.font = font
    field.lineBreakMode = multiline ? .byWordWrapping : .byTruncatingTail
    field.isBordered = bordered
    field.isBezeled = bordered
    field.bezelStyle = .squareBezel
    field.drawsBackground = bordered
    field.backgroundColor = bordered ? .textBackgroundColor : .clear
    field.focusRingType = bordered ? .default : .none
    guard let cell = field.cell as? NSTextFieldCell else { return }
    cell.usesSingleLineMode = !multiline
    cell.wraps = multiline
    cell.isScrollable = true
  }

  final class Coordinator: NSObject, NSTextFieldDelegate, NSControlTextEditingDelegate {
    var parent: SecureTextField

    init(parent: SecureTextField) {
      self.parent = parent
    }

    func controlTextDidChange(_ notification: Notification) {
      guard let field = notification.object as? NSTextField else { return }
      parent.text = field.stringValue
      field.invalidateIntrinsicContentSize()
    }

    func control(
      _ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector
    ) -> Bool {
      switch commandSelector {
      case #selector(NSResponder.insertNewline(_:)):
        if parent.multiline {
          // Bypasses the field editor's "end editing" handling and puts a
          // literal newline in the text instead.
          textView.insertNewlineIgnoringFieldEditor(nil)
          return true
        }
        guard let onSubmit = parent.onSubmit else { return false }
        onSubmit()
        return true
      case #selector(NSResponder.cancelOperation(_:)):
        guard let onCancel = parent.onCancel else { return false }
        onCancel()
        return true
      default:
        return false
      }
    }
  }
}
