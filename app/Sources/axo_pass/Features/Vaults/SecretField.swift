import AppKit
import SwiftUI

extension NSPasteboard.PasteboardType {
  /// Clipboard managers skip an item carrying this type, so a copied secret
  /// does not land in their history.
  static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
  /// Marks the item as short-lived, a hint for managers not to persist it.
  static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
}

/// Copy a secret to the general pasteboard, tagged so well-behaved clipboard
/// managers keep it out of their history and treat it as short-lived.
func secureCopy(_ secret: String) {
  let pasteboard = NSPasteboard.general
  pasteboard.clearContents()
  pasteboard.setString(secret, forType: .string)
  pasteboard.setString(secret, forType: .concealed)
  pasteboard.setData(Data(), forType: .transient)
}

/// A secure text field that paints no background of its own, so it can sit
/// inside an existing value box. SwiftUI's `SecureField` keeps NSTextField's
/// opaque background even under `.textFieldStyle(.plain)`, which covers the box
/// with the system text background colour.
struct PlainSecureField: NSViewRepresentable {
  let placeholder: String
  @Binding var text: String

  func makeNSView(context: Context) -> NSSecureTextField {
    let field = NSSecureTextField()
    field.delegate = context.coordinator
    field.isBordered = false
    field.isBezeled = false
    field.drawsBackground = false
    field.backgroundColor = .clear
    field.focusRingType = .none
    field.placeholderString = placeholder
    field.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
    field.cell?.usesSingleLineMode = true
    field.setContentHuggingPriority(.defaultLow, for: .horizontal)
    return field
  }

  func updateNSView(_ field: NSSecureTextField, context: Context) {
    context.coordinator.text = $text
    if field.stringValue != text {
      field.stringValue = text
    }
  }

  func makeCoordinator() -> Coordinator {
    Coordinator(text: $text)
  }

  final class Coordinator: NSObject, NSTextFieldDelegate {
    var text: Binding<String>

    init(text: Binding<String>) {
      self.text = text
    }

    func controlTextDidChange(_ notification: Notification) {
      guard let field = notification.object as? NSTextField else { return }
      text.wrappedValue = field.stringValue
    }
  }
}

/// The rounded value box shared by the vault credential rows and the key
/// passphrase field: a masked placeholder that swaps to the revealed value,
/// toggling on click. Selecting text is allowed once revealed.
struct SecretBox: View {
  /// The revealed value, or nil to show the masked placeholder.
  let revealed: String?
  /// Wrap the revealed value on any character, for long unbroken tokens like an
  /// age secret key. The masked placeholder is unaffected.
  var charWraps: Bool = false
  /// Lines the revealed value may occupy. Nil lets it grow to fit; 1 keeps a
  /// single-line credential on one line and truncates the rest. The masked
  /// placeholder is one line either way.
  var lineLimit: Int? = nil
  let onToggle: () -> Void

  var body: some View {
    Group {
      if let revealed, charWraps {
        CharWrappingText(text: revealed)
          .padding(.vertical, 6)
          .padding(.horizontal, 8)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      } else {
        Button(action: onToggle) {
          Text(revealed ?? "••••••••")
            .font(.system(.body, design: .monospaced))
            .foregroundStyle(revealed == nil ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.primary))
            .lineSpacing(8)
            .lineLimit(lineLimit)
            .truncationMode(.tail)
            .padding(.vertical, 6)
            .padding(.horizontal, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
        .textSelection(.enabled)
        .buttonStyle(RevealPlaceholderButtonStyle())
      }
    }
  }
}
