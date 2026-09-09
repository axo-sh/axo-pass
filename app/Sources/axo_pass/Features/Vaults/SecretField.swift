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
