import AppKit
import SwiftUI

/// A key's saved passphrase, shown the way the vault detail pane shows a
/// credential secret: a full-width rounded box that toggles between a masked
/// placeholder and the revealed value, with Copy and Remove beside the header.
/// When nothing is saved the box becomes a button that starts the save flow.
/// Reveal and copy read the passphrase back from the keychain, which prompts
/// for Touch ID.
struct PassphraseField: View {
  /// The row label. Defaults to "Passphrase"; age keys pass "Secret Key".
  var label: String = "Passphrase"
  /// Wrap the revealed value on any character, for a long unbroken token like
  /// an age secret key. Adds a Hide button, since the wrapped box is selectable
  /// rather than a tap target.
  var charWraps: Bool = false
  let hasSaved: Bool
  /// Reads the passphrase from the keychain. Returns nil if it cannot.
  let reveal: () async -> String?
  let save: () -> Void
  let remove: () -> Void

  @State private var revealed: String?
  @State private var isBusy = false

  var body: some View {
    LabeledContent(label) {
      HStack(spacing: 6) {
        valueBox
        if hasSaved {
          if charWraps && revealed != nil {
            Button("Hide") { revealed = nil }
              .buttonStyle(.bordered)
              .controlSize(.small)
          }
          Button("Copy") { Task { await copy() } }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(isBusy)
          Button("Remove", role: .destructive, action: remove)
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(isBusy)
        }
      }
    }
    .labeledContentStyle(.inspectorField)
    .onChange(of: hasSaved) { _, saved in
      if !saved { revealed = nil }
    }
  }

  @ViewBuilder
  private var valueBox: some View {
    if !hasSaved {
      Button(action: save) {
        Label("Save Passphrase", systemImage: "plus")
          .padding(.vertical, 6)
          .padding(.horizontal, 8)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      }
      .buttonStyle(RevealPlaceholderButtonStyle())
    } else {
      SecretBox(revealed: revealed, charWraps: charWraps) {
        if revealed == nil {
          Task { await revealNow() }
        } else {
          revealed = nil
        }
      }
      .overlay(alignment: .trailing) {
        if isBusy {
          ProgressView()
            .controlSize(.small)
            .padding(.trailing, 8)
        }
      }
      .disabled(isBusy)
    }
  }

  private func revealNow() async {
    isBusy = true
    revealed = await reveal()
    isBusy = false
  }

  private func copy() async {
    var value = revealed
    if value == nil {
      isBusy = true
      value = await reveal()
      isBusy = false
    }
    guard let value else { return }
    secureCopy(value)
  }
}
