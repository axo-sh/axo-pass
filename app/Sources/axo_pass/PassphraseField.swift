import AppKit
import SwiftUI

/// A key's saved passphrase, shown the way the vault detail pane shows a
/// credential secret: a full-width rounded box that toggles between a masked
/// placeholder and the revealed value, with Copy and Remove beside the header.
/// When nothing is saved the box becomes a button that starts the save flow.
/// Reveal and copy read the passphrase back from the keychain, which prompts
/// for Touch ID.
struct PassphraseField: View {
  let hasSaved: Bool
  /// Reads the passphrase from the keychain. Returns nil if it cannot.
  let reveal: () async -> String?
  let save: () -> Void
  let remove: () -> Void

  @State private var revealed: String?
  @State private var isBusy = false

  var body: some View {
    LabeledContent("Passphrase") {
      HStack(spacing: 6) {
        valueBox
        if hasSaved {
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
      SecretBox(revealed: revealed) {
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
