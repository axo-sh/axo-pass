import AxoPassFFI
import CryptoKit
import SwiftUI

struct CredentialRow: View {
  let cred: CredentialInfo
  let secret: SymmetricKey?
  let error: String?
  let isRevealing: Bool
  let isEditing: Bool
  let onReveal: () -> Void
  let onHide: () -> Void
  let onCopy: () -> Void
  let onSave: (String) -> Void
  let onDelete: () -> Void

  @State private var draftTitle: String = ""

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      VStack(alignment: .leading, spacing: 2) {
        if isEditing {
          TextField("Title", text: $draftTitle)
            .fontWeight(.semibold)
        } else {
          Text(cred.title).fontWeight(.semibold)
        }
        Text(cred.key).font(.caption).foregroundStyle(.secondary)
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      .onChange(of: isEditing) { wasEditing, editing in
        if editing {
          draftTitle = cred.title
        } else if wasEditing, draftTitle != cred.title, !draftTitle.isEmpty {
          onSave(draftTitle)
        }
      }

      if let err = error {
        Text(err).font(.caption).foregroundStyle(.red)
      }

      HStack(spacing: 6) {
        valueBox
        actionButtons
      }
    }
    .padding(.vertical, 2)
    .padding(.horizontal, 6)
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  private var valueBox: some View {
    SecretBox(revealed: revealedText, onToggle: { secret == nil ? onReveal() : onHide() })
  }

  private var revealedText: String? {
    guard let secret else { return nil }
    return secret.withUnsafeBytes { String(bytes: $0, encoding: .utf8) ?? "(binary data)" }
  }

  @ViewBuilder
  private var actionButtons: some View {
    if isRevealing {
      ProgressView().controlSize(.small)
    } else {
      if secret != nil {
        Button("Copy", action: onCopy).buttonStyle(.bordered).controlSize(.small)
      }
      if isEditing {
        Button("Delete", role: .destructive, action: onDelete)
          .buttonStyle(.bordered)
          .controlSize(.small)
      }
    }
  }
}

struct RevealPlaceholderButtonStyle: ButtonStyle {
  @State private var isHovered = false

  func makeBody(configuration: Configuration) -> some View {
    configuration.label
      .overlay(
        RoundedRectangle(cornerRadius: 6)
          .strokeBorder(.primary.opacity(isHovered ? 0.2 : 0), lineWidth: 1)
      )
      .scaleEffect(configuration.isPressed ? 0.98 : 1.0)
      .animation(.easeInOut(duration: 0.1), value: configuration.isPressed)
      .animation(.easeInOut(duration: 0.15), value: isHovered)
      .onHover { isHovered = $0 }
  }
}

