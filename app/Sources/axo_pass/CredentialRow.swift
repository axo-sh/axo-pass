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
      LabeledContent {
        actionButtons
      } label: {
        VStack(alignment: .leading, spacing: 2) {
          if isEditing {
            TextField("Title", text: $draftTitle)
              .fontWeight(.semibold)
          } else {
            Text(cred.title).fontWeight(.semibold)
          }
          Text(cred.key).font(.caption).foregroundStyle(.secondary)
        }
      }
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

      if let secret {
        // LabeledContent("Value") {
        SecretValueView(secret: secret, onHide: onHide)
        // }
      } else {
        Button(action: onReveal) {
          Text("••••••••")
            .font(.system(.body, design: .monospaced))
            .foregroundStyle(.tertiary)
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(RevealPlaceholderButtonStyle())
      }
    }
    .padding(.vertical, 2)
    .padding(.horizontal, 6)
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  @ViewBuilder
  private var actionButtons: some View {
    if isRevealing {
      ProgressView().controlSize(.small)
    } else {
      HStack(spacing: 4) {
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
}

private struct RevealPlaceholderButtonStyle: ButtonStyle {
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

private struct SecretValueView: View {
  let secret: SymmetricKey
  let onHide: () -> Void

  var body: some View {
    let value = secret.withUnsafeBytes { ptr in
      String(bytes: ptr, encoding: .utf8) ?? "(binary data)"
    }
    Button(action: onHide) {
      Text(value)
        .font(.system(.body, design: .monospaced))
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .lineSpacing(8)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }
    .textSelection(.enabled)
    .buttonStyle(RevealPlaceholderButtonStyle())
  }
}
