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
  let onSave: (_ key: String, _ title: String, _ value: String) -> Void
  let onDelete: () -> Void

  @State private var draftTitle: String = ""
  @State private var draftKey: String = ""
  @State private var draftValue: String = ""
  // The value at the moment editing began. Nil when the secret could not be
  // revealed, in which case the value cannot be resubmitted and no edit saves.
  @State private var originalValue: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      if isEditing {
        editForm
      } else {
        readView
      }
      if let err = error {
        Text(err).font(.caption).foregroundStyle(.red)
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(.vertical, 2)
    .padding(.horizontal, 6)
    .onChange(of: isEditing) { wasEditing, editing in
      if editing {
        resetDrafts()
      } else if wasEditing {
        commitIfChanged()
      }
    }
    .onChange(of: revealedText) { _, _ in
      if isEditing, originalValue == nil {
        originalValue = revealedText
        draftValue = revealedText ?? ""
      }
    }
  }

  // MARK: - Read

  private var readView: some View {
    VStack(alignment: .leading, spacing: 8) {
      VStack(alignment: .leading, spacing: 2) {
        Text(cred.title).fontWeight(.semibold)
        Text(cred.key).font(.caption).foregroundStyle(.secondary)
      }
      .frame(maxWidth: .infinity, alignment: .leading)

      HStack(spacing: 6) {
        SecretBox(revealed: revealedText, onToggle: { secret == nil ? onReveal() : onHide() })
        if isRevealing {
          ProgressView().controlSize(.small)
        } else if secret != nil {
          Button("Copy", action: onCopy).buttonStyle(.bordered).controlSize(.small)
        }
      }
    }
  }

  // MARK: - Edit

  private var editForm: some View {
    VStack(alignment: .leading, spacing: 2) {
      TextField("Title", text: $draftTitle)
        .textFieldStyle(.plain)
        .font(.body)
        .fontWeight(.semibold)

      TextField("ID", text: $draftKey)
        .textFieldStyle(.plain)
        .font(.body)
        .foregroundStyle(.secondary)

      Group {
        if originalValue == nil {
          Text(isRevealing ? "Revealing…" : "Value unavailable")
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
          TextField("Value", text: $draftValue, axis: .vertical)
            .textFieldStyle(.plain)
            .lineLimit(1...5)
        }
      }
      .font(.system(.body, design: .monospaced))
      .padding(.vertical, 6)
      .padding(.horizontal, 8)
      .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      .overlay(
        RoundedRectangle(cornerRadius: 6)
          .strokeBorder(.separator, lineWidth: 1)
      )
      .padding(.top, 6)

      Button("Delete", role: .destructive, action: onDelete)
        .buttonStyle(.bordered)
        .controlSize(.small)
        .padding(.top, 8)
    }
  }

  // MARK: - Helpers

  private var revealedText: String? {
    guard let secret else { return nil }
    return secret.withUnsafeBytes { String(bytes: $0, encoding: .utf8) ?? "(binary data)" }
  }

  private func resetDrafts() {
    draftTitle = cred.title
    draftKey = cred.key
    originalValue = revealedText
    draftValue = revealedText ?? ""
  }

  private func commitIfChanged() {
    let newTitle = draftTitle.trimmingCharacters(in: .whitespacesAndNewlines)
    let newKey = draftKey.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !newTitle.isEmpty, !newKey.isEmpty else { return }

    let valueChanged = originalValue != nil && draftValue != originalValue
    guard newTitle != cred.title || newKey != cred.key || valueChanged else { return }

    // The FFI resubmits title and value together, so a save needs the value.
    guard let value = valueChanged ? draftValue : originalValue else { return }
    onSave(newKey, newTitle, value)
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
