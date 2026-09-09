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
  let onCopy: () async -> Bool
  let onSave: (_ key: String, _ title: String, _ value: String, _ kind: FieldKindInfo?) -> Void
  let onDelete: () -> Void

  @State private var draftTitle: String = ""
  @State private var draftKey: String = ""
  @State private var draftValue: String = ""
  @State private var draftConcealed: Bool = true
  @State private var draftMultiline: Bool = false
  @State private var hoveringValue: Bool = false
  @State private var justCopied: Bool = false
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

      valueBox
        .overlay(alignment: .topTrailing) { copyOverlay }
        .onHover { hoveringValue = $0 }
        .animation(.easeInOut(duration: 0.12), value: hoveringValue)
        .animation(.easeInOut(duration: 0.12), value: justCopied)
    }
  }

  @ViewBuilder
  private var valueBox: some View {
    if cred.kind.concealed {
      SecretBox(revealed: revealedText, onToggle: { secret == nil ? onReveal() : onHide() })
    } else {
      // A plain-text field shows its value directly. The secret is still
      // fetched lazily, so request it the first time the row appears.
      Text(revealedText ?? " ")
        .font(.system(.body, design: .monospaced))
        .foregroundStyle(revealedText == nil ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.primary))
        .textSelection(.enabled)
        .lineSpacing(8)
        .padding(.vertical, 6)
        .padding(.horizontal, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        .task(id: cred.key) {
          if secret == nil, !isRevealing { onReveal() }
        }
    }
  }

  @ViewBuilder
  private var copyOverlay: some View {
    if justCopied {
      Label("Copied", systemImage: "checkmark")
        .labelStyle(.iconOnly)
        .foregroundStyle(.green)
        .controlSize(.small)
        .padding(8)
        .transition(.opacity)
    } else if isRevealing {
      ProgressView().controlSize(.small).padding(6)
    } else if hoveringValue {
      // Copy works before the value is revealed; the handler fetches it first.
      Button("Copy") {
        Task {
          if await onCopy() {
            justCopied = true
            try? await Task.sleep(for: .seconds(1.2))
            justCopied = false
          }
        }
      }
      .buttonStyle(.bordered)
      .controlSize(.small)
      .padding(6)
      .transition(.opacity)
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
            .lineLimit(draftMultiline ? 3...12 : 1...1)
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

      if supportsTextOptions {
        HStack(spacing: 16) {
          Toggle("Concealed", isOn: $draftConcealed)
          Toggle("Multiline", isOn: $draftMultiline)
        }
        .toggleStyle(.checkbox)
        .controlSize(.small)
        .padding(.top, 6)
      }

      Button("Delete", role: .destructive, action: onDelete)
        .buttonStyle(.bordered)
        .controlSize(.small)
        .padding(.top, 8)
    }
  }

  // MARK: - Helpers

  /// Concealed and multiline apply only to freeform text credentials. Other
  /// kinds (email, totp, unknown, ...) hide the toggles.
  private var supportsTextOptions: Bool {
    cred.kind.kind == "text"
  }

  private var revealedText: String? {
    guard let secret else { return nil }
    return secret.withUnsafeBytes { String(bytes: $0, encoding: .utf8) ?? "(binary data)" }
  }

  private func resetDrafts() {
    draftTitle = cred.title
    draftKey = cred.key
    draftConcealed = cred.kind.concealed
    draftMultiline = cred.kind.multiline
    originalValue = revealedText
    draftValue = revealedText ?? ""
  }

  private func commitIfChanged() {
    let newTitle = draftTitle.trimmingCharacters(in: .whitespacesAndNewlines)
    let newKey = draftKey.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !newTitle.isEmpty, !newKey.isEmpty else { return }

    let valueChanged = originalValue != nil && draftValue != originalValue
    let kindChanged =
      supportsTextOptions
      && (draftConcealed != cred.kind.concealed || draftMultiline != cred.kind.multiline)
    guard newTitle != cred.title || newKey != cred.key || valueChanged || kindChanged else { return }

    // The FFI resubmits title and value together, so a save needs the value.
    guard let value = valueChanged ? draftValue : originalValue else { return }
    let kind: FieldKindInfo? =
      supportsTextOptions
      ? FieldKindInfo(kind: "text", concealed: draftConcealed, multiline: draftMultiline)
      : nil
    onSave(newKey, newTitle, value, kind)
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
