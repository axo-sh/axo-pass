import AxoPassFFI
import CryptoKit
import SwiftUI

struct CredentialRow: View {
  let cred: CredentialInfo
  /// Vault and item this credential belongs to, for its `axo://` reference.
  let vaultKey: String
  let itemKey: String
  let secret: SymmetricKey?
  let error: String?
  let isRevealing: Bool
  let isEditing: Bool
  let onReveal: () -> Void
  let onHide: () -> Void
  let onCopy: () async -> Bool
  let onSave: (_ key: String, _ title: String, _ value: String, _ kind: FieldKindInfo?) -> Void
  /// Save a new value for this credential, keeping its title, key and kind.
  let onQuickSaveValue: (_ value: String) -> Void
  let onDelete: () -> Void

  @State private var draftTitle: String = ""
  @State private var draftKey: String = ""
  @State private var draftValue: String = ""
  @State private var draftConcealed: Bool = true
  @State private var draftMultiline: Bool = false
  @State private var hoveringValue: Bool = false
  @State private var justCopied: Bool = false
  @State private var hoveringReference: Bool = false
  @State private var justCopiedReference: Bool = false
  // The value at the moment editing began. Nil when the secret could not be
  // revealed, in which case the value cannot be resubmitted and no edit saves.
  @State private var originalValue: String? = nil

  // Value-only inline edit, available outside the pane's Edit mode.
  @State private var quickEditing: Bool = false
  @State private var quickDraft: String = ""
  // The value the quick editor opened with, used to disable Save until it
  // actually changes. Nil until the secret is revealed.
  @State private var quickOriginal: String? = nil

  // Which edit-mode field the pointer is over, for the hover background.
  @State private var hoveredField: EditField? = nil

  private enum EditField {
    case title, key, value
  }

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
    // Seeds the drafts both when the pane enters edit mode and when a row is
    // built while it is already editing. List creates rows lazily, so a row that
    // did not exist at the moment Edit was pressed never sees that transition.
    .task(id: isEditing) {
      guard isEditing else { return }
      resetDrafts()
      cancelQuickEdit()
    }
    .onChange(of: isEditing) { wasEditing, editing in
      if !editing, wasEditing {
        commitIfChanged()
      }
    }
    .onChange(of: revealedText) { _, _ in
      if isEditing, originalValue == nil {
        originalValue = revealedText
        draftValue = revealedText ?? ""
      }
      // A quick edit opened before the reveal landed records the original as
      // soon as it arrives, whether or not the user has started typing.
      if quickEditing, quickOriginal == nil, let revealed = revealedText {
        quickOriginal = revealed
        if quickDraft.isEmpty {
          quickDraft = revealed
        }
      }
    }
  }

  // MARK: - Read

  private var readView: some View {
    VStack(alignment: .leading, spacing: 8) {
      HStack(alignment: .firstTextBaseline) {
        VStack(alignment: .leading, spacing: 2) {
          Text(cred.title).fontWeight(.semibold)
          referenceLabel
        }
        .frame(maxWidth: .infinity, alignment: .leading)

        if quickEditing {
          Button("Cancel") { cancelQuickEdit() }
            .controlSize(.small)
          Button("Save") { commitQuickEdit() }
            .controlSize(.small)
            .keyboardShortcut(.defaultAction)
            .disabled(quickDraft.isEmpty || quickDraft == quickOriginal)
        }
      }

      if quickEditing {
        quickEditor
      } else {
        valueBox
          .overlay(alignment: .topTrailing) { valueOverlay }
          .onHover { hoveringValue = $0 }
          .animation(.easeInOut(duration: 0.12), value: hoveringValue)
          .animation(.easeInOut(duration: 0.12), value: justCopied)
      }
    }
  }

  /// The credential's `axo://` reference. Clicking it copies it. The trailing
  /// spacer keeps the button's hit area on the text rather than the whole row.
  private var referenceLabel: some View {
    HStack(spacing: 0) {
      referenceButton
      Spacer(minLength: 0)
    }
  }

  private var referenceButton: some View {
    Button {
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(reference, forType: .string)
      justCopiedReference = true
      Task {
        try? await Task.sleep(for: .seconds(1.2))
        justCopiedReference = false
      }
    } label: {
      Text(reference)
        .font(.subheadline)
        .foregroundStyle(referenceColor)
        .lineLimit(1)
        .truncationMode(.middle)
        .contentShape(.rect)
    }
    .buttonStyle(.plain)
    .pointerStyle(.link)
    .help("Copy reference")
    .onHover { hoveringReference = $0 }
    .animation(.easeInOut(duration: 0.12), value: hoveringReference)
    // Slower than the hover fade so the confirmation eases in and back out
    // rather than snapping.
    .animation(.easeInOut(duration: 0.35), value: justCopiedReference)
  }

  private var referenceColor: Color {
    if justCopiedReference { return Color.green.opacity(0.7) }
    return hoveringReference ? .primary : .secondary
  }

  @ViewBuilder
  private var valueBox: some View {
    if cred.kind.concealed {
      SecretBox(
        revealed: revealedText,
        lineLimit: valueLineLimit,
        onToggle: { secret == nil ? onReveal() : onHide() }
      )
    } else {
      // A plain-text field shows its value directly. The secret is still
      // fetched lazily, so request it the first time the row appears.
      Text(revealedText ?? " ")
        .font(.system(.body, design: .monospaced))
        .foregroundStyle(revealedText == nil ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.primary))
        .textSelection(.enabled)
        .lineSpacing(8)
        .lineLimit(valueLineLimit)
        .truncationMode(.tail)
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
  private var quickEditor: some View {
    Group {
      if revealedText == nil {
        Text(isRevealing ? "Revealing…" : "Value unavailable")
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity, alignment: .leading)
      } else {
        ValueTextEditor(
          text: $quickDraft,
          placeholder: "Value",
          multiline: cred.kind.multiline,
          minLines: 3,
          maxLines: 12)
      }
    }
    .font(.system(.body, design: .monospaced))
    .padding(.vertical, 6)
    .padding(.horizontal, 8)
    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    .overlay(
      RoundedRectangle(cornerRadius: 6)
        .strokeBorder(.tint, lineWidth: 2)
    )
  }

  @ViewBuilder
  private var valueOverlay: some View {
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
      HStack(spacing: 4) {
        Button {
          beginQuickEdit()
        } label: {
          Label("Edit Value", systemImage: "pencil")
            .labelStyle(.iconOnly)
        }
        .help("Edit value")

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
        .editableFieldBackground(active: hoveredField == .title)
        .onHover { hoveredField = $0 ? .title : (hoveredField == .title ? nil : hoveredField) }

      TextField("ID", text: $draftKey)
        .textFieldStyle(.plain)
        .font(.body)
        .foregroundStyle(.secondary)
        .editableFieldBackground(active: hoveredField == .key)
        .onHover { hoveredField = $0 ? .key : (hoveredField == .key ? nil : hoveredField) }

      Group {
        if originalValue == nil {
          Text(isRevealing ? "Revealing…" : "Value unavailable")
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
          ValueTextEditor(
            text: $draftValue,
            placeholder: "Value",
            multiline: draftMultiline,
            minLines: 3,
            maxLines: 12)
        }
      }
      .font(.system(.body, design: .monospaced))
      .padding(.vertical, 6)
      .padding(.horizontal, 8)
      .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      .overlay(
        RoundedRectangle(cornerRadius: 6)
          .strokeBorder(
            hoveredField == .value ? AnyShapeStyle(.tint) : AnyShapeStyle(.separator),
            lineWidth: 1)
      )
      .padding(.top, 6)
      .onHover { hoveredField = $0 ? .value : (hoveredField == .value ? nil : hoveredField) }

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
    .animation(.easeInOut(duration: 0.12), value: hoveredField)
  }

  // MARK: - Helpers

  /// The reference `ap exec` and `ap inject` resolve for this credential.
  private var reference: String {
    "axo://\(vaultKey)/\(itemKey)/\(cred.key)"
  }

  /// Concealed and multiline apply only to freeform text credentials. Other
  /// kinds (email, totp, unknown, ...) hide the toggles.
  private var supportsTextOptions: Bool {
    cred.kind.kind == "text"
  }

  /// Lines the value gets in the read view. A multiline credential grows to fit
  /// its content; a single-line one stays on one line and truncates.
  private var valueLineLimit: Int? {
    cred.kind.multiline ? nil : 1
  }

  private var revealedText: String? {
    guard let secret else { return nil }
    return secret.withUnsafeBytes { String(bytes: $0, encoding: .utf8) ?? "(binary data)" }
  }

  private func beginQuickEdit() {
    quickOriginal = revealedText
    quickDraft = revealedText ?? ""
    if revealedText == nil {
      onReveal()
    }
    quickEditing = true
  }

  private func cancelQuickEdit() {
    quickEditing = false
    quickDraft = ""
    quickOriginal = nil
  }

  private func commitQuickEdit() {
    let value = quickDraft
    guard !value.isEmpty, value != quickOriginal else {
      cancelQuickEdit()
      return
    }
    onQuickSaveValue(value)
    cancelQuickEdit()
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
    guard newTitle != cred.title || newKey != cred.key || valueChanged || kindChanged else {
      return
    }

    // The FFI resubmits title and value together, so a save needs the value.
    guard let value = valueChanged ? draftValue : originalValue else { return }
    let kind: FieldKindInfo? =
      supportsTextOptions
      ? FieldKindInfo(kind: "text", concealed: draftConcealed, multiline: draftMultiline)
      : nil
    onSave(newKey, newTitle, value, kind)
  }
}

/// A subtle rounded fill behind an edit-mode text field, shown while the pointer
/// is over it.
private struct EditableFieldBackground: ViewModifier {
  let active: Bool

  func body(content: Content) -> some View {
    content
      .padding(.vertical, 3)
      .padding(.horizontal, 4)
      .background(
        RoundedRectangle(cornerRadius: 4)
          .fill(.quaternary.opacity(active ? 1 : 0))
      )
      .animation(.easeInOut(duration: 0.12), value: active)
  }
}

extension View {
  fileprivate func editableFieldBackground(active: Bool) -> some View {
    modifier(EditableFieldBackground(active: active))
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
