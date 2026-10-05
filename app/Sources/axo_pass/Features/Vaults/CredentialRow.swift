import AxoPassFFI
import CryptoKit
import SwiftUI

struct CredentialRow: View {
  /// Credential field being renamed in place.
  enum RenameField {
    case title, key
  }

  let cred: CredentialInfo
  /// Vault and item this credential belongs to, for its `axo://` reference.
  let vaultKey: String
  let itemKey: String
  let secret: SymmetricKey?
  let error: String?
  let isRevealing: Bool
  /// The field being renamed, or nil.
  let renaming: RenameField?
  let onReveal: () -> Void
  let onHide: () -> Void
  let onCopy: () async -> Bool
  /// Save a renamed field. Text is trimmed and non-empty.
  let onRename: (_ field: RenameField, _ text: String) -> Void
  let onCancelRename: () -> Void
  /// Save a new value for this credential, keeping its title, key and kind.
  let onQuickSaveValue: (_ value: String) -> Void
  /// Delete this passkey after confirmation. Only passkey rows offer it.
  let onDelete: () -> Void
  /// Move this passkey to another item or vault. Only passkey rows offer it.
  let onMove: () -> Void

  @State private var confirmingPasskeyDelete: Bool = false
  @State private var hoveringValue: Bool = false
  @State private var justCopied: Bool = false
  @State private var hoveringReference: Bool = false
  @State private var justCopiedReference: Bool = false

  // Value-only inline edit.
  @State private var quickEditing: Bool = false
  @State private var quickDraft: String = ""
  // The value the quick editor opened with, used to disable Save until it
  // actually changes. Nil until the secret is revealed.
  @State private var quickOriginal: String? = nil

  /// Passkeys are shown read only: their value is a structured record the
  /// authenticator owns, not free text to edit.
  private var isPasskey: Bool { cred.kind.kind == "passkey" }

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      if isPasskey {
        passkeyView
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
    .onChange(of: revealedText) { _, _ in
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
          if renaming == .title {
            InlineRenameField(
              initial: cred.title, placeholder: "Title",
              onCommit: { onRename(.title, $0) }, onCancel: onCancelRename
            )
            .fontWeight(.semibold)
          } else {
            Text(cred.title).fontWeight(.semibold)
          }
          if renaming == .key {
            HStack(spacing: 0) {
              Text(referencePrefix).foregroundStyle(.secondary)
              InlineRenameField(
                initial: cred.key, placeholder: "id",
                onCommit: { onRename(.key, $0) }, onCancel: onCancelRename)
            }
            .font(.subheadline)
          } else {
            referenceLabel
          }
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

  // MARK: - Passkey

  private var passkeyView: some View {
    VStack(alignment: .leading, spacing: 8) {
      HStack(alignment: .firstTextBaseline, spacing: 6) {
        Image(systemName: "person.badge.key.fill")
          .foregroundStyle(.tint)
        VStack(alignment: .leading, spacing: 2) {
          Text(cred.title).fontWeight(.semibold)
          referenceLabel
        }
      }

      VStack(alignment: .leading, spacing: 4) {
        passkeyRow("Site", passkeyRecord?.rpId)
        passkeyRow("Account", passkeyRecord?.displayAccount)
        passkeyRow("Credential ID", passkeyRecord?.credentialId)
      }
      .padding(.vertical, 6)
      .padding(.horizontal, 8)
      .frame(maxWidth: .infinity, alignment: .leading)
      .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      .task(id: cred.key) {
        if secret == nil, !isRevealing { onReveal() }
      }

      HStack(spacing: 8) {
        Button("Move to…", action: onMove)
        Button("Delete…", role: .destructive) { confirmingPasskeyDelete = true }
      }
      .buttonStyle(.bordered)
      .controlSize(.small)
    }
    .confirmationDialog(
      "Delete this passkey?", isPresented: $confirmingPasskeyDelete, titleVisibility: .visible
    ) {
      Button("Delete Passkey", role: .destructive, action: onDelete)
      Button("Cancel", role: .cancel) {}
    } message: {
      Text(
        "\(passkeyRecord?.rpId ?? "The site") still lists this passkey until you remove it there. You will not be able to sign in with it again."
      )
    }
  }

  @ViewBuilder
  private func passkeyRow(_ label: String, _ value: String?) -> some View {
    if let value, !value.isEmpty {
      HStack(alignment: .firstTextBaseline, spacing: 8) {
        Text(label)
          .font(.caption)
          .foregroundStyle(.secondary)
          .frame(width: 96, alignment: .leading)
        Text(value)
          .font(.system(.callout, design: .monospaced))
          .textSelection(.enabled)
          .lineLimit(1)
          .truncationMode(.middle)
      }
    }
  }

  private var passkeyRecord: PasskeyRecord? {
    guard let json = revealedText, let data = json.data(using: .utf8) else { return nil }
    return try? JSONDecoder().decode(PasskeyRecord.self, from: data)
  }

  // MARK: - Helpers

  /// The reference `ap exec` and `ap inject` resolve for this credential.
  private var reference: String {
    referencePrefix + cred.key
  }

  /// Reference prefix before the credential key. Shown beside the key during
  /// rename.
  private var referencePrefix: String {
    "axo://\(vaultKey)/\(itemKey)/"
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
}

/// The stored passkey record, decoded for the read-only detail view. Mirrors
/// `StoredRecord` in crates/core/src/secrets/vaults/passkey.rs.
struct PasskeyRecord: Decodable {
  let rpId: String
  let credentialId: String
  let username: String?
  let userDisplayName: String?

  var displayAccount: String? {
    userDisplayName?.isEmpty == false ? userDisplayName : username
  }

  enum CodingKeys: String, CodingKey {
    case rpId = "rp_id"
    case credentialId = "credential_id"
    case username
    case userDisplayName = "user_display_name"
  }
}

/// Text field that replaces a label during rename, as in Finder. Takes focus on
/// appear. Return or clicking away commits. Escape cancels. Sized to its text,
/// so the rest of the row can still be selected and dragged.
struct InlineRenameField: View {
  let initial: String
  let placeholder: String
  /// Called with the trimmed text when it is not empty. The text may equal
  /// `initial`.
  let onCommit: (String) -> Void
  /// Called on Escape or on commit with empty text.
  let onCancel: () -> Void

  @State private var text: String
  @State private var finished = false
  @FocusState private var focused: Bool

  init(
    initial: String, placeholder: String, onCommit: @escaping (String) -> Void,
    onCancel: @escaping () -> Void
  ) {
    self.initial = initial
    self.placeholder = placeholder
    self.onCommit = onCommit
    self.onCancel = onCancel
    _text = State(initialValue: initial)
  }

  var body: some View {
    TextField(placeholder, text: $text)
      .textFieldStyle(.plain)
      .focused($focused)
      .autoWidth(text.isEmpty ? placeholder : text)
      .padding(.horizontal, 3)
      .background(.background, in: RoundedRectangle(cornerRadius: 3))
      .overlay(RoundedRectangle(cornerRadius: 3).strokeBorder(.tint, lineWidth: 1))
      .padding(.horizontal, -3)
      .onSubmit { finish(commit: true) }
      .onExitCommand { finish(commit: false) }
      .onChange(of: focused) { _, isFocused in
        if !isFocused { finish(commit: true) }
      }
      .task {
        // Wait for the field to reach the window before focusing it.
        await Task.yield()
        focused = true
      }
  }

  private func finish(commit: Bool) {
    guard !finished else { return }
    finished = true
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    if commit, !trimmed.isEmpty {
      onCommit(trimmed)
    } else {
      onCancel()
    }
  }
}

extension View {
  /// Size a text field to `text` rather than the full row width.
  func autoWidth(_ text: String) -> some View {
    Text(text)
      .lineLimit(1)
      .padding(.trailing, 8)
      .hidden()
      .overlay(alignment: .leading) { self }
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
