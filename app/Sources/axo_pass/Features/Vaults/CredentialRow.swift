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
  /// Assign (`true`) or clear (`false`) one of the credential's autofill roles:
  /// "username", "password", or "totp".
  let onSetRole: (_ role: String, _ assign: Bool) -> Void
  /// The field name a login card shows beside the value, such as "Password".
  /// Nil for a row in the item's credential list, which shows the credential's
  /// title and reference instead.
  var fieldLabel: String? = nil
  /// Another passkey on the item has the same site and account.
  var isDuplicatePasskey: Bool = false

  @State private var confirmingPasskeyDelete: Bool = false
  @State private var showingPasskeyDetails: Bool = false
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
      } else if let fieldLabel {
        fieldView(fieldLabel)
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
    .confirmationDialog(
      "Delete this passkey?", isPresented: $confirmingPasskeyDelete, titleVisibility: .visible
    ) {
      Button("Delete Passkey", role: .destructive, action: onDelete)
      Button("Cancel", role: .cancel) {}
    } message: {
      Text(
        "\(cred.passkey?.rpId ?? "The site") still lists this passkey until you remove it there. You will not be able to sign in with it again."
      )
    }
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

  // MARK: - Roles

  /// Context menu of a login card row. Rows in the item outline get their menu
  /// from the outline instead.
  @ViewBuilder
  private var cardMenu: some View {
    roleMenu
    if isPasskey {
      Button("Move to…", action: onMove)
      Button("Delete…", role: .destructive) { confirmingPasskeyDelete = true }
    }
    Divider()
    Button("Copy Reference", action: copyReference)
  }

  /// The autofill roles this credential can take. A one-time code credential can
  /// only be the code source, and a passkey takes no role.
  @ViewBuilder
  private var roleMenu: some View {
    switch cred.kind.kind {
    case "passkey", "unknown":
      EmptyView()
    case "totp":
      roleButton("totp", assign: "Use for one-time code", clear: "Stop using for one-time code")
    default:
      roleButton("username", assign: "Use as username", clear: "Stop using as username")
      roleButton("password", assign: "Use as password", clear: "Stop using as password")
    }
  }

  @ViewBuilder
  private func roleButton(_ role: String, assign: String, clear: String) -> some View {
    if cred.role == role {
      Button(clear) { onSetRole(role, false) }
    } else {
      Button(assign) { onSetRole(role, true) }
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

  private func copyReference() {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(reference, forType: .string)
    justCopiedReference = true
    Task {
      try? await Task.sleep(for: .seconds(1.2))
      justCopiedReference = false
    }
  }

  private var referenceButton: some View {
    Button(action: copyReference) {
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
        .task(id: "\(vaultKey)/\(itemKey)/\(cred.key)") {
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

  /// One line: the account, when it was created, and a details popover. The
  /// fields come from the item listing, so showing a passkey never decrypts
  /// its private key into the app.
  private var passkeyView: some View {
    HStack(alignment: .firstTextBaseline, spacing: 12) {
      LoginFieldLabel(fieldLabel ?? "Passkey")
      HStack(alignment: .firstTextBaseline, spacing: 6) {
        Image(systemName: "person.badge.key.fill")
          .foregroundStyle(.tint)
        Text(passkeyAccount)
          .lineLimit(1)
          .truncationMode(.middle)
        if let subtitle = passkeySubtitle {
          Text(subtitle)
            .foregroundStyle(.secondary)
            .lineLimit(1)
        }
        if isDuplicatePasskey {
          Text("Duplicate")
            .font(.caption.weight(.medium))
            .foregroundStyle(.orange)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(.orange.opacity(0.15), in: Capsule())
            .help(
              "Another passkey on this login has the same site and account. The site uses one of them, so the other is likely unused."
            )
        }
      }
      .frame(maxWidth: .infinity, alignment: .leading)

      Button {
        showingPasskeyDetails = true
      } label: {
        Label("Passkey Details", systemImage: "info.circle")
          .labelStyle(.iconOnly)
      }
      .buttonStyle(.borderless)
      .help("Passkey details")
      .popover(isPresented: $showingPasskeyDetails, arrowEdge: .trailing) {
        passkeyDetails
      }
    }
    .contentShape(.rect)
    .contextMenu { cardMenu }
  }

  private var passkeyDetails: some View {
    VStack(alignment: .leading, spacing: 12) {
      Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 6) {
        passkeyDetail("Site", cred.passkey?.rpId)
        passkeyDetail("Account", cred.passkey?.username)
        if cred.passkey?.userDisplayName != cred.passkey?.username {
          passkeyDetail("Name", cred.passkey?.userDisplayName)
        }
        passkeyDetail("Created", passkeyCreated)
        passkeyDetail("Credential ID", cred.passkey?.credentialId, monospaced: true)
        passkeyDetail("Reference", reference, monospaced: true)
      }
      if cred.passkey == nil {
        Text("The passkey record could not be read.")
          .font(.caption)
          .foregroundStyle(.red)
      }
      HStack {
        Button(justCopiedReference ? "Copied" : "Copy Reference", action: copyReference)
        Spacer()
        Button("Move to…") {
          showingPasskeyDetails = false
          onMove()
        }
        Button("Delete…", role: .destructive) {
          showingPasskeyDetails = false
          confirmingPasskeyDelete = true
        }
      }
      .controlSize(.small)
    }
    .padding(14)
    .frame(width: 360)
  }

  @ViewBuilder
  private func passkeyDetail(_ label: String, _ value: String?, monospaced: Bool = false)
    -> some View
  {
    if let value, !value.isEmpty {
      GridRow {
        Text(label)
          .foregroundStyle(.secondary)
          .gridColumnAlignment(.trailing)
        Text(value)
          .font(monospaced ? .system(.callout, design: .monospaced) : .callout)
          .textSelection(.enabled)
          .lineLimit(1)
          .truncationMode(.middle)
      }
    }
  }

  /// The account the passkey signs in as, falling back to the credential
  /// title for a record that names none.
  private var passkeyAccount: String {
    let info = cred.passkey
    for name in [info?.userDisplayName, info?.username] {
      if let name, !name.isEmpty { return name }
    }
    return cred.title
  }

  /// When the passkey was created, or its site for a record that predates
  /// creation times.
  private var passkeySubtitle: String? {
    if let created = passkeyCreated { return "Created \(created)" }
    return cred.passkey?.rpId
  }

  private var passkeyCreated: String? {
    guard let createdAt = cred.passkey?.createdAt else { return nil }
    return Date(timeIntervalSince1970: TimeInterval(createdAt))
      .formatted(date: .abbreviated, time: .omitted)
  }

  // MARK: - Login field

  /// A login card row: the field name, the value, and actions that appear on
  /// hover. A one-time code shows the live code instead of its secret.
  private func fieldView(_ label: String) -> some View {
    HStack(alignment: quickEditing ? .center : .firstTextBaseline, spacing: 12) {
      LoginFieldLabel(label)
      if cred.kind.kind == "totp" {
        TotpCodeValue(vaultKey: vaultKey, itemKey: itemKey, credKey: cred.key)
      } else if quickEditing {
        quickEditor
        HStack(spacing: 4) {
          Button("Cancel") { cancelQuickEdit() }
          Button("Save") { commitQuickEdit() }
            .keyboardShortcut(.defaultAction)
            .disabled(quickDraft.isEmpty || quickDraft == quickOriginal)
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
      } else {
        fieldValue
        fieldActions
      }
    }
    .contentShape(.rect)
    .contextMenu { cardMenu }
    .onHover { hoveringValue = $0 }
    .animation(.easeInOut(duration: 0.12), value: hoveringValue)
    .animation(.easeInOut(duration: 0.12), value: justCopied)
  }

  private var fieldValue: some View {
    let concealed = cred.kind.concealed
    let shown = revealedText ?? (concealed ? "••••••••" : " ")
    return Text(shown)
      .font(.system(.body, design: .monospaced))
      .foregroundStyle(revealedText == nil ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.primary))
      .textSelection(.enabled)
      .lineLimit(1)
      .truncationMode(.tail)
      .frame(maxWidth: .infinity, alignment: .leading)
      .task(id: "\(vaultKey)/\(itemKey)/\(cred.key)") {
        // A plain value shows without a click; a concealed one waits for one.
        if !concealed, secret == nil, !isRevealing { onReveal() }
      }
  }

  /// The actions stay in the layout while hidden, so the row keeps the same
  /// height whether or not the pointer is over it.
  private var fieldActions: some View {
    let visible =
      justCopied || isRevealing || hoveringValue || (cred.kind.concealed && secret != nil)
    return
      fieldActionButtons
      .opacity(visible ? 1 : 0)
      .allowsHitTesting(visible)
  }

  /// The buttons always lay out so the row height is constant. The copy
  /// confirmation and the revealing spinner overlay them.
  private var fieldActionButtons: some View {
    let busy = justCopied || isRevealing
    return HStack(spacing: 4) {
      if cred.kind.concealed {
        Button {
          secret == nil ? onReveal() : onHide()
        } label: {
          Label(
            secret == nil ? "Show" : "Hide",
            systemImage: secret == nil ? "eye" : "eye.slash"
          )
          .labelStyle(.iconOnly)
        }
        .help(secret == nil ? "Show" : "Hide")
      }
      Button {
        beginQuickEdit()
      } label: {
        Label("Edit Value", systemImage: "pencil")
          .labelStyle(.iconOnly)
      }
      .help("Edit value")
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
    .opacity(busy ? 0 : 1)
    .overlay {
      if justCopied {
        Image(systemName: "checkmark").foregroundStyle(.green)
      } else if isRevealing {
        ProgressView().controlSize(.small)
      }
    }
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

/// Width of the field name column in the login card.
let loginFieldLabelWidth: CGFloat = 84

/// The field name column of a login card row.
struct LoginFieldLabel: View {
  let text: String

  init(_ text: String) { self.text = text }

  var body: some View {
    Text(text)
      .foregroundStyle(.secondary)
      .lineLimit(1)
      .frame(width: loginFieldLabelWidth, alignment: .leading)
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
