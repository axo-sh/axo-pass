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
  /// Ask to delete this credential. Offered by login card rows. The credential
  /// list confirms.
  let onDelete: () -> Void
  /// Move this passkey to another item or vault. Only passkey rows offer it.
  let onMove: () -> Void
  /// Start renaming the title or id. Offered by login card rows. Outline rows
  /// start a rename from the outline menu.
  let onStartRename: (_ field: RenameField) -> Void
  /// Show previous values. Offered by login card rows.
  let onShowPreviousValues: () -> Void
  /// Assign (`true`) or clear (`false`) one of the credential's autofill roles:
  /// "username", "password", or "totp".
  let onSetRole: (_ role: String, _ assign: Bool) -> Void
  /// Why the contents of this file credential could not be read, if they could
  /// not. Only file rows show it.
  var fileFailure: FileFailure? = nil
  /// The contents of this file credential are being read or replaced.
  var isFileBusy: Bool = false
  /// Open the file in Quick Look. Only file rows offer it.
  var onPreviewFile: () -> Void = {}
  /// Save the file to disk. Only file rows offer it.
  var onSaveFile: () -> Void = {}
  /// Replace the file. Only file rows offer it.
  var onReplaceFile: () -> Void = {}
  /// Replace the file with a dropped file. Only file rows offer it.
  var onReplaceFileWith: (URL) -> Void = { _ in }
  /// The field name a login card shows beside the value, such as "Password".
  /// Nil for a row in the item's credential list, which shows the credential's
  /// title and reference instead.
  var fieldLabel: String? = nil
  /// A copy shortcut just copied this credential. The row shows the copy
  /// confirmation.
  var showsCopied: Bool = false
  /// Another passkey on the item has the same site and account.
  var isDuplicatePasskey: Bool = false

  @Environment(VaultsModel.self) private var model

  @State private var showingPasskeyDetails: Bool = false
  @State private var recentSignIns: [AuditLogRow] = []
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

  /// Sign-ins listed in the passkey details.
  private static let recentSignInCount: UInt32 = 5

  /// Passkeys are shown read only: their value is a structured record the
  /// authenticator owns, not free text to edit.
  private var isPasskey: Bool { cred.kind.kind == "passkey" }

  /// A file credential shows the file's details and actions. Its value is a
  /// record with the file key, so the row never reveals or copies it.
  private var isFile: Bool { cred.kind.kind == "file" }

  /// Copied by the Copy button or a copy shortcut.
  private var copied: Bool { justCopied || showsCopied }

  /// A login card row has its own context menu over the whole row, padding
  /// included, so the menu area matches the selection highlight and menu
  /// target outline.
  @ViewBuilder
  var body: some View {
    if fieldLabel != nil {
      content
        .padding(.vertical, 6)
        .contentShape(.rect)
        .contextMenu { cardMenu }
    } else {
      content
    }
  }

  private var content: some View {
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

  /// Context menu of a login card row, in the same order as the outline menu.
  /// Rows in the item outline get their menu from the outline instead. A
  /// passkey record is owned by the authenticator, so a passkey is not renamed
  /// and has no previous values.
  @ViewBuilder
  private var cardMenu: some View {
    if isPasskey {
      Button("Move to…", action: onMove)
      Divider()
      Button("Copy Reference", action: copyReference)
      Divider()
      Button("Delete…", role: .destructive, action: onDelete)
    } else {
      Button("Rename") { onStartRename(.title) }
      Button("Change Key") { onStartRename(.key) }
      Divider()
      Button("History…", action: onShowPreviousValues)
      Divider()
      roleMenu
      Divider()
      Button("Copy Reference", action: copyReference)
      Divider()
      Button("Delete…", role: .destructive, action: onDelete)
    }
  }

  /// The autofill roles this credential can take. A one-time code credential can
  /// only be the code source, and a passkey takes no role.
  @ViewBuilder
  private var roleMenu: some View {
    switch cred.kind.kind {
    case "passkey", "file", "unknown":
      EmptyView()
    case "totp":
      roleButton("totp", assign: "Use for One-Time Code", clear: "Stop Using for One-Time Code")
    default:
      roleButton("username", assign: "Use as Username", clear: "Stop Using as Username")
      roleButton("password", assign: "Use as Password", clear: "Stop Using as Password")
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
            .keyboardShortcut(.cancelAction)
          Button("Save") { commitQuickEdit() }
            .controlSize(.small)
            .keyboardShortcut(.defaultAction)
            .disabled(quickDraft.isEmpty || quickDraft == quickOriginal)
        }
      }

      if isFile {
        FileBox(
          file: cred.file, title: cred.title, failure: fileFailure, isBusy: isFileBusy,
          onPreview: onPreviewFile, onSave: onSaveFile, onReplace: onReplaceFile,
          onReplaceWith: onReplaceFileWith, onDelete: onDelete)
      } else if quickEditing {
        quickEditor
      } else {
        valueBox
          .overlay(alignment: .topTrailing) { valueOverlay }
          .onHover { hoveringValue = $0 }
          .animation(.easeInOut(duration: 0.12), value: hoveringValue)
          .animation(.easeInOut(duration: 0.12), value: copied)
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
    if copied {
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

  /// Account, creation date, and a disclosure chevron. Clicking the line
  /// expands the passkey details below it. The fields come from the item
  /// listing, so showing a passkey never decrypts its private key into the app.
  private var passkeyView: some View {
    VStack(alignment: .leading, spacing: 10) {
      Button {
        withAnimation(.easeInOut(duration: 0.15)) { showingPasskeyDetails.toggle() }
      } label: {
        passkeySummaryLine
      }
      .buttonStyle(.plain)
      .help(showingPasskeyDetails ? "Hide passkey details" : "Show passkey details")

      if showingPasskeyDetails {
        passkeyDetails
          .padding(.leading, loginFieldLabelWidth + 12)
          .padding(.bottom, 4)
          .transition(.opacity)
          .task(id: cred.passkey?.credentialId) {
            guard let credentialId = cred.passkey?.credentialId else {
              recentSignIns = []
              return
            }
            recentSignIns = await model.recentSignIns(
              passkeyCredentialId: credentialId, limit: Self.recentSignInCount)
          }
      }
    }
    .contentShape(.rect)
    .contextMenu { cardMenu }
  }

  private var passkeySummaryLine: some View {
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
        if cred.passkey?.siteRejected == true {
          PasskeyBadge(text: "Not accepted", color: .red)
            .help(
              "\(cred.passkey?.rpId ?? "The site") reported that it no longer accepts this passkey. It is not offered in AutoFill."
            )
        } else if isDuplicatePasskey {
          PasskeyBadge(text: "Duplicate", color: .orange)
            .help(
              "Another passkey on this login has the same site and account. The site uses one of them, so the other is likely unused."
            )
        }
        if cred.passkey?.suggestedName != nil {
          PasskeyBadge(text: "New name", color: .blue)
            .help("The site reported a new account name.")
        }
      }
      .frame(maxWidth: .infinity, alignment: .leading)

      Image(systemName: "chevron.right")
        .font(.caption.weight(.semibold))
        .foregroundStyle(.secondary)
        .rotationEffect(.degrees(showingPasskeyDetails ? 90 : 0))
        .frame(width: 10, height: 10)
    }
    .contentShape(.rect)
  }

  /// Passkey record fields, then the authenticator properties every Axo Pass
  /// passkey shares.
  private var passkeyDetails: some View {
    VStack(alignment: .leading, spacing: 12) {
      passkeyReports

      Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 6) {
        passkeyDetail("Site", cred.passkey?.rpId)
        passkeyDetail("Account", cred.passkey?.username)
        if cred.passkey?.userDisplayName != cred.passkey?.username {
          passkeyDetail("Name", cred.passkey?.userDisplayName)
        }
        passkeyDetail("Created", passkeyCreated)
        passkeyDetail("Last used", passkeyLastUsed ?? "Never")
        passkeyDetail("Credential ID", cred.passkey?.credentialId, monospaced: true)
        passkeyDetail("Reference", reference, monospaced: true)
      }
      if cred.passkey == nil {
        Text("The passkey record could not be read.")
          .font(.caption)
          .foregroundStyle(.red)
      }

      if !recentSignIns.isEmpty {
        Divider()
        signInTable
      }

      Divider()

      Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 6) {
        ForEach(passkeyProperties, id: \.label) { property in
          passkeyDetail(property.label, property.value, help: property.help)
        }
      }

      HStack {
        Button(justCopiedReference ? "Copied" : "Copy Reference", action: copyReference)
        Button("Move to…", action: onMove)
        Spacer()
        Button("Delete…", role: .destructive, action: onDelete)
      }
      .controlSize(.small)
    }
  }

  /// Recent sign-ins of the passkey from the audit log, newest first, with the
  /// client and the exact time.
  private var signInTable: some View {
    Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
      GridRow {
        columnHeader("Client")
        columnHeader("Signed in").gridColumnAlignment(.trailing)
      }
      Divider().gridCellColumns(2)
      ForEach(recentSignIns) { event in
        GridRow {
          Text(event.callerText)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.middle)
          Text(event.timeText)
            .foregroundStyle(.secondary)
        }
        .font(.callout)
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  private func columnHeader(_ text: String) -> some View {
    Text(text.uppercased())
      .font(.caption2)
      .fontWeight(.semibold)
      .foregroundStyle(.secondary)
  }

  /// Site reports about the passkey, with the actions that settle them.
  @ViewBuilder
  private var passkeyReports: some View {
    let site = cred.passkey?.rpId ?? "The site"
    if cred.passkey?.siteRejected == true {
      PasskeyNotice(
        systemImage: "exclamationmark.triangle.fill", color: .red,
        message:
          "\(site) reported that it no longer accepts this passkey, so it is not offered in AutoFill. It may have been removed from your account there."
      ) {
        Button("Keep") { dismissReport(.rejection) }
          .help("Keep this passkey and offer it in AutoFill again")
        Button("Delete…", role: .destructive, action: onDelete)
      }
    }
    if let name = cred.passkey?.suggestedName {
      PasskeyNotice(
        systemImage: "person.text.rectangle", color: .blue,
        message: "\(site) reported a new account name: \(name)."
      ) {
        Button("Ignore") { dismissReport(.rename) }
        Button("Use New Name") {
          let (vaultKey, itemKey, credKey) = (vaultKey, itemKey, cred.key)
          Task {
            await model.applyPasskeyName(
              vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, name: name)
          }
        }
      }
    }
  }

  private func dismissReport(_ kind: PasskeyReportKind) {
    let (vaultKey, itemKey, credKey) = (vaultKey, itemKey, cred.key)
    Task {
      await model.dismissPasskeyReport(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, kind: kind)
    }
  }

  /// Authenticator property of a passkey, with an explanation shown on hover.
  private struct PasskeyProperty {
    let label: String
    let value: String
    let help: String
  }

  /// Properties of the Axo Pass authenticator. PRF support is read from the
  /// record. The rest are the same for every passkey it creates. The
  /// authenticator supports ES256 only, sets the UP, UV, BE, and BS flags, and
  /// returns "none" attestation.
  private var passkeyProperties: [PasskeyProperty] {
    let prf = cred.passkey?.prf == true
    return [
      PasskeyProperty(
        label: "Storage",
        value: "Software key in this vault",
        help:
          "The private key is encrypted with the rest of the vault. It is not bound to the Secure Enclave or a security key."
      ),
      PasskeyProperty(
        label: "Copyable",
        value: "Yes",
        help:
          "The passkey is included in vault exports and bundles, and can be moved to another item or vault."
      ),
      PasskeyProperty(
        label: "Syncable",
        value: "Yes",
        help:
          "Sites see the backup eligible and backed up flags, so they treat this passkey as synced rather than device-bound."
      ),
      PasskeyProperty(
        label: "User presence",
        value: "Yes",
        help: "Each use is approved in Axo Pass, and sites see the user present flag."
      ),
      PasskeyProperty(
        label: "User verified",
        value: "Yes",
        help:
          "Each use requires the vault unlock approval, and sites see the user verified flag."
      ),
      PasskeyProperty(
        label: "Attestation",
        value: "None",
        help:
          "Sites receive no attestation statement. The Axo Pass AAGUID is sent but is not signed, so sites cannot verify it."
      ),
      PasskeyProperty(
        label: "Algorithm",
        value: "ES256 (P-256)",
        help: "ECDSA over the P-256 curve with SHA-256."
      ),
      PasskeyProperty(
        label: "PRF",
        value: prf ? "Supported" : "Not supported",
        help: prf
          ? "Sites can derive encryption keys from this passkey with the WebAuthn PRF extension, after user verification."
          : "This passkey was created before Axo Pass supported the WebAuthn PRF extension. Create a new passkey on the site to use PRF."
      ),
    ]
  }

  @ViewBuilder
  private func passkeyDetail(
    _ label: String, _ value: String?, monospaced: Bool = false, help: String? = nil
  ) -> some View {
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
          .help(help ?? "")
      }
      .font(.callout)
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

  /// When the passkey was last used, or when it was created, or its site for a
  /// record that predates creation times.
  private var passkeySubtitle: String? {
    if let lastUsed = lastUsedDay {
      let calendar = Calendar.current
      if calendar.isDateInToday(lastUsed) { return "Used today" }
      if calendar.isDateInYesterday(lastUsed) { return "Used yesterday" }
      return "Used \(lastUsed.formatted(date: .abbreviated, time: .omitted))"
    }
    if let created = passkeyCreated { return "Created \(created)" }
    return cred.passkey?.rpId
  }

  private var passkeyCreated: String? {
    guard let createdAt = cred.passkey?.createdAt else { return nil }
    return Date(timeIntervalSince1970: TimeInterval(createdAt))
      .formatted(date: .abbreviated, time: .omitted)
  }

  private var passkeyLastUsed: String? {
    lastUsedDay?.formatted(date: .abbreviated, time: .omitted)
  }

  /// Time on the day of the last use. Only the day is meaningful.
  private var lastUsedDay: Date? {
    cred.lastUsedDayAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }
  }

  // MARK: - Login field

  /// A login card row: the field name, the value, and actions that appear on
  /// hover. A one-time code shows the live code instead of its secret. A rename
  /// shows on its own line below.
  private func fieldView(_ label: String) -> some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack(alignment: quickEditing ? .center : .firstTextBaseline, spacing: 12) {
        LoginFieldLabel(label)
        if cred.kind.kind == "totp" {
          TotpCodeValue(
            vaultKey: vaultKey, itemKey: itemKey, credKey: cred.key, showsCopied: showsCopied)
        } else if quickEditing {
          quickEditor
          HStack(spacing: 4) {
            Button("Cancel") { cancelQuickEdit() }
              .keyboardShortcut(.cancelAction)
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
      .onHover { hoveringValue = $0 }
      .animation(.easeInOut(duration: 0.12), value: hoveringValue)
      .animation(.easeInOut(duration: 0.12), value: copied)

      if let renaming {
        fieldRename(renaming)
      }
    }
  }

  /// Rename line of a login card row. The card shows a field name in place of
  /// the title and id, so the one being renamed is shown here.
  private func fieldRename(_ field: RenameField) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 12) {
      LoginFieldLabel(field == .title ? "Title" : "Key")
      switch field {
      case .title:
        InlineRenameField(
          initial: cred.title, placeholder: "Title",
          onCommit: { onRename(.title, $0) }, onCancel: onCancelRename)
      case .key:
        HStack(spacing: 0) {
          Text(referencePrefix)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.head)
          InlineRenameField(
            initial: cred.key, placeholder: "id",
            onCommit: { onRename(.key, $0) }, onCancel: onCancelRename)
        }
      }
    }
  }

  private var fieldValue: some View {
    let concealed = cred.kind.concealed
    let shown = revealedText ?? (concealed ? "••••••••" : " ")
    let text = Text(shown)
      .font(.system(.body, design: .monospaced))
      .foregroundStyle(revealedText == nil ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.primary))
      .lineLimit(1)
      .truncationMode(.tail)
      .frame(maxWidth: .infinity, alignment: .leading)
      .contentShape(.rect)
    return Group {
      if concealed {
        // Clicking the value toggles it, as in the credential box.
        Button {
          secret == nil ? onReveal() : onHide()
        } label: {
          text
        }
        .buttonStyle(.plain)
      } else {
        text
      }
    }
    .textSelection(.enabled)
    .task(id: "\(vaultKey)/\(itemKey)/\(cred.key)") {
      // A plain value shows without a click; a concealed one waits for one.
      if !concealed, secret == nil, !isRevealing { onReveal() }
    }
  }

  /// The actions stay in the layout while hidden, so the row keeps the same
  /// height whether or not the pointer is over it.
  private var fieldActions: some View {
    let visible =
      copied || isRevealing || hoveringValue || (cred.kind.concealed && secret != nil)
    return
      fieldActionButtons
      .opacity(visible ? 1 : 0)
      .allowsHitTesting(visible)
  }

  /// The buttons always lay out so the row height is constant. The copy
  /// confirmation and the revealing spinner overlay them.
  private var fieldActionButtons: some View {
    let busy = copied || isRevealing
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
      if copied {
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

/// Small colored label beside a passkey account.
private struct PasskeyBadge: View {
  let text: String
  let color: Color

  var body: some View {
    Text(text)
      .font(.caption.weight(.medium))
      .foregroundStyle(color)
      .padding(.horizontal, 6)
      .padding(.vertical, 1)
      .background(color.opacity(0.15), in: Capsule())
  }
}

/// Site report shown at the top of the passkey details, with its actions.
private struct PasskeyNotice<Actions: View>: View {
  let systemImage: String
  let color: Color
  let message: String
  @ViewBuilder let actions: () -> Actions

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      Label {
        Text(message)
          .fixedSize(horizontal: false, vertical: true)
      } icon: {
        Image(systemName: systemImage).foregroundStyle(color)
      }
      .font(.callout)
      HStack {
        Spacer()
        actions()
      }
      .controlSize(.small)
    }
    .padding(10)
    .background(color.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
  }
}

/// Width of the field name column in the login card.
let loginFieldLabelWidth: CGFloat = 104

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
