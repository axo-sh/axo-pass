import AppKit
import AxoPassFFI
import SwiftUI

private let loginRowInsets = EdgeInsets(
  top: credentialRowInset, leading: credentialRowInset,
  bottom: credentialRowInset, trailing: credentialRowInset)

extension CredentialList {
  /// What a login shows above its other credentials: the banners, then one card
  /// with the username, password, one-time code, passkeys, and websites. An
  /// item that is not a login shows only the conversion banner, when it
  /// qualifies.
  @ViewBuilder
  func loginSection(isEmphasized: Bool) -> some View {
    if item.canConvertToLogin, !model.dismissedConversions.contains(item.id) {
      conversionBanner
        .listRowSeparator(.hidden)
        .listRowInsets(loginRowInsets)
    }
    if item.passwordRoleBroken {
      repairBanner
        .listRowSeparator(.hidden)
        .listRowInsets(loginRowInsets)
    }
    if let other = mergeCandidate {
      MergeBanner(item: item, other: other, vaultKey: vaultKey)
        .listRowSeparator(.hidden)
        .listRowInsets(loginRowInsets)
    }
    if item.isLogin {
      loginCard(isEmphasized: isEmphasized)
        .listRowSeparator(.hidden)
        .listRowInsets(loginRowInsets)
      if !item.listCredentials.isEmpty {
        Text("Other credentials")
          .font(.subheadline.weight(.semibold))
          .foregroundStyle(.secondary)
          .padding(.horizontal, 6)
          .padding(.top, 8)
          .listRowSeparator(.hidden)
          .listRowInsets(loginRowInsets)
      }
    }
  }

  /// The first login in the same vault that looks like the same site, unless
  /// the user dismissed merging the two.
  private var mergeCandidate: ItemInfo? {
    item.mergeCandidates(in: model.cachedItems(in: vaultKey)).first { other in
      !model.dismissedMerges.contains(VaultsModel.mergeKey(item, other))
    }
  }

  /// One part of the login card.
  private enum LoginCardEntry: Identifiable {
    case credential(CredentialInfo, label: String)
    case add(LoginField)
    case websites

    var id: String {
      switch self {
      case .credential(let cred, _): return "credential:\(cred.key)"
      case .add(let field): return "add:\(field)"
      case .websites: return "websites"
      }
    }
  }

  /// The parts of the login in the order the card shows them: username,
  /// password, one-time code, passkeys, websites. A missing username, password,
  /// or code shows as a row that adds it.
  private var loginCardEntries: [LoginCardEntry] {
    var entries: [LoginCardEntry] = []
    if let username = item.usernameCredential {
      entries.append(.credential(username, label: "Username"))
    } else {
      entries.append(.add(.username))
    }
    if let password = item.passwordCredential {
      entries.append(.credential(password, label: "Password"))
    } else {
      entries.append(.add(.password))
    }
    if let totp = item.totpCredential {
      entries.append(.credential(totp, label: "Code"))
    }
    entries += item.passkeyCredentials.map { .credential($0, label: "Passkey") }
    if item.totpCredential == nil {
      entries.append(.add(.totp))
    }
    entries.append(.websites)
    return entries
  }

  /// Login card. `isEmphasized` gives the selected row the accent highlight.
  private func loginCard(isEmphasized: Bool) -> some View {
    let entries = loginCardEntries
    return VStack(alignment: .leading, spacing: 0) {
      ForEach(Array(entries.enumerated()), id: \.element.id) { index, entry in
        if index > 0, !isAddEntry(entry) || !isAddEntry(entries[index - 1]) {
          Divider().padding(.leading, 14)
        }
        if case .credential(let cred, let label) = entry {
          cardCredentialRow(cred, label: label, isEmphasized: isEmphasized)
        } else {
          loginCardRow(entry)
            .padding(.vertical, isAddEntry(entry) ? 4 : 8)
            .padding(.horizontal, 8)
        }
      }
    }
    .padding(.vertical, 4)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.separator, lineWidth: 1))
  }

  /// Consecutive add rows sit together without a divider between them.
  private func isAddEntry(_ entry: LoginCardEntry) -> Bool {
    if case .add = entry { return true }
    return false
  }

  /// Credential row of the login card. A click selects it and moves focus to
  /// the outline, so ⌘C copies it.
  private func cardCredentialRow(_ cred: CredentialInfo, label: String, isEmphasized: Bool)
    -> some View
  {
    let isSelected = cardSelection == cred.key
    // Hierarchical colors turn light on the accent highlight, as in the outline.
    return credentialRowBody(cred, fieldLabel: label)
      .environment(\.backgroundProminence, isSelected && isEmphasized ? .increased : .standard)
      .padding(.vertical, 6)
      .background {
        if isSelected {
          RoundedRectangle(cornerRadius: 6)
            .fill(
              Color(
                nsColor: isEmphasized
                  ? .selectedContentBackgroundColor : .unemphasizedSelectedContentBackgroundColor))
        }
      }
      .contentShape(.rect)
      .simultaneousGesture(TapGesture().onEnded { selectCardRow(cred.key) })
      .padding(.vertical, 2)
      .padding(.horizontal, 8)
  }

  @ViewBuilder
  private func loginCardRow(_ entry: LoginCardEntry) -> some View {
    switch entry {
    case .credential(let cred, let label):
      credentialRowBody(cred, fieldLabel: label)
    case .add(let field):
      AddLoginFieldRow(field: field, item: item, vaultKey: vaultKey)
    case .websites:
      WebsitesEditor(item: item, vaultKey: vaultKey)
    }
  }

  private func selectCardRow(_ key: String) {
    selection = []
    cardSelection = key
    outlineFocusRequest += 1
  }

  private var conversionBanner: some View {
    VStack(alignment: .leading, spacing: 6) {
      Label("Use this item for AutoFill?", systemImage: "key.viewfinder")
        .font(.subheadline.weight(.semibold))
      Text(
        "It has a password and a website. Axo Pass can offer it in Safari and other apps. Credential keys stay as they are."
      )
      .font(.caption)
      .foregroundStyle(.secondary)
      HStack {
        Button("Use for AutoFill") {
          Task { await model.convertItemToLogin(vaultKey: vaultKey, itemKey: item.key) }
        }
        Button("Dismiss") { model.dismissConversion(item) }
      }
      .controlSize(.small)
    }
    .padding(10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
  }

  private var repairBanner: some View {
    VStack(alignment: .leading, spacing: 6) {
      Label("This login has no password field", systemImage: "exclamationmark.triangle")
        .font(.subheadline.weight(.semibold))
      Text("The credential it filled as the password is gone or can no longer be one.")
        .font(.caption)
        .foregroundStyle(.secondary)
      Menu("Use as password") {
        ForEach(item.passwordCandidates, id: \.key) { cred in
          Button(cred.title) {
            Task { await setRole(cred, role: "password", assign: true) }
          }
        }
      }
      .fixedSize()
      .controlSize(.small)
      .disabled(item.passwordCandidates.isEmpty)
    }
    .padding(10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
  }

  /// Assign or clear a role, reporting a failure on the credential's row.
  func setRole(_ cred: CredentialInfo, role: String, assign: Bool) async {
    let ok = await model.setCredentialRole(
      vaultKey: vaultKey, itemKey: item.key, role: role, credKey: assign ? cred.key : nil)
    if ok {
      errors.removeValue(forKey: cred.key)
    } else if let err = model.actionError {
      errors[cred.key] = err
    }
  }

  /// Copy the selected credential with ⌘C. Copies nothing if several rows or
  /// a section are selected.
  func copySelection() {
    if let key = cardSelection, let cred = item.credentials.first(where: { $0.key == key }) {
      copyFromShortcut(cred, isCardRow: true)
    } else if selection.count == 1, case .credential(let key)? = selection.first,
      let cred = item.credentials.first(where: { $0.key == key })
    {
      copyFromShortcut(cred, isCardRow: false)
    }
  }

  /// Copy the username with ⇧⌘C.
  func copyUsername() {
    guard let cred = item.usernameCredential else { return }
    copyFromShortcut(cred, isCardRow: item.isLogin)
  }

  /// Copy a credential and show the copy confirmation on its row. The login
  /// card code row copies the current code. Passkeys and files are not copied.
  private func copyFromShortcut(_ cred: CredentialInfo, isCardRow: Bool) {
    guard !cred.hasRecordValue else { return }
    Task {
      let copied =
        isCardRow && cred.kind.kind == "totp" ? await copyCurrentCode(cred) : await copy(cred)
      guard copied else { return }
      shortcutCopied = cred.key
      try? await Task.sleep(for: .seconds(1.2))
      if shortcutCopied == cred.key {
        shortcutCopied = nil
      }
    }
  }

  /// Copy the current one-time code of a TOTP credential.
  private func copyCurrentCode(_ cred: CredentialInfo) async -> Bool {
    do {
      let code = try await model.currentTotpCode(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key)
      secureCopy(code.code)
      errors.removeValue(forKey: cred.key)
      return true
    } catch {
      errors[cred.key] = String(describing: error)
      return false
    }
  }
}

/// Offers to fold another login for the same site into this one.
private struct MergeBanner: View {
  @Environment(VaultsModel.self) private var model
  let item: ItemInfo
  let other: ItemInfo
  let vaultKey: String

  @State private var confirming = false
  @State private var merging = false
  @State private var error: String?

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      Label("Another login for \(site)", systemImage: "square.on.square")
        .font(.subheadline.weight(.semibold))
      Text("“\(other.title)” \(otherSummary). Merging moves its credentials here and deletes it.")
        .font(.caption)
        .foregroundStyle(.secondary)
      HStack {
        Button("Merge into This Login…") { confirming = true }
          .disabled(merging)
        Button("Dismiss") { model.dismissMerge(item, other) }
      }
      .controlSize(.small)
      if let error {
        Text(error).font(.caption).foregroundStyle(.red)
      }
    }
    .padding(10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
    .confirmationDialog(
      "Merge “\(other.title)” into “\(item.title)”?", isPresented: $confirming,
      titleVisibility: .visible
    ) {
      Button("Merge") { merge() }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text(
        "Its \(credentialCount) move to “\(item.title)”, and “\(other.title)” is deleted. Anything “\(item.title)” already has, such as the same username, is skipped. References to “\(other.key)” stop working."
      )
    }
  }

  private var site: String {
    let mine = Set(item.siteHosts.map(siteKey(of:)))
    return other.siteHosts.first { mine.contains(siteKey(of: $0)) } ?? other.title
  }

  /// What the other login holds, such as "has 1 passkey".
  private var otherSummary: String {
    var parts: [String] = []
    if let username = other.username { parts.append("signs in as \(username)") }
    let passkeys = other.passkeyCredentials.count
    if passkeys > 0 { parts.append("has \(passkeys) passkey\(passkeys == 1 ? "" : "s")") }
    if other.passwordCredential != nil { parts.append("has a password") }
    if parts.isEmpty { return "is in this vault" }
    return parts.joined(separator: " and ")
  }

  private var credentialCount: String {
    let count = other.credentials.count
    return "\(count) credential\(count == 1 ? "" : "s")"
  }

  private func merge() {
    merging = true
    error = nil
    Task {
      if !(await model.mergeItems(
        vaultKey: vaultKey, sourceItemKey: other.key, destItemKey: item.key))
      {
        error = model.actionError
      }
      merging = false
    }
  }
}

/// A login field the card can add when the login lacks it.
enum LoginField: String {
  case username, password, totp
}

/// A faint "Add password" row that opens an inline editor. Saving creates the
/// credential and gives it the field's role.
private struct AddLoginFieldRow: View {
  @Environment(VaultsModel.self) private var model
  let field: LoginField
  let item: ItemInfo
  let vaultKey: String

  @State private var adding = false
  @State private var draft = ""
  @State private var saving = false
  @State private var error: String?
  @FocusState private var focused: Bool

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      if adding {
        // Matches the quick editor of a login card row.
        HStack(alignment: .center, spacing: 12) {
          LoginFieldLabel(label)
          ValueTextEditor(text: $draft, placeholder: placeholder)
            .focused($focused)
            .padding(.vertical, 6)
            .padding(.horizontal, 8)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            .overlay(
              RoundedRectangle(cornerRadius: 6)
                .strokeBorder(.tint, lineWidth: 2)
            )
          HStack(spacing: 4) {
            if field == .password {
              Button("Generate") {
                if let generated = model.generatePassword() { draft = generated }
              }
            }
            Button("Cancel") {
              adding = false
              draft = ""
              error = nil
            }
            Button("Save", action: save)
              .keyboardShortcut(.defaultAction)
              .disabled(saving || draft.trimmingCharacters(in: .whitespaces).isEmpty)
          }
          .buttonStyle(.bordered)
          .controlSize(.small)
        }
        if let error {
          Text(error).font(.caption).foregroundStyle(.red)
            .padding(.leading, loginFieldLabelWidth + 12)
        }
      } else {
        Button {
          adding = true
          focused = true
        } label: {
          Label(addTitle, systemImage: "plus.circle")
            .foregroundStyle(.secondary)
        }
        .buttonStyle(.borderless)
      }
    }
    .padding(.horizontal, 6)
  }

  private var label: String {
    switch field {
    case .username: return "Username"
    case .password: return "Password"
    case .totp: return "Code"
    }
  }

  private var addTitle: String {
    switch field {
    case .username: return "Add Username"
    case .password: return "Add Password"
    case .totp: return "Set Up One-Time Code"
    }
  }

  private var placeholder: String {
    switch field {
    case .username: return "Username or email"
    case .password: return "Password"
    case .totp: return "Setup key or otpauth:// link"
    }
  }

  /// The credential key and kind the new field is stored under.
  private var keyAndKind: (String, FieldKindInfo) {
    let value = draft.trimmingCharacters(in: .whitespacesAndNewlines)
    switch field {
    case .username:
      let email = value.contains("@") && !value.contains(" ")
      return (
        "username",
        FieldKindInfo(kind: email ? "email" : "text", concealed: false, multiline: false)
      )
    case .password:
      return ("password", FieldKindInfo(kind: "text", concealed: true, multiline: false))
    case .totp:
      return ("one-time-code", FieldKindInfo(kind: "totp", concealed: false, multiline: false))
    }
  }

  /// `base`, or `base-2` and so on, whichever the item does not use yet.
  private func unusedKey(_ base: String) -> String {
    let taken = Set(item.credentials.map(\.key))
    var key = base
    var n = 2
    while taken.contains(key) {
      key = "\(base)-\(n)"
      n += 1
    }
    return key
  }

  private func save() {
    let value = field == .password ? draft : draft.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !value.isEmpty, !saving else { return }
    let (base, kind) = keyAndKind
    let key = unusedKey(base)
    saving = true
    error = nil
    Task {
      defer { saving = false }
      guard
        await model.addCredential(
          vaultKey: vaultKey, itemKey: item.key, credKey: key, title: label, value: value,
          kind: kind)
      else {
        error = model.actionError
        return
      }
      guard
        await model.setCredentialRole(
          vaultKey: vaultKey, itemKey: item.key, role: field.rawValue, credKey: key)
      else {
        error = model.actionError
        return
      }
      draft = ""
      adding = false
    }
  }
}

/// The live one-time code of a login and the time left on it, for the value
/// column of a login card row.
struct TotpCodeValue: View {
  @Environment(VaultsModel.self) private var model
  let vaultKey: String
  let itemKey: String
  let credKey: String
  /// A copy shortcut just copied the code. The copy confirmation shows.
  var showsCopied = false

  @State private var code: String?
  @State private var expiresAt = Date.distantPast
  @State private var error: String?
  @State private var justCopied = false
  @State private var hovering = false

  var body: some View {
    HStack(alignment: .firstTextBaseline, spacing: 10) {
      if let error {
        Text(error)
          .font(.caption)
          .foregroundStyle(.red)
          .frame(maxWidth: .infinity, alignment: .leading)
      } else {
        Text(grouped(code))
          .font(.system(.body, design: .monospaced))
          .foregroundStyle(code == nil ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.primary))
          .textSelection(.enabled)
          .frame(maxWidth: .infinity, alignment: .leading)
      }
      if code != nil {
        TimelineView(.periodic(from: .now, by: 1)) { context in
          let left = max(0, Int(expiresAt.timeIntervalSince(context.date).rounded(.up)))
          Text("\(left)s")
            .font(.callout.monospacedDigit())
            .foregroundStyle(left <= 5 ? Color.orange : Color.secondary)
        }
        if justCopied || showsCopied {
          Image(systemName: "checkmark").foregroundStyle(.green)
        } else if hovering {
          Button("Copy", action: copy)
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
      }
    }
    .contentShape(.rect)
    .onHover { hovering = $0 }
    .task(id: credKey) { await refreshLoop() }
  }

  /// Fetch a code, then fetch the next when this one expires.
  private func refreshLoop() async {
    while !Task.isCancelled {
      do {
        let next = try await model.currentTotpCode(
          vaultKey: vaultKey, itemKey: itemKey, credKey: credKey)
        code = next.code
        error = nil
        expiresAt = Date().addingTimeInterval(TimeInterval(next.secondsRemaining))
        try await Task.sleep(for: .seconds(max(1, Int(next.secondsRemaining))))
      } catch is CancellationError {
        return
      } catch {
        code = nil
        self.error = String(describing: error)
        return
      }
    }
  }

  private func grouped(_ code: String?) -> String {
    guard let code else { return "••• •••" }
    guard code.count == 6 else { return code }
    return "\(code.prefix(3)) \(code.suffix(3))"
  }

  private func copy() {
    guard let code else { return }
    secureCopy(code)
    justCopied = true
    Task {
      try? await Task.sleep(for: .seconds(1.2))
      justCopied = false
    }
  }
}

/// The websites a login applies to, each with its match kind, beside the
/// "Websites" field name.
struct WebsitesEditor: View {
  @Environment(VaultsModel.self) private var model
  let item: ItemInfo
  let vaultKey: String

  @State private var adding = false
  @State private var draft = ""
  @State private var error: String?

  var body: some View {
    HStack(alignment: .firstTextBaseline, spacing: 12) {
      LoginFieldLabel(item.websites.count == 1 ? "Website" : "Websites")
      VStack(alignment: .leading, spacing: 6) {
        if item.websites.isEmpty, item.passkeySites.isEmpty, !adding {
          Text("None. AutoFill offers this login nowhere.")
            .foregroundStyle(.secondary)
        }

        ForEach(Array(item.websites.enumerated()), id: \.offset) { index, website in
          websiteRow(index, website)
        }

        ForEach(item.uncoveredPasskeySites, id: \.self) { site in
          suggestionRow(site)
        }

        if adding {
          HStack {
            TextField("github.com", text: $draft)
              .textFieldStyle(.roundedBorder)
              .onSubmit(commitDraft)
            Button("Cancel") {
              adding = false
              draft = ""
            }
            Button("Add", action: commitDraft)
              .keyboardShortcut(.defaultAction)
              .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
          }
          .controlSize(.small)
        } else {
          Button {
            adding = true
          } label: {
            Label("Add Website", systemImage: "plus.circle")
              .foregroundStyle(.secondary)
          }
          .buttonStyle(.borderless)
        }

        if let error {
          Text(error).font(.caption).foregroundStyle(.red)
        }

        if !item.passkeySites.isEmpty {
          Text(
            "Passkeys are offered on the site they were created for and its subdomains. This list does not change that."
          )
          .font(.caption)
          .foregroundStyle(.tertiary)
          .fixedSize(horizontal: false, vertical: true)
        }
      }
    }
    .padding(.horizontal, 6)
  }

  /// Whether the login's passkeys are offered on a website. Nothing for a
  /// login without passkeys.
  @ViewBuilder
  private func passkeyBadge(for host: String?) -> some View {
    if !item.passkeySites.isEmpty, let host {
      switch item.passkeyCoverage(of: host) {
      case .whole:
        Label("Passkey", systemImage: "person.badge.key.fill")
          .font(.caption)
          .foregroundStyle(.tint)
          .help("This login's passkey is offered on \(host).")
      case .subdomain(let rp):
        Label("Passkey on \(rp) only", systemImage: "person.badge.key")
          .font(.caption)
          .foregroundStyle(.secondary)
          .help("This login's passkey is offered on \(rp) and its subdomains, not all of \(host).")
      case .none:
        Text("No passkey")
          .font(.caption)
          .foregroundStyle(.tertiary)
          .help("None of this login's passkeys were created for \(host), so none is offered there.")
      }
    }
  }

  private func websiteRow(_ index: Int, _ website: WebsiteInfo) -> some View {
    HStack(alignment: .firstTextBaseline) {
      VStack(alignment: .leading, spacing: 1) {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
          Text(displayHost(of: website.url) ?? website.url)
            .lineLimit(1)
            .truncationMode(.middle)
          passkeyBadge(for: displayHost(of: website.url))
        }
        if website.url != displayHost(of: website.url) {
          Text(website.url)
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.middle)
        }
      }
      Spacer()
      Menu {
        ForEach(Self.matchKinds, id: \.kind) { choice in
          Button {
            update(index) { $0.matchKind = choice.kind }
          } label: {
            if website.matchKind == choice.kind {
              Label(choice.label, systemImage: "checkmark")
            } else {
              Text(choice.label)
            }
          }
        }
        Divider()
        Button("Open") {
          if let url = openableURL(for: website.url) { NSWorkspace.shared.open(url) }
        }
        Button("Remove", role: .destructive) { remove(index) }
      } label: {
        Text(Self.label(for: website.matchKind))
      }
      .menuStyle(.borderlessButton)
      .fixedSize()
      .controlSize(.small)
      .foregroundStyle(.secondary)
    }
  }

  /// A passkey's site that no website covers. The passkey is offered there
  /// regardless; adding it as a website offers the password there too.
  private func suggestionRow(_ site: String) -> some View {
    HStack(alignment: .firstTextBaseline) {
      HStack(alignment: .firstTextBaseline, spacing: 8) {
        Text(site)
          .lineLimit(1)
          .truncationMode(.middle)
        Label("Passkey only", systemImage: "person.badge.key.fill")
          .font(.caption)
          .foregroundStyle(.tint)
          .help(
            "This login's passkey is offered on \(site), but it is not one of the login's websites."
          )
      }
      Spacer()
      Button("Add as Website") {
        var websites = item.websites
        websites.append(WebsiteInfo(url: site, matchKind: "domain"))
        save(websites)
      }
      .controlSize(.small)
      .help(
        item.passwordCredential == nil
          ? "Add \(site) as a website, so new passkeys and passwords for it can be saved to this login."
          : "Offer this login's password on \(site) too.")
    }
  }

  private static let matchKinds: [(kind: String, label: String)] = [
    ("domain", "This site and subdomains"),
    ("host", "Only this host"),
    ("starts-with", "Pages starting with this URL"),
  ]

  private static func label(for kind: String) -> String {
    switch kind {
    case "never": return "Never offered"
    default: return matchKinds.first { $0.kind == kind }?.label ?? kind
    }
  }

  private func commitDraft() {
    let value = draft.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !value.isEmpty else { return }
    var websites = item.websites
    websites.append(WebsiteInfo(url: value, matchKind: "domain"))
    save(websites) {
      adding = false
      draft = ""
    }
  }

  private func update(_ index: Int, _ change: (inout WebsiteInfo) -> Void) {
    var websites = item.websites
    guard websites.indices.contains(index) else { return }
    change(&websites[index])
    save(websites)
  }

  private func remove(_ index: Int) {
    var websites = item.websites
    guard websites.indices.contains(index) else { return }
    websites.remove(at: index)
    save(websites)
  }

  private func save(_ websites: [WebsiteInfo], onSuccess: (() -> Void)? = nil) {
    Task {
      error = nil
      if await model.setItemWebsites(vaultKey: vaultKey, itemKey: item.key, websites: websites) {
        onSuccess?()
      } else {
        error = model.actionError
      }
    }
  }
}
