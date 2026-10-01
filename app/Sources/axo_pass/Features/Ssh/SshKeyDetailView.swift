import AppKit
import AxoPassFFI
import SwiftUI

struct SshKeyDetailView: View {
  @Bindable var model: SshModel

  var body: some View {
    Group {
      if let key = model.selectedKey {
        SshKeyDetail(model: model, key: key)
      } else {
        ContentUnavailableView("Select a key", systemImage: "key.horizontal")
      }
    }
    .paneBackground()
  }
}

private struct SshKeyDetail: View {
  @Bindable var model: SshModel
  let key: SshKeyEntry

  @State private var recentEvents: [AuditLogRow] = []
  @State private var appGrants: [SshAppGrant] = []
  @State private var relatedHosts: [SshRelatedHost] = []
  @State private var showingSavePasswordSheet = false
  @State private var showingDeleteConfirmation = false
  @State private var showingDeletePassphraseConfirmation = false
  @State private var copiedPublicKey = false

  private static let recentEventCount: UInt32 = 5

  /// Comes from the key itself, not its `.pub` file, so a managed key whose
  /// file was deleted still shows one.
  private var publicKeyText: String? { key.publicKeyOpenssh }

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 0) {
        header
        badges.padding(.top, 10).padding(.bottom, 16)
        if let publicKeyText {
          sectionTitle("Public Key")
          InsetGroupedSection {
            CharWrappingText(text: publicKeyText, dimsOuterFields: true)
              .frame(maxWidth: .infinity, alignment: .leading)
          }
        }
        // Everything the pills already say is left to them.
        if !detailItems.isEmpty || showsMissingPublicKey || showsPassphrase || showsAutoload {
          sectionTitle("Details")
          InsetGroupedSection {
            VStack(spacing: 8) {
              ForEach(Array(detailItems.enumerated()), id: \.element.label) { index, item in
                if index > 0 {
                  Divider()
                }
                InspectorRow(item.label, value: item.value, monospaced: true)
              }
              if showsMissingPublicKey {
                if !detailItems.isEmpty {
                  Divider()
                }
                missingPublicKeyRow
              }
              if showsPassphrase {
                if !detailItems.isEmpty || showsMissingPublicKey {
                  Divider()
                }
                PassphraseField(
                  hasSaved: key.hasSavedPassword,
                  reveal: { await model.revealPassword(fingerprint: key.fingerprintSha256) },
                  save: { showingSavePasswordSheet = true },
                  remove: { showingDeletePassphraseConfirmation = true }
                )
              }
              if showsAutoload {
                if !detailItems.isEmpty || showsMissingPublicKey || showsPassphrase {
                  Divider()
                }
                autoloadRow
              }
            }
          }
        }
        sectionTitle("Fingerprints")
        InsetGroupedSection {
          VStack(spacing: 8) {
            InspectorRow("SHA256", value: key.fingerprintSha256, monospaced: true)
            Divider()
            InspectorRow("MD5", value: key.fingerprintMd5, monospaced: true)
          }
        }
        if !relatedHosts.isEmpty {
          sectionTitle("Known Hosts")
          InsetGroupedSection { hostsTable }
        }
        if grantsApply {
          sectionTitle("Allowed Apps")
          InsetGroupedSection { allowedApps }
        }
        if !recentEvents.isEmpty {
          sectionTitle("Recent Activity")
          InsetGroupedSection { activityTable }
        }
      }
      .padding()
    }
    .labeledContentStyle(.inspectorField)
    .navigationTitle(key.name)
    .task(id: key.fingerprintSha256) {
      recentEvents = await model.recentEvents(
        fingerprintSha256: key.fingerprintSha256, limit: Self.recentEventCount)
      relatedHosts = await model.relatedHosts(fingerprintSha256: key.fingerprintSha256)
      appGrants =
        grantsApply
        ? await model.appGrants(fingerprintSha256: key.fingerprintSha256) : []
    }
    .onChange(of: key.fingerprintSha256) { copiedPublicKey = false }
    .sheet(isPresented: $showingSavePasswordSheet) {
      SavePasswordSheet(keyName: key.name) { password in
        await model.savePassword(fingerprint: key.fingerprintSha256, password: password)
      }
    }
    .confirmationDialog(
      "Delete \(key.name)?", isPresented: $showingDeleteConfirmation, titleVisibility: .visible
    ) {
      Button("Delete", role: .destructive) {
        Task { await model.deleteManagedKey(fingerprintSha256: key.fingerprintSha256) }
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text("The private key lives in the Secure Enclave and cannot be recovered.")
    }
    .confirmationDialog(
      "Remove saved passphrase for \(key.name)?",
      isPresented: $showingDeletePassphraseConfirmation, titleVisibility: .visible
    ) {
      Button("Remove", role: .destructive) {
        Task { await model.forgetPassword(fingerprint: key.fingerprintSha256) }
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text("ssh will ask for the passphrase again the next time it needs this key.")
    }
  }

  /// A key file on disk can carry a passphrase worth saving. Secure Enclave
  /// keys and agent-only identities have none.
  private var showsPassphrase: Bool { key.location == .sshDir }

  /// Only a key file on disk can be auto-loaded.
  /// A key file on disk can be auto-loaded. A configured key shows here
  /// wherever it was found, e.g. one added to the agent by hand, so it can be
  /// turned off.
  private var showsAutoload: Bool {
    key.autoload || (key.location == .sshDir && key.path != nil)
  }

  /// Every key can hold app grants except a Secure Enclave key that always
  /// requires authentication.
  private var grantsApply: Bool { key.policy != .alwaysRequireAuth }

  /// When a key the agent holds uses its grants. Nil for Secure Enclave keys,
  /// where grants always apply.
  private var grantsNote: String? {
    guard !key.isManaged else { return nil }
    let confirmNote = "Keys added with ssh-add -c ask every time."
    if key.autoload {
      return confirmNote
    }
    return "These apps sign without asking only while auto-load is on. \(confirmNote)"
  }

  // MARK: - Header

  private var header: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "key.horizontal.fill")
        .font(.system(size: 26))
        .foregroundStyle(.tint)
        .frame(width: 34)
      VStack(alignment: .leading, spacing: 2) {
        Text(key.name).font(.title2).fontWeight(.semibold)
        if let subtitle {
          Text(subtitle)
            .font(.callout)
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
        }
      }
      Spacer(minLength: 12)
      actions
    }
  }

  @ViewBuilder
  private var actions: some View {
    HStack(spacing: 8) {
      if publicKeyText != nil {
        Button(copiedPublicKey ? "Copied" : "Copy Public Key") { copyPublicKey() }
      }
      if key.isManaged {
        Button("Delete", role: .destructive) { showingDeleteConfirmation = true }
      }
      if let path = key.path, key.location == .sshDir {
        Button {
          NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
        } label: {
          Label("Reveal in Finder", systemImage: "folder")
            .labelStyle(.iconOnly)
        }
        .help("Reveal in Finder")
      }
    }
  }

  private var badges: some View {
    HStack(spacing: 8) {
      KeyBadge(text: keyTypeLabel, size: .regular)
      KeyBadge(text: locationLabel, size: .regular)
      if key.policy == .alwaysRequireAuth {
        KeyBadge(text: "Always requires authentication", size: .regular)
      }
      if key.autoload {
        KeyBadge(text: "Auto-load", size: .regular)
      }
      // Secure Enclave keys have no passphrase to save.
      if key.location == .sshDir {
        KeyBadge(
          text: key.hasSavedPassword ? "Passphrase saved" : "No passphrase saved", size: .regular)
      }
      if key.agents.isEmpty {
        KeyBadge(text: "Not in agent", size: .regular)
      } else {
        ForEach(key.agents, id: \.self) { agent in
          KeyBadge(text: agentLabel(agent), tint: .green, size: .regular)
        }
      }
    }
  }

  // MARK: - Rows

  private func sectionTitle(_ text: String) -> some View {
    Text(text.uppercased())
      .font(.caption)
      .fontWeight(.semibold)
      .foregroundStyle(.secondary)
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(.bottom, 4)
  }

  /// A Grid rather than a `Table`, which needs a height of its own and would
  /// scroll inside this pane's scroll view.
  private var activityTable: some View {
    Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
      GridRow {
        columnHeader("Action")
        columnHeader("Caller")
        columnHeader("Outcome")
        columnHeader("When").gridColumnAlignment(.trailing)
      }
      Divider().gridCellColumns(4)
      ForEach(recentEvents) { event in
        GridRow {
          Text(actionLabel(event.action))
          Text(event.callerText)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.middle)
          Text(event.outcomeText)
            .foregroundStyle(event.record.outcome == .succeeded ? Color.secondary : .orange)
          Text(event.timeText)
            .foregroundStyle(.secondary)
        }
        .font(.callout)
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  /// Hosts this key signed in to, most recently used first.
  private var hostsTable: some View {
    Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
      GridRow {
        columnHeader("Host")
        columnHeader("User")
        columnHeader("Last Used").gridColumnAlignment(.trailing)
      }
      Divider().gridCellColumns(3)
      ForEach(Array(relatedHosts.enumerated()), id: \.offset) { _, host in
        GridRow {
          hostName(host)
          Text(host.user ?? "—")
            .foregroundStyle(.secondary)
            .lineLimit(1)
          Text(lastUsedText(host))
            .foregroundStyle(.secondary)
            .help(useCountText(host))
        }
        .font(.callout)
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  /// A host key missing from `known_hosts`, or only in a hashed entry, has no
  /// name, so its fingerprint stands in.
  @ViewBuilder
  private func hostName(_ host: SshRelatedHost) -> some View {
    if let name = host.host {
      Text(name)
        .lineLimit(1)
        .truncationMode(.middle)
    } else {
      Text(host.hostkeyFingerprint)
        .font(.callout.monospaced())
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .truncationMode(.middle)
        .help(
          "Host key \(host.hostkeyFingerprint). The host is not in known_hosts, or only as a "
            + "hashed entry.")
    }
  }

  private func lastUsedText(_ host: SshRelatedHost) -> String {
    Date(timeIntervalSince1970: TimeInterval(host.lastUsed))
      .formatted(.relative(presentation: .named))
  }

  /// The count covers the signatures the audit log still holds, so it is
  /// stated from the oldest of them.
  private func useCountText(_ host: SshRelatedHost) -> String {
    let since = Date(timeIntervalSince1970: TimeInterval(host.firstUsed))
      .formatted(date: .abbreviated, time: .shortened)
    if host.useCount == 1 {
      return "Used once, on \(since)"
    }
    return "Used \(host.useCount) times since \(since)"
  }

  /// Apps that sign with this key without a prompt.
  @ViewBuilder
  private var allowedApps: some View {
    if appGrants.isEmpty {
      Text(
        "No apps. Tick \u{201C}Allow\u{201D} when an app asks to sign to let it use this key "
          + "without asking."
      )
      .font(.callout)
      .foregroundStyle(.secondary)
      .frame(maxWidth: .infinity, alignment: .leading)
    } else {
      VStack(spacing: 8) {
        ForEach(Array(appGrants.enumerated()), id: \.element.app.bundleId) { index, grant in
          if index > 0 {
            Divider()
          }
          allowedAppRow(grant)
        }
        Text(
          ["Anything these apps run, such as git hooks, can also use this key.", grantsNote]
            .compactMap { $0 }.joined(separator: " ")
        )
        .font(.caption)
        .foregroundStyle(.secondary)
        .frame(maxWidth: .infinity, alignment: .leading)
      }
    }
  }

  private func allowedAppRow(_ grant: SshAppGrant) -> some View {
    HStack(spacing: 8) {
      if let icon = CallerAppIcon.icon(bundleId: grant.app.bundleId) {
        Image(nsImage: icon)
          .resizable()
          .frame(width: 20, height: 20)
      } else {
        Image(systemName: "app.dashed")
          .frame(width: 20, height: 20)
          .foregroundStyle(.secondary)
      }
      VStack(alignment: .leading, spacing: 1) {
        Text(grant.app.displayName)
        Text(grant.app.bundleId)
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer()
      Text(expiryText(grant))
        .font(.caption)
        .foregroundStyle(.secondary)
      Button("Remove") {
        Task {
          if await model.removeAppGrant(fingerprintSha256: key.fingerprintSha256, app: grant.app) {
            appGrants = await model.appGrants(fingerprintSha256: key.fingerprintSha256)
          }
        }
      }
      .controlSize(.small)
    }
  }

  /// The list is loaded when the key is selected, so a grant can pass its
  /// expiration while shown. It stops applying at that time regardless.
  private func expiryText(_ grant: SshAppGrant) -> String {
    guard let expiresAt = grant.expiresAt else { return "No expiration" }
    let date = Date(timeIntervalSince1970: TimeInterval(expiresAt))
    if date <= Date() {
      return "Expired"
    }
    return "Expires \(date.formatted(.relative(presentation: .named)))"
  }

  private func columnHeader(_ text: String) -> some View {
    Text(text.uppercased())
      .font(.caption2)
      .fontWeight(.semibold)
      .foregroundStyle(.secondary)
  }

  private func actionLabel(_ action: String) -> String {
    switch action {
    case "ssh.sign": return "Signed"
    case "ssh.passphrase": return "Passphrase requested"
    case "ssh.key_add": return "Added to agent"
    case "ssh.key_remove": return "Removed from agent"
    case "ssh.session_bind": return "Session bound"
    case "ssh.app_grant_add": return "App allowed"
    case "ssh.app_grant_remove": return "App removed"
    default: return action
    }
  }

  /// A managed key signs without its public key file, so a missing one is an
  /// inconvenience rather than a broken key: it can be written again from the
  /// key in the Secure Enclave.
  private var missingPublicKeyRow: some View {
    HStack(alignment: .firstTextBaseline, spacing: 12) {
      Text("Public Key")
        .foregroundStyle(.secondary)
        .frame(width: 100, alignment: .leading)
      Text("File is missing")
      Spacer()
      Button("Recreate") {
        Task { await model.writeManagedKeyPubkey(fingerprintSha256: key.fingerprintSha256) }
      }
      .controlSize(.small)
    }
  }

  /// The Axo agent lists the key from the start and reads it from disk the
  /// first time something signs with it.
  private var autoloadRow: some View {
    // An untitled checkbox has no text baseline, so this row centers it on the
    // label instead of using the inspector style's baseline alignment.
    HStack(alignment: .center, spacing: 8) {
      Text("Auto-load")
        .foregroundStyle(.secondary)
        .frame(width: 100, alignment: .leading)
      Toggle(
        "Auto-load",
        isOn: Binding(
          get: { key.autoload },
          set: { enabled in
            guard let path = key.path else { return }
            Task {
              await model.setAutoload(
                fingerprintSha256: key.fingerprintSha256, path: path, enabled: enabled)
            }
          })
      )
      .toggleStyle(.checkbox)
      .labelsHidden()
      Spacer()
    }
  }

  // MARK: - Values

  /// The Details rows, in order. A Secure Enclave key's id names its keychain
  /// entry, its `.pub` file and that file's comment.
  private var detailItems: [(label: String, value: String)] {
    var items: [(label: String, value: String)] = []
    if key.isManaged {
      items.append((label: "Key ID", value: key.name))
    }
    if let path = key.path, key.location == .sshDir {
      items.append((label: "Path", value: path))
    }
    if let publicKeyPath = key.publicKey {
      items.append((label: "Public Key", value: publicKeyPath))
    }
    return items
  }

  private var showsMissingPublicKey: Bool { key.publicKey == nil && key.isManaged }

  private var subtitle: String? {
    guard let comment = key.comment, !comment.isEmpty else { return nil }
    return comment
  }

  private var keyTypeLabel: String {
    switch key.keyType {
    case .rsa: return "RSA"
    case .ed25519: return "ed25519"
    case .ecdsa: return "ECDSA"
    case .dsa: return "DSA"
    case .unknown: return "Unknown"
    }
  }

  private var locationLabel: String {
    switch key.location {
    case .vault: return "Secure Enclave"
    case .sshDir: return "~/.ssh"
    case .transient: return "Agent only"
    }
  }

  private func agentLabel(_ agent: SshKeyAgent) -> String {
    switch agent {
    case .systemAgent: return "System agent"
    case .axoPassAgent: return "Axo agent"
    }
  }

  // MARK: - Actions

  /// `publicKey` holds the path to the `.pub` file, so the text is read from
  /// disk. Keys known only to an agent have no file and show no public key.
  private func copyPublicKey() {
    guard let publicKeyText else { return }
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(publicKeyText, forType: .string)
    copiedPublicKey = true
  }
}

struct KeyBadge: View {
  enum Size {
    /// Fits a list row alongside the key's name.
    case compact
    /// The detail pane, where the badges carry the key's status.
    case regular
  }

  let text: String
  var tint: Color? = nil
  var size: Size = .compact

  var body: some View {
    Text(text)
      .font(size == .compact ? .caption2 : .callout)
      .foregroundStyle(tint ?? .secondary)
      .padding(.horizontal, size == .compact ? 6 : 10)
      .padding(.vertical, size == .compact ? 2 : 4)
      .background((tint ?? .gray).opacity(0.15), in: Capsule())
  }
}

struct SavePasswordSheet: View {
  let keyName: String
  let onSubmit: (_ password: String) async -> Bool

  @Environment(\.dismiss) private var dismiss
  @State private var password: String = ""
  @State private var isSubmitting = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Save Password for \(keyName)").font(.headline)
      SecureField("Password", text: $password)

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Save") {
          Task {
            isSubmitting = true
            if await onSubmit(password) { dismiss() }
            isSubmitting = false
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || password.isEmpty)
      }
    }
    .padding(20)
    .frame(width: 320)
  }
}
