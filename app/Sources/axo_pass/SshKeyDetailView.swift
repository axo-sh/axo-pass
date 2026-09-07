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
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(.windowBackground)
  }
}

private struct SshKeyDetail: View {
  @Bindable var model: SshModel
  let key: SshKeyEntry

  @State private var recentEvents: [AuditLogRow] = []
  @State private var showingSavePasswordSheet = false
  @State private var showingDeleteConfirmation = false
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
            Text(publicKeyText)
              .font(.system(.caption, design: .monospaced))
              .textSelection(.enabled)
              .frame(maxWidth: .infinity, alignment: .leading)
          }
        }
        // Everything the pills already say is left to them.
        if !detailItems.isEmpty || showsMissingPublicKey {
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
      if !key.hasSavedPassword && key.location == .sshDir {
        Button("Save Password") { showingSavePasswordSheet = true }
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
      if key.isManaged {
        KeyBadge(text: "Secure Enclave", tint: .blue, size: .regular)
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
    case .vault: return "Vault"
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
