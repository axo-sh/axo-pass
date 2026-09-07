import AppKit
import AxoPassFFI
import SwiftUI

struct GpgKeyDetailView: View {
  @Bindable var model: GpgModel

  var body: some View {
    Group {
      if let key = model.selectedKey {
        GpgKeyDetail(model: model, key: key)
      } else {
        ContentUnavailableView("Select a key", systemImage: "lock.doc")
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(.windowBackground)
  }
}

private struct GpgKeyDetail: View {
  @Bindable var model: GpgModel
  let key: GpgKeyEntry

  @State private var recentEvents: [AuditLogRow] = []
  @State private var copiedPublicKey = false
  @State private var isExporting = false
  @State private var showingForgetConfirmation = false
  @State private var showingSavePassphraseSheet = false
  @State private var selectedSubkey: GpgSubkeyEntry? = nil

  private static let recentEventCount: UInt32 = 5

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 0) {
        header
        badges.padding(.top, 10).padding(.bottom, 16)
        sectionTitle("Fingerprint")
        InsetGroupedSection { fingerprintBlock }
        sectionTitle("Details")
        InsetGroupedSection { factList }
        if key.userIds.count > 1 {
          sectionTitle("User IDs")
          InsetGroupedSection { userIdList }
        }
        if !key.subkeys.isEmpty {
          sectionTitle("Subkeys")
          InsetGroupedSection { subkeyTable }
        }
        if !recentEvents.isEmpty {
          sectionTitle("Recent Activity")
          InsetGroupedSection { activityTable }
        }
      }
      .padding()
    }
    .navigationTitle(key.name)
    .task(id: key.fingerprint) {
      recentEvents = await model.recentEvents(for: key, limit: Self.recentEventCount)
    }
    .onChange(of: key.fingerprint) { copiedPublicKey = false }
    .sheet(item: $selectedSubkey) { subkey in
      GpgSubkeySheet(subkey: subkey, keyName: key.name)
    }
    .sheet(isPresented: $showingSavePassphraseSheet) {
      GpgSavePassphraseSheet(keyName: key.name) { passphrase in
        await model.savePassphrase(fingerprint: key.fingerprint, passphrase: passphrase)
      }
    }
    .confirmationDialog(
      "Forget saved passphrase for \(key.name)?",
      isPresented: $showingForgetConfirmation, titleVisibility: .visible
    ) {
      Button("Forget", role: .destructive) {
        Task { await model.forgetPasswords(for: key) }
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text("gpg will ask for the passphrase again the next time it needs this key.")
    }
  }

  // MARK: - Header

  private var header: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "lock.doc.fill")
        .font(.system(size: 26))
        .foregroundStyle(.tint)
        .frame(width: 34)
      VStack(alignment: .leading, spacing: 2) {
        Text(key.name).font(.title2).fontWeight(.semibold)
        if let email = key.email {
          Text(email)
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
      Button(copiedPublicKey ? "Copied" : "Export Public") {
        Task { await copyPublicKey() }
      }
      .disabled(isExporting)
      // A smartcard or offline stub has no local key material to unlock, and a
      // key gpg stores unencrypted has no passphrase to save.
      if key.secretState == .present && key.requiresPassphrase {
        if key.hasSavedPassword {
          Button("Forget Passphrase", role: .destructive) { showingForgetConfirmation = true }
        } else {
          Button("Save Passphrase") { showingSavePassphraseSheet = true }
        }
      }
    }
  }

  private var badges: some View {
    HStack(spacing: 8) {
      KeyBadge(text: key.algorithmLabel, size: .regular)
      if !key.capabilities.isEmpty {
        KeyBadge(text: GpgFormat.capabilityList(key.capabilities), size: .regular)
      }
      // A key that is expired, revoked or otherwise unusable says so in the
      // status badge below, and its validity field carries the same word, so
      // the trust badge is only shown when it adds something.
      if let trust = trustBadgeText {
        KeyBadge(text: trust, tint: trustTint, size: .regular)
      }
      KeyBadge(text: GpgFormat.label(key.secretState), size: .regular)
      if key.isRevoked {
        KeyBadge(text: "Revoked", tint: .red, size: .regular)
      } else if key.isExpired {
        KeyBadge(text: "Expired", tint: .orange, size: .regular)
      } else if key.isDisabled {
        KeyBadge(text: "Disabled", tint: .orange, size: .regular)
      }
      if key.hasSavedPassword {
        KeyBadge(text: "Passphrase saved", tint: .green, size: .regular)
      }
    }
  }

  /// The trust levels worth a badge. `expired`, `revoked`, `invalid` and
  /// `disabled` describe the key's state rather than how much it is trusted,
  /// and the status badge already says those.
  private var trustBadgeText: String? {
    switch key.trust {
    case .unknown, .undefined, .never, .marginal, .full, .ultimate:
      return GpgFormat.label(key.trust)
    default:
      return nil
    }
  }

  private var trustTint: Color? {
    switch key.trust {
    case .ultimate, .full: return .green
    case .never: return .orange
    default: return nil
    }
  }

  // MARK: - Sections

  /// The fingerprint in gpg's grouped form, spanning the pane.
  private var fingerprintBlock: some View {
    Text(GpgFormat.groupedFingerprint(key.fingerprint))
      .font(.system(.callout, design: .monospaced))
      .textSelection(.enabled)
      .fixedSize(horizontal: false, vertical: true)
      .frame(maxWidth: .infinity, alignment: .leading)
  }

  private var factList: some View {
    VStack(spacing: 8) {
      ForEach(Array(facts.enumerated()), id: \.element.label) { index, fact in
        if index > 0 { Divider() }
        detailRow(fact.label, value: fact.value, monospaced: fact.monospaced)
      }
    }
  }

  private var userIdList: some View {
    VStack(spacing: 8) {
      ForEach(Array(key.userIds.enumerated()), id: \.offset) { index, uid in
        if index > 0 { Divider() }
        HStack(alignment: .firstTextBaseline, spacing: 8) {
          Text(uid.uid)
            .textSelection(.enabled)
            .strikethrough(uid.isRevoked)
          Spacer(minLength: 8)
          if uid.isRevoked {
            KeyBadge(text: "Revoked", tint: .orange)
          }
          Text(GpgFormat.label(uid.trust))
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
      }
    }
  }

  /// A Grid rather than a `Table`, which needs a height of its own and would
  /// scroll inside this pane's scroll view. A row opens the subkey sheet;
  /// the id is not selectable here so a click anywhere on the row lands.
  private var subkeyTable: some View {
    Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
      GridRow {
        columnHeader("Capability")
        columnHeader("Algorithm")
        columnHeader("ID")
        columnHeader("Expires").gridColumnAlignment(.trailing)
        Color.clear.frame(width: 10, height: 0)
      }
      Divider().gridCellColumns(5)
      ForEach(key.subkeys) { subkey in
        GridRow {
          Text(
            subkey.capabilities.isEmpty
              ? "—" : GpgFormat.capabilityList(subkey.capabilities)
          )
          Text(subkey.algorithmLabel).foregroundStyle(.secondary)
          Text(GpgFormat.keyIdLabel(subkey.keyId))
            .font(.system(.callout, design: .monospaced))
          Text(expiryText(subkey))
            .foregroundStyle(subkey.isExpired || subkey.isRevoked ? .orange : .secondary)
          Image(systemName: "chevron.right")
            .font(.caption2)
            .foregroundStyle(.tertiary)
        }
        .font(.callout)
        .opacity(subkey.isRevoked ? 0.6 : 1)
        // Applied per cell, which is what makes the whole row clickable.
        .contentShape(Rectangle())
        .onTapGesture { selectedSubkey = subkey }
        .help("Show subkey details")
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

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

  // MARK: - Rows

  private func sectionTitle(_ text: String) -> some View {
    Text(text.uppercased())
      .font(.caption)
      .fontWeight(.semibold)
      .foregroundStyle(.secondary)
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(.bottom, 4)
  }

  private func columnHeader(_ text: String) -> some View {
    Text(text.uppercased())
      .font(.caption2)
      .fontWeight(.semibold)
      .foregroundStyle(.secondary)
  }

  private func detailRow(_ label: String, value: String, monospaced: Bool = false) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 12) {
      Text(label)
        .foregroundStyle(.secondary)
        .frame(width: 100, alignment: .leading)
      Text(value)
        .font(monospaced ? .system(.body, design: .monospaced) : .body)
        .textSelection(.enabled)
        .lineLimit(1)
        .truncationMode(.middle)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
  }

  // MARK: - Values

  /// The Details rows, in order. The dates close the section, most recent
  /// first, so the identifiers above them stay together.
  private var facts: [(label: String, value: String, monospaced: Bool)] {
    var items: [(label: String, value: String, monospaced: Bool)] = [
      (label: "Key ID", value: GpgFormat.keyIdLabel(key.shortKeyId), monospaced: true)
    ]
    if let keygrip = key.keygrip {
      items.append((label: "Keygrip", value: keygrip, monospaced: true))
    }
    if let dir = key.secretKeyDir {
      items.append((label: "Stored", value: dir, monospaced: true))
    }
    if let last = recentEvents.first {
      items.append((
        label: "Last used", value: "\(last.timeText) · \(actionLabel(last.action))",
        monospaced: false
      ))
    }
    items.append((label: "Expires", value: expiryText(key), monospaced: false))
    if let created = GpgFormat.date(key.createdAt) {
      items.append((label: "Created", value: created, monospaced: false))
    }
    return items
  }

  private func expiryText(_ key: GpgKeyEntry) -> String {
    if key.isRevoked { return "Revoked" }
    guard let expires = GpgFormat.date(key.expiresAt) else { return "Never" }
    return key.isExpired ? "Expired \(expires)" : expires
  }

  private func expiryText(_ subkey: GpgSubkeyEntry) -> String {
    if subkey.isRevoked { return "Revoked" }
    guard let expires = GpgFormat.date(subkey.expiresAt) else { return "Never" }
    return subkey.isExpired ? "Expired \(expires)" : expires
  }

  private func actionLabel(_ action: String) -> String {
    switch action {
    case "gpg.passphrase": return "Passphrase requested"
    case "gpg.passphrase_saved": return "Passphrase saved"
    case "gpg.confirm": return "Confirmation requested"
    case "gpg.message": return "Message shown"
    case "gpg.agent_conf_changed": return "Agent config changed"
    default: return action
    }
  }

  // MARK: - Actions

  private func copyPublicKey() async {
    isExporting = true
    defer { isExporting = false }
    guard let armored = await model.exportPublicKey(fingerprint: key.fingerprint) else { return }
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(armored, forType: .string)
    copiedPublicKey = true
  }
}
