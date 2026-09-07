import AppKit
import AxoPassFFI
import SwiftUI

/// Everything about one subkey that the subkey table in the detail pane has no
/// room for: its full fingerprint, keygrip, and secret key state.
struct GpgSubkeySheet: View {
  @Bindable var model: GpgModel
  /// The subkey the row was for. `subkey` re-reads it from the model, so
  /// saving a passphrase updates this sheet rather than a stale copy.
  let selected: GpgSubkeyEntry
  /// The primary key's name, so the sheet says which key this belongs to.
  let keyName: String

  @Environment(\.dismiss) private var dismiss
  @State private var showingSavePassphraseSheet = false
  @State private var showingForgetConfirmation = false

  private var subkey: GpgSubkeyEntry {
    model.selectedKey?.subkeys.first { $0.keyId == selected.keyId } ?? selected
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      header
      Divider()
      badges
      if let fingerprint = subkey.fingerprint {
        labelledBlock("Fingerprint", value: GpgFormat.groupedFingerprint(fingerprint))
      }
      VStack(spacing: 8) {
        ForEach(Array(facts.enumerated()), id: \.element.label) { index, fact in
          if index > 0 { Divider() }
          InspectorRow(
            fact.label, value: fact.value, monospaced: fact.monospaced,
            truncatesMiddle: true)
        }
      }
      .labeledContentStyle(.inspectorField)
      Divider()
      footer
    }
    .padding(20)
    .frame(width: 460)
    .sheet(isPresented: $showingSavePassphraseSheet) {
      GpgSavePassphraseSheet(keyName: subkeyName) { passphrase in
        guard let keygrip = subkey.keygrip else { return "This subkey has no keygrip" }
        return await model.savePassphrase(
          keyId: subkey.keyId, keygrip: keygrip, passphrase: passphrase)
      }
    }
    .confirmationDialog(
      "Forget saved passphrase for \(subkeyName)?",
      isPresented: $showingForgetConfirmation, titleVisibility: .visible
    ) {
      Button("Forget", role: .destructive) {
        guard let keygrip = subkey.keygrip else { return }
        Task { await model.forgetPassphrase(keygrip: keygrip) }
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text("gpg will ask for the passphrase again the next time it needs this subkey.")
    }
  }

  /// How the subkey is named in prompts: its capabilities read better than the
  /// key id alone.
  private var subkeyName: String {
    let capabilities = GpgFormat.capabilityList(subkey.capabilities)
    return capabilities.isEmpty
      ? GpgFormat.keyIdLabel(subkey.keyId) : "\(keyName) (\(capabilities.lowercased()))"
  }

  private var header: some View {
    HStack(spacing: 10) {
      Image(systemName: "key.fill")
        .font(.title2)
        .foregroundStyle(.tint)
      VStack(alignment: .leading, spacing: 2) {
        Text(GpgFormat.keyIdLabel(subkey.keyId))
          .font(.headline.monospaced())
          .textSelection(.enabled)
        Text("Subkey of \(keyName)")
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer()
    }
  }

  private var badges: some View {
    HStack(spacing: 8) {
      KeyBadge(text: subkey.algorithmLabel, size: .regular)
      if !subkey.capabilities.isEmpty {
        KeyBadge(text: GpgFormat.capabilityList(subkey.capabilities), size: .regular)
      }
      KeyBadge(text: GpgFormat.label(subkey.secretState), size: .regular)
      if subkey.isRevoked {
        KeyBadge(text: "Revoked", tint: .red, size: .regular)
      } else if subkey.isExpired {
        KeyBadge(text: "Expired", tint: .orange, size: .regular)
      }
      if subkey.hasSavedPassword {
        KeyBadge(text: "Passphrase saved", tint: .green, size: .regular)
      }
    }
  }

  private var footer: some View {
    HStack {
      Button("Copy Fingerprint") { copy(subkey.fingerprint ?? subkey.keyId) }
      Spacer()
      // Each secret half is encrypted on its own, so a subkey's passphrase is
      // saved here rather than with the primary key's.
      if subkey.secretState == .present && subkey.requiresPassphrase {
        if subkey.hasSavedPassword {
          Button("Forget Passphrase", role: .destructive) { showingForgetConfirmation = true }
        } else {
          Button("Save Passphrase") { showingSavePassphraseSheet = true }
        }
      }
      Button("Done") { dismiss() }
        .keyboardShortcut(.defaultAction)
    }
  }

  private func labelledBlock(_ label: String, value: String) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(label.uppercased())
        .font(.caption)
        .fontWeight(.semibold)
        .foregroundStyle(.secondary)
      Text(value)
        .font(.system(.callout, design: .monospaced))
        .textSelection(.enabled)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
  }

  private var facts: [(label: String, value: String, monospaced: Bool)] {
    var items: [(label: String, value: String, monospaced: Bool)] = []
    if let created = GpgFormat.date(subkey.createdAt) {
      items.append((label: "Created", value: created, monospaced: false))
    }
    items.append((label: "Expires", value: expiryText, monospaced: false))
    items.append((
      label: "Capability",
      value: subkey.capabilities.isEmpty ? "—" : GpgFormat.capabilityList(subkey.capabilities),
      monospaced: false
    ))
    if let curve = subkey.curve {
      items.append((label: "Curve", value: curve, monospaced: false))
    }
    if let keygrip = subkey.keygrip {
      items.append((label: "Keygrip", value: keygrip, monospaced: true))
    }
    return items
  }

  private var expiryText: String {
    if subkey.isRevoked { return "Revoked" }
    guard let expires = GpgFormat.date(subkey.expiresAt) else { return "Never" }
    return subkey.isExpired ? "Expired \(expires)" : expires
  }

  private func copy(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
  }
}
