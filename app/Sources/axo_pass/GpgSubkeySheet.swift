import AppKit
import AxoPassFFI
import SwiftUI

/// Everything about one subkey that the subkey table in the detail pane has no
/// room for: its full fingerprint, keygrip, and secret key state.
struct GpgSubkeySheet: View {
  let subkey: GpgSubkeyEntry
  /// The primary key's name, so the sheet says which key this belongs to.
  let keyName: String

  @Environment(\.dismiss) private var dismiss

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
          detailRow(fact.label, value: fact.value, monospaced: fact.monospaced)
        }
      }
      Divider()
      footer
    }
    .padding(20)
    .frame(width: 460)
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

  private func detailRow(_ label: String, value: String, monospaced: Bool) -> some View {
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
