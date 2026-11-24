import AppKit
import AxoPassFFI
import SwiftUI

// Support for SSH key credentials: a credential of kind "ssh-key" holds an
// OpenSSH private key. Rows show the key from the SSH key listing and never
// reveal the private key.

/// Details of an SSH key credential, shown in place of a value. The key type,
/// comment and fingerprint come from the SSH key listing. Show in SSH selects
/// the key in the SSH pane.
struct SshKeyBox: View {
  let vaultKey: String
  let itemKey: String
  let credKey: String
  let onDelete: () -> Void

  @Environment(VaultsModel.self) private var vaults
  /// Nil in windows without the SSH pane.
  @Environment(SshModel.self) private var ssh: SshModel?

  @State private var isHovering = false
  @State private var copied = false
  @State private var error: String? = nil

  @State private var exportTarget: SshKeyExportTarget? = nil

  private var entry: SshKeyEntry? {
    ssh?.vaultKeyEntry(vaultKey: vaultKey, itemKey: itemKey, credentialKey: credKey)
  }

  private var location: SshVaultKeyLocation {
    SshVaultKeyLocation(
      vaultKey: vaultKey, itemKey: itemKey, credentialKey: credKey, credentialId: nil)
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack(spacing: 10) {
        Image(systemName: KeyIcon.ssh.symbol)
          .font(.title3)
          .foregroundStyle(.secondary)
          .frame(width: 24)
        VStack(alignment: .leading, spacing: 2) {
          HStack(spacing: 6) {
            Text(summary)
              .lineLimit(1)
              .truncationMode(.middle)
            if let entry, !entry.agents.isEmpty {
              KeyBadge(text: "In agent", tint: .green)
            }
          }
          Text(entry.map { "SHA256:\($0.fingerprintSha256)" } ?? "Not in the SSH key list yet")
            .font(.system(.callout, design: .monospaced))
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.middle)
            .textSelection(.enabled)
        }
        Spacer(minLength: 0)
        if copied {
          Image(systemName: "checkmark").foregroundStyle(.green)
        }
        actionMenu
        if ssh != nil {
          Button("Details", action: show)
            .controlSize(.small)
            .disabled(entry == nil)
            .help("Show this key in SSH")
        }
      }
      if let error {
        Text(error).font(.caption).foregroundStyle(.red).textSelection(.enabled)
      }
    }
    .padding(.vertical, 6)
    .padding(.horizontal, 10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    .onHover { isHovering = $0 }
    .animation(.easeInOut(duration: 0.12), value: copied)
    .sheet(item: $exportTarget) { target in
      ExportSshKeySheet(target: target)
    }
    // A key added outside the SSH pane is missing until the listing reloads.
    .task(id: "\(vaultKey)/\(itemKey)/\(credKey)") {
      if entry == nil { await ssh?.reload() }
    }
  }

  /// Key type and comment, such as `ed25519 · tp@example.com`.
  private var summary: String {
    guard let entry else { return "SSH key" }
    var parts = [sshKeyTypeLabel(entry.keyType)]
    if let comment = entry.comment, !comment.isEmpty { parts.append(comment) }
    return parts.joined(separator: " · ")
  }

  private var actionMenu: some View {
    Menu {
      Button("Copy Public Key", action: copyPublicKey)
      Button("Copy Fingerprint", action: copyFingerprint).disabled(entry == nil)
      if ssh != nil {
        Button("Show in SSH", action: show).disabled(entry == nil)
      }
      Divider()
      Button("Export Private Key…") {
        exportTarget = SshKeyExportTarget(location: location, fileName: entry?.name ?? itemKey)
      }
      Divider()
      Button("Delete…", role: .destructive, action: onDelete)
    } label: {
      Image(systemName: "ellipsis")
    }
    .menuStyle(.borderlessButton)
    .menuIndicator(.hidden)
    .foregroundStyle(.secondary)
    .fixedSize()
    .help("SSH key actions")
    .opacity(isHovering ? 1 : 0)
    .animation(.easeInOut(duration: 0.12), value: isHovering)
  }

  private func show() {
    guard let ssh, let entry else { return }
    ssh.show(fingerprintSha256: entry.fingerprintSha256, vaults: vaults)
  }

  /// The listing holds the public key. A key missing from it is read from the
  /// vault.
  private func copyPublicKey() {
    Task {
      do {
        let line: String
        if let known = entry?.publicKeyOpenssh {
          line = known
        } else {
          line = try await vaults.sshKeyPublicKey(location: location)
        }
        error = nil
        copy(line)
      } catch {
        self.error = error.userMessage
      }
    }
  }

  private func copyFingerprint() {
    guard let entry else { return }
    copy("SHA256:\(entry.fingerprintSha256)")
  }

  private func copy(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
    copied = true
    Task {
      try? await Task.sleep(for: .seconds(1.2))
      copied = false
    }
  }
}

/// Lowercase key type label, as in the SSH key list.
func sshKeyTypeLabel(_ type: SshKeyType) -> String {
  switch type {
  case .rsa: return "rsa"
  case .ed25519: return "ed25519"
  case .ecdsa: return "ecdsa"
  case .dsa: return "dsa"
  case .unknown: return "unknown"
  }
}
