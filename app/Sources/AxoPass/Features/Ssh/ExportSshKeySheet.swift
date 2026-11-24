import AppKit
import AxoPassFFI
import SwiftUI

/// Vault key to export, for `ExportSshKeySheet`.
struct SshKeyExportTarget: Identifiable {
  let location: SshVaultKeyLocation
  /// Default file name, such as `id_vault_<id>`.
  let fileName: String

  var id: String { "\(location.vaultKey)/\(location.itemKey)/\(location.credentialKey)" }
}

/// Context menu items of a vault key, in the SSH list and the key detail.
/// Empty for other keys.
struct VaultKeyMenuItems: View {
  let key: SshKeyEntry
  /// Open the export sheet.
  let onExport: (SshKeyExportTarget) -> Void

  @Environment(VaultsModel.self) private var vaults

  var body: some View {
    if let location = key.vaultKey {
      Button("Copy Public Key") {
        Task {
          if let line = try? await vaults.sshKeyPublicKey(location: location) {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(line, forType: .string)
          }
        }
      }
      Button("Show in Vault") {
        Task { await vaults.showSshKeyItem(location) }
      }
      Divider()
      Button("Export Private Key…") {
        onExport(SshKeyExportTarget(location: location, fileName: key.name))
      }
    }
  }
}

/// Writes the private key of a vault key to a file the user picks. An optional
/// passphrase encrypts the file.
struct ExportSshKeySheet: View {
  let target: SshKeyExportTarget

  @Environment(VaultsModel.self) private var vaults
  @Environment(\.dismiss) private var dismiss

  @State private var passphrase = ""
  @State private var confirmation = ""
  @State private var savesPassphrase = true
  @State private var isWorking = false
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      HStack(spacing: 10) {
        Image(systemName: KeyIcon.ssh.filledSymbol)
          .font(.title2)
          .foregroundStyle(.tint)
        Text("Export Private Key").font(.headline)
      }
      Text(
        "Writes the private key to an OpenSSH key file. Add a passphrase to protect your private "
          + "key from unauthorized access."
      )
      .fixedSize(horizontal: false, vertical: true)
      Form {
        SecureField("Passphrase (optional)", text: $passphrase)
        SecureField("Confirm passphrase", text: $confirmation)
          .disabled(passphrase.isEmpty)
        Toggle("Save passphrase in item", isOn: $savesPassphrase)
          .disabled(passphrase.isEmpty)
      }
      .formStyle(.columns)
      if let message {
        Label(message, systemImage: "exclamationmark.triangle.fill")
          .font(.callout)
          .foregroundStyle(.red)
          .fixedSize(horizontal: false, vertical: true)
      }
      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Export…") { Task { await export() } }
          .keyboardShortcut(.defaultAction)
          .disabled(!canExport)
      }
    }
    .padding(20)
    .frame(width: 420)
  }

  private var passphrasesMatch: Bool { passphrase == confirmation }

  private var canExport: Bool { !isWorking && passphrasesMatch }

  /// Mismatch shows once the confirmation has text.
  private var message: String? {
    if !confirmation.isEmpty && !passphrasesMatch { return "The passphrases do not match." }
    return error
  }

  private func export() async {
    let panel = NSSavePanel()
    panel.nameFieldStringValue = safeFileName(target.fileName)
    panel.showsHiddenFiles = true
    panel.isExtensionHidden = false
    guard panel.runModal() == .OK, let url = panel.url else { return }
    isWorking = true
    error = nil
    defer { isWorking = false }
    do {
      try await vaults.exportSshKey(
        location: target.location, to: url, passphrase: passphrase.isEmpty ? nil : passphrase)
      if savesPassphrase && !passphrase.isEmpty,
        let failure = await vaults.saveSshKeyPassphrase(
          location: target.location, passphrase: passphrase)
      {
        error = "The key was exported, but the passphrase was not saved. \(failure)"
        return
      }
      dismiss()
    } catch FfiError.AuthExpired, FfiError.AuthCancelled {
      error = "Authentication expired."
    } catch FfiError.InvalidInput(let message), FfiError.Internal(let message),
      FfiError.NotFound(let message)
    {
      error = message
    } catch {
      self.error = error.userMessage
    }
  }
}
