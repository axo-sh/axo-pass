import AppKit
import AxoPassFFI
import SwiftUI

/// Generates an Ed25519 key in a vault, or imports a private key file into one.
/// The key goes into a new item or an existing item of the chosen vault. An
/// encrypted key file asks for its passphrase and is stored unencrypted.
struct AddVaultKeySheet: View {
  enum Mode {
    case generate
    case importFile

    var title: String {
      switch self {
      case .generate: return "Generate Vault Key"
      case .importFile: return "Import Key from File"
      }
    }

    var action: String {
      switch self {
      case .generate: return "Generate"
      case .importFile: return "Import"
      }
    }
  }

  let mode: Mode
  let ssh: SshModel

  @Environment(VaultsModel.self) private var vaults
  @Environment(\.dismiss) private var dismiss

  @State private var vaultKey = ""
  @State private var usesExistingItem = false
  @State private var itemTitle = ""
  @State private var itemKey: String? = nil
  @State private var items: [ItemInfo] = []
  @State private var comment = ""
  @State private var file: URL? = nil
  @State private var passphrase = ""
  @State private var needsPassphrase = false
  @State private var isWorking = false
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      HStack(spacing: 10) {
        Image(systemName: KeyIcon.ssh.filledSymbol)
          .font(.title2)
          .foregroundStyle(.tint)
        Text(mode.title).font(.headline)
      }
      Text(explanation)
        .fixedSize(horizontal: false, vertical: true)
      Form {
        if mode == .importFile {
          fileRow
          if needsPassphrase {
            SecureField("Passphrase", text: $passphrase)
          }
        }
        Picker("Vault", selection: $vaultKey) {
          ForEach(vaults.vaults, id: \.key) { vault in
            Text(vault.name ?? vault.key).tag(vault.key)
          }
        }
        Picker("Store in", selection: $usesExistingItem) {
          Text("New item").tag(false)
          Text("Existing item").tag(true)
        }
        .pickerStyle(.segmented)
        if usesExistingItem {
          Picker("Item", selection: $itemKey) {
            Text("Choose an item").tag(String?.none)
            ForEach(items, id: \.key) { item in
              Text(item.title).tag(String?.some(item.key))
            }
          }
        } else {
          TextField("Item title", text: $itemTitle)
        }
        TextField(commentLabel, text: $comment)
      }
      .formStyle(.columns)
      if let error {
        Label(error, systemImage: "exclamationmark.circle.fill")
          .font(.callout)
          .foregroundStyle(.red)
          .fixedSize(horizontal: false, vertical: true)
      }
      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button(mode.action) { Task { await submit() } }
          .keyboardShortcut(.defaultAction)
          .disabled(!canSubmit)
      }
    }
    .padding(20)
    .frame(width: 420)
    .onAppear {
      if vaultKey.isEmpty {
        vaultKey = vaults.vaults.first?.key ?? ""
      }
    }
    .task(id: vaultKey) {
      guard !vaultKey.isEmpty else { return }
      items = await vaults.destinationItems(in: vaultKey)
      if let itemKey, !items.contains(where: { $0.key == itemKey }) {
        self.itemKey = nil
      }
    }
  }

  private var explanation: String {
    switch mode {
    case .generate:
      return
        "Creates an Ed25519 key in a vault. It syncs with the vault. The private key stays "
        + "inside the app, which signs for ssh."
    case .importFile:
      return
        "Stores an OpenSSH private key in a vault. An encrypted key is decrypted with its "
        + "passphrase and stored unencrypted. The original file is not changed."
    }
  }

  private var commentLabel: String {
    mode == .importFile ? "Comment (optional)" : "Comment"
  }

  private var fileRow: some View {
    LabeledContent("Key file") {
      HStack {
        Text(file?.path ?? "None chosen")
          .foregroundStyle(file == nil ? .secondary : .primary)
          .lineLimit(1)
          .truncationMode(.middle)
        Spacer(minLength: 6)
        Button("Choose…") { chooseFile() }
      }
    }
  }

  private var canSubmit: Bool {
    guard !isWorking, !vaultKey.isEmpty else { return false }
    if mode == .importFile {
      guard file != nil else { return false }
      if needsPassphrase && passphrase.isEmpty { return false }
    }
    return usesExistingItem ? itemKey != nil : true
  }

  private func chooseFile() {
    let panel = NSOpenPanel()
    panel.canChooseFiles = true
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    panel.showsHiddenFiles = true
    panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".ssh")
    panel.prompt = "Choose"
    if panel.runModal() == .OK, let url = panel.url { choose(url) }
  }

  private func choose(_ url: URL) {
    file = url
    needsPassphrase = false
    passphrase = ""
    error = nil
    if itemTitle.isEmpty { itemTitle = url.lastPathComponent }
  }

  private func submit() async {
    isWorking = true
    error = nil
    defer { isWorking = false }
    let existing = usesExistingItem ? itemKey : nil
    let title = itemTitle.trimmingCharacters(in: .whitespaces)
    do {
      let added: VaultSshKeyInfo
      switch mode {
      case .generate:
        added = try await vaults.generateSshKey(
          vaultKey: vaultKey, itemKey: existing, itemTitle: title, comment: comment)
      case .importFile:
        guard let file else { return }
        added = try await vaults.importSshKey(
          vaultKey: vaultKey, itemKey: existing, itemTitle: title, url: file,
          passphrase: needsPassphrase ? passphrase : nil, comment: comment)
      }
      await ssh.reload()
      ssh.selectedFingerprint = String(added.fingerprintSha256.dropFirst("SHA256:".count))
      dismiss()
    } catch FfiError.SshKeyPassphraseRequired {
      needsPassphrase = true
      error = "The key file is encrypted. Enter its passphrase."
    } catch FfiError.SshKeyWrongPassphrase {
      needsPassphrase = true
      error = "The passphrase does not decrypt the key."
    } catch FfiError.SshKeyDuplicate(let fingerprint) {
      error = "This vault already holds the key \(fingerprint)."
    } catch FfiError.InvalidInput(let message), FfiError.Internal(let message),
      FfiError.NotFound(let message)
    {
      error = message
    } catch FfiError.AuthExpired, FfiError.AuthCancelled {
      error = "Authentication expired."
    } catch {
      self.error = error.userMessage
    }
  }
}
