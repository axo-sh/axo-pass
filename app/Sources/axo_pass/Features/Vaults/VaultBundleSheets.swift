import AppKit
import AxoPassFFI
import SwiftUI
import UniformTypeIdentifiers

/// The file extension for an exported vault bundle. Matches the CLI's
/// `VAULT_EXTENSION`.
private let bundleExtension = "axovault"

/// Today's date as a `-YYYYMMDD` filename suffix.
private func dateSuffix(_ date: Date = Date()) -> String {
  let f = DateFormatter()
  f.locale = Locale(identifier: "en_US_POSIX")
  f.dateFormat = "yyyyMMdd"
  return "-\(f.string(from: date))"
}

/// The save-panel filename for a bundle holding `keys`. One vault takes the
/// vault's key, otherwise `vaults`. Both are suffixed with today's date.
func bundleFileName(for keys: [String]) -> String {
  let base = keys.count == 1 ? keys[0] : "vaults"
  return "\(base)\(dateSuffix()).\(bundleExtension)"
}

/// Export one or more vaults to a passphrase-encrypted bundle file. Pick the
/// vaults, set a passphrase, then choose a destination with the save panel.
/// Passing `only` locks the export to that one vault and hides the picker.
struct VaultExportSheet: View {
  let model: VaultsModel
  private let lockedKey: String?

  @Environment(\.dismiss) private var dismiss
  @State private var selectedKeys: Set<String>
  @State private var passphrase = ""
  @State private var confirmPassphrase = ""
  @State private var isExporting = false
  @State private var error: String?
  @State private var done = false

  init(model: VaultsModel, only: String? = nil) {
    self.model = model
    self.lockedKey = only
    let initial = only.map { Set([$0]) } ?? Set(model.vaults.map(\.key))
    _selectedKeys = State(initialValue: initial)
  }

  /// The vaults the picker offers. Empty when locked to a single vault.
  private var pickableVaults: [VaultInfo] {
    lockedKey == nil ? model.vaults : []
  }

  private var passphraseMismatch: Bool {
    !confirmPassphrase.isEmpty && passphrase != confirmPassphrase
  }

  private var canExport: Bool {
    !selectedKeys.isEmpty && !passphrase.isEmpty && passphrase == confirmPassphrase
      && !isExporting
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      VStack(alignment: .leading, spacing: 4) {
        Text("Export Vaults").font(.headline)
        Text("Writes the selected vaults to a single encrypted file you can import on another Mac.")
          .font(.caption)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
      }

      if let lockedKey {
        let vault = model.vaults.first { $0.key == lockedKey }
        GroupBox {
          VStack(alignment: .leading, spacing: 1) {
            Text(vault?.name ?? lockedKey)
            if vault?.name != nil {
              Text(lockedKey).font(.caption).foregroundStyle(.secondary)
            }
          }
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(6)
        }
      } else {
        GroupBox {
          if pickableVaults.isEmpty {
            Text("No vaults to export.")
              .font(.callout)
              .foregroundStyle(.secondary)
              .frame(maxWidth: .infinity, alignment: .leading)
              .padding(6)
          } else {
            ScrollView {
              VStack(alignment: .leading, spacing: 6) {
                ForEach(pickableVaults, id: \.key) { vault in
                  Toggle(isOn: binding(for: vault.key)) {
                    VStack(alignment: .leading, spacing: 1) {
                      Text(vault.name ?? vault.key)
                      if vault.name != nil {
                        Text(vault.key).font(.caption).foregroundStyle(.secondary)
                      }
                    }
                  }
                }
              }
              .padding(6)
              .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 160)
          }
        }
      }

      Form {
        SecureField("Vault passphrase", text: $passphrase)
        SecureField("Confirm passphrase", text: $confirmPassphrase)
      }

      if passphraseMismatch {
        Label("Passphrases do not match.", systemImage: "exclamationmark.triangle.fill")
          .font(.caption)
          .foregroundStyle(.orange)
      }
      if let error {
        Label(error, systemImage: "xmark.circle.fill")
          .font(.caption)
          .foregroundStyle(.red)
          .lineLimit(3)
          .fixedSize(horizontal: false, vertical: true)
      }

      HStack {
        if isExporting {
          ProgressView().controlSize(.small)
          Text("Exporting…").font(.caption).foregroundStyle(.secondary)
        }
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Export…") { export() }
          .keyboardShortcut(.defaultAction)
          .disabled(!canExport)
      }
    }
    .padding(20)
    .frame(width: 420)
  }

  private func binding(for key: String) -> Binding<Bool> {
    Binding(
      get: { selectedKeys.contains(key) },
      set: { on in
        if on { selectedKeys.insert(key) } else { selectedKeys.remove(key) }
      })
  }

  private func export() {
    guard canExport, let destination = promptForDestination() else { return }
    let keys = model.vaults.map(\.key).filter(selectedKeys.contains)
    Task {
      isExporting = true
      error = await model.exportBundle(
        vaultKeys: keys, destination: destination, passphrase: passphrase)
      isExporting = false
      if error == nil { dismiss() }
    }
  }

  private func promptForDestination() -> URL? {
    let panel = NSSavePanel()
    let keys = model.vaults.map(\.key).filter(selectedKeys.contains)
    panel.nameFieldStringValue = bundleFileName(for: keys)
    if let type = UTType(filenameExtension: bundleExtension) {
      panel.allowedContentTypes = [type]
    }
    panel.isExtensionHidden = false
    return panel.runModal() == .OK ? panel.url : nil
  }
}

/// Import vaults from a bundle file. Pick the file and enter its passphrase,
/// then choose which vaults to import and the key to import each under.
struct VaultImportSheet: View {
  let model: VaultsModel

  @Environment(\.dismiss) private var dismiss

  @State private var source: URL?
  @State private var passphrase = ""
  @State private var isOpening = false
  @State private var isImporting = false
  @State private var error: String?
  @State private var rows: [Row] = []

  /// One vault in an opened bundle, with the user's import choices.
  private struct Row: Identifiable {
    let info: BundleVaultInfo
    var include: Bool
    var targetKey: String
    var id: String { info.id }
  }

  private var opened: Bool { !rows.isEmpty }

  private var canOpen: Bool { source != nil && !passphrase.isEmpty && !isOpening }

  private var canImport: Bool {
    let chosen = rows.filter(\.include)
    return !chosen.isEmpty
      && chosen.allSatisfy { !$0.targetKey.trimmingCharacters(in: .whitespaces).isEmpty }
      && !isImporting
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      VStack(alignment: .leading, spacing: 4) {
        Text("Import Vaults").font(.headline)
        Text("Reads vaults from an encrypted bundle file exported from Axo Pass.")
          .font(.caption)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
      }

      HStack(spacing: 8) {
        Button("Choose File…") { chooseFile() }
        Text(source?.lastPathComponent ?? "No file selected")
          .font(.callout)
          .foregroundStyle(source == nil ? .secondary : .primary)
          .lineLimit(1)
          .truncationMode(.middle)
      }

      if !opened {
        SecureField("Passphrase", text: $passphrase)
          .onSubmit { open() }
      } else {
        GroupBox {
          ScrollView {
            VStack(alignment: .leading, spacing: 8) {
              ForEach($rows) { $row in
                HStack(spacing: 8) {
                  Toggle("", isOn: $row.include).labelsHidden()
                  VStack(alignment: .leading, spacing: 1) {
                    Text(row.info.name ?? row.info.defaultKey ?? row.info.id)
                      .lineLimit(1)
                    TextField("Import as", text: $row.targetKey)
                      .textFieldStyle(.roundedBorder)
                      .disabled(!row.include)
                  }
                }
              }
            }
            .padding(4)
            .frame(maxWidth: .infinity, alignment: .leading)
          }
          .frame(maxHeight: 200)
        }
      }

      if let error {
        Label(error, systemImage: "xmark.circle.fill")
          .font(.caption)
          .foregroundStyle(.red)
          .lineLimit(3)
          .fixedSize(horizontal: false, vertical: true)
      }

      HStack {
        if isOpening || isImporting {
          ProgressView().controlSize(.small)
          Text(isOpening ? "Opening…" : "Importing…")
            .font(.caption).foregroundStyle(.secondary)
        }
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        if opened {
          Button("Import") { performImport() }
            .keyboardShortcut(.defaultAction)
            .disabled(!canImport)
        } else {
          Button("Open") { open() }
            .keyboardShortcut(.defaultAction)
            .disabled(!canOpen)
        }
      }
    }
    .padding(20)
    .frame(width: 440)
  }

  private func chooseFile() {
    let panel = NSOpenPanel()
    panel.canChooseFiles = true
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    if let type = UTType(filenameExtension: bundleExtension) {
      panel.allowedContentTypes = [type]
    }
    if panel.runModal() == .OK {
      source = panel.url
      rows = []
      error = nil
    }
  }

  private func open() {
    guard canOpen, let source else { return }
    Task {
      isOpening = true
      let result = await model.inspectBundle(source: source, passphrase: passphrase)
      isOpening = false
      if let vaults = result.vaults {
        error = nil
        rows = vaults.map { info in
          Row(
            info: info, include: true,
            targetKey: info.defaultKey ?? info.name ?? "imported")
        }
      } else {
        error = result.message
      }
    }
  }

  private func performImport() {
    guard canImport, let source else { return }
    let selection = rows.filter(\.include).map {
      BundleImportSelection(
        id: $0.info.id, targetKey: $0.targetKey.trimmingCharacters(in: .whitespaces))
    }
    Task {
      isImporting = true
      let result = await model.importBundle(
        source: source, passphrase: passphrase, selection: selection)
      isImporting = false
      if result.keys != nil {
        dismiss()
      } else {
        error = result.message
      }
    }
  }
}
