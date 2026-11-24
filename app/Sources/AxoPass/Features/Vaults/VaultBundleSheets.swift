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

/// Bridges the FFI export-progress callback, which fires on a background
/// thread, to a main-actor closure.
final class ExportProgressForwarder: VaultExportProgressDelegate, @unchecked Sendable {
  private let handler: @MainActor (VaultExportStage, UInt32, UInt32) -> Void

  init(_ handler: @escaping @MainActor (VaultExportStage, UInt32, UInt32) -> Void) {
    self.handler = handler
  }

  func onStage(stage: VaultExportStage, index: UInt32, total: UInt32) {
    Task { @MainActor in handler(stage, index, total) }
  }
}

/// The work-factor presets offered in the export sheet, in ascending cost.
private let workFactorChoices: [(label: String, value: ExportWorkFactor)] = [
  ("Fast", .fast),
  ("Balanced", .balanced),
  ("Secure (recommended)", .secure),
  ("Paranoid", .paranoid),
]

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
  @State private var workFactor: ExportWorkFactor = .secure
  @State private var includePasskeys = true
  @State private var progressText: String?
  /// Report of a finished export that left file blobs out. Nil until then.
  @State private var report: VaultExportReport?

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

      if let lockedKey {
        VStack(alignment: .leading, spacing: 4) {
          VaultSheetTitle(
            name: model.vaults.first { $0.key == lockedKey }?.name ?? lockedKey,
            key: lockedKey, section: "Export Backup")
          Text(
            "Backs up the selected vault to a single encrypted file. For exporting multiple vaults at once, see settings."
          )
          .font(.body)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        }
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
        VStack(alignment: .leading, spacing: 4) {
          Text("Export Vaults").font(.headline)
          Text("Backs up the selected vaults to a single encrypted file.")
            .font(.body)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
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
        Picker("Encryption strength", selection: $workFactor) {
          ForEach(workFactorChoices, id: \.label) { choice in
            Text(choice.label).tag(choice.value)
          }
        }.padding(.top, 4)
        Text(exportWorkFactorCostHint(factor: workFactor))
          .font(.caption)
          .foregroundStyle(.secondary)
        Toggle("Include passkeys", isOn: $includePasskeys)
          .padding(.top, 4)
        if !includePasskeys {
          Text("Passkeys stay in your vaults and are left out of the file.")
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        Text("Files in Recently Deleted are not exported.")
          .font(.caption)
          .foregroundStyle(.secondary)
          .padding(.top, 4)
      }
      .disabled(isExporting || report != nil)

      if let report {
        missingBlobsView(report)
      }

      if passphraseMismatch {
        Label("Passphrases do not match.", systemImage: "exclamationmark.circle.fill")
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
          Text(progressText ?? "Exporting…").font(.caption).foregroundStyle(.secondary)
        }
        Spacer()
        if report != nil {
          Button("Done") { dismiss() }
            .keyboardShortcut(.defaultAction)
        } else {
          Button("Cancel") { dismiss() }
            .keyboardShortcut(.cancelAction)
          Button("Export…") { export() }
            .keyboardShortcut(.defaultAction)
            .disabled(!canExport)
        }
      }
    }
    .padding(20)
    .frame(width: 420)
  }

  /// Notice for an export that wrote the bundle without some file blobs. The
  /// files import as missing locally.
  private func missingBlobsView(_ report: VaultExportReport) -> some View {
    VStack(alignment: .leading, spacing: 6) {
      Label(
        "The export finished, but \(report.missingBlobs.count) file(s) could not be included.",
        systemImage: "exclamationmark.circle.fill"
      )
      .font(.callout)
      .foregroundStyle(.orange)
      .fixedSize(horizontal: false, vertical: true)
      Text(
        "Their records are in the file. After an import they show as missing until the contents are available on that Mac."
      )
      .font(.caption)
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
      GroupBox {
        ScrollView {
          VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(report.missingBlobs.enumerated()), id: \.offset) { _, missing in
              VStack(alignment: .leading, spacing: 1) {
                Text(vaultName(forId: missing.vaultId))
                Text(missing.reason).font(.caption).foregroundStyle(.secondary)
                Text(String(missing.blob.prefix(12)))
                  .font(.caption.monospaced())
                  .foregroundStyle(.tertiary)
              }
            }
          }
          .padding(4)
          .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxHeight: 120)
      }
    }
  }

  /// Name of the vault with short id `id`, or the id if no vault matches.
  private func vaultName(forId id: String) -> String {
    let vault = model.vaults.first { $0.id == id }
    return vault?.name ?? vault?.key ?? id
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
      progressText = "Preparing…"
      let result = await model.exportBundle(
        vaultKeys: keys, destination: destination, passphrase: passphrase,
        workFactor: workFactor, includePasskeys: includePasskeys,
        onStage: { stage, index, total in
          switch stage {
          case .collectingVault:
            progressText = "Collecting vault \(index)/\(total)…"
          case .derivingKey:
            progressText = "Deriving key…"
          case .writing:
            progressText = "Writing file…"
          }
        })
      isExporting = false
      progressText = nil
      error = result.message
      if let exported = result.report {
        if exported.missingBlobs.isEmpty {
          dismiss()
        } else {
          report = exported
        }
      }
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

  /// One vault in an opened bundle, with the user's import choices. A vault
  /// whose id exists on this Mac is imported as a copy or skipped, and is
  /// skipped until the user picks a copy.
  private struct Row: Identifiable {
    let info: BundleVaultInfo
    var include: Bool
    var copy: Bool
    var targetKey: String
    var id: String { info.id }

    /// A vault that is on this Mac and holds files can only be skipped. Its
    /// file blobs are bound to the vault id, so a copy is refused.
    var skipOnly: Bool { info.idExists && info.files > 0 }

    /// Whether the vault is written by the import.
    var imports: Bool { info.idExists ? copy && !skipOnly : include }

    /// Action sent for the vault. Only read if the vault is imported.
    var action: BundleImportAction { info.idExists ? .copy : .default }
  }

  private var opened: Bool { !rows.isEmpty }

  private var canOpen: Bool { source != nil && !passphrase.isEmpty && !isOpening }

  private var canImport: Bool {
    let chosen = rows.filter(\.imports)
    return !chosen.isEmpty
      && chosen.allSatisfy { !$0.targetKey.trimmingCharacters(in: .whitespaces).isEmpty }
      && !isImporting
  }

  /// Key suggested for a vault of the bundle. A vault whose id exists on this
  /// Mac is suggested `{key}-copy`, since its bundle key is usually the key of
  /// the vault it was exported from. Keys of vaults on this Mac and of earlier
  /// rows are skipped.
  private func suggestedKey(for info: BundleVaultInfo, taken: Set<String>) -> String {
    let base = info.defaultKey ?? info.name ?? "imported"
    guard info.idExists else { return base }
    let existing = Set(model.vaults.map(\.key)).union(taken)
    let copy = "\(base)-copy"
    var candidate = copy
    var n = 2
    while existing.contains(candidate) {
      candidate = "\(copy)-\(n)"
      n += 1
    }
    return candidate
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
        Form {
          SecureField("Passphrase", text: $passphrase)
            .onSubmit { open() }
        }
      } else {
        GroupBox {
          ScrollView {
            VStack(alignment: .leading, spacing: 8) {
              ForEach($rows) { $row in
                HStack(alignment: .top, spacing: 8) {
                  Toggle("", isOn: $row.include).labelsHidden()
                    .disabled(row.info.idExists)
                    .opacity(row.info.idExists ? 0 : 1)
                  VStack(alignment: .leading, spacing: 4) {
                    Text(row.info.name ?? row.info.defaultKey ?? row.info.id)
                      .lineLimit(1)
                    if row.info.idExists {
                      Text("Vault is already on this Mac.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                      if row.skipOnly {
                        Text(
                          "It holds files, which are tied to the vault and cannot be imported as a copy. It is skipped."
                        )
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                      } else {
                        Picker("", selection: $row.copy) {
                          Text("Skip").tag(false)
                          Text("Import as Copy").tag(true)
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .fixedSize()
                      }
                    }
                    if row.info.files > 0 {
                      Text(fileSummary(row.info))
                        .font(.caption)
                        .foregroundStyle(row.info.missingFiles > 0 ? .orange : .secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    }
                    if !row.skipOnly {
                      TextField("Import as", text: $row.targetKey)
                        .textFieldStyle(.roundedBorder)
                        .disabled(!row.imports)
                    }
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

  /// File count of a bundle vault, and how many of them lack their contents.
  /// A file without contents imports as missing on this Mac.
  private func fileSummary(_ info: BundleVaultInfo) -> String {
    let files = info.files == 1 ? "1 file" : "\(info.files) files"
    switch info.missingFiles {
    case 0: return files
    case info.files:
      return "\(files), without contents in the bundle. They import as missing."
    default:
      return
        "\(files), \(info.missingFiles) without contents in the bundle. Those import as missing."
    }
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
        var taken = Set<String>()
        rows = vaults.map { info in
          let key = suggestedKey(for: info, taken: taken)
          taken.insert(key)
          return Row(info: info, include: true, copy: false, targetKey: key)
        }
      } else {
        error = result.message
      }
    }
  }

  private func performImport() {
    guard canImport, let source else { return }
    let selection = rows.filter(\.imports).map { row in
      BundleImportSelection(
        id: row.info.id, targetKey: row.targetKey.trimmingCharacters(in: .whitespaces),
        action: row.action)
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
