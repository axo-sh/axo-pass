import AppKit
import AxoPassFFI
import SwiftUI
import UniformTypeIdentifiers

/// Password manager that an export comes from.
enum ImportSource: String, CaseIterable, Identifiable {
  case onePassword
  case applePasswords

  var id: String { rawValue }

  var title: String {
    switch self {
    case .onePassword: "1Password"
    case .applePasswords: "Apple Passwords"
    }
  }

  /// Name of the new vault.
  var defaultVaultName: String { title }

  var symbol: String {
    switch self {
    case .onePassword: "1.circle.fill"
    case .applePasswords: "key.fill"
    }
  }

  /// Steps to export from the source.
  var exportSteps: [String] {
    switch self {
    case .onePassword:
      [
        "Open 1Password 7 and unlock it.",
        "Choose File > Export > All Items.",
        "Choose the 1Password Interchange Format (.1pif) and save the export.",
      ]
    case .applePasswords:
      [
        "Open the Passwords app and unlock it.",
        "Choose File > Export All Passwords.",
        "Save the .csv file.",
      ]
    }
  }

  /// Note on what the format holds.
  var formatNote: String {
    switch self {
    case .onePassword:
      "1Password 8 exports a different format (.1pux), which Axo Pass cannot read yet. Use 1Password 7 or earlier."
    case .applePasswords:
      "The export holds logins only. It has no notes, attachments, or folders, and no record ids, so importing it twice adds every login twice."
    }
  }

  /// Whether the source can have trashed items.
  var hasTrash: Bool { self == .onePassword }
}

/// Import items from a password manager export into a new vault. Steps: pick
/// the source, read the export steps, choose the file and options, review the
/// report, confirm, and see the result. The export is plain text, so the last
/// step offers to move it to the Trash.
struct ItemImportSheet: View {
  let model: VaultsModel
  /// Called with the new vault key when the user finishes the last step.
  var onFinished: ((String) -> Void)? = nil

  @Environment(\.dismiss) private var dismiss

  private enum Step {
    case format
    case instructions
    case options
    case report
    case importing
    case done
  }

  @State private var step: Step = .format
  @State private var source: ImportSource = .onePassword
  @State private var file: URL?
  @State private var vaultName = ImportSource.onePassword.defaultVaultName
  @State private var includeTrashed = false
  @State private var preview: ItemImportPreview?
  @State private var result: ItemImportResult?
  @State private var isWorking = false
  @State private var error: String?
  @State private var confirmingTrash = false
  @State private var trashed = false
  @State private var trashError: String?

  private var trimmedName: String { vaultName.trimmingCharacters(in: .whitespaces) }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      switch step {
      case .format: formatStep
      case .instructions: instructionsStep
      case .options: optionsStep
      case .report: reportStep
      case .importing: importingStep
      case .done: doneStep
      }

      if let error {
        Label(error, systemImage: "xmark.circle.fill")
          .font(.caption)
          .foregroundStyle(.red)
          .lineLimit(4)
          .fixedSize(horizontal: false, vertical: true)
      }
    }
    .padding(20)
    .frame(width: 460)
    .interactiveDismissDisabled(step == .importing)
  }

  // MARK: - Steps

  private var formatStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      header("Import Passwords", "Choose where the export comes from.")
      VStack(spacing: 8) {
        ForEach(ImportSource.allCases) { option in
          Button {
            choose(option)
          } label: {
            HStack(spacing: 10) {
              Image(systemName: option.symbol)
                .frame(width: 24)
                .foregroundStyle(Color.accentColor)
              Text(option.title)
              Spacer()
              Image(systemName: "chevron.right").foregroundStyle(.tertiary)
            }
            .padding(10)
            .contentShape(.rect)
          }
          .buttonStyle(.plain)
          .background(.quaternary.opacity(0.5), in: .rect(cornerRadius: 8))
        }
      }
      HStack {
        Spacer()
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
      }
    }
  }

  private var instructionsStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      header("Export from \(source.title)", "Axo Pass reads an export file, not the app.")
      VStack(alignment: .leading, spacing: 6) {
        ForEach(Array(source.exportSteps.enumerated()), id: \.offset) { index, text in
          Text("\(index + 1). \(text)").fixedSize(horizontal: false, vertical: true)
        }
      }
      Text(source.formatNote)
        .font(.caption)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
      Label(
        "The export holds every password as plain text. Delete it after the import.",
        systemImage: "exclamationmark.triangle.fill"
      )
      .font(.caption)
      .foregroundStyle(.orange)
      .fixedSize(horizontal: false, vertical: true)
      HStack {
        Button("Back") { goBack(to: .format) }
        Spacer()
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Continue") { step = .options }.keyboardShortcut(.defaultAction)
      }
    }
  }

  private var optionsStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      header("Import from \(source.title)", "Choose the export and name the new vault.")
      HStack(spacing: 8) {
        Button("Choose Export…") { chooseFile() }
        Text(file?.lastPathComponent ?? "No export selected")
          .font(.callout)
          .foregroundStyle(file == nil ? .secondary : .primary)
          .lineLimit(1)
          .truncationMode(.middle)
      }
      Form {
        TextField("Vault name", text: $vaultName)
        if source.hasTrash {
          Toggle("Include deleted items", isOn: $includeTrashed)
        }
      }
      if source.hasTrash {
        Text("Deleted items go to Recently Deleted in the new vault.")
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      HStack {
        Button("Back") { goBack(to: .instructions) }
        Spacer()
        if isWorking {
          ProgressView().controlSize(.small)
        }
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Review") { runPreview() }
          .keyboardShortcut(.defaultAction)
          .disabled(file == nil || trimmedName.isEmpty || isWorking)
      }
    }
  }

  @ViewBuilder
  private var reportStep: some View {
    if let preview {
      VStack(alignment: .leading, spacing: 16) {
        header("Review", "Nothing is written until you import.")
        GroupBox {
          VStack(alignment: .leading, spacing: 4) {
            Text(countLine("item", preview.items))
            if preview.trashed > 0 {
              Text("\(preview.trashed) of them deleted").foregroundStyle(.secondary)
            }
            if preview.files > 0 { Text(countLine("attachment", preview.files)) }
            if preview.folders > 0 { Text(countLine("folder", preview.folders)) }
            if preview.skippedTrashed > 0 {
              Text("\(preview.skippedTrashed) deleted left out").foregroundStyle(.secondary)
            }
            Text("New vault: \(trimmedName)").foregroundStyle(.secondary)
          }
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(6)
        }
        if source == .applePasswords {
          note("The export has no record ids, so importing it again adds every login again.")
        } else {
          note("The vault is new, so importing the same export again creates another vault.")
        }
        if !preview.repeatedUuids.isEmpty {
          note(
            "\(countLine("record", UInt32(preview.repeatedUuids.count))) repeat an earlier record id. Each is still imported."
          )
        }
        if !preview.dropped.isEmpty { droppedList(preview.dropped) }
        HStack {
          Button("Back") { goBack(to: .options) }
          Spacer()
          Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
          Button("Import") { runImport() }
            .keyboardShortcut(.defaultAction)
            .disabled(preview.items == 0)
        }
      }
    }
  }

  private var importingStep: some View {
    VStack(spacing: 12) {
      ProgressView()
      Text("Importing…").foregroundStyle(.secondary)
      Text("A large export with many attachments can take a while.")
        .font(.caption)
        .foregroundStyle(.tertiary)
    }
    .frame(maxWidth: .infinity, minHeight: 120)
  }

  @ViewBuilder
  private var doneStep: some View {
    if let result {
      VStack(alignment: .leading, spacing: 16) {
        header("Import Complete", "Added \(countLine("item", result.added)) to “\(trimmedName)”.")
        if result.filesAdded > 0 {
          Text(countLine("attachment", result.filesAdded)).font(.callout)
        }
        if !result.fileFailures.isEmpty {
          GroupBox {
            ScrollView {
              VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(result.fileFailures.enumerated()), id: \.offset) { _, failure in
                  Text(
                    "\(failure.item): \(URL(fileURLWithPath: failure.path).lastPathComponent), \(failure.reason)"
                  )
                  .font(.caption)
                  .fixedSize(horizontal: false, vertical: true)
                }
              }
              .frame(maxWidth: .infinity, alignment: .leading)
              .padding(4)
            }
            .frame(maxHeight: 100)
          } label: {
            Text("\(countLine("attachment", UInt32(result.fileFailures.count))) could not be read")
              .foregroundStyle(.orange)
          }
        }
        Label(
          "The export holds every password as plain text. Delete it now.",
          systemImage: "exclamationmark.triangle.fill"
        )
        .font(.caption)
        .foregroundStyle(.orange)
        if let trashError {
          Text(trashError).font(.caption).foregroundStyle(.red)
            .fixedSize(horizontal: false, vertical: true)
        }
        HStack {
          if trashed {
            Label("Moved to the Trash", systemImage: "checkmark.circle.fill")
              .font(.callout)
              .foregroundStyle(.secondary)
          } else {
            Button("Move Export to Trash…") { confirmingTrash = true }
          }
          Spacer()
          Button("Done") { finish(result.vaultKey) }.keyboardShortcut(.defaultAction)
        }
      }
      .confirmationDialog(
        "Move “\(file?.lastPathComponent ?? "the export")” to the Trash?",
        isPresented: $confirmingTrash
      ) {
        Button("Move to Trash", role: .destructive) { moveExportToTrash() }
      } message: {
        Text("Empty the Trash to delete the passwords for good.")
      }
    }
  }

  // MARK: - Pieces

  private func header(_ title: String, _ detail: String) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(title).font(.headline)
      Text(detail)
        .font(.callout)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }
  }

  private func note(_ text: String) -> some View {
    Text(text)
      .font(.caption)
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
  }

  /// Kinds of data the import does not keep, with the number of records and
  /// the record titles.
  private func droppedList(_ dropped: [ItemImportDropped]) -> some View {
    let kinds = Dictionary(grouping: dropped, by: \.kind)
      .sorted { $0.key < $1.key }
    return GroupBox {
      ScrollView {
        VStack(alignment: .leading, spacing: 6) {
          ForEach(kinds, id: \.key) { kind, entries in
            VStack(alignment: .leading, spacing: 1) {
              Text("\(kind): \(entries.count)").font(.caption).fontWeight(.medium)
              Text(
                entries.prefix(5).map(\.item).joined(separator: ", ")
                  + (entries.count > 5 ? ", and \(entries.count - 5) more" : "")
              )
              .font(.caption)
              .foregroundStyle(.secondary)
              .lineLimit(2)
            }
          }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(4)
      }
      .frame(maxHeight: 120)
    } label: {
      Text("Data the import leaves out")
    }
  }

  private func countLine(_ noun: String, _ count: UInt32) -> String {
    "\(count) \(noun)\(count == 1 ? "" : "s")"
  }

  // MARK: - Actions

  private func choose(_ option: ImportSource) {
    if option != source {
      source = option
      vaultName = option.defaultVaultName
      file = nil
      includeTrashed = false
    }
    error = nil
    step = .instructions
  }

  private func goBack(to previous: Step) {
    error = nil
    preview = nil
    step = previous
  }

  /// Pick the export. A 1Password export is a `.1pif` file or a folder, and
  /// Finder may show the folder as a package.
  private func chooseFile() {
    let panel = NSOpenPanel()
    panel.allowsMultipleSelection = false
    panel.canChooseFiles = true
    switch source {
    case .onePassword:
      panel.canChooseDirectories = true
      panel.treatsFilePackagesAsDirectories = false
    case .applePasswords:
      panel.canChooseDirectories = false
      panel.allowedContentTypes = [.commaSeparatedText]
    }
    if panel.runModal() == .OK {
      file = panel.url
      error = nil
    }
  }

  private func runPreview() {
    guard let file, !trimmedName.isEmpty, !isWorking else { return }
    isWorking = true
    error = nil
    Task {
      let outcome = await model.previewItemImport(
        source: file, includeTrashed: source.hasTrash && includeTrashed)
      isWorking = false
      if let found = outcome.preview {
        preview = found
        step = .report
      } else {
        error = outcome.message
      }
    }
  }

  private func runImport() {
    guard let file, !trimmedName.isEmpty else { return }
    step = .importing
    error = nil
    Task {
      let outcome = await model.importItems(
        source: file, name: trimmedName, includeTrashed: source.hasTrash && includeTrashed)
      if let done = outcome.result {
        result = done
        step = .done
      } else {
        error = outcome.message
        step = .report
      }
    }
  }

  /// Move the export, a file or a whole folder, to the Trash. A failure shows
  /// the reason and leaves the button in place.
  private func moveExportToTrash() {
    guard let file else { return }
    do {
      try FileManager.default.trashItem(at: file, resultingItemURL: nil)
      trashed = true
      trashError = nil
    } catch {
      trashError =
        "Could not move the export to the Trash: \(error.localizedDescription) Delete it in Finder."
    }
  }

  private func finish(_ vaultKey: String) {
    onFinished?(vaultKey)
    dismiss()
  }
}
