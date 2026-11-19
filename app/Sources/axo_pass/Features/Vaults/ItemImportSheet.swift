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

  /// Detail line of the source in the format list.
  var listDetail: String {
    switch self {
    case .onePassword: "1Password 7 and earlier, .1pif export"
    case .applePasswords: "Passwords app, .csv export"
    }
  }

  /// Symbol of the source in the format list.
  var symbol: String {
    switch self {
    case .onePassword: "lock.fill"
    case .applePasswords: "key.fill"
    }
  }

  /// Name of the new vault.
  var defaultVaultName: String { title }

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
      "1Password 8 (.1pux) is not supported yet. Warning: Export is saved without encryption. Passwords will be visible to anyone with access to the file. Delete it after import."
    case .applePasswords:
      "Only logins are exported. Other items such as passkeys and wifi passwords are not supported. Warning: Export is saved without encryption. Passwords will be visible to anyone with access to the file. Delete it after import."
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
  /// Called in place of dismissing if the user cancels. Set if the view is
  /// shown in a window instead of a sheet.
  var onCancel: (() -> Void)? = nil

  @Environment(\.dismiss) private var dismiss

  private var isEmbedded: Bool { onCancel != nil }

  /// Minimum height of the flow. Steps of different lengths resize the window
  /// less.
  private static let minHeight: CGFloat = 360

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

  /// Direction of the last step change. Sets the slide direction.
  @State private var forward = true

  private var trimmedName: String { vaultName.trimmingCharacters(in: .whitespaces) }

  /// Slide of a step. Forward steps come in from the right.
  private var stepTransition: AnyTransition {
    .asymmetric(
      insertion: .move(edge: forward ? .trailing : .leading),
      removal: .move(edge: forward ? .leading : .trailing))
  }

  var body: some View {
    ZStack(alignment: .topLeading) {
      page
        .id(step)
        .transition(stepTransition)
    }
    .frame(width: isEmbedded ? nil : 460)
    .frame(
      maxWidth: isEmbedded ? .infinity : nil, minHeight: Self.minHeight,
      alignment: .topLeading
    )
    .clipped()
    .interactiveDismissDisabled(step == .importing)
  }

  private var page: some View {
    VStack(alignment: .leading, spacing: 16) {
      // Each step ends with its button row, which is pushed to the bottom.
      Group {
        switch step {
        case .format: formatStep
        case .instructions: instructionsStep
        case .options: optionsStep
        case .report: reportStep
        case .importing: importingStep
        case .done: doneStep
        }
      }
      .frame(maxHeight: .infinity)

      if let error {
        Label(error, systemImage: "xmark.circle.fill")
          .font(.caption)
          .foregroundStyle(.red)
          .lineLimit(4)
          .fixedSize(horizontal: false, vertical: true)
      }
    }
    .padding(isEmbedded ? 36 : 28)
    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
  }

  // MARK: - Steps

  private var formatStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      header("Import Passwords", "Import items from another password manager.")
      VStack(spacing: 8) {
        ForEach(ImportSource.allCases) { option in
          Button {
            choose(option)
          } label: {
            SourceRow(source: option)
          }
          .buttonStyle(.plain)
        }
      }
      Spacer(minLength: 0)
      HStack {
        if isEmbedded {
          Button("Back") { cancel() }.keyboardShortcut(.cancelAction)
          Spacer()
        } else {
          Spacer()
          Button("Cancel") { cancel() }.keyboardShortcut(.cancelAction)
        }
      }
    }
  }

  private var instructionsStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      header("Export from \(source.title)", source.formatNote)
      VStack(alignment: .leading, spacing: 6) {
        ForEach(Array(source.exportSteps.enumerated()), id: \.offset) { index, text in
          HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text("\(index + 1).")
              .monospacedDigit()
              .frame(width: 16, alignment: .trailing)
            Text(text).fixedSize(horizontal: false, vertical: true)
          }
        }
      }
      Spacer(minLength: 0)
      HStack {
        Button("Back") { goBack(to: .format) }
        Spacer()
        Button("Cancel") { cancel() }.keyboardShortcut(.cancelAction)
        Button("Continue") { go(to: .options) }.keyboardShortcut(.defaultAction)
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
        Spacer(minLength: 0)
      }
      .padding(10)
      .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.quaternary))
      Form {
        TextField("Vault name", text: $vaultName)
        if source.hasTrash {
          Toggle("Import deleted items into Recently Deleted", isOn: $includeTrashed)
        }
      }
      Spacer(minLength: 0)
      HStack {
        Button("Back") { goBack(to: .instructions) }
        Spacer()
        if isWorking {
          ProgressView().controlSize(.small)
        }
        Button("Cancel") { cancel() }.keyboardShortcut(.cancelAction)
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
        VStack(alignment: .leading, spacing: 4) {
          title("Review")
          Text(
            "\(countLine("item", preview.items)) will be imported into a new vault, \(trimmedName)."
          )
          .fixedSize(horizontal: false, vertical: true)
        }
        if preview.trashed > 0 || preview.files > 0 || preview.folders > 0
          || preview.skippedTrashed > 0
        {
          GroupBox {
            VStack(alignment: .leading, spacing: 4) {
              if preview.trashed > 0 {
                Text("\(preview.trashed) of them deleted").foregroundStyle(.secondary)
              }
              if preview.files > 0 { Text(countLine("attachment", preview.files)) }
              if preview.folders > 0 { Text(countLine("folder", preview.folders)) }
              if preview.skippedTrashed > 0 {
                Text("\(preview.skippedTrashed) deleted left out").foregroundStyle(.secondary)
              }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
          }
        }
        if source != .applePasswords {
          note("The vault is new, so importing the same export again creates another vault.")
        }
        if !preview.repeatedUuids.isEmpty {
          note(
            "\(countLine("record", UInt32(preview.repeatedUuids.count))) repeat an earlier record id. Each is still imported."
          )
        }
        if !preview.dropped.isEmpty { droppedList(preview.dropped) }
        Spacer(minLength: 0)
        HStack {
          Button("Back") { goBack(to: .options) }
          Spacer()
          Button("Cancel") { cancel() }.keyboardShortcut(.cancelAction)
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
        title("Import Complete")
        VStack(spacing: 10) {
          Image(systemName: "checkmark.circle.fill")
            .font(.system(size: 48))
            .foregroundStyle(.green)
          Text("Imported \(countLine("item", result.added)) to \(trimmedName).")
            .font(.callout)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
        .foregroundStyle(.orange)
        if let trashError {
          Text(trashError).font(.caption).foregroundStyle(.red)
            .fixedSize(horizontal: false, vertical: true)
        }
        Spacer(minLength: 0)
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

  private func title(_ text: String) -> some View {
    Text(text)
      .font(.title2)
      .fontWeight(.semibold)
  }

  private func header(_ title: String, _ detail: String) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      self.title(title)
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
    go(to: .instructions)
  }

  private func goBack(to previous: Step) {
    go(to: previous, forward: false) { preview = nil }
  }

  /// Slide to `next` and clear the error. `update` runs with the step change.
  /// Direction is set one update before the step changes, so the outgoing step
  /// slides the same way as the incoming one.
  private func go(
    to next: Step, forward: Bool = true, _ update: @escaping () -> Void = {}
  ) {
    self.forward = forward
    DispatchQueue.main.async {
      withAnimation(.smooth(duration: 0.35)) {
        error = nil
        update()
        step = next
      }
    }
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
        go(to: .report) { preview = found }
      } else {
        error = outcome.message
      }
    }
  }

  private func runImport() {
    guard let file, !trimmedName.isEmpty else { return }
    go(to: .importing)
    Task {
      let outcome = await model.importItems(
        source: file, name: trimmedName, includeTrashed: source.hasTrash && includeTrashed)
      if let done = outcome.result {
        go(to: .done) { result = done }
      } else {
        go(to: .report, forward: false) { error = outcome.message }
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

  private func cancel() {
    if let onCancel { onCancel() } else { dismiss() }
  }

  private func finish(_ vaultKey: String) {
    onFinished?(vaultKey)
    if !isEmbedded { dismiss() }
  }
}

/// Row of an import source in the format list. Matches the welcome screen
/// choice cards. Background is lighter on hover.
private struct SourceRow: View {
  let source: ImportSource

  @State private var hovering = false

  var body: some View {
    HStack(spacing: 12) {
      TodayIcon(symbol: source.symbol, color: .accentColor)
      VStack(alignment: .leading, spacing: 2) {
        Text(source.title)
          .fontWeight(.medium)
        Text(source.listDetail)
          .font(.callout)
          .foregroundStyle(.secondary)
      }
      Spacer(minLength: 0)
      Image(systemName: "chevron.right")
        .font(.callout.weight(.semibold))
        .foregroundStyle(.tertiary)
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(
      hovering ? AnyShapeStyle(.quaternary) : AnyShapeStyle(.background.secondary),
      in: RoundedRectangle(cornerRadius: 10)
    )
    .overlay {
      RoundedRectangle(cornerRadius: 10)
        .strokeBorder(.separator)
    }
    .contentShape(.rect)
    .onHover { hovering = $0 }
    .animation(.easeOut(duration: 0.12), value: hovering)
  }
}
