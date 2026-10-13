import AppKit
import AxoPassFFI
import CryptoKit
import SwiftUI

/// Inset applied to each credential row.
let credentialRowInset: CGFloat = 8

/// Horizontal inset of rows inside a section. Leaves room for the section
/// outline.
private let sectionContentInset: CGFloat = 14

/// Placeholder title for new sections. The title field opens immediately for
/// renaming.
private let newSectionTitle = "New Section"

/// Item credentials and sections, edited in place as in Finder. Rows can be
/// selected and dragged at any time. Return or double-click renames the
/// selected row. Delete removes the selection, with undo. Other actions are in
/// the context menu.
struct CredentialList: View {
  /// A title or id being renamed in place.
  enum RenameTarget: Equatable {
    case credential(String, CredentialRow.RenameField)
    case section(String)
  }

  @Environment(VaultsModel.self) var model
  @Environment(\.undoManager) var undoManager
  let item: ItemInfo
  let vaultKey: String

  @State var secrets: [String: SymmetricKey] = [:]
  @State var errors: [String: String] = [:]
  @State var sectionErrors: [String: String] = [:]
  @State var revealing: Set<String> = []
  @State var selection: Set<CredentialEntry> = []
  @State var renaming: RenameTarget? = nil
  @State var collapsedSections: Set<String> = []
  // Local override of the row order while a move is being saved. Cleared once
  // the save finishes and the model has reloaded.
  @State var pendingEntries: [CredentialEntry]? = nil
  // Section created by New Section with an unconfirmed title. Escape while
  // naming deletes it.
  @State private var unnamedSection: String? = nil
  // Section creation error. Shown separately since there is no row for it.
  @State private var listError: String? = nil
  @State private var showingNewCredentialSheet = false
  @State private var showingRecentlyDeleted = false

  var body: some View {
    CredentialOutline(
      entries: entries,
      collapsedSections: collapsedSections,
      selection: $selection,
      scrollTarget: renamingSection.map(CredentialEntry.section),
      isRenaming: renaming != nil,
      banner: AnyView(banner),
      row: { entry, state in AnyView(row(entry, state: state)) },
      menu: { menuItems(for: $0) },
      normalizeSelection: normalizedSelection,
      onSetCollapsed: { id, collapsed in
        if collapsed {
          collapsedSections.insert(id)
        } else {
          collapsedSections.remove(id)
        }
      },
      onMove: moveEntries,
      onPrimaryAction: startRename,
      onDelete: delete
    )
    .navigationTitle(item.title)
    .toolbar {
      ToolbarItemGroup(placement: .primaryAction) {
        // Push the item actions to the trailing edge of the toolbar.
        Spacer()

        Button(allRevealed ? "Hide All" : "Reveal All") {
          if allRevealed {
            hideAll()
          } else {
            Task { await revealAll() }
          }
        }
        .disabled(!hasConcealed || !revealing.isEmpty)

        Menu {
          Button("New Credential…") { showingNewCredentialSheet = true }
          Button("New Section") { newSection() }
          Divider()
          Button("Recently Deleted…") { showingRecentlyDeleted = true }
        } label: {
          Label("Add", systemImage: "plus")
        }
        .menuIndicator(.hidden)
        .help("New credential or section, or restore a deleted credential.")
      }
    }
    .sheet(isPresented: $showingRecentlyDeleted) {
      RecentlyDeletedSheet(vaultKey: vaultKey, itemKey: item.key)
    }
    .sheet(isPresented: $showingNewCredentialSheet) {
      NewCredentialSheet { key, title, value, kind in
        if await model.addCredential(
          vaultKey: vaultKey, itemKey: item.key, credKey: key, title: title, value: value,
          kind: kind
        ) {
          return nil
        }
        return model.actionError ?? "Failed to create credential."
      }
    }
  }

  private var renamingSection: String? {
    if case .section(let id)? = renaming { return id }
    return nil
  }

  /// Top row. Item title and key, then list messages.
  private var banner: some View {
    VStack(alignment: .leading, spacing: 0) {
      header
        .padding(EdgeInsets(top: 20, leading: 4, bottom: 16, trailing: 4))

      if let listError {
        Text(listError)
          .font(.caption)
          .foregroundStyle(.red)
          .padding(4)
      }

      if let undoFailure = model.undoFailure, undoFailure.vaultKey == vaultKey,
        undoFailure.itemKey == item.key
      {
        Text(undoFailure.message)
          .font(.caption)
          .foregroundStyle(.red)
          .textSelection(.enabled)
          .padding(4)
      }

      if item.credentials.isEmpty, item.sections.isEmpty {
        // Aligned with a credential row's text, which sits at the row inset
        // plus CredentialRow's own horizontal padding.
        Text("No credentials")
          .foregroundStyle(.secondary)
          .padding(
            EdgeInsets(
              top: credentialRowInset, leading: credentialRowInset + 6,
              bottom: credentialRowInset, trailing: credentialRowInset + 6
            ))
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  private var header: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "lock.fill")
        .font(.system(size: 26))
        .foregroundStyle(.tint)
        .frame(width: 34)
      VStack(alignment: .leading, spacing: 2) {
        Text(item.title).font(.title2).fontWeight(.semibold)
        Text(item.key)
          .font(.callout)
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
      }
    }
  }

  /// Row content with insets. The outline row view draws the highlight and
  /// section outline behind it.
  private func row(_ entry: CredentialEntry, state: OutlineRowState) -> some View {
    // Hierarchical colors turn light on the accent highlight, matching the
    // native highlight.
    rowContent(entry, outline: state.outline)
      .environment(\.backgroundProminence, state.isProminent ? .increased : .standard)
  }

  @ViewBuilder
  private func rowContent(_ entry: CredentialEntry, outline: SectionOutline.Position?)
    -> some View
  {
    switch entry {
    case .section(let id):
      if let section = item.sections.first(where: { $0.id == id }) {
        // Insets are the same expanded and collapsed, so the header height
        // does not change. The bottom inset leaves room for the outline and
        // highlight to close under a collapsed title.
        sectionHeader(section)
          .padding(
            EdgeInsets(
              top: SectionOutline.gap + 12, leading: sectionContentInset + 6,
              bottom: 12, trailing: sectionContentInset + 6))
      }
    case .credential(let key):
      if let cred = item.credentials.first(where: { $0.key == key }) {
        // Credentials in a section are inset further to clear the outline.
        let side = outline == nil ? credentialRowInset : sectionContentInset
        credentialRow(cred)
          .padding(
            EdgeInsets(
              top: credentialRowInset, leading: side,
              bottom: outline == .bottom ? credentialRowInset + 8 : credentialRowInset,
              trailing: side))
      }
    }
  }

  private func sectionHeader(_ section: SectionInfo) -> some View {
    SectionHeader(
      title: section.title,
      count: credentialCount(inSection: section.id),
      isCollapsed: collapsedSections.contains(section.id),
      isRenaming: renaming == .section(section.id),
      error: sectionErrors[section.id],
      onToggleCollapsed: {
        if collapsedSections.remove(section.id) == nil {
          collapsedSections.insert(section.id)
        }
      },
      onRename: { renameSection(section, to: $0) },
      onCancelRename: { cancelSectionRename(section.id) }
    )
  }

  private func credentialRow(_ cred: CredentialInfo) -> some View {
    CredentialRow(
      cred: cred,
      vaultKey: vaultKey,
      itemKey: item.key,
      secret: secrets[cred.key],
      error: errors[cred.key],
      isRevealing: revealing.contains(cred.key),
      renaming: renamingField(of: cred.key),
      onReveal: { Task { await reveal(cred) } },
      onHide: { hide(cred) },
      onCopy: { await copy(cred) },
      onRename: { field, text in rename(cred, field: field, to: text) },
      onCancelRename: { renaming = nil },
      onQuickSaveValue: { newValue in
        Task { await quickSaveValue(cred, newValue: newValue) }
      }
    )
  }

  private func renamingField(of key: String) -> CredentialRow.RenameField? {
    if case .credential(key, let field)? = renaming { return field }
    return nil
  }

  // MARK: - Context menu

  /// Context menu for the targeted rows. Empty targets mean empty space.
  private func menuItems(for selected: Set<CredentialEntry>) -> [OutlineMenuItem] {
    guard !selected.isEmpty else {
      return [
        .action("New Credential…") { showingNewCredentialSheet = true },
        .action("New Section") { newSection() },
      ]
    }

    var items: [OutlineMenuItem] = []
    if let entry = renameTarget(selected) {
      items += singleEntryMenu(entry)
      items.append(.divider)
    }

    let keys = Set(
      selected.compactMap { entry -> String? in
        if case .credential(let key) = entry { return key }
        return nil
      })
    // Selected sections move as a whole by dragging. They cannot be moved
    // into another section.
    if !keys.isEmpty, !selected.contains(where: \.isSection), !item.sections.isEmpty {
      items.append(
        .submenu(
          "Move to Section",
          [.action("No Section") { moveCredentials(keys, toSection: nil) }, .divider]
            + item.sections.map { section in
              .action(section.title) { moveCredentials(keys, toSection: section.id) }
            }))
      items.append(.divider)
    }

    items.append(.action("Delete") { delete(selected) })
    return items
  }

  private func singleEntryMenu(_ entry: CredentialEntry) -> [OutlineMenuItem] {
    switch entry {
    case .section(let id):
      return [.action("Rename") { renaming = .section(id) }]
    case .credential(let key):
      guard let cred = item.credentials.first(where: { $0.key == key }) else { return [] }
      var items: [OutlineMenuItem] = [
        .action("Rename") { renaming = .credential(key, .title) },
        .action("Change ID") { renaming = .credential(key, .key) },
      ]
      // Concealed and multiline apply only to freeform text credentials.
      if cred.kind.kind == "text" {
        items += [
          .divider,
          .toggle("Concealed", isOn: cred.kind.concealed) {
            setTextOptions(cred, concealed: $0, multiline: cred.kind.multiline)
          },
          .toggle("Multiline", isOn: cred.kind.multiline) {
            setTextOptions(cred, concealed: cred.kind.concealed, multiline: $0)
          },
        ]
      }
      return items
    }
  }

  /// Rename the title of the single selected row. Triggered by Return or
  /// double-click.
  private func startRename(_ selected: Set<CredentialEntry>) {
    guard let entry = renameTarget(selected) else { return }
    switch entry {
    case .section(let id): renaming = .section(id)
    case .credential(let key): renaming = .credential(key, .title)
    }
  }

  // MARK: - Sections

  /// Create a section with a placeholder title and start renaming it.
  private func newSection() {
    listError = nil
    Task {
      do {
        let id = try await model.createSection(
          vaultKey: vaultKey, itemKey: item.key, title: newSectionTitle)
        unnamedSection = id
        selection = [.section(id)]
        renaming = .section(id)
      } catch {
        listError = String(describing: error)
      }
    }
  }

  private func renameSection(_ section: SectionInfo, to title: String) {
    renaming = nil
    unnamedSection = nil
    guard title != section.title else { return }
    Task {
      sectionErrors[section.id] = await failureMessage {
        try await model.renameSection(
          vaultKey: vaultKey, itemKey: item.key, sectionId: section.id, title: title)
      }
    }
  }

  /// Handle Escape while renaming a section. Removes a new section that was
  /// never named.
  private func cancelSectionRename(_ id: String) {
    renaming = nil
    guard unnamedSection == id else { return }
    unnamedSection = nil
    selection.remove(.section(id))
    Task {
      try? await model.deleteSection(vaultKey: vaultKey, itemKey: item.key, sectionId: id)
    }
  }
}

/// Section header with a title and disclosure chevron. Collapsed sections show
/// a credential count.
private struct SectionHeader: View {
  let title: String
  let count: Int
  let isCollapsed: Bool
  let isRenaming: Bool
  let error: String?
  let onToggleCollapsed: () -> Void
  let onRename: (String) -> Void
  let onCancelRename: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      HStack(spacing: 6) {
        Button(action: onToggleCollapsed) {
          Image(systemName: "chevron.right")
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .rotationEffect(.degrees(isCollapsed ? 0 : 90))
            .animation(.snappy(duration: 0.2), value: isCollapsed)
            .frame(width: 12, height: 12)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .help(isCollapsed ? "Expand" : "Collapse")

        Group {
          if isRenaming {
            InlineRenameField(
              initial: title, placeholder: "Section", onCommit: onRename,
              onCancel: onCancelRename)
          } else {
            Text(title)
          }
        }
        .font(.title3)
        .fontWeight(.semibold)

        if isCollapsed {
          Text("\(count)")
            .font(.callout)
            .foregroundStyle(.secondary)
        }
        Spacer(minLength: 0)
      }
      if let error {
        Text(error).font(.caption).foregroundStyle(.red)
      }
    }
  }
}
