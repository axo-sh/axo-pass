import AxoPassFFI
import SwiftUI

/// Credential list row, either a section header or a credential. The list is
/// flat. A credential belongs to the nearest section header above it, or to no
/// section if there is none. The flat list lets a single `onMove` move
/// credentials across sections and move sections.
enum CredentialEntry: Hashable {
  case section(String)
  case credential(String)

  var isSection: Bool {
    if case .section = self { return true }
    return false
  }

  /// Item entries as returned by the model. Credentials without sections are
  /// returned first, then section headers followed by their credentials.
  static func entries(of item: ItemInfo) -> [CredentialEntry] {
    var entries = item.credentials.filter { $0.sectionId == nil }.map {
      CredentialEntry.credential($0.key)
    }
    for section in item.sections {
      entries.append(.section(section.id))
      entries += item.credentials.filter { $0.sectionId == section.id }.map {
        CredentialEntry.credential($0.key)
      }
    }
    return entries
  }

  /// Section order and credential placements described by `entries`.
  static func arrangement(of entries: [CredentialEntry]) -> (
    sectionIds: [String], placements: [CredentialPlacementInfo]
  ) {
    var sectionIds: [String] = []
    var placements: [CredentialPlacementInfo] = []
    var currentSection: String? = nil
    for entry in entries {
      switch entry {
      case .section(let id):
        sectionIds.append(id)
        currentSection = id
      case .credential(let key):
        placements.append(CredentialPlacementInfo(key: key, sectionId: currentSection))
      }
    }
    return (sectionIds, placements)
  }
}

extension CredentialList {
  /// Entries in display order. Uses the pending move if set, otherwise the
  /// model order. Ignores a pending move that no longer covers the same
  /// entries.
  var entries: [CredentialEntry] {
    let current = CredentialEntry.entries(of: item)
    guard let pendingEntries, pendingEntries.count == current.count,
      Set(pendingEntries) == Set(current)
    else { return current }
    return pendingEntries
  }

  /// Entries shown in the outline. A login shows its role credentials and
  /// passkeys in the login card, so they are left out.
  var listedEntries: [CredentialEntry] {
    let listed = Set(item.listCredentials.map(\.key))
    return entries.filter {
      if case .credential(let key) = $0 { return listed.contains(key) }
      return true
    }
  }

  /// `arranged` with the entries left out of the outline added back. Each
  /// hidden credential goes after the nearest earlier section header or hidden
  /// credential, so it keeps its section and its order among the hidden ones.
  func restoringHiddenEntries(_ arranged: [CredentialEntry]) -> [CredentialEntry] {
    let shown = Set(arranged)
    let all = entries
    var result = arranged
    for (index, entry) in all.enumerated() where !shown.contains(entry) {
      let anchor = all[..<index].last { $0.isSection || !shown.contains($0) }
      let insertAt = anchor.flatMap { result.firstIndex(of: $0) }.map { $0 + 1 } ?? 0
      result.insert(entry, at: insertAt)
    }
    return result
  }

  /// Credential count for a section. Shown on collapsed section headers.
  func credentialCount(inSection id: String) -> Int {
    item.listCredentials.filter { $0.sectionId == id }.count
  }

  /// Credentials under a section header in the outline, including collapsed
  /// ones.
  func sectionChildren(_ id: String) -> Set<CredentialEntry> {
    let entries = listedEntries
    guard let header = entries.firstIndex(of: .section(id)) else { return [] }
    var children: Set<CredentialEntry> = []
    var next = header + 1
    while next < entries.count, !entries[next].isSection {
      children.insert(entries[next])
      next += 1
    }
    return children
  }

  /// `targets` plus the credentials of every section in it. A selected section
  /// includes its contents.
  func withSectionChildren(_ targets: Set<CredentialEntry>) -> Set<CredentialEntry> {
    var result = targets
    for case .section(let id) in targets {
      result.formUnion(sectionChildren(id))
    }
    return result
  }

  /// Sync section selection with credential selection. Selecting a header
  /// selects its credentials so the highlight covers the whole section.
  /// Deselecting only the header deselects its credentials. Deselecting a
  /// credential deselects its header.
  func normalizedSelection(from old: Set<CredentialEntry>, to new: Set<CredentialEntry>)
    -> Set<CredentialEntry>
  {
    var result = new
    for section in item.sections {
      let header = CredentialEntry.section(section.id)
      let children = sectionChildren(section.id)
      switch (old.contains(header), new.contains(header)) {
      case (false, true):
        result.formUnion(children)
      case (true, false) where children.isSubset(of: new):
        result.subtract(children)
      case (true, true) where !children.isSubset(of: new):
        result.remove(header)
      default:
        break
      }
    }
    return result
  }

  /// Row to rename. Either a single selected credential, or a section selected
  /// with its credentials.
  func renameTarget(_ selected: Set<CredentialEntry>) -> CredentialEntry? {
    let sections = selected.filter(\.isSection)
    if sections.count == 1, let header = sections.first, case .section(let id) = header {
      return selected.subtracting([header]).isSubset(of: sectionChildren(id)) ? header : nil
    }
    return selected.count == 1 ? selected.first : nil
  }

  /// Move entries to an index in `listedEntries`. A moved section header brings
  /// its credentials and lands on a section boundary, so it does not split
  /// another section.
  func moveEntries(_ moved: [CredentialEntry], to destination: Int) {
    let current = listedEntries
    let source = IndexSet(moved.compactMap { current.firstIndex(of: $0) })
    var moving = source
    for index in source where current[index].isSection {
      var next = index + 1
      while next < current.count, !current[next].isSection {
        moving.insert(next)
        next += 1
      }
    }

    let block = moving.map { current[$0] }
    var arranged = current.indices.filter { !moving.contains($0) }.map { current[$0] }
    var insertAt = destination - moving.count(in: 0..<destination)
    if block.contains(where: \.isSection) {
      while insertAt < arranged.count, !arranged[insertAt].isSection {
        insertAt += 1
      }
    }
    arranged.insert(contentsOf: block, at: insertAt)
    apply(restoringHiddenEntries(arranged), moved: Set(block))
  }

  /// Move credentials to the end of a section. A nil section moves them to the
  /// end of the unsectioned credentials.
  func moveCredentials(_ keys: Set<String>, toSection sectionId: String?) {
    let current = listedEntries
    let moved = current.filter {
      if case .credential(let key) = $0 { return keys.contains(key) }
      return false
    }
    var arranged = current.filter { !moved.contains($0) }
    let insertAt: Int
    if let sectionId, let header = arranged.firstIndex(of: .section(sectionId)) {
      var end = header + 1
      while end < arranged.count, !arranged[end].isSection { end += 1 }
      insertAt = end
    } else {
      insertAt = arranged.firstIndex(where: \.isSection) ?? arranged.count
    }
    arranged.insert(contentsOf: moved, at: insertAt)
    apply(restoringHiddenEntries(arranged), moved: Set(moved))
  }

  /// Show `arranged` immediately and save it. On failure, rows revert and the
  /// moved rows show the error.
  private func apply(_ arranged: [CredentialEntry], moved: Set<CredentialEntry>) {
    guard arranged != entries else { return }
    pendingEntries = arranged
    Task {
      let error = await failureMessage {
        try await model.arrangeItem(vaultKey: vaultKey, itemKey: item.key, entries: arranged)
      }
      // The model has reloaded with either the new or old arrangement. The
      // override is no longer needed.
      if pendingEntries == arranged {
        pendingEntries = nil
      }
      if let error {
        setError(error, on: moved)
      }
    }
  }

  /// Ask to delete entries. Every delete entry point calls this. The
  /// confirmation dialog calls `performDelete`.
  func delete(_ selected: Set<CredentialEntry>) {
    guard !withSectionChildren(selected).isEmpty else { return }
    pendingDelete = selected
  }

  /// Title of the delete confirmation for `selected`.
  func deleteTitle(_ selected: Set<CredentialEntry>) -> String {
    let targets = withSectionChildren(selected)
    let credentialCount = targets.filter { !$0.isSection }.count
    let sectionCount = targets.count - credentialCount
    if sectionCount == 0, credentialCount == 1, case .credential(let key)? = targets.first {
      let title = item.credentials.first { $0.key == key }?.title ?? key
      return "Delete \"\(title)\"?"
    }
    if sectionCount == 1, selected.count == 1, case .section(let id)? = selected.first {
      let title = item.sections.first { $0.id == id }?.title ?? id
      return credentialCount == 0
        ? "Delete section \"\(title)\"?"
        : "Delete section \"\(title)\" and its \(credentialsPhrase(credentialCount))?"
    }
    var parts: [String] = []
    if credentialCount > 0 { parts.append(credentialsPhrase(credentialCount)) }
    if sectionCount > 0 {
      parts.append(sectionCount == 1 ? "1 section" : "\(sectionCount) sections")
    }
    return "Delete \(parts.joined(separator: " and "))?"
  }

  /// Message of the delete confirmation for `selected`. Passkeys add the sites
  /// that still list them.
  func deleteMessage(_ selected: Set<CredentialEntry>) -> String {
    let keys = Set(
      withSectionChildren(selected).compactMap { entry -> String? in
        if case .credential(let key) = entry { return key }
        return nil
      })
    let passkeys = item.credentials.filter { keys.contains($0.key) && $0.kind.kind == "passkey" }
    var message = "You can restore deleted entries from Recently Deleted."
    if passkeys.count == 1 {
      let site = passkeys[0].passkey?.rpId ?? "The site"
      message =
        "\(site) still lists this passkey until you remove it there. You will not be able to sign in with it again. \(message)"
    } else if passkeys.count > 1 {
      message =
        "Sites still list the deleted passkeys until you remove them there. You will not be able to sign in with them again. \(message)"
    }
    return message
  }

  private func credentialsPhrase(_ count: Int) -> String {
    count == 1 ? "1 credential" : "\(count) credentials"
  }

  /// Delete entries with undo. Deleting a section deletes its credentials.
  /// Errors show on the remaining rows.
  func performDelete(_ selected: Set<CredentialEntry>) {
    let targets = withSectionChildren(selected)
    guard !targets.isEmpty else { return }
    selection.subtract(targets)
    renaming = nil
    let work = model.deleteEntries(
      vaultKey: vaultKey, itemKey: item.key, targets, undoManager: undoManager)
    Task {
      if let error = await work.value {
        setError(error, on: targets)
        return
      }
      for case .credential(let key) in targets {
        secrets.removeValue(forKey: key)
        errors.removeValue(forKey: key)
      }
      for case .section(let id) in targets {
        sectionErrors.removeValue(forKey: id)
      }
    }
  }

  func setError(_ message: String, on targets: Set<CredentialEntry>) {
    for target in targets {
      switch target {
      case .credential(let key): errors[key] = message
      case .section(let id): sectionErrors[id] = message
      }
    }
  }
}
