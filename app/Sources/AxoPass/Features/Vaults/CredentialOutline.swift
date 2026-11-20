import AppKit
import SwiftUI

/// Horizontal margin between the outline edge and row content.
private let cellMargin: CGFloat = 10

/// Horizontal margin between the outline edge and row chrome.
private let chromeMargin: CGFloat = 12

/// Horizontal margin between the outline edge and a section outline. Aligns
/// with the edge of the login card.
private let sectionChromeMargin: CGFloat = cellMargin + credentialRowInset

/// Pasteboard type of a row drag. Drags are local to the outline, so the
/// pasteboard carries no data that is read back.
private let entryPasteboardType = NSPasteboard.PasteboardType("axo-pass.credential-entry")

/// Image component key of the background behind a dragged row.
private let dragBackgroundKey = NSDraggingItem.ImageComponentKey("background")

/// Translucent rounded background behind a dragged row. Space above `top` is
/// left clear.
private func dragBackground(size: CGSize, top: CGFloat, appearance: NSAppearance) -> NSImage {
  NSImage(size: size, flipped: true) { rect in
    appearance.performAsCurrentDrawingAppearance {
      var area = rect
      area.origin.y += top
      area.size.height -= top
      let path = NSBezierPath(roundedRect: area.insetBy(dx: 0.5, dy: 0.5), xRadius: 8, yRadius: 8)
      NSColor.windowBackgroundColor.withAlphaComponent(0.8).setFill()
      path.fill()
      NSColor.separatorColor.setStroke()
      path.lineWidth = 1
      path.stroke()
    }
    return true
  }
}

/// Row state passed to the SwiftUI row content.
struct OutlineRowState {
  /// Section outline segment drawn behind the row.
  var outline: SectionOutline.Position?
  /// Whether the row has the accent highlight. Hierarchical colors turn light.
  var isProminent: Bool
}

/// Context menu item. Converted to an `NSMenuItem` when the menu opens.
enum OutlineMenuItem {
  case action(String, () -> Void)
  case toggle(String, isOn: Bool, (Bool) -> Void)
  case submenu(String, [OutlineMenuItem])
  case divider
}

/// Credential entries in an `NSOutlineView`. Section headers are parent rows
/// and section credentials are their children. Unsectioned credentials are
/// root rows before the sections. A banner row at the top holds item details
/// and messages. Row content is SwiftUI. The row view draws the selection
/// highlight, context menu outline, and section outline.
struct CredentialOutline: NSViewRepresentable {
  let entries: [CredentialEntry]
  let collapsedSections: Set<String>
  @Binding var selection: Set<CredentialEntry>
  /// Row scrolled into view when it changes.
  let scrollTarget: CredentialEntry?
  /// Whether a row is being renamed. The outline takes focus back after a
  /// rename ends.
  let isRenaming: Bool
  /// Count of focus requests. The outline takes focus when it changes.
  let focusRequest: Int
  /// Banner content. Takes whether the outline has focus in the key window.
  let banner: (_ isEmphasized: Bool) -> AnyView
  let row: (CredentialEntry, OutlineRowState) -> AnyView
  /// Context menu for the targeted rows. Empty targets mean empty space.
  let menu: (Set<CredentialEntry>) -> [OutlineMenuItem]
  /// Selection after a user change from `old` to `new`.
  let normalizeSelection:
    (_ old: Set<CredentialEntry>, _ new: Set<CredentialEntry>) -> Set<CredentialEntry>
  let onSetCollapsed: (_ sectionId: String, _ collapsed: Bool) -> Void
  /// Move entries to an index in `entries`.
  let onMove: (_ moved: [CredentialEntry], _ destination: Int) -> Void
  /// Return.
  let onPrimaryAction: (Set<CredentialEntry>) -> Void
  /// Double-click on a row.
  let onOpen: (Set<CredentialEntry>) -> Void
  /// Space. Returns false if the selection has nothing to preview.
  let onQuickLook: (Set<CredentialEntry>) -> Bool
  let onDelete: (Set<CredentialEntry>) -> Void
  /// Mouse down that reaches the outline. Row content that handles a click
  /// itself does not report it.
  let onMouseDown: () -> Void

  func makeCoordinator() -> Coordinator { Coordinator(self) }

  func makeNSView(context: Context) -> NSScrollView {
    let outline = EntryOutlineView()
    let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("entry"))
    column.resizingMask = .autoresizingMask
    outline.addTableColumn(column)
    outline.outlineTableColumn = column
    outline.headerView = nil
    outline.style = .plain
    outline.backgroundColor = .clear
    outline.intercellSpacing = .zero
    outline.indentationPerLevel = 0
    outline.gridStyleMask = []
    outline.allowsMultipleSelection = true
    outline.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
    outline.registerForDraggedTypes([entryPasteboardType])
    outline.setDraggingSourceOperationMask(.move, forLocal: true)
    // Drop feedback is drawn by the row views and `DropIndicatorView`, inset
    // to the target section.
    outline.draggingDestinationFeedbackStyle = .none
    outline.dataSource = context.coordinator
    outline.delegate = context.coordinator
    outline.target = context.coordinator
    outline.doubleAction = #selector(Coordinator.doubleClicked(_:))
    outline.coordinator = context.coordinator
    context.coordinator.outline = outline

    let scroll = NSScrollView()
    scroll.documentView = outline
    scroll.hasVerticalScroller = true
    scroll.autohidesScrollers = true
    scroll.drawsBackground = false
    context.coordinator.load()
    return scroll
  }

  func updateNSView(_ nsView: NSScrollView, context: Context) {
    context.coordinator.update(self)
  }

  // MARK: - Coordinator

  @MainActor
  final class Coordinator: NSObject, NSOutlineViewDataSource, NSOutlineViewDelegate,
    NSMenuDelegate
  {
    var parent: CredentialOutline
    weak var outline: EntryOutlineView?

    /// Entries as shown by the outline. Updated step by step while changes
    /// are applied, so data source answers match each outline update.
    private var tree = OutlineTree()
    private let bannerNode = OutlineNode(.banner)
    private var nodes: [CredentialEntry: OutlineNode] = [:]
    /// Content heights reported by row content, by node.
    private var heights: [ObjectIdentifier: CGFloat] = [:]
    private var heightChanges: Set<ObjectIdentifier> = []
    private lazy var sizingController = NSHostingController(rootView: AnyView(EmptyView()))
    /// Set while the outline is changed to match `parent`. Outline callbacks
    /// are not reported back to `parent` meanwhile.
    private var isSyncing = false
    private var draggedEntries: [CredentialEntry] = []
    /// Location the dragged rows drop at, shown while dragging.
    private var dropLocation: OutlineTree.Location?
    /// Rows the open context menu acts on.
    private var menuTargets: Set<CredentialEntry> = []
    private var scrolledTarget: CredentialEntry?
    private var wasRenaming = false
    private var focusRequest: Int

    init(_ parent: CredentialOutline) {
      self.parent = parent
      focusRequest = parent.focusRequest
    }

    // MARK: Updates

    /// Show the initial entries.
    func load() {
      guard let outline else { return }
      tree = OutlineTree(entries: parent.entries)
      isSyncing = true
      outline.reloadData()
      syncExpansion(animated: false)
      syncSelection()
      isSyncing = false
    }

    func update(_ parent: CredentialOutline) {
      self.parent = parent
      guard let outline else { return }
      let target = OutlineTree(entries: parent.entries)
      isSyncing = true
      if target != tree {
        apply(target)
      }
      syncExpansion(animated: true)
      syncSelection()
      isSyncing = false
      refreshRows()

      if parent.scrollTarget != scrolledTarget {
        if let target = parent.scrollTarget {
          let row = nodes[target].map(outline.row(forItem:)) ?? -1
          if row >= 0 {
            outline.scrollRowToVisible(row)
            scrolledTarget = target
          }
        } else {
          scrolledTarget = nil
        }
      }

      if wasRenaming, !parent.isRenaming {
        // The rename field is removed after this update. Focus returns to the
        // outline unless the rename ended by focusing something else.
        DispatchQueue.main.async { [weak outline] in
          guard let outline, let window = outline.window else { return }
          let responder = window.firstResponder
          if responder == nil || responder === window
            || (responder as? NSView)?.isDescendant(of: outline) == true
          {
            window.makeFirstResponder(outline)
          }
        }
      }
      wasRenaming = parent.isRenaming

      if parent.focusRequest != focusRequest {
        focusRequest = parent.focusRequest
        if let window = outline.window, window.firstResponder !== outline {
          window.makeFirstResponder(outline)
        }
      }
    }

    /// Change the outline from `tree` to `target` with animated row moves,
    /// insertions, and removals.
    private func apply(_ target: OutlineTree) {
      guard let outline else { return }
      let kept = Set(target.entries)
      outline.beginUpdates()
      for entry in tree.entries where !entry.isSection && !kept.contains(entry) {
        remove(entry)
      }
      place(target.root, in: nil)
      for case .section(let id) in target.root {
        place(target.children[id, default: []], in: id)
      }
      // Credentials of removed sections were removed or moved above.
      for entry in tree.root where entry.isSection && !kept.contains(entry) {
        remove(entry)
      }
      outline.endUpdates()

      if tree != target || !rowsMatchTree() {
        tree = target
        outline.reloadData()
      }
      nodes = nodes.filter { kept.contains($0.key) }
      let liveNodes = Set(nodes.values.map(ObjectIdentifier.init))
      heights = heights.filter {
        liveNodes.contains($0.key) || $0.key == ObjectIdentifier(bannerNode)
      }
    }

    private func remove(_ entry: CredentialEntry) {
      guard let outline, let location = tree.location(of: entry) else { return }
      tree.remove(at: location)
      outline.removeItems(
        at: [outlineIndex(location)], inParent: parentNode(location.section),
        withAnimation: .effectFade)
    }

    /// Move or insert `entries` so they are the first children of `section`,
    /// in order. A nil section is the root.
    private func place(_ entries: [CredentialEntry], in section: String?) {
      guard let outline else { return }
      for (index, entry) in entries.enumerated() {
        let destination = OutlineTree.Location(section: section, index: index)
        if let location = tree.location(of: entry) {
          guard location != destination else { continue }
          tree.remove(at: location)
          tree.insert(entry, at: destination)
          outline.moveItem(
            at: outlineIndex(location), inParent: parentNode(location.section),
            to: outlineIndex(destination), inParent: parentNode(section))
        } else {
          tree.insert(entry, at: destination)
          outline.insertItems(
            at: [outlineIndex(destination)], inParent: parentNode(section),
            withAnimation: .effectFade)
        }
      }
    }

    /// Whether the outline rows are the banner followed by `tree` with
    /// collapsed children left out.
    private func rowsMatchTree() -> Bool {
      guard let outline else { return false }
      var expected: [OutlineNode] = [bannerNode]
      for entry in tree.root {
        let item = node(for: entry)
        expected.append(item)
        if case .section(let id) = entry, outline.isItemExpanded(item) {
          expected += tree.children[id, default: []].map(node(for:))
        }
      }
      guard expected.count == outline.numberOfRows else { return false }
      return expected.enumerated().allSatisfy {
        outline.item(atRow: $0.offset) as? OutlineNode === $0.element
      }
    }

    private func syncExpansion(animated: Bool) {
      guard let outline else { return }
      for case .section(let id) in tree.root {
        let node = node(for: .section(id))
        let expand = !parent.collapsedSections.contains(id)
        guard outline.isItemExpanded(node) != expand else { continue }
        if animated {
          NSAnimationContext.runAnimationGroup { context in
            context.duration = 0.2
            if expand {
              outline.animator().expandItem(node)
            } else {
              outline.animator().collapseItem(node)
            }
          }
        } else if expand {
          outline.expandItem(node)
        } else {
          outline.collapseItem(node)
        }
      }
    }

    private func syncSelection() {
      guard let outline else { return }
      let rows = self.rows(for: parent.selection)
      if rows != outline.selectedRowIndexes {
        outline.selectRowIndexes(rows, byExtendingSelection: false)
      }
    }

    /// Update the content and chrome of every row on screen.
    func refreshRows() {
      guard let outline else { return }
      for row in 0..<outline.numberOfRows {
        if let rowView = outline.rowView(atRow: row, makeIfNecessary: false) as? EntryRowView {
          configure(rowView, row: row)
        }
        refreshCell(row: row)
      }
    }

    private func refreshCell(row: Int) {
      // Read the cell from the row view directly. `NSTableView.view(atColumn:row:)` raises
      // if the row view has no cell yet, which happens while selection changes during an update.
      guard let outline, let node = outline.item(atRow: row) as? OutlineNode,
        let rowView = outline.rowView(atRow: row, makeIfNecessary: false),
        let cell = rowView.subviews.lazy.compactMap({ $0 as? RowHostingView }).first
      else { return }
      cell.rootView = rootView(for: node, row: row)
    }

    // MARK: Rows

    private func node(for entry: CredentialEntry) -> OutlineNode {
      if let node = nodes[entry] { return node }
      let node = OutlineNode(.entry(entry))
      nodes[entry] = node
      return node
    }

    private func parentNode(_ section: String?) -> OutlineNode? {
      section.map { node(for: .section($0)) }
    }

    /// Outline child index of a tree location. Root indices are offset by the
    /// banner row.
    private func outlineIndex(_ location: OutlineTree.Location) -> Int {
      location.section == nil ? location.index + 1 : location.index
    }

    private func entry(atRow row: Int) -> CredentialEntry? {
      guard let outline, row >= 0, row < outline.numberOfRows else { return nil }
      return (outline.item(atRow: row) as? OutlineNode)?.entry
    }

    private func rows(for entries: Set<CredentialEntry>) -> IndexSet {
      guard let outline else { return [] }
      return IndexSet(
        entries.compactMap { nodes[$0].map(outline.row(forItem:)) }.filter { $0 >= 0 })
    }

    private struct RowLayout {
      var outline: SectionOutline.Position?
      var isSection = false
      var previous: CredentialEntry?
      var next: CredentialEntry?
      var nextIsCredential: Bool { next.map { !$0.isSection } ?? false }
    }

    /// Section outline segment and neighbors of a row. Neighbors determine
    /// whether highlights join.
    private func layout(atRow row: Int) -> RowLayout {
      guard let outline, let entry = entry(atRow: row) else { return RowLayout() }
      var layout = RowLayout(
        isSection: entry.isSection, previous: self.entry(atRow: row - 1),
        next: self.entry(atRow: row + 1))
      if entry.isSection {
        layout.outline = layout.nextIsCredential ? .top : .single
      } else if outline.parent(forItem: outline.item(atRow: row)) != nil {
        layout.outline = layout.nextIsCredential ? .middle : .bottom
      }
      return layout
    }

    private func configure(_ rowView: EntryRowView, row: Int) {
      let layout = layout(atRow: row)
      rowView.outline = layout.outline
      rowView.isSectionHeader = layout.isSection
      rowView.nextIsCredential = layout.nextIsCredential
      if let entry = entry(atRow: row), menuTargets.contains(entry) {
        rowView.menuOutline = EntryRowView.MenuOutline(
          joinsAbove: !layout.isSection && layout.previous.map(menuTargets.contains) == true,
          joinsBelow: layout.nextIsCredential && layout.next.map(menuTargets.contains) == true)
      } else {
        rowView.menuOutline = nil
      }
      rowView.isDropTarget =
        dropLocation?.section != nil && section(ofRow: row) == dropLocation?.section
    }

    /// Section a row belongs to. A header belongs to its own section.
    private func section(ofRow row: Int) -> String? {
      guard let outline else { return nil }
      switch entry(atRow: row) {
      case .section(let id)?:
        return id
      case .credential?:
        return (outline.parent(forItem: outline.item(atRow: row)) as? OutlineNode)?.entry
          .flatMap { if case .section(let id) = $0 { id } else { nil } }
      case nil:
        return nil
      }
    }

    private func content(for node: OutlineNode, row: Int) -> AnyView {
      switch node.kind {
      case .banner:
        return parent.banner(outline?.isEmphasized ?? false)
      case .entry(let entry):
        let isProminent =
          outline.map { $0.isRowSelected(row) && $0.isEmphasized } ?? false
        return parent.row(
          entry, OutlineRowState(outline: layout(atRow: row).outline, isProminent: isProminent))
      }
    }

    /// Row content at its natural height, top aligned. Height changes are
    /// reported so the row resizes. Zero minimum height limits the frame to
    /// the row height. Content taller than the row extends below it until the
    /// row resizes, instead of being centered by the hosting view.
    private func rootView(for node: OutlineNode, row: Int) -> AnyView {
      AnyView(
        content(for: node, row: row)
          .fixedSize(horizontal: false, vertical: true)
          .onGeometryChange(for: CGFloat.self) {
            $0.size.height
          } action: { [weak self, weak node] in
            guard let node else { return }
            self?.contentHeightChanged($0, node: node)
          }
          .frame(maxWidth: .infinity, minHeight: 0, maxHeight: .infinity, alignment: .top)
          .ignoresSafeArea()
          .id(ObjectIdentifier(node))
      )
    }

    private func contentHeightChanged(_ height: CGFloat, node: OutlineNode) {
      let id = ObjectIdentifier(node)
      let height = ceil(height)
      guard heights[id] != height else { return }
      heights[id] = height
      // Coalesce changes and apply them after the current layout pass.
      if heightChanges.isEmpty {
        DispatchQueue.main.async { [weak self] in self?.applyHeightChanges() }
      }
      heightChanges.insert(id)
    }

    private func applyHeightChanges() {
      guard let outline else { return }
      let changed = heightChanges
      heightChanges = []
      let rows = IndexSet(
        (0..<outline.numberOfRows).filter { row in
          (outline.item(atRow: row) as? OutlineNode).map { changed.contains(ObjectIdentifier($0)) }
            ?? false
        })
      guard !rows.isEmpty else { return }
      NSAnimationContext.runAnimationGroup { context in
        context.duration = 0
        outline.noteHeightOfRows(withIndexesChanged: rows)
      }
    }

    /// Height of a row not yet on screen. Measured from its content at the
    /// current width.
    private func measuredHeight(of node: OutlineNode, row: Int) -> CGFloat {
      let width = max((outline?.bounds.width ?? 0) - 2 * cellMargin, 200)
      sizingController.rootView = AnyView(content(for: node, row: row).ignoresSafeArea())
      let size = sizingController.sizeThatFits(
        in: CGSize(width: width, height: .greatestFiniteMagnitude))
      return ceil(size.height)
    }

    // MARK: Data source

    private func children(of item: Any?) -> [OutlineNode] {
      guard let owner = item as? OutlineNode else {
        return [bannerNode] + tree.root.map(node(for:))
      }
      if case .entry(.section(let id)) = owner.kind {
        return tree.children[id, default: []].map(node(for:))
      }
      return []
    }

    func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
      children(of: item).count
    }

    func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
      children(of: item)[index]
    }

    func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
      (item as? OutlineNode)?.entry?.isSection == true
    }

    // MARK: Delegate

    func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any)
      -> NSView?
    {
      guard let node = item as? OutlineNode else { return nil }
      return RowHostingView(rootView: rootView(for: node, row: outlineView.row(forItem: node)))
    }

    func outlineView(_ outlineView: NSOutlineView, rowViewForItem item: Any) -> NSTableRowView? {
      let rowView = EntryRowView()
      rowView.onStateChange = { [weak self, weak rowView] in
        guard let self, let rowView, let row = self.outline?.row(for: rowView), row >= 0 else {
          return
        }
        self.refreshCell(row: row)
      }
      return rowView
    }

    func outlineView(_ outlineView: NSOutlineView, didAdd rowView: NSTableRowView, forRow row: Int)
    {
      if let rowView = rowView as? EntryRowView {
        configure(rowView, row: row)
      }
    }

    func outlineView(_ outlineView: NSOutlineView, heightOfRowByItem item: Any) -> CGFloat {
      guard let node = item as? OutlineNode else { return 1 }
      let id = ObjectIdentifier(node)
      if let height = heights[id] { return max(height, 1) }
      let height = measuredHeight(of: node, row: outlineView.row(forItem: node))
      heights[id] = height
      return max(height, 1)
    }

    func outlineViewItemDidExpand(_ notification: Notification) {
      expansionChanged(notification, collapsed: false)
    }

    func outlineViewItemDidCollapse(_ notification: Notification) {
      expansionChanged(notification, collapsed: true)
    }

    private func expansionChanged(_ notification: Notification, collapsed: Bool) {
      refreshRows()
      guard !isSyncing, let node = notification.userInfo?["NSObject"] as? OutlineNode,
        case .entry(.section(let id)) = node.kind
      else { return }
      parent.onSetCollapsed(id, collapsed)
    }

    // MARK: Selection

    /// Selection for proposed selected rows. Selected rows hidden in collapsed
    /// sections stay selected.
    private func normalizedSelection(rows proposed: IndexSet) -> Set<CredentialEntry> {
      let old = parent.selection
      let visible = Set(proposed.compactMap(entry(atRow:)))
      let hidden = old.subtracting(visible).filter { rows(for: [$0]).isEmpty }
      return parent.normalizeSelection(old, visible.union(hidden))
    }

    func outlineView(
      _ outlineView: NSOutlineView,
      selectionIndexesForProposedSelection proposedSelectionIndexes: IndexSet
    ) -> IndexSet {
      guard !isSyncing else { return proposedSelectionIndexes }
      return rows(for: normalizedSelection(rows: proposedSelectionIndexes))
    }

    func outlineViewSelectionDidChange(_ notification: Notification) {
      guard !isSyncing, let outline else { return }
      let selection = normalizedSelection(rows: outline.selectedRowIndexes)
      if selection != parent.selection {
        parent.selection = selection
      }
    }

    // MARK: Actions

    @objc func doubleClicked(_ sender: Any?) {
      guard let outline, entry(atRow: outline.clickedRow) != nil else { return }
      parent.onOpen(parent.selection)
    }

    func primaryAction() {
      parent.onPrimaryAction(parent.selection)
    }

    func quickLook() -> Bool {
      parent.onQuickLook(parent.selection)
    }

    func deleteSelection() {
      parent.onDelete(parent.selection)
    }

    /// Whether `row` is the banner row.
    func isBanner(row: Int) -> Bool {
      guard let outline, row >= 0, row < outline.numberOfRows else { return false }
      return (outline.item(atRow: row) as? OutlineNode) === bannerNode
    }

    // MARK: Context menu

    /// Menu for a right click on a row, or on empty space if `row` is -1. Acts
    /// on the selection if the row is selected, otherwise on the row alone.
    func menu(forRow row: Int) -> NSMenu? {
      let targets: Set<CredentialEntry> =
        entry(atRow: row).map { parent.selection.contains($0) ? parent.selection : [$0] } ?? []
      let items = parent.menu(targets)
      guard !items.isEmpty else { return nil }
      let menu = NSMenu()
      menu.items = menuItems(items)
      menu.delegate = self
      menuTargets = targets
      refreshRows()
      return menu
    }

    func menuDidClose(_ menu: NSMenu) {
      menuTargets = []
      refreshRows()
    }

    private func menuItems(_ items: [OutlineMenuItem]) -> [NSMenuItem] {
      items.map { item in
        switch item {
        case .action(let title, let handler):
          return ClosureMenuItem(title: title, handler: handler)
        case .toggle(let title, let isOn, let handler):
          let menuItem = ClosureMenuItem(title: title) { handler(!isOn) }
          menuItem.state = isOn ? .on : .off
          return menuItem
        case .submenu(let title, let children):
          let menuItem = NSMenuItem(title: title, action: nil, keyEquivalent: "")
          let submenu = NSMenu(title: title)
          submenu.items = menuItems(children)
          menuItem.submenu = submenu
          return menuItem
        case .divider:
          return .separator()
        }
      }
    }

    // MARK: Drag and drop

    func outlineView(_ outlineView: NSOutlineView, pasteboardWriterForItem item: Any)
      -> (any NSPasteboardWriting)?
    {
      guard let entry = (item as? OutlineNode)?.entry else { return nil }
      let pasteboardItem = NSPasteboardItem()
      pasteboardItem.setString(String(describing: entry), forType: entryPasteboardType)
      return pasteboardItem
    }

    func outlineView(
      _ outlineView: NSOutlineView, draggingSession session: NSDraggingSession,
      willBeginAt screenPoint: NSPoint, forItems draggedItems: [Any]
    ) {
      draggedEntries = draggedItems.compactMap { ($0 as? OutlineNode)?.entry }
      let appearance = outlineView.effectiveAppearance
      let entries = draggedEntries
      session.enumerateDraggingItems(
        options: [], for: outlineView, classes: [NSPasteboardItem.self], searchOptions: [:]
      ) { item, index, _ in
        // Add a translucent background under the row image from the table.
        // Dragging items are in the order of `draggedItems`. A header
        // background starts at its section outline, below the gap.
        let rowImage = item.imageComponentsProvider
        let size = item.draggingFrame.size
        let isSection = index < entries.count && entries[index].isSection
        let top = isSection ? SectionOutline.gap : 0
        item.imageComponentsProvider = {
          let background = NSDraggingImageComponent(key: dragBackgroundKey)
          background.contents = dragBackground(size: size, top: top, appearance: appearance)
          background.frame = CGRect(origin: .zero, size: size)
          return [background] + (rowImage?() ?? [])
        }
      }
    }

    func outlineView(
      _ outlineView: NSOutlineView, draggingSession session: NSDraggingSession,
      endedAt screenPoint: NSPoint, operation: NSDragOperation
    ) {
      draggedEntries = []
      showDrop(nil)
    }

    func outlineView(
      _ outlineView: NSOutlineView, validateDrop info: any NSDraggingInfo, proposedItem item: Any?,
      proposedChildIndex index: Int
    ) -> NSDragOperation {
      guard info.draggingSource as? NSOutlineView === outlineView,
        let target = dropTarget(item: item, childIndex: index)
      else {
        showDrop(nil)
        return []
      }
      outlineView.setDropItem(parentNode(target.section), dropChildIndex: outlineIndex(target))
      showDrop(target)
      return .move
    }

    func outlineView(
      _ outlineView: NSOutlineView, acceptDrop info: any NSDraggingInfo, item: Any?,
      childIndex index: Int
    ) -> Bool {
      showDrop(nil)
      guard let target = dropTarget(item: item, childIndex: index) else { return false }
      parent.onMove(draggedEntries, destination(of: target))
      return true
    }

    /// Show the drop location, or hide it if nil. A section target is
    /// highlighted. The insertion line spans the section, or the list for a
    /// root target.
    func showDrop(_ location: OutlineTree.Location?) {
      guard let outline, location != dropLocation else { return }
      dropLocation = location
      for row in 0..<outline.numberOfRows {
        if let rowView = outline.rowView(atRow: row, makeIfNecessary: false) as? EntryRowView {
          configure(rowView, row: row)
        }
      }
      outline.dropIndicator.line = location.flatMap(insertionLine)
    }

    /// Insertion line for a drop location, in outline coordinates. Nil for a
    /// collapsed or empty section, which shows only its highlight.
    private func insertionLine(_ location: OutlineTree.Location) -> DropIndicatorView.Line? {
      guard let outline else { return nil }
      let chrome = outline.bounds.insetBy(dx: chromeMargin, dy: 0)
      func rect(_ entry: CredentialEntry) -> CGRect? {
        let row = nodes[entry].map(outline.row(forItem:)) ?? -1
        return row >= 0 ? outline.rect(ofRow: row) : nil
      }

      if let section = location.section {
        let children = tree.children[section, default: []]
        guard outline.isItemExpanded(node(for: .section(section))), let last = children.last
        else { return nil }
        // Inset to the section highlight area.
        let inner = outline.bounds.insetBy(
          dx: sectionChromeMargin + EntryRowView.sectionPadding, dy: 0)
        let y: CGFloat?
        if location.index < children.count {
          y = rect(children[location.index])?.minY
        } else {
          y = rect(last).map { $0.maxY - 0.5 - EntryRowView.sectionPadding }
        }
        return y.map { DropIndicatorView.Line(y: $0, minX: inner.minX, maxX: inner.maxX) }
      }

      let y: CGFloat?
      if location.index < tree.root.count {
        let entry = tree.root[location.index]
        // Above a section, the line is centered in the gap over its outline.
        y = rect(entry).map { entry.isSection ? $0.minY + SectionOutline.gap / 2 : $0.minY }
      } else {
        let last = outline.numberOfRows - 1
        y = last >= 0 ? outline.rect(ofRow: last).maxY + SectionOutline.gap / 2 : nil
      }
      let isSection = location.index < tree.root.count && tree.root[location.index].isSection
      let line = isSection ? outline.bounds.insetBy(dx: sectionChromeMargin, dy: 0) : chrome
      return y.map { DropIndicatorView.Line(y: $0, minX: line.minX, maxX: line.maxX) }
    }

    /// Valid drop location for the dragged rows near a proposed one. Sections
    /// drop at the root after the unsectioned credentials. Credentials dropped
    /// at the root between sections go to the end of the section above.
    private func dropTarget(item: Any?, childIndex: Int) -> OutlineTree.Location? {
      guard !draggedEntries.isEmpty else { return nil }
      // Proposed section and index. A nil index means a drop on the item.
      let section: String?
      let index: Int?
      switch (item as? OutlineNode)?.kind {
      case nil:
        section = nil
        index = childIndex < 0 ? nil : max(childIndex - 1, 0)
      case .banner:
        section = nil
        index = 0
      case .entry(.section(let id)):
        section = id
        index = childIndex < 0 ? nil : childIndex
      case .entry(let entry):
        guard let location = tree.location(of: entry) else { return nil }
        section = location.section
        index = location.index + 1
      }

      let unsectioned = tree.root.prefix { !$0.isSection }.count
      if draggedEntries.contains(where: \.isSection) {
        if let section {
          guard let rootIndex = tree.root.firstIndex(of: .section(section)) else { return nil }
          return .init(section: nil, index: (index ?? 0) == 0 ? rootIndex : rootIndex + 1)
        }
        guard let index else { return nil }
        return .init(section: nil, index: max(index, unsectioned))
      }
      if let section {
        return .init(section: section, index: index ?? tree.children[section, default: []].count)
      }
      guard let index else { return nil }
      if index <= unsectioned {
        return .init(section: nil, index: index)
      }
      guard case .section(let above) = tree.root[index - 1] else { return nil }
      return .init(section: above, index: tree.children[above, default: []].count)
    }

    /// Index in `tree.entries` of a drop location.
    private func destination(of location: OutlineTree.Location) -> Int {
      let entries = tree.entries
      if let section = location.section {
        let children = tree.children[section, default: []]
        if location.index < children.count {
          return entries.firstIndex(of: children[location.index]) ?? entries.count
        }
        let header = entries.firstIndex(of: .section(section)) ?? entries.count
        return header + 1 + children.count
      }
      if location.index < tree.root.count {
        return entries.firstIndex(of: tree.root[location.index]) ?? entries.count
      }
      return entries.count
    }
  }
}

/// Outline item. Items are objects so the outline can track them by identity.
final class OutlineNode: NSObject {
  enum Kind {
    case banner
    case entry(CredentialEntry)
  }

  let kind: Kind

  init(_ kind: Kind) {
    self.kind = kind
  }

  var entry: CredentialEntry? {
    if case .entry(let entry) = kind { return entry }
    return nil
  }
}

/// Entries as root rows and section children.
struct OutlineTree: Equatable {
  struct Location: Equatable {
    /// Parent section, or nil for the root.
    var section: String?
    var index: Int
  }

  /// Unsectioned credentials, then section headers.
  var root: [CredentialEntry] = []
  /// Section credentials by section id.
  var children: [String: [CredentialEntry]] = [:]

  init() {}

  init(entries: [CredentialEntry]) {
    var current: String? = nil
    for entry in entries {
      switch entry {
      case .section(let id):
        root.append(entry)
        children[id] = []
        current = id
      case .credential:
        if let current {
          children[current, default: []].append(entry)
        } else {
          root.append(entry)
        }
      }
    }
  }

  /// Flat entries, each section header followed by its credentials.
  var entries: [CredentialEntry] {
    root.flatMap { entry -> [CredentialEntry] in
      guard case .section(let id) = entry else { return [entry] }
      return [entry] + children[id, default: []]
    }
  }

  func location(of entry: CredentialEntry) -> Location? {
    if let index = root.firstIndex(of: entry) {
      return Location(section: nil, index: index)
    }
    for (section, entries) in children {
      if let index = entries.firstIndex(of: entry) {
        return Location(section: section, index: index)
      }
    }
    return nil
  }

  /// Remove an entry. A section keeps its children until it is inserted again
  /// or replaced.
  mutating func remove(at location: Location) {
    if let section = location.section {
      children[section]?.remove(at: location.index)
    } else {
      root.remove(at: location.index)
    }
  }

  mutating func insert(_ entry: CredentialEntry, at location: Location) {
    if let section = location.section {
      children[section, default: []].insert(entry, at: location.index)
    } else {
      root.insert(entry, at: location.index)
      if case .section(let id) = entry, children[id] == nil {
        children[id] = []
      }
    }
  }

  static func == (lhs: OutlineTree, rhs: OutlineTree) -> Bool {
    lhs.entries == rhs.entries
  }
}

/// Outline with cells spanning the row width, no indentation, and no
/// disclosure buttons. Handles keys and context menus for the coordinator.
final class EntryOutlineView: NSOutlineView {
  weak var coordinator: CredentialOutline.Coordinator?

  /// Insertion line shown while dragging. Kept above the rows.
  lazy var dropIndicator: DropIndicatorView = {
    let view = DropIndicatorView(frame: bounds)
    view.autoresizingMask = [.width, .height]
    view.onShow = { [weak self, weak view] in
      guard let self, let view else { return }
      view.frame = self.bounds
      self.addSubview(view, positioned: .above, relativeTo: nil)
    }
    return view
  }()

  override func draggingExited(_ sender: (any NSDraggingInfo)?) {
    super.draggingExited(sender)
    coordinator?.showDrop(nil)
  }

  override func draggingEnded(_ sender: any NSDraggingInfo) {
    super.draggingEnded(sender)
    coordinator?.showDrop(nil)
  }

  override func mouseDown(with event: NSEvent) {
    coordinator?.parent.onMouseDown()
    super.mouseDown(with: event)
  }

  override func frameOfCell(atColumn column: Int, row: Int) -> NSRect {
    rect(ofRow: row).insetBy(dx: cellMargin, dy: 0)
  }

  override func frameOfOutlineCell(atRow row: Int) -> NSRect { .zero }

  override func menu(for event: NSEvent) -> NSMenu? {
    coordinator?.menu(forRow: row(at: convert(event.locationInWindow, from: nil)))
  }

  /// Let views in the banner row take focus on the first click. By default a
  /// table only lets a text field in a selected row take focus, and the banner
  /// row is never selected.
  override func validateProposedFirstResponder(_ responder: NSResponder, for event: NSEvent?)
    -> Bool
  {
    if let view = responder as? NSView, coordinator?.isBanner(row: row(for: view)) == true {
      return true
    }
    return super.validateProposedFirstResponder(responder, for: event)
  }

  // The row view draws the context menu outline. Skipping super leaves out the
  // table menu outline, which spans the full row width.
  override func willOpenMenu(_ menu: NSMenu, with event: NSEvent) {}
  override func didCloseMenu(_ menu: NSMenu, with event: NSEvent?) {}

  // The banner shows a selected login card row in the accent color only while
  // the outline has focus. `isEmphasized` changes after these return.
  override func becomeFirstResponder() -> Bool {
    let became = super.becomeFirstResponder()
    DispatchQueue.main.async { [weak self] in self?.coordinator?.refreshRows() }
    return became
  }

  override func resignFirstResponder() -> Bool {
    let resigned = super.resignFirstResponder()
    DispatchQueue.main.async { [weak self] in self?.coordinator?.refreshRows() }
    return resigned
  }

  override func keyDown(with event: NSEvent) {
    let modifiers = event.modifierFlags.intersection([.command, .option, .control, .shift])
    guard modifiers.isEmpty else { return super.keyDown(with: event) }
    switch event.keyCode {
    // Return and keypad Enter.
    case 36, 76: coordinator?.primaryAction()
    // Delete and forward delete.
    case 51, 117: coordinator?.deleteSelection()
    // Space.
    case 49 where coordinator?.quickLook() == true: break
    default: super.keyDown(with: event)
    }
  }

  /// Edit > Delete.
  @objc func delete(_ sender: Any?) {
    coordinator?.deleteSelection()
  }

  /// Whether selected rows use the accent highlight.
  var isEmphasized: Bool {
    window?.isKeyWindow == true && window?.firstResponder === self
  }
}

/// SwiftUI row content. Sized by the outline.
final class RowHostingView: NSHostingView<AnyView> {
  required init(rootView: AnyView) {
    super.init(rootView: rootView)
    sizingOptions = []
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    fatalError("init(coder:) is not supported")
  }
}

/// Row background. Draws the selection highlight, context menu outline, and
/// section outline segment. Inside a section, the highlight and menu outline
/// are inset from the section outline.
final class EntryRowView: NSTableRowView {
  /// Outline around the rows a context menu acts on.
  struct MenuOutline: Equatable {
    var joinsAbove: Bool
    var joinsBelow: Bool
  }

  private static let radius: CGFloat = 6
  /// Space between a section outline and the highlight inside it.
  static let sectionPadding: CGFloat = 6

  var outline: SectionOutline.Position? {
    didSet { if oldValue != outline { needsDisplay = true } }
  }
  var isSectionHeader = false {
    didSet { if oldValue != isSectionHeader { needsDisplay = true } }
  }
  var nextIsCredential = false {
    didSet { if oldValue != nextIsCredential { needsDisplay = true } }
  }
  var menuOutline: MenuOutline? {
    didSet { if oldValue != menuOutline { needsDisplay = true } }
  }
  /// Whether the row is in the section that dragged rows drop into.
  var isDropTarget = false {
    didSet { if oldValue != isDropTarget { needsDisplay = true } }
  }
  /// Called when the selected or emphasized state changes.
  var onStateChange: (() -> Void)?

  override var isFlipped: Bool { true }

  override var isSelected: Bool {
    didSet { if oldValue != isSelected { onStateChange?() } }
  }
  override var isEmphasized: Bool {
    didSet { if oldValue != isEmphasized { onStateChange?() } }
  }
  override var isPreviousRowSelected: Bool {
    didSet { needsDisplay = true }
  }
  override var isNextRowSelected: Bool {
    didSet { needsDisplay = true }
  }

  private var chromeRect: CGRect {
    bounds.insetBy(dx: chromeMargin, dy: 0)
  }

  private var sectionChromeRect: CGRect {
    bounds.insetBy(dx: sectionChromeMargin, dy: 0)
  }

  /// Rectangle shared by the highlight and menu outline.
  private var highlightRect: CGRect {
    let startsSection = outline == .top || outline == .single
    let endsSection = outline == .bottom || outline == .single
    let inner = outline == nil ? 0 : Self.sectionPadding
    let top = startsSection ? SectionOutline.gap + inner : 0
    let bottom = endsSection ? 0.5 + inner : 0
    var rect = (outline == nil ? chromeRect : sectionChromeRect).insetBy(dx: inner, dy: 0)
    rect.origin.y += top
    rect.size.height -= top + bottom
    return rect
  }

  override func drawBackground(in dirtyRect: NSRect) {}

  override func drawSeparator(in dirtyRect: NSRect) {}

  override func drawSelection(in dirtyRect: NSRect) {
    let topRadius = !isSectionHeader && isPreviousRowSelected ? 0 : Self.radius
    let bottomRadius = nextIsCredential && isNextRowSelected ? 0 : Self.radius
    let shape = UnevenRoundedRectangle(
      topLeadingRadius: topRadius, bottomLeadingRadius: bottomRadius,
      bottomTrailingRadius: bottomRadius, topTrailingRadius: topRadius)
    let color: NSColor =
      isEmphasized ? .selectedContentBackgroundColor : .unemphasizedSelectedContentBackgroundColor
    color.setFill()
    NSBezierPath(cgPath: shape.path(in: highlightRect).cgPath).fill()
  }

  override func draw(_ dirtyRect: NSRect) {
    if isDropTarget, let outline {
      NSColor.controlAccentColor.withAlphaComponent(0.12).setFill()
      NSBezierPath(cgPath: SectionOutline(position: outline).fillPath(in: sectionChromeRect).cgPath)
        .fill()
    }

    super.draw(dirtyRect)

    if let menuOutline {
      let shape = MenuTargetOutline(
        radius: Self.radius, openTop: menuOutline.joinsAbove, openBottom: menuOutline.joinsBelow)
      // The accent color, or white over the accent highlight.
      let color: NSColor =
        isSelected && isEmphasized ? .alternateSelectedControlTextColor : .controlAccentColor
      stroke(shape.path(in: highlightRect), color: color, width: MenuTargetOutline.lineWidth)
    }

    if let outline {
      stroke(
        SectionOutline(position: outline).path(in: sectionChromeRect),
        color: isDropTarget ? .controlAccentColor : .separatorColor, width: 1)
    }
  }
}

private func stroke(_ path: Path, color: NSColor, width: CGFloat) {
  let bezier = NSBezierPath(cgPath: path.cgPath)
  bezier.lineWidth = width
  color.setStroke()
  bezier.stroke()
}

/// Insertion line for a drop between rows. Drawn in accent color with a ring
/// at the leading end, like the native drop indicator.
final class DropIndicatorView: NSView {
  struct Line: Equatable {
    var y: CGFloat
    var minX: CGFloat
    var maxX: CGFloat
  }

  private static let ringRadius: CGFloat = 3
  private static let lineWidth: CGFloat = 2

  var line: Line? {
    didSet {
      guard oldValue != line else { return }
      if line != nil { onShow?() }
      needsDisplay = true
    }
  }
  /// Called before the line is shown. Moves the view above the rows.
  var onShow: (() -> Void)?

  override var isFlipped: Bool { true }

  // Drags and clicks pass through to the outline.
  override func hitTest(_ point: NSPoint) -> NSView? { nil }

  override func draw(_ dirtyRect: NSRect) {
    guard let line else { return }
    let r = Self.ringRadius
    var path = Path()
    path.addEllipse(
      in: CGRect(x: line.minX, y: line.y - r, width: 2 * r, height: 2 * r))
    path.move(to: CGPoint(x: line.minX + 2 * r, y: line.y))
    path.addLine(to: CGPoint(x: line.maxX, y: line.y))
    stroke(path, color: .controlAccentColor, width: Self.lineWidth)
  }
}

/// Menu item that runs a closure.
private final class ClosureMenuItem: NSMenuItem {
  private let handler: () -> Void

  init(title: String, handler: @escaping () -> Void) {
    self.handler = handler
    super.init(title: title, action: #selector(ClosureMenuItem.runHandler), keyEquivalent: "")
    target = self
  }

  @available(*, unavailable)
  required init(coder: NSCoder) {
    fatalError("init(coder:) is not supported")
  }

  @objc private func runHandler() {
    handler()
  }
}

/// Rounded outline drawn inside its rectangle. An open top or bottom omits that
/// edge and squares its corners, so consecutive row outlines join into one.
struct MenuTargetOutline: Shape {
  static let lineWidth: CGFloat = 2

  let radius: CGFloat
  let openTop: Bool
  let openBottom: Bool

  func path(in rect: CGRect) -> Path {
    // Inset by half the stroke so the stroke stays inside the rectangle.
    let inset = Self.lineWidth / 2
    let r = max(radius - inset, 0)
    let minX = rect.minX + inset
    let maxX = rect.maxX - inset
    let top = openTop ? rect.minY : rect.minY + inset
    let bottom = openBottom ? rect.maxY : rect.maxY - inset
    var path = Path()
    switch (openTop, openBottom) {
    case (true, true):
      path.move(to: CGPoint(x: minX, y: top))
      path.addLine(to: CGPoint(x: minX, y: bottom))
      path.move(to: CGPoint(x: maxX, y: top))
      path.addLine(to: CGPoint(x: maxX, y: bottom))
    case (true, false):
      path.move(to: CGPoint(x: minX, y: top))
      path.addArc(
        tangent1End: CGPoint(x: minX, y: bottom), tangent2End: CGPoint(x: minX + r, y: bottom),
        radius: r)
      path.addArc(
        tangent1End: CGPoint(x: maxX, y: bottom), tangent2End: CGPoint(x: maxX, y: bottom - r),
        radius: r)
      path.addLine(to: CGPoint(x: maxX, y: top))
    case (false, true):
      path.move(to: CGPoint(x: minX, y: bottom))
      path.addArc(
        tangent1End: CGPoint(x: minX, y: top), tangent2End: CGPoint(x: minX + r, y: top),
        radius: r)
      path.addArc(
        tangent1End: CGPoint(x: maxX, y: top), tangent2End: CGPoint(x: maxX, y: top + r),
        radius: r)
      path.addLine(to: CGPoint(x: maxX, y: bottom))
    case (false, false):
      path.addRoundedRect(
        in: CGRect(x: minX, y: top, width: maxX - minX, height: bottom - top),
        cornerSize: CGSize(width: r, height: r))
    }
    return path
  }
}

/// Segment of the rounded outline around a section. Each row draws its segment
/// across its full height so the segments join into one outline. The header
/// draws the top, credentials draw the sides, and the last credential draws
/// the bottom.
struct SectionOutline: Shape {
  enum Position {
    /// Header of a section with visible credentials.
    case top
    case middle
    case bottom
    /// Header of an empty or collapsed section.
    case single
  }

  /// Space above the outline, separating a section from the previous row.
  static let gap: CGFloat = 8
  private static let radius: CGFloat = 8

  let position: Position

  /// Area inside this segment of the outline. Rounded only where the outline
  /// starts or ends.
  func fillPath(in rect: CGRect) -> Path {
    let startsSection = position == .top || position == .single
    let endsSection = position == .bottom || position == .single
    let top = startsSection ? rect.minY + Self.gap : rect.minY
    let bottom = endsSection ? rect.maxY - 0.5 : rect.maxY
    let topRadius = startsSection ? Self.radius : 0
    let bottomRadius = endsSection ? Self.radius : 0
    return UnevenRoundedRectangle(
      topLeadingRadius: topRadius, bottomLeadingRadius: bottomRadius,
      bottomTrailingRadius: bottomRadius, topTrailingRadius: topRadius
    )
    .path(in: CGRect(x: rect.minX, y: top, width: rect.width, height: bottom - top))
  }

  func path(in rect: CGRect) -> Path {
    let r = Self.radius
    let top = rect.minY + Self.gap
    // The bottom stroke is drawn inside the row so it is not clipped.
    let bottom = rect.maxY - 0.5
    var path = Path()
    switch position {
    case .top:
      path.move(to: CGPoint(x: rect.minX, y: rect.maxY))
      path.addLine(to: CGPoint(x: rect.minX, y: top + r))
      path.addArc(
        tangent1End: CGPoint(x: rect.minX, y: top), tangent2End: CGPoint(x: rect.minX + r, y: top),
        radius: r)
      path.addLine(to: CGPoint(x: rect.maxX - r, y: top))
      path.addArc(
        tangent1End: CGPoint(x: rect.maxX, y: top), tangent2End: CGPoint(x: rect.maxX, y: top + r),
        radius: r)
      path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
    case .middle:
      path.move(to: CGPoint(x: rect.minX, y: rect.minY))
      path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY))
      path.move(to: CGPoint(x: rect.maxX, y: rect.minY))
      path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
    case .bottom:
      path.move(to: CGPoint(x: rect.minX, y: rect.minY))
      path.addLine(to: CGPoint(x: rect.minX, y: bottom - r))
      path.addArc(
        tangent1End: CGPoint(x: rect.minX, y: bottom),
        tangent2End: CGPoint(x: rect.minX + r, y: bottom), radius: r)
      path.addLine(to: CGPoint(x: rect.maxX - r, y: bottom))
      path.addArc(
        tangent1End: CGPoint(x: rect.maxX, y: bottom),
        tangent2End: CGPoint(x: rect.maxX, y: bottom - r), radius: r)
      path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
    case .single:
      path.addRoundedRect(
        in: CGRect(x: rect.minX, y: top, width: rect.width, height: bottom - top),
        cornerSize: CGSize(width: r, height: r))
    }
    return path
  }
}
