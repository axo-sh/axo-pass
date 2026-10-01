import AppKit
import AxoPassFFI
import CryptoKit
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import Observation

/// One thing a palette result can do. Returns an error message on failure.
struct PaletteAction: Identifiable {
  let id: String
  let title: String
  let systemImage: String
  /// False for an action that changes what the palette shows, such as Unlock.
  var closesPalette = true
  let perform: @MainActor () async -> String?
}

/// A row in the palette: a vault, an item, a credential, a key, or a command.
struct PaletteResult: Identifiable {
  enum Kind {
    case vault, item, credential, sshKey, gpgKey, ageKey, command

    var label: String {
      switch self {
      case .vault: return "Vault"
      case .item: return "Item"
      case .credential: return "Credential"
      case .sshKey: return "SSH Key"
      case .gpgKey: return "GPG Key"
      case .ageKey: return "age Key"
      case .command: return "Command"
      }
    }
  }

  let id: String
  let kind: Kind
  let title: String
  let subtitle: String?
  let systemImage: String
  /// Further text the query matches against, ranked below the title.
  var keywords: [String] = []
  /// The first action runs on Return.
  let actions: [PaletteAction]
  /// Runs on Command-Return.
  var secondaryAction: PaletteAction? = nil
  /// The query Tab completes to for this row, in `vault/item/credential`
  /// form. A vault or item completes with a trailing slash, ready for the
  /// next segment.
  var completion: String? = nil
  /// Set for a credential row, whose value the row can show.
  var credential: PaletteCredential? = nil
  /// Names of the vault and item a row sits in, shown before its title.
  var breadcrumb: [String] = []
  /// The menu key equivalent of a command row, shown in place of the kind.
  var shortcut: String? = nil

  var defaultAction: PaletteAction? { actions.first }
}

/// The credential behind a palette row.
struct PaletteCredential {
  let ref: ItemRef
  let key: String
  let concealed: Bool
}

/// State behind the command palette: the query, the results it matches, and the
/// action list for one result.
///
/// While the app is locked the palette shows only its unlock prompt; the
/// status item's menu covers the commands. Recently used results are kept in
/// memory only, since item keys are vault metadata that is encrypted at rest.
@Observable
@MainActor
final class PaletteModel {
  enum Mode: Equatable {
    case search
    /// The action list for `actionTarget`.
    case actions
    /// The vaults are locked and the palette is showing the unlock prompt.
    case unlock
  }

  let vaults: VaultsModel
  private let windows: WindowRequests
  private let checkForUpdates: () -> Void
  let sshModel = SshModel()
  private let gpgModel = GpgModel()
  private let ageModel = AgeModel()

  /// Hides the panel. Set by `StatusItemController`.
  var close: () -> Void = {}
  /// Returns key to the panel. Set by `StatusItemController`.
  var refocus: () -> Void = {}

  private(set) var mode: Mode = .search
  var query = "" {
    didSet { if query != oldValue { selectedIndex = 0 } }
  }
  var actionQuery = "" {
    didSet { if actionQuery != oldValue { selectedActionIndex = 0 } }
  }
  var selectedIndex = 0 {
    didSet { updateReveal() }
  }
  var selectedActionIndex = 0
  private(set) var actionTarget: PaletteResult?
  /// The last action's failure, shown in the footer until the next one runs.
  private(set) var message: String?

  /// Values of plain-text credentials, by result id, shown in their rows.
  /// Cleared when the palette closes or the app locks.
  private(set) var plainValues: [String: String] = [:]
  /// Whether Option is held. While it is, the selected concealed credential
  /// shows its value.
  private(set) var optionHeld = false
  /// The concealed value on show, and the id of the row it belongs to.
  private(set) var revealedID: String?
  private(set) var revealedValue: String?

  /// The context the palette's unlock prompt evaluates on, and the view drawing
  /// it. Nil when the palette has no unlock attempt of its own.
  private(set) var unlockContext: LAContext?
  private(set) var unlockView: LAAuthenticationView?
  private var unlockAttempt: Task<Void, Never>?
  /// True while the login password dialog is up. The panel stays open when it
  /// loses key to that dialog.
  private(set) var awaitingSystemDialog = false

  private var recents: [String] = []
  private static let recentLimit = 8

  init(vaults: VaultsModel, windows: WindowRequests, checkForUpdates: @escaping () -> Void) {
    self.vaults = vaults
    self.windows = windows
    self.checkForUpdates = checkForUpdates
  }

  // MARK: - Lifecycle

  /// Reset for a fresh open, and start loading what the results draw on. A
  /// locked app goes straight to the unlock prompt.
  func prepareForOpen() {
    mode = .search
    query = ""
    actionQuery = ""
    selectedIndex = 0
    actionTarget = nil
    message = nil
    clearValues()
    // The vault list is otherwise loaded by the main window, which a broker
    // launch never opens.
    vaults.reload()
    if vaults.isAppUnlocked {
      loadSearchData()
    } else {
      // A locked palette shows only the unlock prompt. The menu, on an
      // Option-click, covers the rest.
      mode = .unlock
      startUnlock()
    }
  }

  /// The panel closed. An unlock prompt left running would hold the auth lock
  /// with nothing on screen, so it is cancelled.
  func didClose() {
    cancelOwnUnlock()
    awaitingSystemDialog = false
    optionHeld = false
    clearValues()
  }

  private func loadSearchData() {
    Task { await vaults.loadAllItems() }
    Task { await sshModel.reload() }
    Task { await gpgModel.reload() }
    Task { await ageModel.reload() }
  }

  // MARK: - Unlock

  /// Raise the unlock prompt in the palette: the embedded biometric when this
  /// Mac has Touch ID, otherwise the login password dialog.
  ///
  /// A prompt already up elsewhere, such as on the lock screen of an open main
  /// window, is taken over rather than waited on.
  func startUnlock() {
    guard !vaults.isAppUnlocked, !vaults.isBrokerPromptVisible, !awaitingSystemDialog else {
      return
    }
    // The palette's own attempt is still running.
    guard unlockContext == nil else { return }
    mode = .unlock
    message = nil
    guard vaults.biometry == .touchID else {
      unlockWithPassword()
      return
    }
    // The view is built before the evaluation starts, so the system dialog is
    // suppressed for this context from the first moment.
    let context = LAContext()
    unlockContext = context
    unlockView = LAAuthenticationView(context: context, controlSize: .regular)
    guard let attempt = vaults.unlock(on: context) else {
      unlockContext = nil
      unlockView = nil
      return
    }
    unlockAttempt = attempt
    Task {
      await attempt.value
      // Drop the prompt once this attempt is over, unless a newer one has
      // replaced it.
      guard unlockContext === context else { return }
      unlockContext = nil
      unlockView = nil
      unlockAttempt = nil
    }
  }

  /// Stop the palette's Touch ID attempt, whether it is evaluating or still
  /// waiting for an attempt it took over to finish.
  private func cancelOwnUnlock() {
    unlockAttempt?.cancel()
    unlockAttempt = nil
    if let unlockContext { vaults.cancelUnlock(on: unlockContext) }
    unlockContext = nil
    unlockView = nil
  }

  /// Unlock through the system dialog, which offers the login password.
  func unlockWithPassword() {
    cancelOwnUnlock()
    awaitingSystemDialog = true
    NSApp.activate()
    vaults.unlockWithPassword()
  }

  /// Called when `vaults.isUnlocking` changes. The palette's own Touch ID
  /// prompt is cleared by `startUnlock` when its attempt ends, since this also
  /// fires between a taken-over attempt ending and the palette's starting.
  func unlockingChanged() {
    guard !vaults.isUnlocking, awaitingSystemDialog else { return }
    awaitingSystemDialog = false
    refocus()
  }

  /// Called when `vaults.isAppUnlocked` changes.
  func unlockedChanged() {
    if vaults.isAppUnlocked {
      unlockContext = nil
      unlockView = nil
      if mode == .unlock { mode = .search }
      loadSearchData()
    } else {
      // A lock while the palette is open, such as the idle timer, leaves the
      // prompt for the user to start.
      clearValues()
      actionTarget = nil
      mode = .unlock
    }
  }

  // MARK: - Credential values

  /// Fetch a plain-text credential's value for its row. Concealed credentials
  /// are fetched only on reveal.
  func loadPlainValue(for result: PaletteResult) async {
    guard let credential = result.credential, !credential.concealed,
      plainValues[result.id] == nil
    else { return }
    guard let value = await credentialText(credential) else { return }
    // A lock or close while the fetch ran has cleared the values since.
    guard vaults.isAppUnlocked else { return }
    plainValues[result.id] = value
  }

  /// Called when Option goes down or up.
  func optionChanged(_ held: Bool) {
    guard held != optionHeld else { return }
    optionHeld = held
    updateReveal()
  }

  /// Show the selected row's concealed value while Option is held, and drop it
  /// otherwise.
  private func updateReveal() {
    guard optionHeld, mode == .search, let result = selectedResult,
      let credential = result.credential, credential.concealed
    else {
      revealedID = nil
      revealedValue = nil
      return
    }
    guard revealedID != result.id else { return }
    revealedID = nil
    revealedValue = nil
    let id = result.id
    Task {
      let value = await credentialText(credential)
      // Option may have been released, or the selection moved, meanwhile.
      guard optionHeld, selectedResult?.id == id else { return }
      revealedID = id
      revealedValue = value
    }
  }

  private func clearValues() {
    plainValues = [:]
    revealedID = nil
    revealedValue = nil
  }

  private func credentialText(_ credential: PaletteCredential) async -> String? {
    guard
      let secret = try? await vaults.credentialSecret(
        vaultKey: credential.ref.vaultKey, itemKey: credential.ref.itemKey,
        credKey: credential.key)
    else { return nil }
    return secret.withUnsafeBytes { String(bytes: $0, encoding: .utf8) }
  }

  // MARK: - Results

  /// A query containing a slash is a `vault/item/credential` path, matched one
  /// segment at a time by prefix. Any other query is a fuzzy search over
  /// everything.
  var results: [PaletteResult] {
    if query.contains("/") { return pathResults }
    let candidates = vaultResults + searchableResults + allCredentialResults + commands
    guard !query.isEmpty else {
      let byID = Dictionary(candidates.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
      let recent = recents.compactMap { byID[$0] }
      let recentIDs = Set(recent.map(\.id))
      return recent + (vaultResults + commands).filter { !recentIDs.contains($0.id) }
    }
    let needle = Array(query.lowercased())
    return
      candidates
      .compactMap { result -> (PaletteResult, Int)? in
        var best = Self.score(needle, in: result.title)
        for keyword in result.keywords {
          if let s = Self.score(needle, in: keyword) { best = max(best ?? .min, s - 20) }
        }
        return best.map { (result, $0) }
      }
      .sorted { $0.1 > $1.1 }
      .map(\.0)
  }

  var selectedResult: PaletteResult? {
    let results = results
    guard results.indices.contains(selectedIndex) else { return nil }
    return results[selectedIndex]
  }

  var filteredActions: [PaletteAction] {
    guard let actionTarget else { return [] }
    let all = actionTarget.actions + [actionTarget.secondaryAction].compactMap { $0 }
    guard !actionQuery.isEmpty else { return all }
    let needle = Array(actionQuery.lowercased())
    return
      all
      .compactMap { action in Self.score(needle, in: action.title).map { (action, $0) } }
      .sorted { $0.1 > $1.1 }
      .map(\.0)
  }

  /// Items and keys. Empty while locked.
  private var searchableResults: [PaletteResult] {
    guard vaults.isAppUnlocked else { return [] }
    return vaults.allItems.map { itemResult($0) }
      + sshModel.keys.map(sshResult)
      + gpgModel.keys.map(gpgResult)
      + ageModel.keys.map(ageResult)
  }

  // MARK: - Paths

  /// Results for a `vault/item/credential` query. Every segment but the last
  /// narrows to the vaults or items it names: an exact key match if there is
  /// one, otherwise every key or title it is a prefix of. The last segment
  /// filters the rows listed, by the same prefix rule.
  private var pathResults: [PaletteResult] {
    guard vaults.isAppUnlocked else { return [] }
    let segments = query.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
    guard segments.count <= 3 else { return [] }

    let matchedVaults = Self.narrow(
      vaults.vaults, to: segments[0], exact: true, key: \.key, title: { $0.name ?? $0.key })
    let items = matchedVaults.flatMap { vault in
      vaults.allItems.filter { $0.vaultKey == vault.key }
    }
    let byTitle: (PaletteResult, PaletteResult) -> Bool = {
      $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending
    }

    if segments.count == 2 {
      return Self.narrow(items, to: segments[1], exact: false, key: \.item.key, title: \.item.title)
        .map { itemResult($0) }
        .sorted(by: byTitle)
    }

    let matchedItems = Self.narrow(
      items, to: segments[1], exact: true, key: \.item.key, title: \.item.title)
    return matchedItems.flatMap { display in
      Self.narrow(
        display.item.credentials, to: segments[2], exact: false, key: \.key, title: \.title
      )
      .map { credentialResult($0, in: display) }
      .sorted(by: byTitle)
    }
  }

  /// Keep the candidates whose key or title starts with `prefix`, ignoring
  /// case. With `exact`, candidates whose key or title equals `prefix` win
  /// outright, so a completed segment such as `work` does not also take in
  /// `workshop`.
  private static func narrow<T>(
    _ candidates: [T], to prefix: String, exact: Bool,
    key: (T) -> String, title: (T) -> String
  ) -> [T] {
    guard !prefix.isEmpty else { return candidates }
    let prefix = prefix.lowercased()
    if exact {
      let exactMatches = candidates.filter {
        key($0).lowercased() == prefix || title($0).lowercased() == prefix
      }
      if !exactMatches.isEmpty { return exactMatches }
    }
    return candidates.filter {
      key($0).lowercased().hasPrefix(prefix) || title($0).lowercased().hasPrefix(prefix)
    }
  }

  /// Complete the query from the results, the way zsh completes a path: first
  /// to the longest prefix every completion shares, and once that adds
  /// nothing, to the selected row. A credential is the end of a path, so on a
  /// credential row this shows its actions instead.
  func complete() {
    if let selected = selectedResult, selected.credential != nil {
      showActions(for: selected)
      return
    }
    let results = results
    let completions = results.compactMap(\.completion)
    if query.contains("/"), completions.count == results.count,
      let common = Self.commonPrefix(completions),
      common.count > query.count, common.lowercased().hasPrefix(query.lowercased())
    {
      query = common
      return
    }
    if let completion = selectedResult?.completion, completion != query {
      query = completion
    }
  }

  /// Undo a completion: go up one segment of the path. A partial segment is
  /// dropped (`work/git` becomes `work/`), and a completed one goes with its
  /// slash (`work/github/` becomes `work/`, `work/` becomes empty). The row
  /// that was left is selected, so Tab returns to it.
  func uncomplete() {
    guard !query.isEmpty else { return }
    let left = query
    var trimmed = query
    if trimmed.hasSuffix("/") { trimmed.removeLast() }
    if let slash = trimmed.lastIndex(of: "/") {
      query = String(trimmed[...slash])
    } else {
      query = ""
    }
    let leftLowered = left.lowercased()
    if let index = results.firstIndex(where: { $0.completion?.lowercased() == leftLowered }) {
      selectedIndex = index
    }
  }

  /// The longest prefix all `strings` share, ignoring case. The characters are
  /// taken from the first string.
  private static func commonPrefix(_ strings: [String]) -> String? {
    guard let first = strings.first else { return nil }
    var prefix = Array(first)
    for string in strings.dropFirst() {
      let chars = Array(string)
      var n = 0
      while n < prefix.count, n < chars.count,
        prefix[n].lowercased() == chars[n].lowercased()
      {
        n += 1
      }
      prefix = Array(prefix.prefix(n))
    }
    return String(prefix)
  }

  // MARK: - Rows

  private var vaultNames: [String: String] {
    Dictionary(vaults.vaults.map { ($0.key, $0.name ?? $0.key) }, uniquingKeysWith: { a, _ in a })
  }

  /// One row per vault, which Tab or Return opens as `vault/`. Empty while
  /// locked.
  private var vaultResults: [PaletteResult] {
    guard vaults.isAppUnlocked else { return [] }
    return vaults.vaults.map { vault in
      let path = "\(vault.key)/"
      return PaletteResult(
        id: "vault:\(vault.key)",
        kind: .vault,
        title: vault.name ?? vault.key,
        subtitle: vault.name == nil ? nil : vault.key,
        systemImage: "archivebox",
        keywords: [vault.key],
        actions: [showContents(path, title: "Show Items")],
        completion: path
      )
    }
  }

  /// Every credential of every cached item. Empty while locked, since a lock
  /// clears the item cache.
  private var allCredentialResults: [PaletteResult] {
    vaults.allItems.flatMap { display in
      display.item.credentials.map { credentialResult($0, in: display) }
    }
  }

  /// An item row. Return lists its credentials, which is where copying
  /// happens.
  private func itemResult(_ display: DisplayItem) -> PaletteResult {
    let item = display.item
    let ref = display.id
    let vaultName = vaultNames[ref.vaultKey]
    let path = "\(ref.vaultKey)/\(ref.itemKey)/"
    return PaletteResult(
      id: "item:\(ref.vaultKey)/\(ref.itemKey)",
      kind: .item,
      title: item.title,
      subtitle: nil,
      systemImage: "key",
      keywords: [item.key, vaultName ?? ""],
      actions: [showContents(path, title: "Show Credentials")],
      secondaryAction: openItemAction(ref),
      completion: path,
      breadcrumb: [vaultName ?? ref.vaultKey]
    )
  }

  private func credentialResult(_ cred: CredentialInfo, in display: DisplayItem) -> PaletteResult {
    let ref = display.id
    let vaultName = vaultNames[ref.vaultKey] ?? ref.vaultKey
    let id = "cred:\(ref.vaultKey)/\(ref.itemKey)/\(cred.key)"
    let reference = "axo://\(ref.vaultKey)/\(ref.itemKey)/\(cred.key)"
    // A plain-text value is named in its copy action once its row has fetched
    // it. Only the first line is shown.
    let copyTitle: String
    if !cred.kind.concealed, let value = plainValues[id] {
      let line = value.split(separator: "\n", maxSplits: 1).first.map(String.init) ?? value
      copyTitle = "Copy “\(line)”"
    } else {
      copyTitle = "Copy Value"
    }
    return PaletteResult(
      id: id,
      kind: .credential,
      title: cred.title,
      subtitle: nil,
      systemImage: cred.kind.concealed ? "lock" : "text.alignleft",
      // The path as words, so a query like `gh pass` finds the GitHub item's
      // password, and the path as keys, as in an `axo://` reference.
      keywords: [
        "\(display.item.title) \(cred.title)",
        "\(vaultName) \(display.item.title) \(cred.title)",
        "\(ref.itemKey) \(cred.key)",
        cred.key,
      ],
      actions: [
        copyAction(cred, of: ref, title: copyTitle),
        referenceAction(cred, of: ref, title: "Copy “\(reference)”"),
      ],
      secondaryAction: openItemAction(ref),
      completion: "\(ref.vaultKey)/\(ref.itemKey)/\(cred.key)",
      credential: PaletteCredential(ref: ref, key: cred.key, concealed: cred.kind.concealed),
      breadcrumb: [vaultName, display.item.title]
    )
  }

  private func copyAction(_ cred: CredentialInfo, of ref: ItemRef, title: String) -> PaletteAction {
    PaletteAction(id: "copy:\(cred.key)", title: title, systemImage: "doc.on.doc") { [vaults] in
      await vaults.copyCredential(vaultKey: ref.vaultKey, itemKey: ref.itemKey, credKey: cred.key)
    }
  }

  private func referenceAction(
    _ cred: CredentialInfo, of ref: ItemRef, title: String
  ) -> PaletteAction {
    PaletteAction(id: "ref:\(cred.key)", title: title, systemImage: "link") {
      Self.copyPlain("axo://\(ref.vaultKey)/\(ref.itemKey)/\(cred.key)")
    }
  }

  private func openItemAction(_ ref: ItemRef) -> PaletteAction {
    PaletteAction(
      id: "open", title: "Show in Axo Pass", systemImage: "arrow.up.forward.app"
    ) { [vaults, windows] in
      vaults.showItem(ref)
      windows.requestMain()
      return nil
    }
  }

  /// Replace the query with `path`, listing what is inside it.
  private func showContents(_ path: String, title: String) -> PaletteAction {
    PaletteAction(
      id: "show", title: title, systemImage: "chevron.right", closesPalette: false
    ) { [weak self] in
      guard let self else { return nil }
      self.query = path
      self.actionTarget = nil
      self.mode = .search
      return nil
    }
  }

  private func sshResult(_ key: SshKeyEntry) -> PaletteResult {
    var actions: [PaletteAction] = []
    if let publicKey = key.publicKeyOpenssh {
      actions.append(
        PaletteAction(id: "pub", title: "Copy Public Key", systemImage: "doc.on.doc") {
          Self.copyPlain(publicKey)
        })
    }
    actions.append(
      PaletteAction(id: "fp", title: "Copy Fingerprint", systemImage: "touchid") {
        Self.copyPlain(key.fingerprintSha256)
      })
    return PaletteResult(
      id: "ssh:\(key.fingerprintSha256)",
      kind: .sshKey,
      title: key.name,
      subtitle: key.comment,
      systemImage: "terminal",
      keywords: [key.comment ?? ""],
      actions: actions,
      secondaryAction: openSection(.ssh)
    )
  }

  private func gpgResult(_ key: GpgKeyEntry) -> PaletteResult {
    let fingerprint = key.fingerprint
    return PaletteResult(
      id: "gpg:\(fingerprint)",
      kind: .gpgKey,
      title: key.name,
      subtitle: key.email,
      systemImage: "signature",
      keywords: [key.email ?? "", key.keyId],
      actions: [
        PaletteAction(id: "pub", title: "Copy Public Key", systemImage: "doc.on.doc") {
          [gpgModel] in
          guard let armored = await gpgModel.exportPublicKey(fingerprint: fingerprint) else {
            return gpgModel.loadError ?? "The public key could not be exported."
          }
          return Self.copyPlain(armored)
        },
        PaletteAction(id: "fp", title: "Copy Fingerprint", systemImage: "touchid") {
          Self.copyPlain(fingerprint)
        },
      ],
      secondaryAction: openSection(.gpg)
    )
  }

  private func ageResult(_ key: AgeKeyEntry) -> PaletteResult {
    PaletteResult(
      id: "age:\(key.recipient)",
      kind: .ageKey,
      title: key.name,
      subtitle: nil,
      systemImage: "lock.doc",
      keywords: [key.recipient],
      actions: [
        PaletteAction(id: "recipient", title: "Copy Recipient", systemImage: "doc.on.doc") {
          Self.copyPlain(key.recipient)
        }
      ],
      secondaryAction: openSection(.age)
    )
  }

  private func openSection(_ dest: SidebarDestination) -> PaletteAction {
    PaletteAction(id: "open", title: "Show in Axo Pass", systemImage: "arrow.up.forward.app") {
      [vaults, windows] in
      vaults.selectSidebarDestination(dest)
      windows.requestMain()
      return nil
    }
  }

  private var commands: [PaletteResult] {
    var commands: [PaletteResult] = []
    func add(
      _ id: String, _ title: String, _ systemImage: String, shortcut: String? = nil,
      closes: Bool = true,
      _ perform: @escaping @MainActor () async -> String?
    ) {
      commands.append(
        PaletteResult(
          id: "cmd:\(id)", kind: .command, title: title, subtitle: nil, systemImage: systemImage,
          actions: [
            PaletteAction(
              id: id, title: title, systemImage: systemImage, closesPalette: closes,
              perform: perform)
          ], shortcut: shortcut))
    }

    if vaults.isAppUnlocked {
      add("lock", "Lock Axo Pass", "lock", shortcut: "⌘L") { [vaults] in
        vaults.lock()
        return nil
      }
    }
    add("open", "Open Axo Pass", "macwindow") { [windows] in
      windows.requestMain()
      return nil
    }
    if vaults.isAppUnlocked {
      add("settings", "Settings…", "gearshape", shortcut: "⌘,") { [windows] in
        windows.requestSettings()
        return nil
      }
    }
    add("updates", "Check for Updates…", "arrow.triangle.2.circlepath") { [checkForUpdates] in
      checkForUpdates()
      return nil
    }
    add("quit", "Quit Axo Pass Completely", "power", shortcut: "⌘Q") {
      NSApp.terminate(nil)
      return nil
    }
    return commands
  }

  // MARK: - Running

  func run(_ action: PaletteAction, of result: PaletteResult) {
    message = nil
    Task {
      if let error = await action.perform() {
        message = error
        return
      }
      guard action.closesPalette else { return }
      remember(result)
      close()
    }
  }

  func runDefault(at index: Int) {
    let results = results
    guard results.indices.contains(index), let action = results[index].defaultAction else {
      return
    }
    run(action, of: results[index])
  }

  private func remember(_ result: PaletteResult) {
    recents.removeAll { $0 == result.id }
    recents.insert(result.id, at: 0)
    if recents.count > Self.recentLimit { recents.removeLast() }
  }

  func showActions(for result: PaletteResult) {
    actionTarget = result
    actionQuery = ""
    selectedActionIndex = 0
    mode = .actions
  }

  private func leaveActions() {
    actionTarget = nil
    mode = .search
  }

  // MARK: - Keys

  /// Handle a navigation key from the panel. Returns false to let the key
  /// reach the focused field.
  func handle(_ key: PaletteKey) -> Bool {
    switch mode {
    case .unlock:
      switch key {
      case .escape:
        close()
      case .enter, .commandEnter:
        startUnlock()
      default:
        return false
      }
      return true

    case .search:
      let count = results.count
      switch key {
      case .up:
        selectedIndex = max(selectedIndex - 1, 0)
      case .down:
        selectedIndex = min(selectedIndex + 1, max(count - 1, 0))
      case .enter:
        runDefault(at: selectedIndex)
      case .commandEnter:
        guard let result = selectedResult, let action = result.secondaryAction else { return true }
        run(action, of: result)
      case .commandK:
        if let result = selectedResult { showActions(for: result) }
      case .tab:
        complete()
      case .shiftTab:
        uncomplete()
      case .escape:
        close()
      case .deleteInEmptyField:
        return false
      }
      return true

    case .actions:
      let actions = filteredActions
      switch key {
      case .up:
        selectedActionIndex = max(selectedActionIndex - 1, 0)
      case .down:
        selectedActionIndex = min(selectedActionIndex + 1, max(actions.count - 1, 0))
      case .enter:
        guard let target = actionTarget, actions.indices.contains(selectedActionIndex) else {
          return true
        }
        run(actions[selectedActionIndex], of: target)
      case .commandEnter, .tab:
        break
      case .commandK, .shiftTab, .escape, .deleteInEmptyField:
        leaveActions()
      }
      return true
    }
  }

  // MARK: - Helpers

  /// Copy text that is not secret, such as a public key or a reference.
  private static func copyPlain(_ text: String) -> String? {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
    return nil
  }

  /// Score `text` against `needle`, a lowercased query, as a case-insensitive
  /// subsequence. Nil when the query characters do not all appear in order.
  /// Matches at the start of the text or of a word, and runs of consecutive
  /// characters, score higher.
  static func score(_ needle: [Character], in text: String) -> Int? {
    let haystack = Array(text.lowercased())
    guard !needle.isEmpty, needle.count <= haystack.count else { return nil }

    var score = 0
    var n = 0
    var previousMatch = -2
    for (i, char) in haystack.enumerated() where n < needle.count && char == needle[n] {
      score += 1
      if i == previousMatch + 1 { score += 5 }
      if i == 0 {
        score += 15
      } else if !haystack[i - 1].isLetter && !haystack[i - 1].isNumber {
        score += 10
      }
      previousMatch = i
      n += 1
    }
    guard n == needle.count else { return nil }
    // Prefer shorter text among equal matches.
    return score * 4 - haystack.count / 4
  }
}
