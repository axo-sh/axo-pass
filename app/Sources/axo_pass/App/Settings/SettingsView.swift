import AppKit
import AuthenticationServices
import AxoPassFFI
import SunshineUI
import SwiftUI

/// The content of the Settings scene in `App.swift`.
///
/// Settings are only available while the app is unlocked, so a lock closes the
/// window as well as disabling the menu item.
struct SettingsView: View {
  @Environment(VaultsModel.self) private var model
  @EnvironmentObject private var updaterUI: SunshineUpdaterUIController
  @State private var window: NSWindow?
  @State private var titleLock = WindowTitleLock()

  var body: some View {
    TabView {
      TerminalSettingsView()
        .settingsPane()
        .tabItem { SettingsTab.label("Terminal", symbol: "terminal") }
      VaultsSettingsView()
        .settingsPane()
        .tabItem { SettingsTab.label("Vaults", symbol: "archivebox") }
      AutoFillSettingsView()
        .settingsPane()
        .tabItem { SettingsTab.label("AutoFill", symbol: "key.viewfinder") }
      GeneralSettingsView()
        .settingsPane()
        .tabItem { SettingsTab.label("General", symbol: "gearshape") }
      SunshineUpdateSettingsView(controller: updaterUI)
        .settingsPane()
        .tabItem { SettingsTab.label("About", symbol: "info.circle") }
    }
    .background(
      WindowAccessor {
        window = $0
        if $0.toolbarStyle != .preference { $0.toolbarStyle = .preference }
        titleLock.lock($0, to: "Axo Pass")
        closeIfLocked()
      }
    )
    .onChange(of: model.isAppUnlocked) { _, _ in closeIfLocked() }
  }

  private func closeIfLocked() {
    guard !model.isAppUnlocked else { return }
    window?.close()
  }
}

/// Keeps a window's title fixed. The Settings scene's `TabView` is an
/// `NSTabViewController`, which copies the selected tab's label into the
/// window title on every tab switch.
@MainActor
private final class WindowTitleLock {
  private var observation: NSKeyValueObservation?
  private weak var window: NSWindow?

  func lock(_ window: NSWindow, to title: String) {
    if window.title != title { window.title = title }
    guard self.window !== window else { return }
    self.window = window
    observation = window.observe(\.title) { window, _ in
      MainActor.assumeIsolated {
        if window.title != title { window.title = title }
      }
    }
  }
}

/// A Settings toolbar tab label whose icon is a symbol drawn into a fixed-size
/// template image. Toolbar items given the symbol directly place it by its own
/// size and alignment insets, which differ per symbol and between the selected
/// and unselected states, so the icons shift on every tab switch.
///
/// This returns a `Label` rather than being a view, because `tabItem` only reads
/// a `Label`, `Text`, or `Image` passed to it directly.
private enum SettingsTab {
  static func label(_ title: String, symbol: String) -> Label<Text, Image> {
    Label {
      Text(title)
    } icon: {
      Image(nsImage: icon(symbol))
    }
  }

  private static let canvas = NSSize(width: 28, height: 28)
  /// Empty space at the bottom of the canvas, which separates the icon from
  /// the label below it.
  private static let labelGap: CGFloat = 4

  private static func icon(_ name: String) -> NSImage {
    let configuration = NSImage.SymbolConfiguration(pointSize: 18, weight: .regular)
    guard
      let symbol = NSImage(systemSymbolName: name, accessibilityDescription: nil)?
        .withSymbolConfiguration(configuration)
    else { return NSImage(size: canvas) }
    let image = NSImage(size: canvas, flipped: false) { rect in
      let size = symbol.size
      let origin = NSPoint(
        x: (rect.width - size.width) / 2,
        y: labelGap + (rect.height - labelGap - size.height) / 2)
      symbol.draw(in: NSRect(origin: origin, size: size))
      return true
    }
    image.isTemplate = true
    return image
  }
}

/// Axo Pass ▸ Settings, replacing the item the `Settings` scene installs so it
/// can be disabled while the app is locked.
struct SettingsMenuItem: View {
  @Environment(VaultsModel.self) private var model
  @Environment(\.openSettings) private var openSettings

  var body: some View {
    Button("Settings…") {
      NSApp.setActivationPolicy(.regular)
      NSApp.activate(ignoringOtherApps: true)
      openSettings()
    }
    .keyboardShortcut(",", modifiers: .command)
    .disabled(!model.isAppUnlocked)
  }
}

private struct GeneralSettingsView: View {
  @AppStorage(Preferences.Key.autoLockMinutes)
  private var autoLockMinutes = Preferences.defaultAutoLockMinutes
  @AppStorage(Preferences.Key.reuseApprovals)
  private var reuseApprovals = Preferences.defaultReuseApprovals
  @AppStorage(Preferences.Key.paletteHotKey)
  private var paletteHotKey: HotKey?
  @State private var audit = AuditSettingsModel()
  @State private var confirmingClear = false

  var body: some View {
    SettingsForm {
      SettingsRow("Show palette:") {
        HotKeyRecorder(hotKey: $paletteHotKey)
        if GlobalHotKey.shared.registrationFailed {
          Text("This shortcut is in use by another app. Choose a different one.")
            .foregroundStyle(.red)
            .captionStyle()
        }
        Text("Opens the search palette from any app.")
          .captionStyle()
      }

      SettingsRow("Lock when idle for:") {
        Picker("Lock when idle for:", selection: $autoLockMinutes) {
          ForEach(Preferences.autoLockChoices, id: \.self) { minutes in
            Text(Preferences.label(forAutoLockMinutes: minutes)).tag(minutes)
          }
        }
        .labelsHidden()
        .fixedSize()
        Text("Always locks on screen lock or sleep.")
          .captionStyle()
      }

      SettingsDivider()

      SettingsRow("Approvals:") {
        Toggle("Reuse an approval for up to \(Self.absolute)", isOn: $reuseApprovals)
          .help(
            """
            Reuse ends \(Self.idle) after the last request, or \(Self.absolute) after the \
            initial approval, whichever comes first. SSH signatures always prompt, except for \
            apps allowed in a key's details.
            """)
        Text(
          """
          Lets a program repeat a GPG or `ap` request on the same key without asking again. \
          Reading a secret always asks.
          """
        )
        .captionStyle()
      }

      SettingsDivider()

      SettingsRow("Activity log:") {
        Toggle(
          "Include account details",
          isOn: Binding(get: { audit.includeDetails }, set: { audit.setIncludeDetails($0) })
        )
        .help(
          """
          Events are always recorded. This setting turns off only the details, and does not \
          change entries already written. The setting is stored in the keychain, where other \
          programs cannot change it. Events that `ap` records while this app is not running \
          are written without details.
          """)
        Text(
          """
          Records site names, hosts, file paths, and similar details with each event. Details \
          are stored in plaintext, and any program that runs as you can read them.
          """
        )
        .captionStyle()
        HStack(spacing: 8) {
          Button("Clear Details…") { confirmingClear = true }
            .disabled(audit.isClearing)
            .help("Remove details from entries already written.")
          if let result = audit.clearResult {
            Text(result).captionStyle()
          }
        }
        if let error = audit.error {
          Text(error)
            .foregroundStyle(.red)
            .captionStyle()
        }
      }
    }
    .confirmationDialog(
      "Clear details from existing entries?", isPresented: $confirmingClear,
      titleVisibility: .visible
    ) {
      Button("Clear Details", role: .destructive) {
        Task { await audit.clearDetails() }
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text(
        "Rewrites every audit file without site names, hosts, key comments, item and vault names, file paths, and error text. This cannot be undone."
      )
    }
  }

  private static let absolute = duration(GrantPolicy.reuseWindow.absolute)
  private static let idle = duration(GrantPolicy.reuseWindow.idle)

  /// A reuse window in words. The windows are whole minutes in a release build
  /// and seconds in a debug one.
  private static func duration(_ seconds: TimeInterval) -> String {
    let value = Int(seconds)
    if value >= 60, value % 60 == 0 {
      let minutes = value / 60
      return minutes == 1 ? "1 minute" : "\(minutes) minutes"
    }
    return value == 1 ? "1 second" : "\(value) seconds"
  }
}

/// Synced folder of the vaults, and export of vaults to an encrypted bundle
/// file or import from one.
private struct VaultsSettingsView: View {
  @Environment(VaultsModel.self) private var model
  @Environment(SyncModel.self) private var sync
  @State private var showingExport = false
  @State private var showingImport = false
  /// Vault files moved to `unreadable/` on new hardware.
  @State private var moved: [MovedVaultInfo] = []
  @State private var showingMoved = false

  var body: some View {
    SettingsForm {
      if !moved.isEmpty {
        SettingsRow("Moved vaults:") {
          HStack(spacing: 8) {
            Text(
              moved.count == 1
                ? "1 vault file from another Mac" : "\(moved.count) vault files from another Mac"
            )
            Button("Show…") { showingMoved = true }
          }
        }
        SettingsDivider()
      }

      SettingsRow("Synced folder:") {
        HStack(spacing: 8) {
          Text(sync.folder.map(rootDescription) ?? "None")
            .foregroundStyle(sync.folder == nil ? .secondary : .primary)
            .lineLimit(1)
            .truncationMode(.middle)
            .help(sync.folder.map(rootDescription) ?? "")
          Button(sync.folder == nil ? "Choose…" : "Change…") { chooseSyncFolder() }
        }
        .help("A change applies only to vaults turned on later. The path can differ on each Mac.")
        Text("Use a folder that a sync service or shared drive copies to your other Macs.")
          .captionStyle()
      }

      SettingsDivider()

      SettingsRow("Backups:") {
        HStack {
          Button("Export…") { showingExport = true }
            .disabled(model.vaults.isEmpty)
          Button("Import…") { showingImport = true }
        }
        Text(
          "Backups are passphrase-encrypted. Import adds vaults and does not overwrite existing ones."
        )
        .captionStyle()
      }
    }
    .sheet(isPresented: $showingExport) {
      VaultExportSheet(model: model)
    }
    .sheet(isPresented: $showingImport) {
      VaultImportSheet(model: model)
    }
    .sheet(isPresented: $showingMoved) {
      MovedVaultsSheet(moved: moved)
    }
    .task { moved = (try? await sync.movedVaults()) ?? [] }
  }

  private func chooseSyncFolder() {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.canCreateDirectories = true
    panel.allowsMultipleSelection = false
    panel.prompt = "Choose"
    panel.message = "Choose the synced folder for your vaults."
    if panel.runModal() == .OK, let url = panel.url { sync.setFolder(url) }
  }
}

/// Whether the system's AutoFill provider for Safari and other apps is on, and
/// the native messaging manifest of each browser.
private struct AutoFillSettingsView: View {
  @State private var isEnabled: Bool? = nil
  @State private var browsers: [BrowserManifestStatus] = []
  @State private var installing: BrowserKind? = nil
  @State private var installError: String? = nil
  @State private var listingGrants: [BrowserListingGrant] = []
  private let core = AxoPass()

  var body: some View {
    SettingsForm {
      SettingsRow("Safari and apps:") {
        HStack(spacing: 10) {
          switch isEnabled {
          case .some(true):
            StatusLabel("Enabled", symbol: "checkmark.circle.fill", color: .green)
          case .some(false):
            StatusLabel("Not Enabled", symbol: "xmark.circle.fill", color: .secondary)
          case .none:
            ProgressView().controlSize(.small)
          }
          Button("Open System Settings…") {
            ASSettingsHelper.openCredentialProviderAppSettings { _ in }
          }
        }
        Text(
          isEnabled == false
            ? "Turn on Axo Pass under Passwords > Password Options to fill logins, one-time codes, and passkeys."
            : "Fills logins, one-time codes, and passkeys."
        )
        .captionStyle()
      }

      SettingsDivider()

      SettingsRow("Browser extensions:") {
        if installedBrowsers.isEmpty {
          Text("No supported browsers found")
            .foregroundStyle(.secondary)
        } else {
          HStack {
            ForEach(installedBrowsers, id: \.name) { status in
              Button("Get \(BrowserManifestStyle.shortName(status.browser)) Extension…") {
                NSWorkspace.shared.open(BrowserManifestStyle.storeURL(status.browser))
              }
            }
          }
        }
        // Only broken connections are listed. The app rewrites the manifests on
        // launch, so a current one needs no attention.
        ForEach(brokenBrowsers, id: \.name) { status in
          HStack(spacing: 10) {
            StatusLabel(
              "\(status.name): \(BrowserManifestStyle.label(status))",
              symbol: "exclamationmark.triangle.fill", color: .orange)
            if installing == status.browser {
              ProgressView().controlSize(.small)
            } else if let action = BrowserManifestStyle.action(status) {
              Button(action) { Task { await install(status.browser) } }
                .disabled(installing != nil)
            }
          }
        }
        if let error = installError {
          Text(error)
            .foregroundStyle(.red)
            .captionStyle()
        }
        Text("Fills logins in Chrome and Firefox through the Axo Pass extension.")
          .captionStyle()
      }

      SettingsDivider()

      SettingsRow("Approvals:") {
        if listingGrants.isEmpty {
          Text("All browsers prompt to show saved logins.")
            .foregroundStyle(.secondary)
        } else {
          ForEach(listingGrants, id: \.teamId) { grant in
            HStack(spacing: 8) {
              Text(grant.name)
              Text(Self.expiryText(grant))
                .foregroundStyle(.secondary)
              Button("Remove") { Task { await removeListingGrant(grant) } }
            }
          }
          Text(
            "These browsers can show saved logins without prompting while Axo Pass is unlocked. Autofills and saves still prompt."
          )
          .captionStyle()
        }
      }
    }
    .task { await refresh() }
    .onReceive(
      NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
    ) { _ in
      Task { await refresh() }
    }
  }

  private var installedBrowsers: [BrowserManifestStatus] {
    browsers.filter(\.browserInstalled)
  }

  private var brokenBrowsers: [BrowserManifestStatus] {
    installedBrowsers.filter {
      if case .current = $0.state { return false }
      return true
    }
  }

  private func refresh() async {
    browsers = browserManifestStatuses()
    isEnabled = await ASCredentialIdentityStore.shared.state().isEnabled
    listingGrants = (try? await core.listBrowserListingGrants()) ?? []
  }

  private func removeListingGrant(_ grant: BrowserListingGrant) async {
    do {
      try await core.removeBrowserListingGrant(name: grant.name, teamId: grant.teamId)
    } catch {
      installError = String(describing: error)
    }
    listingGrants = (try? await core.listBrowserListingGrants()) ?? []
  }

  /// A grant can pass its expiration while shown. It stops applying then.
  private static func expiryText(_ grant: BrowserListingGrant) -> String {
    guard let expiresAt = grant.expiresAt else { return "No expiration" }
    let date = Date(timeIntervalSince1970: TimeInterval(expiresAt))
    if date <= Date() { return "Expired" }
    return "Expires \(date.formatted(.relative(presentation: .named)))"
  }

  private func install(_ browser: BrowserKind) async {
    installing = browser
    installError = nil
    do {
      _ = try await installBrowserManifest(browser: browser)
    } catch {
      installError = String(describing: error)
    }
    browsers = browserManifestStatuses()
    installing = nil
  }
}

/// Labels and links for a browser and its manifest state in Settings > AutoFill.
private enum BrowserManifestStyle {
  static func label(_ status: BrowserManifestStatus) -> String {
    switch status.state {
    case .notInstalled: return "Not Connected"
    case .current: return "Connected"
    case .pointsElsewhere: return "Points to Another Host"
    case .outdated: return "Outdated"
    case .foreign: return "Used by Another App"
    case .unreadable: return "Unreadable"
    }
  }

  static func shortName(_ browser: BrowserKind) -> String {
    switch browser {
    case .chrome: return "Chrome"
    case .firefox: return "Firefox"
    }
  }

  /// Store page of the Axo Pass extension. The ids match `CHROME_EXTENSION_ID`
  /// and `FIREFOX_EXTENSION_ID` in the core crate.
  static func storeURL(_ browser: BrowserKind) -> URL {
    switch browser {
    case .chrome:
      return URL(
        string: "https://chromewebstore.google.com/detail/dnpdmaobhnnkiknbgbfbpjmmgjchfkob")!
    case .firefox:
      return URL(string: "https://addons.mozilla.org/firefox/addon/axo-pass@breakfastlabs.com/")!
    }
  }

  /// Button title, or nil if the manifest is current or must not be written.
  static func action(_ status: BrowserManifestStatus) -> String? {
    guard status.browserInstalled else { return nil }
    switch status.state {
    case .notInstalled: return "Install"
    case .pointsElsewhere, .outdated, .unreadable: return "Repair"
    case .current, .foreign: return nil
    }
  }
}

/// SSH, GPG, and `ap` setup. Each group reports whether a config file routes
/// the tool into this app.
private struct TerminalSettingsView: View {
  @State private var ssh = SshModel()
  @State private var gpg = GpgModel()
  @State private var shell = ShellIntegrationModel()
  @State private var setup: TerminalSetup?

  var body: some View {
    SettingsForm {
      SshSettingsRows(model: ssh) { setup = .ssh }
      SettingsDivider()
      GpgSettingsRows(model: gpg) { setup = .gpg }
      SettingsDivider()
      ShellSettingsRows(model: shell) { setup = .shell }
    }
    .task { refresh() }
    // The files may be edited outside the app, so re-read them on reactivation.
    // The user may also have allowed the background item in System Settings.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      refresh()
    }
    .sheet(item: $setup) { setup in
      switch setup {
      case .ssh: SshSetupSheet(model: ssh)
      case .gpg: GpgSetupSheet(model: gpg)
      case .shell: ShellIntegrationSetupSheet(model: shell)
      }
    }
  }

  private func refresh() {
    ssh.refreshConfStatus()
    ssh.agentService.refreshStatus()
    gpg.refreshConfStatus()
    shell.refreshStatus()
  }
}

/// Setup sheet shown from the Terminal pane.
private enum TerminalSetup: Identifiable {
  case ssh, gpg, shell

  var id: Self { self }
}

/// SSH agent login item, and the `IdentityAgent` line in `~/.ssh/config`,
/// which decides whether ssh talks to this app's agent. The agents' own status
/// lives in the SSH pane.
private struct SshSettingsRows: View {
  let model: SshModel
  let showSetup: () -> Void
  @State private var startAtLoginError: String? = nil

  private var state: SshIdentityAgentState? { model.confStatus?.state }

  private var startAtLogin: Binding<Bool> {
    Binding(
      get: { model.agentService.startsOnLogin },
      set: { on in
        startAtLoginError = nil
        Task {
          do {
            try await model.agentService.setStartsOnLogin(on)
          } catch {
            startAtLoginError = String(describing: error)
          }
          await model.reload()
        }
      }
    )
  }

  var body: some View {
    SettingsRow("SSH agent:") {
      Toggle("Start at login", isOn: startAtLogin)
      Text("Runs the agent in the background and restarts it if it stops.")
        .captionStyle()
      if model.agentService.startsOnLogin && model.agentService.status == .requiresApproval {
        Text("Allow Axo Pass in System Settings > General > Login Items & Extensions.")
          .foregroundStyle(.orange)
          .captionStyle()
        Button("Open Login Items…") { model.agentService.openLoginItemsSettings() }
      }
      if let error = startAtLoginError {
        Text(error)
          .foregroundStyle(.red)
          .captionStyle()
      }
    }
    SettingsRow("SSH config:") {
      HStack(spacing: 8) {
        if let state {
          StatusLabel(
            label(state), symbol: icon(state), color: color(state),
            path: model.confStatus?.configPath)
        }
        if model.isConfiguring || model.isTesting {
          ProgressView().controlSize(.small)
        }
      }
      Text("Lets ssh use keys stored in Axo Pass.")
        .captionStyle()
      HStack {
        if state != .configured {
          Button("Add to ~/.ssh/config") {
            Task { await model.configureAgentConf() }
          }
          .disabled(model.isConfiguring)
        }
        Button("Setup…", action: showSetup)
        if state == .configured {
          Button("Test Connection") {
            Task { await model.testIntegration() }
          }
          .disabled(model.isTesting)
        }
      }
      if let error = model.configureError {
        Text(error)
          .foregroundStyle(.red)
          .captionStyle()
      }
      if let result = model.testResult {
        switch result {
        case .success:
          Text("SSH connected to Axo Pass SSH agent")
            .foregroundStyle(.green)
            .captionStyle()
        case .failure(let message):
          Text(message)
            .foregroundStyle(.red)
            .lineLimit(2)
            .captionStyle()
        }
      }
    }
  }

  private func label(_ state: SshIdentityAgentState) -> String {
    switch state {
    case .configured: return "Configured"
    case .notConfigured: return "Not Configured"
    case .otherAgent: return "Other Agent"
    }
  }

  private func icon(_ state: SshIdentityAgentState) -> String {
    switch state {
    case .configured: return "checkmark.circle.fill"
    case .notConfigured: return "circle"
    case .otherAgent: return "exclamationmark.triangle.fill"
    }
  }

  private func color(_ state: SshIdentityAgentState) -> Color {
    switch state {
    case .configured: return .green
    case .notConfigured: return .secondary
    case .otherAgent: return .orange
    }
  }
}

/// The `pinentry-program` line in `gpg-agent.conf`, which decides whether
/// gpg's passphrase prompts appear in this app.
private struct GpgSettingsRows: View {
  let model: GpgModel
  let showSetup: () -> Void

  private var state: GpgPinentryState? { model.confStatus?.state }

  var body: some View {
    SettingsRow("GPG agent:") {
      HStack(spacing: 8) {
        if let state {
          StatusLabel(
            GpgPinentryStyle.label(state), symbol: GpgPinentryStyle.icon(state),
            color: GpgPinentryStyle.color(state), path: model.confStatus?.confPath)
        }
        if model.isConfiguring || model.isTesting {
          ProgressView().controlSize(.small)
        }
      }
      Text("Shows GPG passphrase prompts in Axo Pass.")
        .captionStyle()
      HStack {
        Button("Setup…", action: showSetup)
        if state != .configured {
          Button("Add to gpg-agent.conf") {
            Task { await model.configureAgentConf() }
          }
          .disabled(model.isConfiguring || model.confStatus?.expectedLine == nil)
        } else {
          Button("Test Signing") {
            Task { await model.testIntegration() }
          }
          .disabled(model.isTesting)
        }
      }
      if let error = model.configureError {
        Text(error)
          .foregroundStyle(.red)
          .captionStyle()
      }
      if let result = model.testResult {
        switch result {
        case .success:
          Text("Signing successful")
            .foregroundStyle(.green)
            .captionStyle()
        case .failure(let message):
          Text(message)
            .foregroundStyle(.red)
            .lineLimit(2)
            .captionStyle()
        }
      }
    }
  }
}

/// The `ap` integration: a `~/.local/bin/ap` symlink plus a `~/.zshrc` block
/// that adds it to PATH and routes ssh askpass prompts into this app.
private struct ShellSettingsRows: View {
  let model: ShellIntegrationModel
  let showSetup: () -> Void

  var body: some View {
    SettingsRow("Shell:") {
      HStack(spacing: 8) {
        if let status = model.status {
          StatusLabel(
            status.configured ? "Configured" : "Not Configured",
            symbol: status.configured ? "checkmark.circle.fill" : "circle",
            color: status.configured ? .green : .secondary,
            path: status.zshrcPath)
        }
        if model.isConfiguring {
          ProgressView().controlSize(.small)
        }
      }
      Text("Adds the `ap` command to zsh and shows ssh passphrase prompts in Axo Pass.")
        .captionStyle()
      HStack {
        if model.status?.configured != true {
          Button("Add to .zshrc") {
            Task { await model.configure() }
          }
          .disabled(model.isConfiguring)
        }
        Button("Setup…", action: showSetup)
      }
      if let error = model.configureError {
        Text(error)
          .foregroundStyle(.red)
          .captionStyle()
      }
    }
  }
}

/// Status line in a settings row. Only the icon is colored. An optional config
/// file path follows in secondary text, with the home directory shown as `~`.
private struct StatusLabel: View {
  let title: String
  let symbol: String
  let color: Color
  let path: String?

  init(_ title: String, symbol: String, color: Color, path: String? = nil) {
    self.title = title
    self.symbol = symbol
    self.color = color
    self.path = path
  }

  var body: some View {
    HStack(spacing: 6) {
      Image(systemName: symbol)
        .foregroundStyle(color)
      Text(title)
      if let path {
        Text((path as NSString).abbreviatingWithTildeInPath)
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
          .textSelection(.enabled)
          .help(path)
      }
    }
  }
}

/// Layout constants of the settings panes.
private enum SettingsLayout {
  static let paneWidth: CGFloat = 540
  /// Label column width. Every pane uses the same width, so the control column
  /// does not move between tabs.
  static let labelWidth: CGFloat = 140
  static let columnSpacing: CGFloat = 10
  static let rowSpacing: CGFloat = 16
  /// Spacing between a control and its captions within one row.
  static let rowContentSpacing: CGFloat = 6
}

/// Settings pane content of rows and dividers.
private struct SettingsForm<Content: View>: View {
  @ViewBuilder let content: Content

  var body: some View {
    VStack(alignment: .leading, spacing: SettingsLayout.rowSpacing) {
      content
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

/// Settings row with a trailing-aligned label and leading-aligned content. An
/// empty label leaves the label column blank.
private struct SettingsRow<Content: View>: View {
  let label: String
  @ViewBuilder let content: Content

  init(_ label: String = "", @ViewBuilder content: () -> Content) {
    self.label = label
    self.content = content()
  }

  var body: some View {
    HStack(alignment: .firstTextBaseline, spacing: SettingsLayout.columnSpacing) {
      Text(label)
        .frame(width: SettingsLayout.labelWidth, alignment: .trailing)
      VStack(alignment: .leading, spacing: SettingsLayout.rowContentSpacing) {
        content
      }
      .frame(maxWidth: .infinity, alignment: .leading)
    }
  }
}

/// Full-width line between groups of rows.
private struct SettingsDivider: View {
  var body: some View {
    Divider()
      .padding(.vertical, 2)
  }
}

extension View {
  /// Gives every tab the same width and its own fitting height. The tab
  /// controller resizes the window to each tab's fitting size, so a size set on
  /// the `TabView` itself does not apply. A width change moves the centered
  /// toolbar items, and a height change does not.
  fileprivate func settingsPane() -> some View {
    self
      .padding(.horizontal, 28)
      .padding(.vertical, 24)
      .frame(width: SettingsLayout.paneWidth, alignment: .top)
      .fixedSize(horizontal: false, vertical: true)
  }

  /// The look of explanatory text under a control: smaller and secondary.
  fileprivate func captionStyle() -> some View {
    self
      .font(.callout)
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
  }
}
