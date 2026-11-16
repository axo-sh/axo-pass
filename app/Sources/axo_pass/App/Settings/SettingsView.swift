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
      GeneralSettingsView()
        .settingsPane()
        .tabItem { SettingsTab.label("General", symbol: "gearshape") }
      VaultsSettingsView()
        .settingsPane()
        .tabItem { SettingsTab.label("Vaults", symbol: "archivebox") }
      AutoFillSettingsView()
        .settingsPane()
        .tabItem { SettingsTab.label("AutoFill", symbol: "key.viewfinder") }
      SshSettingsView()
        .settingsPane()
        .tabItem { SettingsTab.label("SSH", symbol: "key.horizontal") }
      GpgSettingsView()
        .settingsPane()
        .tabItem { SettingsTab.label("GPG", symbol: "lock.doc") }
      ShellSettingsView()
        .settingsPane()
        .tabItem { SettingsTab.label("Shell", symbol: "terminal") }
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

  var body: some View {
    Form {
      LabeledContent("Show palette:") {
        HotKeyRecorder(hotKey: $paletteHotKey)
      }
      if GlobalHotKey.shared.registrationFailed {
        Text("This shortcut is in use by another app. Choose a different one.")
          .foregroundStyle(.red)
          .settingsCaption()
      }
      Text("Opens the search palette from any app.")
        .settingsCaption()

      Picker("Lock when idle for:", selection: $autoLockMinutes) {
        ForEach(Preferences.autoLockChoices, id: \.self) { minutes in
          Text(Preferences.label(forAutoLockMinutes: minutes)).tag(minutes)
        }
      }
      .fixedSize()
      Text("App always locks on screen lock or sleep.")
        .settingsCaption()

      Toggle(
        "Reuse an approval for up to \(Self.absolute)",
        isOn: $reuseApprovals)
      Text(
        """
        After you approve a GPG or `ap` request, the same program can repeat it on the \
        same key without prompting. That ends \(Self.idle) after its last request, or \
        \(Self.absolute) after the initial approval, whichever comes first. Reading a secret \
        always prompts. SSH signatures always prompt, except for apps allowed in a key's \
        details.
        """
      )
      .settingsCaption()
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
    Form {
      if !moved.isEmpty {
        LabeledContent("Moved vaults:") {
          HStack(spacing: 8) {
            Text(
              moved.count == 1
                ? "1 vault file from another Mac" : "\(moved.count) vault files from another Mac"
            )
            Button("Show…") { showingMoved = true }
          }
        }
      }

      LabeledContent("Synced folder:") {
        VStack(alignment: .leading) {
          HStack(spacing: 8) {
            Text(sync.folder.map(rootDescription) ?? "None")
              .foregroundStyle(sync.folder == nil ? .secondary : .primary)
              .lineLimit(1)
              .truncationMode(.middle)
              .help(sync.folder.map(rootDescription) ?? "")
            Button("Choose…") { chooseSyncFolder() }
          }
          Text(
            "Vaults sync here when you turn on sync. A change applies only to vaults turned on later. Use a folder that a sync service or shared drive copies to each Mac. The path can differ on each Mac."
          )
          .captionStyle()
          if !syncIcloudAvailable() {
            Text("iCloud Drive is not available yet.")
              .captionStyle()
          }
        }
      }

      LabeledContent("Backups:") {
        VStack(alignment: .leading) {
          Button("Export…") { showingExport = true }
            .disabled(model.vaults.isEmpty)
          Text(
            "Export the selected vaults into one passphrase-encrypted file."
          )
          .captionStyle()

          Button("Import…") { showingImport = true }
          Text(
            "Import vaults from a backup file; new vaults are created and existing vaults are not overwritten."
          )
          .captionStyle()
        }
      }
    }
    .padding(.horizontal, 10)
    .padding(.vertical, 12)
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
    Form {
      LabeledContent("Safari and apps:") {
        VStack(alignment: .leading, spacing: 6) {
          switch isEnabled {
          case .some(true):
            Label("Axo Pass is on", systemImage: "checkmark.circle.fill")
              .foregroundStyle(.green)
          case .some(false):
            Label("Axo Pass is off", systemImage: "xmark.circle.fill")
              .foregroundStyle(.orange)
          case .none:
            ProgressView().controlSize(.small)
          }
          Button("Open System Settings…") {
            ASSettingsHelper.openCredentialProviderAppSettings { _ in }
          }
        }
      }
      Text(
        "Turn on Axo Pass under Passwords > Password Options to fill logins, one-time codes, and passkeys in Safari and other apps."
      )
      .settingsCaption()
      Divider()
      ForEach(browsers, id: \.name) { status in
        LabeledContent("\(status.name):") {
          HStack(spacing: 6) {
            Label(
              BrowserManifestStyle.label(status),
              systemImage: BrowserManifestStyle.icon(status)
            )
            .foregroundStyle(BrowserManifestStyle.color(status))
            if installing == status.browser {
              ProgressView().controlSize(.small)
            } else if let action = BrowserManifestStyle.action(status) {
              Button(action) { Task { await install(status.browser) } }
                .disabled(installing != nil)
            }
          }
        }
      }
      if let error = installError {
        Text(error)
          .foregroundStyle(.red)
          .settingsCaption()
      }
      Text(
        "Lets the Axo Pass extension in Chrome and Firefox reach this app. Axo Pass installs and repairs these on launch."
      )
      .settingsCaption()
      Divider()
      LabeledContent("Allowed to list logins:") {
        VStack(alignment: .leading, spacing: 6) {
          if listingGrants.isEmpty {
            Text("No browsers")
              .foregroundStyle(.secondary)
          }
          ForEach(listingGrants, id: \.teamId) { grant in
            HStack(spacing: 8) {
              Text(grant.name)
              Text(Self.expiryText(grant))
                .font(.caption)
                .foregroundStyle(.secondary)
              Button("Remove") { Task { await removeListingGrant(grant) } }
                .controlSize(.small)
            }
          }
        }
      }
      Text(
        "Browsers allowed to list logins while Axo Pass is unlocked. Fills, one-time codes, and saves still prompt. Add a browser from its listing prompt."
      )
      .settingsCaption()
    }
    .padding(.horizontal, 10)
    .padding(.vertical, 12)
    .task { await refresh() }
    .onReceive(
      NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
    ) { _ in
      Task { await refresh() }
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

/// Labels for a browser manifest state in Settings > AutoFill.
private enum BrowserManifestStyle {
  static func label(_ status: BrowserManifestStatus) -> String {
    switch status.state {
    case .notInstalled: return status.browserInstalled ? "Not Installed" : "Browser Not Found"
    case .current: return "Installed"
    case .pointsElsewhere: return "Points to Another Host"
    case .outdated: return "Outdated"
    case .foreign: return "Used by Another App"
    case .unreadable: return "Unreadable"
    }
  }

  static func icon(_ status: BrowserManifestStatus) -> String {
    switch status.state {
    case .current: return "checkmark.circle.fill"
    case .notInstalled: return "circle"
    case .pointsElsewhere, .outdated, .foreign, .unreadable: return "exclamationmark.triangle.fill"
    }
  }

  static func color(_ status: BrowserManifestStatus) -> Color {
    switch status.state {
    case .current: return .green
    case .notInstalled: return .secondary
    case .pointsElsewhere, .outdated, .foreign, .unreadable: return .orange
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

/// The `IdentityAgent` line in `~/.ssh/config`, which decides whether ssh
/// talks to this app's agent. The agents' own status lives in the SSH pane.
private struct SshSettingsView: View {
  @State private var model = SshModel()
  @State private var showingSetup = false
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
    Form {
      LabeledContent("Agent:") {
        Toggle("Start at login", isOn: startAtLogin)
      }
      if model.agentService.startsOnLogin && model.agentService.status == .requiresApproval {
        Text("Allow Axo Pass in System Settings > General > Login Items & Extensions.")
          .foregroundStyle(.orange)
          .settingsCaption()
        LabeledContent("") {
          Button("Open Login Items…") { model.agentService.openLoginItemsSettings() }
        }
      }
      if let error = startAtLoginError {
        Text(error)
          .foregroundStyle(.red)
          .settingsCaption()
      }
      Text("Runs the agent in the background and restarts it if it stops.")
        .settingsCaption()
      Divider()
      LabeledContent("IdentityAgent:") {
        HStack(spacing: 6) {
          if let state {
            Label(label(state), systemImage: icon(state))
              .foregroundStyle(color(state))
          }
          if model.isConfiguring {
            ProgressView().controlSize(.small)
          }
        }
      }
      if let path = model.confStatus?.configPath {
        Text(path)
          .font(.callout.monospaced())
          .textSelection(.enabled)
          .settingsCaption()
      }
      LabeledContent("") {
        HStack {
          if state != .configured {
            Button("Add to ~/.ssh/config") {
              Task { await model.configureAgentConf() }
            }
            .disabled(model.isConfiguring)
          }
          Button("Setup Assistant…") { showingSetup = true }
        }
      }
      if let error = model.configureError {
        Text(error)
          .foregroundStyle(.red)
          .settingsCaption()
      }
      Text("ssh asks whatever `IdentityAgent` names for your keys and signatures.")
        .settingsCaption()
    }
    // This pane's rows are denser than the other tabs', which are a control
    // and a caption apiece, so they need the room.
    .padding(.horizontal, 10)
    .padding(.vertical, 12)
    .task {
      model.refreshConfStatus()
      model.agentService.refreshStatus()
    }
    // The file may be edited outside the app, so re-read it on reactivation.
    // The user may also have allowed the background item in System Settings.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      model.refreshConfStatus()
      model.agentService.refreshStatus()
    }
    .sheet(isPresented: $showingSetup) {
      SshSetupSheet(model: model)
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
/// gpg's passphrase prompts appear in this app. Mirrors the SSH tab.
private struct GpgSettingsView: View {
  @State private var model = GpgModel()
  @State private var showingSetup = false

  private var state: GpgPinentryState? { model.confStatus?.state }

  var body: some View {
    Form {
      LabeledContent("Pinentry:") {
        HStack(spacing: 6) {
          if let state {
            Label(GpgPinentryStyle.label(state), systemImage: GpgPinentryStyle.icon(state))
              .foregroundStyle(GpgPinentryStyle.color(state))
          }
          if model.isConfiguring || model.isTesting {
            ProgressView().controlSize(.small)
          }
        }
      }
      if let path = model.confStatus?.confPath {
        Text(path)
          .font(.callout.monospaced())
          .textSelection(.enabled)
          .settingsCaption()
      }
      LabeledContent("") {
        HStack {
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
          Button("Setup Assistant…") { showingSetup = true }
        }
      }
      if let error = model.configureError {
        Text(error)
          .foregroundStyle(.red)
          .settingsCaption()
      }
      if let result = model.testResult {
        switch result {
        case .success:
          Text("Signing works")
            .foregroundStyle(.green)
            .settingsCaption()
        case .failure(let message):
          Text(message)
            .foregroundStyle(.red)
            .lineLimit(2)
            .settingsCaption()
        }
      }
      Text("gpg-agent runs whatever `pinentry-program` names when it needs a passphrase.")
        .settingsCaption()
    }
    // This pane's rows are denser than the other tabs', which are a control
    // and a caption apiece, so they need the room.
    .padding(.horizontal, 10)
    .padding(.vertical, 12)
    .task { model.refreshConfStatus() }
    // The file may be edited outside the app, so re-read it on reactivation.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      model.refreshConfStatus()
    }
    .sheet(isPresented: $showingSetup) {
      GpgSetupSheet(model: model)
    }
  }
}

/// The `ap` integration: a `~/.local/bin/ap` symlink plus a `~/.zshrc` block
/// that adds it to PATH and routes ssh askpass prompts into this app. Mirrors
/// the SSH and GPG tabs.
private struct ShellSettingsView: View {
  @State private var model = ShellIntegrationModel()
  @State private var showingSetup = false

  var body: some View {
    Form {
      LabeledContent("`ap` integration:") {
        HStack(spacing: 6) {
          if let status = model.status {
            Label(
              status.configured ? "Configured" : "Not Configured",
              systemImage: status.configured ? "checkmark.circle.fill" : "circle"
            )
            .foregroundStyle(status.configured ? .green : .secondary)
          }
          if model.isConfiguring {
            ProgressView().controlSize(.small)
          }
        }
      }
      if let status = model.status {
        Text(status.zshrcPath)
          .font(.callout.monospaced())
          .textSelection(.enabled)
          .settingsCaption()
      }
      LabeledContent("") {
        HStack {
          if model.status?.configured != true {
            Button("Set Up") {
              Task { await model.configure() }
            }
            .disabled(model.isConfiguring)
          }
          Button("Setup Assistant…") { showingSetup = true }
        }
      }
      if let error = model.configureError {
        Text(error)
          .foregroundStyle(.red)
          .settingsCaption()
      }
      Text(
        "Links `ap` into `~/.local/bin` and appends a zsh block that puts it on PATH and routes ssh askpass prompts into Axo Pass."
      )
      .settingsCaption()
    }
    // This pane's rows are denser than the other tabs', which are a control
    // and a caption apiece, so they need the room.
    .padding(.horizontal, 10)
    .padding(.vertical, 12)
    .task { model.refreshStatus() }
    // The file may be edited outside the app, so re-read it on reactivation.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      model.refreshStatus()
    }
    .sheet(isPresented: $showingSetup) {
      ShellIntegrationSetupSheet(model: model)
    }
  }
}

extension View {
  /// Gives every tab the same size. The tab controller resizes the window to
  /// each tab's own fitting size, so a size set on the `TabView` itself does
  /// not apply, and panes of different sizes resize the window on every tab
  /// switch, which moves the centered toolbar items.
  fileprivate func settingsPane() -> some View {
    self
      .padding(20)
      .frame(width: 440, height: 340, alignment: .top)
  }

  /// The look of explanatory text under a control: smaller and secondary.
  fileprivate func captionStyle() -> some View {
    self
      .font(.callout)
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
  }

  /// Explanatory text under a control, in the column the controls occupy.
  fileprivate func settingsCaption() -> some View {
    LabeledContent("") {
      self.captionStyle()
    }
  }
}
