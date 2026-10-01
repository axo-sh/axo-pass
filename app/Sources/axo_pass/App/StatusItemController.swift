import AppKit
import SwiftUI

/// The menu bar icon. A click opens the command palette under it; an Option
/// click or a right click opens a menu instead. The shortcut set in Settings
/// also opens the palette.
@MainActor
final class StatusItemController: NSObject {
  private let model: VaultsModel
  private let windows: WindowRequests
  private let checkForUpdates: () -> Void
  private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
  private let panel = PalettePanel()
  private let palette: PaletteModel
  /// The open menu. Held so its items, which are their own targets, outlive
  /// the click that showed it.
  private var menu: NSMenu?
  /// When the palette last closed. A click on the icon takes key from the
  /// palette before the click's action runs, so without this the click that
  /// should close the palette would reopen it.
  private var lastClose = Date.distantPast

  init(model: VaultsModel, windows: WindowRequests, checkForUpdates: @escaping () -> Void) {
    self.model = model
    self.windows = windows
    self.checkForUpdates = checkForUpdates
    palette = PaletteModel(vaults: model, windows: windows, checkForUpdates: checkForUpdates)
    super.init()

    palette.close = { [weak self] in self?.panel.hide() }
    palette.refocus = { [weak self] in self?.panel.makeKey() }
    panel.onKey = { [weak self] key in self?.palette.handle(key) ?? false }
    panel.onOptionChange = { [weak self] held in self?.palette.optionChanged(held) }
    panel.staysOpenOnResignKey = { [weak self] in self?.palette.awaitingSystemDialog ?? false }
    panel.onClose = { [weak self] in
      self?.palette.didClose()
      self?.lastClose = Date()
    }

    if let button = statusItem.button {
      button.image = Self.icon()
      button.setAccessibilityLabel("Axo Pass")
      button.target = self
      button.action = #selector(clicked)
      button.sendAction(on: [.leftMouseUp, .rightMouseUp])
    }

    GlobalHotKey.shared.action = { [weak self] in self?.hotKeyPressed() }
    GlobalHotKey.shared.start()
  }

  /// The shortcut from Settings toggles the palette, as a click on the icon
  /// does.
  private func hotKeyPressed() {
    if panel.isVisible {
      panel.hide()
    } else if let button = statusItem.button {
      showPalette(below: button)
    }
  }

  @objc private func clicked(_ sender: NSStatusBarButton) {
    let event = NSApp.currentEvent
    if event?.type == .rightMouseUp || event?.modifierFlags.contains(.option) == true {
      panel.hide()
      showMenu(from: sender)
    } else if panel.isVisible {
      panel.hide()
    } else if Date().timeIntervalSince(lastClose) > 0.3 {
      showPalette(below: sender)
    }
  }

  private func showPalette(below button: NSStatusBarButton) {
    palette.prepareForOpen()
    panel.show(PaletteView(model: palette), below: button)
  }

  /// Show the menu. Setting `menu` only for the length of this click keeps a
  /// plain click free for the palette.
  private func showMenu(from button: NSStatusBarButton) {
    let menu = makeMenu()
    self.menu = menu
    statusItem.menu = menu
    button.performClick(nil)
    statusItem.menu = nil
  }

  private func makeMenu() -> NSMenu {
    palette.sshModel.refreshAgentStatus()
    let unlocked = model.isAppUnlocked
    let agentRunning = palette.sshModel.axoAgentStatus?.status == .running
    let menu = NSMenu()
    menu.autoenablesItems = false

    menu.addItem(.label(unlocked ? "Unlocked" : "Locked"))
    if unlocked {
      menu.addItem(ClosureMenuItem("Lock Now") { [model] in model.lock() })
    } else {
      menu.addItem(ClosureMenuItem("Unlock…") { [weak self] in self?.openPaletteFromMenu() })
    }

    menu.addItem(.separator())
    menu.addItem(.label(agentRunning ? "SSH Agent: Running" : "SSH Agent: Stopped"))
    if agentRunning {
      menu.addItem(
        ClosureMenuItem("Stop SSH Agent") { [palette] in
          Task { await palette.sshModel.stopAgent() }
        })
    } else {
      menu.addItem(
        ClosureMenuItem("Start SSH Agent") { [palette] in
          Task { await palette.sshModel.startAgent() }
        })
    }

    menu.addItem(.separator())
    menu.addItem(ClosureMenuItem("Search…") { [weak self] in self?.openPaletteFromMenu() })
    menu.addItem(ClosureMenuItem("Open Axo Pass") { [windows] in windows.requestMain() })
    menu.addItem(
      ClosureMenuItem("Audit Log", enabled: unlocked) { [windows] in windows.requestAudit() })
    menu.addItem(
      ClosureMenuItem("Keychain", enabled: unlocked) { [windows] in windows.requestKeychain() })
    menu.addItem(
      ClosureMenuItem("Settings…", enabled: unlocked) { [windows] in windows.requestSettings() })
    menu.addItem(ClosureMenuItem("Check for Updates…") { [checkForUpdates] in checkForUpdates() })

    menu.addItem(.separator())
    menu.addItem(ClosureMenuItem("Quit Axo Pass") { NSApp.terminate(nil) })
    return menu
  }

  /// Open the palette after the menu has closed and its tracking has ended.
  private func openPaletteFromMenu() {
    DispatchQueue.main.async { [weak self] in
      guard let self, let button = self.statusItem.button else { return }
      self.showPalette(below: button)
    }
  }

  /// The Axo Pass mark as a template image, so the menu bar tints it.
  private static func icon() -> NSImage {
    let mark = ZStack {
      AxoShellShape().fill(Color.black, style: FillStyle(eoFill: true))
      AxoGearShape().fill(Color.black, style: FillStyle(eoFill: true))
    }
    .frame(width: 18, height: 18)
    let renderer = ImageRenderer(content: mark)
    renderer.scale = 2
    let image =
      renderer.nsImage
      ?? NSImage(systemSymbolName: "key.fill", accessibilityDescription: "Axo Pass")
      ?? NSImage()
    image.size = NSSize(width: 18, height: 18)
    image.isTemplate = true
    return image
  }
}

/// A menu item that runs a closure. It is its own target.
private final class ClosureMenuItem: NSMenuItem {
  private let handler: () -> Void

  init(_ title: String, enabled: Bool = true, handler: @escaping () -> Void) {
    self.handler = handler
    super.init(title: title, action: #selector(fire), keyEquivalent: "")
    target = self
    isEnabled = enabled
  }

  required init(coder: NSCoder) {
    fatalError("init(coder:) is not used")
  }

  @objc private func fire() {
    handler()
  }
}

extension NSMenuItem {
  /// A disabled item that shows state rather than doing anything.
  fileprivate static func label(_ title: String) -> NSMenuItem {
    let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
    item.isEnabled = false
    return item
  }
}
