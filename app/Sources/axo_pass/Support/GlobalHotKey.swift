import AppKit
import Carbon.HIToolbox
import Observation

/// A keyboard shortcut: a key code plus Command, Option, Control and Shift.
///
/// Stored in `UserDefaults` as `keyCode:modifiers:name`, where `name` is how
/// the key is shown. The name is recorded with the shortcut because turning a
/// key code back into a character depends on the keyboard layout.
struct HotKey: Equatable, RawRepresentable {
  let keyCode: UInt16
  let modifiers: NSEvent.ModifierFlags
  let keyName: String

  static let allowedModifiers: NSEvent.ModifierFlags = [.command, .option, .control, .shift]

  init(keyCode: UInt16, modifiers: NSEvent.ModifierFlags, keyName: String) {
    self.keyCode = keyCode
    self.modifiers = modifiers.intersection(Self.allowedModifiers)
    self.keyName = keyName
  }

  /// The shortcut a key-down event describes, or nil when it has no Command,
  /// Option or Control. A shortcut without one would take over ordinary
  /// typing in every app.
  init?(event: NSEvent) {
    let modifiers = event.modifierFlags.intersection(Self.allowedModifiers)
    guard !modifiers.intersection([.command, .option, .control]).isEmpty else { return nil }
    let name =
      Self.specialKeyNames[Int(event.keyCode)]
      ?? event.charactersIgnoringModifiers?.uppercased()
      ?? ""
    guard !name.isEmpty else { return nil }
    self.init(keyCode: event.keyCode, modifiers: modifiers, keyName: name)
  }

  init?(rawValue: String) {
    let parts = rawValue.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: false)
    guard parts.count == 3, let code = UInt16(parts[0]), let mods = UInt(parts[1]) else {
      return nil
    }
    self.init(
      keyCode: code, modifiers: NSEvent.ModifierFlags(rawValue: mods), keyName: String(parts[2]))
  }

  var rawValue: String { "\(keyCode):\(modifiers.rawValue):\(keyName)" }

  /// The shortcut as menus show it, such as ⌃⌥⌘P.
  var display: String {
    var text = ""
    if modifiers.contains(.control) { text += "⌃" }
    if modifiers.contains(.option) { text += "⌥" }
    if modifiers.contains(.shift) { text += "⇧" }
    if modifiers.contains(.command) { text += "⌘" }
    return text + keyName
  }

  fileprivate var carbonModifiers: UInt32 {
    var flags = 0
    if modifiers.contains(.command) { flags |= cmdKey }
    if modifiers.contains(.option) { flags |= optionKey }
    if modifiers.contains(.control) { flags |= controlKey }
    if modifiers.contains(.shift) { flags |= shiftKey }
    return UInt32(flags)
  }

  /// Keys whose characters do not name them usefully.
  private static let specialKeyNames: [Int: String] = [
    kVK_Space: "Space", kVK_Return: "↩", kVK_Tab: "⇥", kVK_Delete: "⌫",
    kVK_ForwardDelete: "⌦", kVK_Escape: "⎋", kVK_LeftArrow: "←", kVK_RightArrow: "→",
    kVK_UpArrow: "↑", kVK_DownArrow: "↓", kVK_Home: "↖", kVK_End: "↘",
    kVK_PageUp: "⇞", kVK_PageDown: "⇟",
    kVK_F1: "F1", kVK_F2: "F2", kVK_F3: "F3", kVK_F4: "F4", kVK_F5: "F5", kVK_F6: "F6",
    kVK_F7: "F7", kVK_F8: "F8", kVK_F9: "F9", kVK_F10: "F10", kVK_F11: "F11", kVK_F12: "F12",
  ]
}

/// The system-wide shortcut that shows the palette, registered with Carbon's
/// `RegisterEventHotKey`, which needs no Accessibility permission.
///
/// The shortcut comes from Settings and is re-registered whenever it changes
/// there. Registration fails when another app already holds the same
/// shortcut; `registrationFailed` reports that to Settings.
@Observable
@MainActor
final class GlobalHotKey {
  static let shared = GlobalHotKey()

  /// Runs when the shortcut is pressed. Set by `StatusItemController`.
  var action: () -> Void = {}
  private(set) var registrationFailed = false

  private var hotKeyRef: EventHotKeyRef?
  private var handlerRef: EventHandlerRef?
  private var registered: HotKey?
  private var suspended = false
  private var defaultsObserver: NSObjectProtocol?

  private init() {}

  /// Install the event handler and register the shortcut from Settings. Call
  /// once at launch.
  func start() {
    guard handlerRef == nil else { return }
    var spec = EventTypeSpec(
      eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
    InstallEventHandler(
      GetApplicationEventTarget(),
      { _, _, userData in
        guard let userData else { return OSStatus(eventNotHandledErr) }
        let hotKey = Unmanaged<GlobalHotKey>.fromOpaque(userData).takeUnretainedValue()
        // Carbon delivers hot key events on the main thread.
        MainActor.assumeIsolated { hotKey.action() }
        return noErr
      },
      1, &spec, Unmanaged.passUnretained(self).toOpaque(), &handlerRef)

    defaultsObserver = NotificationCenter.default.addObserver(
      forName: UserDefaults.didChangeNotification, object: nil, queue: .main
    ) { [weak self] _ in
      MainActor.assumeIsolated { self?.sync() }
    }
    sync()
  }

  /// Release the shortcut while Settings records a new one, so pressing the
  /// current shortcut reaches the recorder rather than opening the palette.
  func suspend() {
    suspended = true
    sync()
  }

  func resume() {
    suspended = false
    sync()
  }

  /// Register the shortcut Settings holds, if it is not registered already.
  private func sync() {
    let wanted = suspended ? nil : Preferences.paletteHotKey
    // A shortcut that failed to register is tried again on the next change.
    guard wanted != registered else {
      if wanted == nil { registrationFailed = false }
      return
    }
    unregister()
    guard let wanted else {
      registrationFailed = false
      return
    }
    let id = EventHotKeyID(signature: OSType(0x4158_5041), id: 1)  // "AXPA"
    let status = RegisterEventHotKey(
      UInt32(wanted.keyCode), wanted.carbonModifiers, id, GetApplicationEventTarget(), 0,
      &hotKeyRef)
    registrationFailed = status != noErr
    registered = status == noErr ? wanted : nil
    if status != noErr { hotKeyRef = nil }
  }

  private func unregister() {
    if let hotKeyRef { UnregisterEventHotKey(hotKeyRef) }
    hotKeyRef = nil
    registered = nil
  }
}
