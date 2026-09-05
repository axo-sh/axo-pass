import SwiftUI

@main
struct AxoPassApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

  var body: some Scene {
    // The main window is an NSWindow built by AppDelegate, so a broker-only
    // launch creates no window at all. This scene exists only because `App`
    // needs one; it renders nothing and its Settings menu item is removed.
    Settings { EmptyView() }
      .commands {
        CommandGroup(replacing: .appSettings) {}
        // Declared rather than left to the default menu: the passphrase panel
        // is shown from a launch that builds no window, and pasting a
        // passphrase out of a password manager needs these key equivalents.
        TextEditingCommands()
      }
  }
}
