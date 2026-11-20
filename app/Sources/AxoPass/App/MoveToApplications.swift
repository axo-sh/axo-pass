import AppKit
import Darwin

/// Offers to copy the app from a disk image to `/Applications`.
///
/// Browser manifests and the SSH agent point into the bundle, so a bundle on a
/// volume that is later ejected breaks both.
@MainActor
enum MoveToApplications {
  /// Bundle on a read-only volume, or nil if the app runs from a writable volume.
  /// A translocated launch is resolved to its original path first.
  static func diskImageBundle() -> URL? {
    let bundle = Bundle.main.bundleURL
    let source =
      Translocation.isTranslocated(bundle)
      ? (Translocation.originalURL(of: bundle) ?? bundle) : bundle
    return AppLocationMonitor.isOnReadOnlyVolume(source) ? source : nil
  }

  /// Ask to copy `source` to `/Applications` and reopen from there.
  ///
  /// Exits the process after the copy opens. Returns if the user declines or a
  /// step fails, so the app can run from the disk image.
  static func offer(source: URL) async {
    NSApp.activate(ignoringOtherApps: true)
    let prompt = NSAlert()
    prompt.messageText = "Move Axo Pass to Applications?"
    prompt.informativeText =
      "Axo Pass is running from a disk image. Move it to the Applications folder so it keeps working after the disk image is ejected."
    prompt.addButton(withTitle: "Move to Applications")
    prompt.addButton(withTitle: "Not Now")
    guard prompt.runModal() == .alertFirstButtonReturn else { return }

    let destination = URL(fileURLWithPath: "/Applications", isDirectory: true)
      .appendingPathComponent(source.lastPathComponent)
    do {
      if FileManager.default.fileExists(atPath: destination.path) {
        guard confirmReplace() else { return }
        await quitRunningCopy(at: destination)
        try FileManager.default.trashItem(at: destination, resultingItemURL: nil)
      }
      try FileManager.default.copyItem(at: source, to: destination)
      // The copy keeps the quarantine flag of the disk image, which would
      // translocate the copy on launch.
      removexattr(destination.path, "com.apple.quarantine", 0)

      let configuration = NSWorkspace.OpenConfiguration()
      configuration.createsNewApplicationInstance = true
      _ = try await NSWorkspace.shared.openApplication(
        at: destination, configuration: configuration)
      exit(0)
    } catch {
      let alert = NSAlert(error: error)
      alert.messageText = "Axo Pass could not be moved"
      alert.runModal()
    }
  }

  /// Quit instances running from `destination`. Force quit after five seconds.
  private static func quitRunningCopy(at destination: URL) async {
    let running = NSRunningApplication.runningApplications(
      withBundleIdentifier: Bundle.main.bundleIdentifier ?? ""
    ).filter {
      $0 != NSRunningApplication.current
        && $0.bundleURL?.standardizedFileURL == destination.standardizedFileURL
    }
    for app in running { app.terminate() }
    for _ in 0..<50 where running.contains(where: { !$0.isTerminated }) {
      try? await Task.sleep(for: .milliseconds(100))
    }
    for app in running where !app.isTerminated { app.forceTerminate() }
  }

  private static func confirmReplace() -> Bool {
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = "Replace the copy in Applications?"
    alert.informativeText =
      "Axo Pass is already in the Applications folder. The existing copy is moved to the Trash."
    alert.addButton(withTitle: "Replace")
    alert.addButton(withTitle: "Cancel")
    return alert.runModal() == .alertFirstButtonReturn
  }
}
