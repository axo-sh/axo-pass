import AppKit
import AxoPassFFI
import Darwin

/// Where the app bundle is watched, decided once at launch.
enum BundleLocation: Equatable {
  /// Bundle at a path that can change under the running app.
  case watched(URL)
  /// Bundle on a read-only volume, or a translocated bundle whose original path
  /// could not be found.
  case unwatched
}

/// What happened to the watched bundle.
enum BundleChange: Equatable {
  /// Bundle is at its original path, possibly replaced by an update.
  case unchanged
  case moved(URL)
  case deleted

  /// Classify the bundle's current state.
  ///
  /// `resolved` is the path of the file reference taken at launch, nil if the
  /// file is gone. A bundle that exists at `original` is unchanged, which covers
  /// an updater that replaces the bundle in place. A bundle in a Trash folder
  /// counts as deleted.
  static func classify(original: URL, resolved: URL?, originalExists: Bool) -> BundleChange {
    if originalExists { return .unchanged }
    guard let resolved, !resolved.pathComponents.contains(".Trash") else { return .deleted }
    return .moved(resolved)
  }
}

/// Alerts when the running app bundle is moved or deleted.
///
/// A move offers to reopen the app from the new location. A delete stops the
/// app's work, alerts, and quits.
@MainActor
final class AppLocationMonitor {
  private var source: DispatchSourceFileSystemObject?
  private var reference: NSURL?
  private var original: URL?
  private var handled = false
  /// App icon read at launch. AppKit cannot load it from a bundle that is gone.
  private var icon: NSImage?

  /// Start watching the bundle of the running app.
  func start() {
    icon = NSApp.applicationIconImage.tiffRepresentation.flatMap(NSImage.init(data:))
    guard case .watched(let url) = Self.resolveLocation(bundleURL: Bundle.main.bundleURL) else {
      return
    }
    original = url
    arm()
  }

  // MARK: Location

  /// Decide what to watch for the bundle at `bundleURL`.
  static func resolveLocation(bundleURL: URL) -> BundleLocation {
    if isOnReadOnlyVolume(bundleURL) { return .unwatched }
    if Translocation.isTranslocated(bundleURL) {
      guard let original = Translocation.originalURL(of: bundleURL) else { return .unwatched }
      return isOnReadOnlyVolume(original) ? .unwatched : .watched(original)
    }
    return .watched(bundleURL)
  }

  static func isOnReadOnlyVolume(_ url: URL) -> Bool {
    let values = try? url.resourceValues(forKeys: [.volumeIsReadOnlyKey])
    return values?.volumeIsReadOnly ?? false
  }

  // MARK: Watching

  /// Watch the bundle at the original path and remember its file reference.
  private func arm() {
    source?.cancel()
    source = nil
    guard let original else { return }
    reference = (original as NSURL).fileReferenceURL() as NSURL?
    let fd = open(original.path, O_EVTONLY)
    guard fd >= 0 else { return }
    let source = DispatchSource.makeFileSystemObjectSource(
      fileDescriptor: fd,
      eventMask: [.delete, .rename, .link],
      queue: .main
    )
    source.setEventHandler { [weak self] in
      MainActor.assumeIsolated { self?.changed() }
    }
    source.setCancelHandler { close(fd) }
    source.resume()
    self.source = source
  }

  private func changed() {
    guard !handled, let original else { return }
    let change = BundleChange.classify(
      original: original,
      resolved: reference?.filePathURL,
      originalExists: FileManager.default.fileExists(atPath: original.path)
    )
    switch change {
    case .unchanged:
      // An in-place update replaces the bundle, so watch the new one.
      arm()
    case .moved(let url):
      handled = true
      source?.cancel()
      handleMoved(to: url)
    case .deleted:
      handled = true
      source?.cancel()
      handleDeleted()
    }
  }

  // MARK: Handling

  private func handleMoved(to url: URL) {
    stopWork()
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.icon = icon
    alert.messageText = "Axo Pass was moved"
    alert.informativeText =
      "The app was moved while it was running. Reopen it from its new location to continue."
    alert.addButton(withTitle: "Reopen")
    alert.addButton(withTitle: "Quit")
    NSApp.activate(ignoringOtherApps: true)
    guard alert.runModal() == .alertFirstButtonReturn else { exit(0) }

    let configuration = NSWorkspace.OpenConfiguration()
    configuration.createsNewApplicationInstance = true
    NSWorkspace.shared.openApplication(at: url, configuration: configuration) { _, _ in
      exit(0)
    }
  }

  private func handleDeleted() {
    stopWork()
    let alert = NSAlert()
    alert.alertStyle = .critical
    alert.icon = icon
    alert.messageText = "Axo Pass was deleted"
    alert.informativeText = "The app was deleted while it was running. It will quit now."
    alert.addButton(withTitle: "Quit")
    NSApp.activate(ignoringOtherApps: true)
    alert.runModal()
    exit(0)
  }

  /// Close windows and stop the sync manager before the alert is shown.
  private func stopWork() {
    for window in NSApp.windows where !(window is NSPanel) { window.close() }
    syncShutdown()
  }
}

/// App Translocation lookups. The functions are in Security.framework but not
/// in its public headers, so they are loaded by name. Both return a negative
/// result if the symbols are missing.
enum Translocation {
  private typealias IsTranslocated =
    @convention(c) (
      CFURL, UnsafeMutablePointer<DarwinBoolean>, UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> Bool
  private typealias CreateOriginal =
    @convention(c) (
      CFURL, UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> Unmanaged<CFURL>?

  private static func symbol<T>(_ name: String, as type: T.Type) -> T? {
    guard let handle = dlopen(nil, RTLD_NOW), let pointer = dlsym(handle, name) else { return nil }
    return unsafeBitCast(pointer, to: type)
  }

  static func isTranslocated(_ url: URL) -> Bool {
    guard let function = symbol("SecTranslocateIsTranslocatedURL", as: IsTranslocated.self) else {
      return false
    }
    var translocated = DarwinBoolean(false)
    guard function(url as CFURL, &translocated, nil) else { return false }
    return translocated.boolValue
  }

  static func originalURL(of url: URL) -> URL? {
    guard
      let function = symbol("SecTranslocateCreateOriginalPathForURL", as: CreateOriginal.self),
      let original = function(url as CFURL, nil)
    else { return nil }
    return original.takeRetainedValue() as URL
  }
}
