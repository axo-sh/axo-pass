#if DEBUG
  import Observation

  /// Switches for previewing the first-run screens. Compiled into debug builds
  /// only. Held in memory, so every launch starts with all of them off.
  @Observable
  @MainActor
  final class DevOverrides {
    static let shared = DevOverrides()

    /// Show the welcome window in place of the main window, even if a vault
    /// exists or first run is complete.
    var forceWelcome = false
    /// Show the "Get started" card on Today, even if every step is done or
    /// skipped. The rows are the real state of this Mac.
    var showChecklist = false

    private init() {}
  }
#endif
