/// Entry point of the 1Password import in the app. Step 4 of the first-run plan
/// is not built, so the buttons that start the import are disabled. The
/// welcome window and the empty item list read this.
enum OnePasswordImport {
  static let isAvailable = false

  static let unavailableHelp = "Import from 1Password is not available in the app yet."
}
