import AppKit
import AxoPassFFI
import SwiftUI

/// Resolves the icon of the outermost app in a caller chain.
enum CallerAppIcon {
  /// `chain` is innermost first (the peer process, then its ancestors), so
  /// the outermost app is the one that ultimately launched the request, e.g.
  /// the terminal hosting the shell that ran `ssh-add`. Walk from the end and
  /// take the first verified node that has a bundle identifier and an
  /// executable inside an `.app` bundle. Unverified nodes are skipped so a
  /// forged bundle identifier cannot borrow another app's icon.
  static func icon(for chain: [ProcessNode]) -> NSImage? {
    guard let path = appBundlePath(for: chain) else { return nil }
    return NSWorkspace.shared.icon(forFile: path)
  }

  /// The display name of the app `icon(for:)` would show, e.g. `Ghostty`.
  static func name(for chain: [ProcessNode]) -> String? {
    guard let path = appBundlePath(for: chain) else { return nil }
    let name = FileManager.default.displayName(atPath: path)
    return name.hasSuffix(".app") ? String(name.dropLast(4)) : name
  }

  /// The icon of an installed app, looked up by bundle identifier. `nil` when
  /// no app with that identifier is installed.
  static func icon(bundleId: String) -> NSImage? {
    guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleId) else {
      return nil
    }
    return NSWorkspace.shared.icon(forFile: url.path)
  }

  private static func appBundlePath(for chain: [ProcessNode]) -> String? {
    for node in chain.reversed() {
      guard node.verified,
        let bundleId = node.bundleId, !bundleId.isEmpty,
        let executable = node.executable,
        let path = appBundlePath(fromExecutable: executable)
      else { continue }
      return path
    }
    return nil
  }

  /// `/Applications/Ghostty.app/Contents/MacOS/ghostty` -> `/Applications/Ghostty.app`
  private static func appBundlePath(fromExecutable executable: String) -> String? {
    guard let range = executable.range(of: ".app/Contents/MacOS/") else { return nil }
    let appEnd = executable.index(range.lowerBound, offsetBy: 4)
    return String(executable[..<appEnd])
  }
}
