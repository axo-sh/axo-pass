import AppKit
import AxoPassFFI
import SwiftUI

/// A prompt's headline, with the icon of the outermost real app in the caller
/// chain shown inline before the text (e.g. the terminal emulator that hosts
/// the shell a command ran from). Falls back to plain text when no chain node
/// looks like a signed `.app` bundle — a bare CLI tool, a script, or an
/// unidentified process.
struct PromptTitle: View {
  let text: String
  let callerChain: [ProcessNode]
  var font: Font = .headline
  var color: Color = .primary
  var iconSize: CGFloat = 24

  var body: some View {
    HStack(spacing: 6) {
      if let icon = CallerAppIcon.icon(for: callerChain) {
        Image(nsImage: icon)
          .resizable()
          .frame(width: iconSize, height: iconSize)
      }
      Text(text)
        .font(font)
        .foregroundStyle(color)
        .multilineTextAlignment(.center)
    }
  }
}

/// Resolves the icon of the outermost app in a caller chain.
enum CallerAppIcon {
  /// `chain` is innermost first (the peer process, then its ancestors), so
  /// the outermost app is the one that ultimately launched the request, e.g.
  /// the terminal hosting the shell that ran `ssh-add`. Walk from the end and
  /// take the first node that has a bundle identifier and an executable
  /// inside an `.app` bundle.
  static func icon(for chain: [ProcessNode]) -> NSImage? {
    guard let path = appBundlePath(for: chain) else { return nil }
    return NSWorkspace.shared.icon(forFile: path)
  }

  private static func appBundlePath(for chain: [ProcessNode]) -> String? {
    for node in chain.reversed() {
      guard let bundleId = node.bundleId, !bundleId.isEmpty,
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
