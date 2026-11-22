#if DEBUG
  import AppKit
  import AxoPassFFI

  /// Resets that put this Mac into a given key state. Compiled into debug
  /// builds only. Each asks for confirmation, deletes the state, and quits the
  /// app, so the next launch starts from what is left. Settings has the resets
  /// of release builds.
  @MainActor
  enum DevReset {
    enum Kind: CaseIterable {
      case signingKey
      case deviceKeys
      case vaultFiles

      var title: String {
        switch self {
        case .signingKey: return "Delete Signing Key"
        case .deviceKeys: return "Delete Device Keys (New Hardware)"
        case .vaultFiles: return "Delete Vault Files"
        }
      }

      var detail: String {
        switch self {
        case .signingKey:
          return
            "Deletes device-signing-key. Vault files stay, so the next launch reports a lost signing key."
        case .deviceKeys:
          return
            "Deletes vault-encryption-key and device-signing-key. Vault files stay, so the next launch reports new hardware."
        case .vaultFiles:
          return "Deletes vault, version, sync, and unreadable files. Keys stay."
        }
      }

      fileprivate var scope: DeviceResetScope {
        switch self {
        case .signingKey: return .signingKey
        case .deviceKeys: return .deviceKeys
        case .vaultFiles: return .vaultFiles
        }
      }
    }

    static func run(_ kind: Kind) {
      let alert = NSAlert()
      alert.alertStyle = .critical
      alert.messageText = "\(kind.title)?"
      alert.informativeText = "\(kind.detail) The app quits afterward."
      alert.addButton(withTitle: "Delete and Quit")
      alert.addButton(withTitle: "Cancel")
      guard alert.runModal() == .alertFirstButtonReturn else { return }

      do {
        try resetDeviceState(scope: kind.scope)
      } catch {
        NSAlert(error: error).runModal()
        return
      }
      NSApp.terminate(nil)
    }
  }
#endif
