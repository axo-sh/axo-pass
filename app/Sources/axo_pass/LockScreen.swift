import AppKit
import SwiftUI

struct LockScreen: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    VStack(spacing: 16) {
      // LAAuthenticationView draws nothing unless an evaluation is running, so
      // a static glyph stands in above the title when no prompt is up.
      if !model.isPrompting {
        Image(systemName: "lock.fill")
          .font(.system(size: 40))
          .foregroundStyle(.secondary)
          .frame(width: 64, height: 64)
      }

      Text("Axo Pass")
        .font(.title)
        .fontWeight(.semibold)

      // The icon is bound to the context it was built with, so a replacement
      // context needs a new view.
      if model.isPrompting {
        AuthenticationIcon(context: model.authContext)
          .id(ObjectIdentifier(model.authContext))
          .frame(width: 64, height: 64)
      }

      // Idle, the glyph and the button say everything; instructions only matter
      // once there is a prompt to act on. Omitted entirely when empty, so the
      // stack spacing does not leave a gap.
      if model.isPrompting || model.unlockError != nil {
        VStack(spacing: 6) {
          if model.isPrompting {
            Text(model.unlockInstruction)
              .foregroundStyle(.secondary)
          }

          if let err = model.unlockError {
            Text(err)
              .foregroundStyle(.red)
          }
        }
        .font(.body)
        .multilineTextAlignment(.center)
        .frame(maxWidth: 340)
      }

      if !model.isPrompting {
        Button("Unlock", action: model.unlock)
          .buttonStyle(.borderedProminent)
          .controlSize(.large)
          .keyboardShortcut(.defaultAction)
      } else if model.offersPasswordUnlock {
        // Available during the biometric prompt so a user whose fingerprint is
        // not being read does not have to wait for it to fail.
        Button("Use Login Password…", action: model.unlockWithPassword)
          .buttonStyle(.link)
      }
    }
    .animation(.default, value: model.isPrompting)
    .animation(.default, value: model.unlockError)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .onAppear { model.unlockIfActive() }
    // A lock from the screen locking or the machine sleeping leaves the prompt
    // for whenever the user comes back to the app.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      model.unlockIfActive()
    }
  }
}
