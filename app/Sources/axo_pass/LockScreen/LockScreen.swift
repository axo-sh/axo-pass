import AppKit
import SwiftUI

struct LockScreen: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    VStack(spacing: 12) {
      // The icon is bound to the context it was built with, so a replacement
      // context needs a new view.
      if model.isPrompting {
        AuthenticationIcon(context: model.authContext)
          .id(ObjectIdentifier(model.authContext))
          .frame(width: 320, height: 320)
          .overlay(alignment: .center) {
            AxoLogo()
              .frame(width: 450, height: 450)
              .opacity(0.04)
              .allowsHitTesting(false)
              .offset(y: -30)
          }
      } else {
        Image(systemName: "lock.fill")
          .font(.system(size: 40))
          .foregroundStyle(.secondary)
          .frame(width: 64, height: 64)
        Text("Axo Pass")
          .font(.title)
          .fontWeight(.semibold)
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
    // .padding(.bottom, 48)  // account for invisible toolbar
    .animation(.default, value: model.isPrompting)
    .animation(.default, value: model.unlockError)
    .frame(maxWidth: .infinity, maxHeight: .infinity)

    // An empty toolbar and an empty title keep the window's title bar in place
    // while the lock screen hides it. Prevents flicker.
    .toolbar { Spacer() }
    .navigationTitle("")
    .onAppear { model.unlockIfActive() }
    // A lock from the screen locking or the machine sleeping leaves the prompt
    // for whenever the user comes back to the app.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      model.unlockIfActive()
    }
  }
}
