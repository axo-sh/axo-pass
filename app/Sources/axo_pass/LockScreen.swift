import SwiftUI

struct LockScreen: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    VStack(spacing: 16) {
      Text("Axo Pass")
        .font(.title)
        .fontWeight(.semibold)

      // The icon is bound to the context it was built with, so a replacement
      // context after lock() needs a new view.
      AuthenticationIcon(context: model.authContext)
        .fixedSize()
        .id(ObjectIdentifier(model.authContext))
        .padding(.vertical, 4)

      VStack(spacing: 6) {
        Text(model.unlockInstruction)
          .foregroundStyle(.secondary)

        if let err = model.unlockError {
          Text(err)
            .foregroundStyle(.red)
        }
      }
      .font(.body)
      .multilineTextAlignment(.center)
      .frame(maxWidth: 340)

      // The button is redundant while a prompt is up. Leave the layout instead
      // of hiding in place, which would leave a gap above the password link.
      if !model.isPrompting {
        Button("Unlock", action: model.unlock)
          .buttonStyle(.borderedProminent)
          .controlSize(.large)
          .keyboardShortcut(.defaultAction)
      }

      // Stays available during the biometric prompt so a user whose fingerprint
      // is not being read does not have to wait for it to fail.
      if model.offersPasswordUnlock {
        Button("Use Login Password…", action: model.unlockWithPassword)
          .buttonStyle(.link)
      }
    }
    .animation(.default, value: model.isPrompting)
    .animation(.default, value: model.unlockError)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .onAppear { model.unlock() }
  }
}
