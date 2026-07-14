import SwiftUI

struct LockScreen: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    VStack(spacing: 20) {
      Image(systemName: "lock.fill")
        .font(.system(size: 52))
        .foregroundStyle(.secondary)

      Text("Axo Pass")
        .font(.title)
        .fontWeight(.semibold)

      if let err = model.unlockError {
        Text(err)
          .font(.callout)
          .foregroundStyle(.red)
          .multilineTextAlignment(.center)
          .frame(maxWidth: 320)
      }

      Button {
        Task { await model.unlock() }
      } label: {
        if model.isUnlocking {
          Label("Authenticating…", systemImage: "lock.open")
        } else {
          Label("Unlock with Touch ID", systemImage: "touchid")
        }
      }
      .buttonStyle(.borderedProminent)
      .controlSize(.large)
      .disabled(model.isUnlocking)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .task { await model.unlock() }
  }
}
