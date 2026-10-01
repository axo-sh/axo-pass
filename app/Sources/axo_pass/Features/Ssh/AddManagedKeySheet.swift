import AppKit
import SwiftUI

/// Confirms creating a new Secure Enclave-backed SSH key before `SshModel`
/// generates one, since the private key can never be exported afterward.
///
/// Holding Option turns the button into "Create User Presence Key", which
/// creates a key whose every use the Secure Enclave gates with Touch ID or the
/// password. Such a key cannot be granted to an app.
struct AddManagedKeySheet: View {
  let model: SshModel

  @Environment(\.dismiss) private var dismiss
  @State private var isCreating = false
  @State private var error: String? = nil
  @State private var optionHeld = false
  @State private var flagsMonitor: Any?

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      HStack(spacing: 10) {
        Image(systemName: "key.fill")
          .font(.title2)
          .foregroundStyle(.tint)
        Text("New Managed Key").font(.headline)
      }
      Text(
        "Creates a new SSH key backed by the Secure Enclave. Its private key never leaves "
          + "the chip and cannot be exported or backed up."
      )
      .fixedSize(horizontal: false, vertical: true)
      if let error {
        Label(error, systemImage: "exclamationmark.triangle.fill")
          .font(.callout)
          .foregroundStyle(.red)
      }
      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button(optionHeld ? "Create User Presence Key" : "Create Key") {
          let alwaysRequireAuth = optionHeld
          Task {
            isCreating = true
            error = nil
            if await model.addManagedKey(alwaysRequireAuth: alwaysRequireAuth) {
              dismiss()
            } else {
              error = model.loadError
            }
            isCreating = false
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isCreating)
      }
    }
    .padding(20)
    .frame(width: 360)
    .onAppear {
      optionHeld = NSEvent.modifierFlags.contains(.option)
      flagsMonitor = NSEvent.addLocalMonitorForEvents(matching: .flagsChanged) { event in
        optionHeld = event.modifierFlags.contains(.option)
        return event
      }
    }
    .onDisappear {
      if let flagsMonitor {
        NSEvent.removeMonitor(flagsMonitor)
      }
      flagsMonitor = nil
    }
  }
}
