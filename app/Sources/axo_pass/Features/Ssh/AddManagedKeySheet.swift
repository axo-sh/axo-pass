import SwiftUI

/// Confirms creating a new Secure Enclave-backed SSH key before `SshModel`
/// generates one, since the private key can never be exported afterward.
struct AddManagedKeySheet: View {
  let model: SshModel

  @Environment(\.dismiss) private var dismiss
  @State private var isCreating = false
  @State private var error: String? = nil

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
        Button("Create Key") {
          Task {
            isCreating = true
            error = nil
            if await model.addManagedKey() {
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
  }
}
