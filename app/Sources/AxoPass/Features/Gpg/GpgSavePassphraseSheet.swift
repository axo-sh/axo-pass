import SwiftUI

/// Collects a GPG key's passphrase and hands it to `onSubmit`, which checks it
/// with gpg before saving. A rejected passphrase keeps the sheet open with
/// gpg's complaint, so a typo can be corrected in place.
struct GpgSavePassphraseSheet: View {
  let keyName: String
  /// Returns nil on success, or a message to show.
  let onSubmit: (_ passphrase: String) async -> String?

  @Environment(\.dismiss) private var dismiss
  @State private var passphrase: String = ""
  @State private var isSubmitting = false
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      VStack(alignment: .leading, spacing: 4) {
        Text("Save Passphrase for \(keyName)").font(.headline)
        Text("gpg checks the passphrase before it is saved to the keychain.")
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      SecureField("Passphrase", text: $passphrase)
        .onSubmit { submit() }
      if let error {
        Label(error, systemImage: "xmark.circle.fill")
          .font(.caption)
          .foregroundStyle(.red)
          .lineLimit(3)
          .fixedSize(horizontal: false, vertical: true)
      }

      HStack {
        if isSubmitting {
          ProgressView().controlSize(.small)
          Text("Checking…").font(.caption).foregroundStyle(.secondary)
        }
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Save") { submit() }
          .keyboardShortcut(.defaultAction)
          .disabled(isSubmitting || passphrase.isEmpty)
      }
    }
    .padding(20)
    .frame(width: 380)
  }

  private func submit() {
    guard !isSubmitting, !passphrase.isEmpty else { return }
    Task {
      isSubmitting = true
      error = await onSubmit(passphrase)
      isSubmitting = false
      if error == nil { dismiss() }
    }
  }
}
