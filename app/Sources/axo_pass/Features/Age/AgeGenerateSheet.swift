import SwiftUI

/// Prompts for a name and generates a new x25519 age identity under it.
struct AgeGenerateSheet: View {
  let onSubmit: (_ name: String) async -> Bool

  @Environment(\.dismiss) private var dismiss
  @State private var name: String = ""
  @State private var isSubmitting = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Age Key").font(.headline)
      TextField("Name", text: $name)
      Text("The secret identity is stored in the keychain. Its public recipient is shown once the key is created.")
        .font(.caption)
        .foregroundStyle(.secondary)

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Create") {
          Task { await submit() }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || trimmedName.isEmpty)
      }
    }
    .padding(20)
    .frame(width: 340)
  }

  private var trimmedName: String {
    name.trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private func submit() async {
    isSubmitting = true
    let ok = await onSubmit(trimmedName)
    isSubmitting = false
    if ok { dismiss() }
  }
}
