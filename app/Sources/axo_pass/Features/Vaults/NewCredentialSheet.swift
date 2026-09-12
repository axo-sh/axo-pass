import AppKit
import AxoPassFFI
import SwiftUI

struct NewCredentialSheet: View {
  let onSubmit:
    (_ key: String, _ title: String, _ value: String, _ kind: FieldKindInfo) async -> String?

  @Environment(\.dismiss) private var dismiss
  @State private var title: String = ""
  @State private var key: String = ""
  @State private var concealed: Bool = true
  @State private var multiline: Bool = false
  @State private var isSubmitting = false
  @State private var errorMessage: String?

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Credential").font(.headline)
      Form {
        LabeledContent("Title") {
          TextField("", text: $title)
        }
        LabeledContent("Key") {
          TextField("", text: $key)
        }
        LabeledContent("") {
          Text("a-z, 0-9, -, _")
            .font(.caption)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
        }

        HStack(spacing: 16) {
          Toggle("Concealed", isOn: $concealed)
          Toggle("Multiline", isOn: $multiline)
        }
        .toggleStyle(.checkbox)
      }

      if let errorMessage {
        Text(errorMessage)
          .font(.caption)
          .foregroundStyle(.red)
      }

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Create") {
          Task {
            isSubmitting = true
            errorMessage = nil
            let kind = FieldKindInfo(kind: "text", concealed: concealed, multiline: multiline)
            if let error = await onSubmit(key, title, "", kind) {
              errorMessage = error
            } else {
              dismiss()
            }
            isSubmitting = false
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || key.isEmpty || title.isEmpty)
      }
    }
    .padding(20)
    .frame(width: 320)
  }
}
