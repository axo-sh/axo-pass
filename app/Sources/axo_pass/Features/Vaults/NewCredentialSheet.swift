import AppKit
import AxoPassFFI
import SwiftUI

struct NewCredentialSheet: View {
  let onSubmit:
    (_ key: String, _ title: String, _ value: String, _ kind: FieldKindInfo) async -> Bool

  @Environment(\.dismiss) private var dismiss
  @State private var title: String = ""
  @State private var key: String = ""
  @State private var concealed: Bool = true
  @State private var multiline: Bool = false
  @State private var isSubmitting = false

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

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Create") {
          Task {
            isSubmitting = true
            let kind = FieldKindInfo(kind: "text", concealed: concealed, multiline: multiline)
            if await onSubmit(key, title, "", kind) { dismiss() }
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
