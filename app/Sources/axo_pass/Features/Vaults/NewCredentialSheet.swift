import AxoPassFFI
import SwiftUI

struct NewCredentialSheet: View {
  let onSubmit:
    (_ key: String, _ title: String, _ value: String, _ kind: FieldKindInfo) async -> Bool

  @Environment(\.dismiss) private var dismiss
  @State private var title: String = ""
  @State private var key: String = ""
  @State private var value: String = ""
  @State private var concealed: Bool = true
  @State private var multiline: Bool = false
  @State private var isSubmitting = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Credential").font(.headline)
      Form {
        TextField("Title", text: $title)
        TextField("Key (a-z, 0-9, -, _)", text: $key)
        if concealed && !multiline {
          SecureField("Value", text: $value)
        } else {
          TextField("Value", text: $value, axis: .vertical)
            .lineLimit(multiline ? 3...12 : 1...1)
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
            if await onSubmit(key, title, value, kind) { dismiss() }
            isSubmitting = false
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || key.isEmpty || title.isEmpty || value.isEmpty)
      }
    }
    .padding(20)
    .frame(width: 320)
  }
}
