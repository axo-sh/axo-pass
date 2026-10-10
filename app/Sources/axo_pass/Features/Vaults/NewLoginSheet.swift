import SwiftUI

/// Creates a login from a website, a username, and a password. The item key and
/// title come from the website unless the user edits them under Details.
struct NewLoginSheet: View {
  /// Called with the website, username, password, and the optional key and
  /// title. Returns an error message, or nil once the login is saved.
  let onSubmit:
    (
      _ website: String, _ username: String, _ password: String, _ key: String, _ title: String
    ) async -> String?
  let generatePassword: (_ length: UInt32, _ symbols: Bool) -> String?

  @Environment(\.dismiss) private var dismiss
  @State private var website = ""
  @State private var username = ""
  @State private var password = ""
  @State private var revealPassword = false
  @State private var length = 20
  @State private var symbols = true
  @State private var showingDetails = false
  @State private var title = ""
  @State private var key = ""
  @State private var isSubmitting = false
  @State private var errorMessage: String?

  private var canSubmit: Bool {
    !isSubmitting && !website.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Login").font(.headline)

      Form {
        TextField("Website", text: $website, prompt: Text("github.com"))
          .autocorrectionDisabled()
        TextField("Username", text: $username, prompt: Text("Email or username"))
          .autocorrectionDisabled()
        passwordField
        generatorOptions

        DisclosureGroup("Details", isExpanded: $showingDetails) {
          TextField("Title", text: $title, prompt: Text("From the website"))
          TextField("Key", text: $key, prompt: Text("From the website"))
          LabeledContent("") {
            Text("Key: a-z, 0-9, -, _. A taken key gets a number added.")
              .font(.caption)
              .foregroundStyle(.secondary)
              .frame(maxWidth: .infinity, alignment: .leading)
          }
        }
      }

      if let errorMessage {
        Text(errorMessage)
          .font(.caption)
          .foregroundStyle(.red)
      }

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Create") { submit() }
          .keyboardShortcut(.defaultAction)
          .disabled(!canSubmit)
      }
    }
    .padding(20)
    .frame(width: 400)
  }

  private var passwordField: some View {
    HStack(spacing: 6) {
      Group {
        if revealPassword {
          TextField("Password", text: $password).font(.system(.body, design: .monospaced))
        } else {
          SecureField("Password", text: $password)
        }
      }
      Button {
        revealPassword.toggle()
      } label: {
        Image(systemName: revealPassword ? "eye.slash" : "eye")
      }
      .buttonStyle(.borderless)
      .help(revealPassword ? "Hide password" : "Show password")
      Button("Generate") {
        if let generated = generatePassword(UInt32(length), symbols) {
          password = generated
          revealPassword = true
        }
      }
    }
  }

  private var generatorOptions: some View {
    LabeledContent("") {
      HStack(spacing: 12) {
        Stepper("Length: \(length)", value: $length, in: 8...64)
          .fixedSize()
        Toggle("Symbols", isOn: $symbols)
          .toggleStyle(.checkbox)
        Spacer()
      }
      .controlSize(.small)
    }
  }

  private func submit() {
    Task {
      isSubmitting = true
      errorMessage = nil
      if let error = await onSubmit(website, username, password, key, title) {
        errorMessage = error
      } else {
        dismiss()
      }
      isSubmitting = false
    }
  }
}
