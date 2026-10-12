import SwiftUI

/// Prompt and save action for `TitleSheet`. Identifiable for use with
/// `.sheet(item:)`.
struct TitleSheetRequest: Identifiable {
  let id = UUID()
  let heading: String
  let actionLabel: String
  var initialTitle: String = ""
  /// Saves the trimmed title. Returns an error message, or nil on success.
  let onSubmit: @MainActor (String) async -> String?
}

/// Sheet that asks for a title when creating or renaming a folder or section.
struct TitleSheet: View {
  let request: TitleSheetRequest

  @Environment(\.dismiss) private var dismiss
  @State private var title = ""
  @State private var isSubmitting = false
  @State private var errorMessage: String?

  private var trimmedTitle: String {
    title.trimmingCharacters(in: .whitespacesAndNewlines)
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(request.heading).font(.headline)
      Form {
        TextField("Title", text: $title)
      }

      if let errorMessage {
        Text(errorMessage)
          .font(.caption)
          .foregroundStyle(.red)
      }

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button(request.actionLabel) {
          Task { await submit() }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || trimmedTitle.isEmpty)
      }
    }
    .padding(20)
    .frame(width: 320)
    .onAppear { title = request.initialTitle }
  }

  private func submit() async {
    isSubmitting = true
    errorMessage = nil
    if let error = await request.onSubmit(trimmedTitle) {
      errorMessage = error
    } else {
      dismiss()
    }
    isSubmitting = false
  }
}
