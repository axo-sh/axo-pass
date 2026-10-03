import SwiftUI

/// A password field with a trailing button that toggles between hidden and visible text.
struct RevealableSecureField: View {
  let title: String
  @Binding var text: String
  var focus: FocusState<Bool>.Binding
  var onSubmit: () -> Void = {}

  @State private var revealed = false

  var body: some View {
    HStack(spacing: 6) {
      field
        .textFieldStyle(.roundedBorder)
        .focused(focus)
        .onSubmit(onSubmit)

      Button {
        revealed.toggle()
        focus.wrappedValue = true
      } label: {
        Image(systemName: revealed ? "eye.slash" : "eye")
          .frame(width: 16)
      }
      .buttonStyle(.borderless)
      .help(revealed ? "Hide passphrase" : "Show passphrase")
      .accessibilityLabel(revealed ? "Hide passphrase" : "Show passphrase")
    }
  }

  @ViewBuilder
  private var field: some View {
    if revealed {
      TextField(title, text: $text)
    } else {
      SecureField(title, text: $text)
    }
  }
}
