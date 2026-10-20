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
        .textFieldStyle(.plain)
        .focused(focus)
        .onSubmit(onSubmit)
        .padding(.vertical, 6)
        .padding(.horizontal, 8)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        .overlay(
          RoundedRectangle(cornerRadius: 6)
            .strokeBorder(.tint, lineWidth: 2)
            .opacity(focus.wrappedValue ? 1 : 0)
        )

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
      TextField(title, text: $text).font(.system(.body, design: .monospaced))
    } else {
      SecureField(title, text: $text)
    }
  }
}
