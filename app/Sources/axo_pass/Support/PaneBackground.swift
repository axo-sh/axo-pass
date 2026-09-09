import SwiftUI

private struct PaneBackground: ViewModifier {
  func body(content: Content) -> some View {
    content
      .scrollContentBackground(.hidden)
      .frame(maxWidth: .infinity, maxHeight: .infinity)
      .background(.windowBackground)
  }
}

extension View {
  func paneBackground() -> some View {
    modifier(PaneBackground())
  }
}
