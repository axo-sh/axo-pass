import SwiftUI

/// A section that mimics iOS's `.insetGrouped` list style. SwiftUI's
/// `InsetGroupedListStyle` isn't available on macOS, so there we fall back to a
/// `GroupBox` which gives the same titled, rounded-card appearance.
struct InsetGroupedSection<Content: View>: View {
  let content: Content

  init(@ViewBuilder content: () -> Content) {
    self.content = content()
  }

  var body: some View {
    GroupBox {
      content
        .padding(.vertical, 4)
    }
    .padding(.top, 0)
    .padding(.bottom, 12)
  }
}
