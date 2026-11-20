import SwiftUI

/// A spinner that stays hidden for a short grace period, so loads that finish
/// quickly never flash a spinner. Slower loads fade one in.
struct DelayedProgressView: View {
  var delay: Duration = .milliseconds(250)
  var size: ControlSize = .large
  /// Whether to fill its container, which is what a pane-sized spinner wants.
  /// Inline spinners take their own size instead.
  var expands: Bool = true

  @State private var visible = false

  var body: some View {
    ZStack {
      if visible {
        ProgressView()
          .controlSize(size)
          .transition(.opacity)
      }
    }
    .frame(
      maxWidth: expands ? .infinity : nil,
      maxHeight: expands ? .infinity : nil
    )
    .task {
      try? await Task.sleep(for: delay)
      withAnimation(.easeIn(duration: 0.15)) { visible = true }
    }
  }
}
