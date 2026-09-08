import SwiftUI

/// A spinner that stays hidden for a short grace period, so loads that finish
/// quickly never flash a spinner. Slower loads fade one in.
struct DelayedProgressView: View {
  var delay: Duration = .milliseconds(250)

  @State private var visible = false

  var body: some View {
    ZStack {
      if visible {
        ProgressView()
          .controlSize(.large)
          .transition(.opacity)
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .task {
      try? await Task.sleep(for: delay)
      withAnimation(.easeIn(duration: 0.15)) { visible = true }
    }
  }
}
