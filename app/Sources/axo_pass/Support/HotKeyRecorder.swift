import AppKit
import SwiftUI

/// A control that records a keyboard shortcut. Click it, then press the
/// shortcut; Escape cancels. The clear button removes the shortcut.
///
/// The palette's own shortcut is released while recording, so pressing it is
/// recorded rather than opening the palette.
struct HotKeyRecorder: View {
  @Binding var hotKey: HotKey?
  @State private var recording = false
  @State private var monitor: Any?
  /// Set when the last key pressed while recording had no Command, Option or
  /// Control.
  @State private var rejected = false

  var body: some View {
    HStack(spacing: 4) {
      Button(action: toggleRecording) {
        Text(label)
          .frame(minWidth: 120)
          .foregroundStyle(recording || hotKey == nil ? .secondary : .primary)
      }
      if hotKey != nil, !recording {
        Button {
          hotKey = nil
        } label: {
          Image(systemName: "xmark.circle.fill")
            .foregroundStyle(.secondary)
        }
        .buttonStyle(.plain)
        .help("Remove shortcut")
      }
    }
    .onDisappear(perform: stopRecording)
  }

  private var label: String {
    if recording { return rejected ? "Add ⌘, ⌥ or ⌃" : "Type Shortcut…" }
    return hotKey?.display ?? "Record Shortcut"
  }

  private func toggleRecording() {
    recording ? stopRecording() : startRecording()
  }

  private func startRecording() {
    recording = true
    rejected = false
    GlobalHotKey.shared.suspend()
    monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
      if event.keyCode == 53 {  // Escape
        stopRecording()
        return nil
      }
      guard let recorded = HotKey(event: event) else {
        rejected = true
        return nil
      }
      hotKey = recorded
      stopRecording()
      return nil
    }
  }

  private func stopRecording() {
    if let monitor { NSEvent.removeMonitor(monitor) }
    monitor = nil
    guard recording else { return }
    recording = false
    rejected = false
    GlobalHotKey.shared.resume()
  }
}
