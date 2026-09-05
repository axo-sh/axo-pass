import AppKit
import AxoPassFFI
import SwiftUI

struct ShellIntegrationPane: View {
  @State private var model = ShellIntegrationModel()
  @State private var showingSetup = false

  var body: some View {
    List {
      Section {
        statusRow
      } header: {
        HStack {
          Text("Shell Integration")
          Spacer()
          HelpLink { showingSetup = true }
            .controlSize(.mini)
        }
      }
    }
    .navigationTitle("Setup")
    .navigationSplitViewColumnWidth(min: 200, ideal: 260)
    .sheet(isPresented: $showingSetup) {
      ShellIntegrationSetupSheet(model: model)
    }
    .task { model.refreshStatus() }
    // The file may be edited outside the app, so re-read it on reactivation.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      model.refreshStatus()
    }
  }

  @ViewBuilder
  private var statusRow: some View {
    HStack {
      VStack(alignment: .leading, spacing: 2) {
        Text("`ap` in .zshrc")
        if let status = model.status {
          Text(status.zshrcPath)
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.middle)
        }
      }
      Spacer()
      if let status = model.status {
        Label(
          status.configured ? "Configured" : "Not Configured",
          systemImage: status.configured ? "checkmark.circle.fill" : "circle"
        )
        .foregroundStyle(status.configured ? .green : .secondary)
        .font(.caption)
        Button(status.configured ? "Reconfigure…" : "Set Up…") {
          showingSetup = true
        }
        .controlSize(.small)
      }
    }
    .padding(.vertical, 2)
  }
}
