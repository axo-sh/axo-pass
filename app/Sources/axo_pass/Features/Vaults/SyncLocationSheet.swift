import AppKit
import SwiftUI

/// Sheet that chooses the synced location of the app: a folder or an S3
/// bucket. A folder is picked in an open panel. A bucket continues to the S3
/// settings in the same sheet.
struct SyncLocationSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(\.dismiss) private var dismiss

  private enum Step {
    case choose
    case s3
  }

  @State private var step: Step = .choose

  var body: some View {
    switch step {
    case .choose: chooseStep
    case .s3: S3SettingsSheet(onBack: { step = .choose })
    }
  }

  private var chooseStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      VStack(alignment: .leading, spacing: 4) {
        Text("Sync Location").font(.headline)
        Text("Choose where Axo Pass keeps the synced vault files.")
          .foregroundStyle(.secondary)
      }
      VStack(spacing: 8) {
        Button {
          chooseFolder()
        } label: {
          ChoiceCard(
            symbol: "folder.fill", title: "Synced Folder",
            detail: "A folder on iCloud Drive, Dropbox, or similar")
        }
        .buttonStyle(.plain)
        Button {
          step = .s3
        } label: {
          ChoiceCard(
            symbol: "externaldrive.fill", title: "S3 Bucket",
            detail: "AWS S3 or a compatible service, such as Cloudflare R2")
        }
        .buttonStyle(.plain)
      }
      Spacer(minLength: 0)
      HStack {
        Spacer()
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
      }
    }
    .padding(20)
    .frame(width: 520, height: 280)
  }

  private func chooseFolder() {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.canCreateDirectories = true
    panel.allowsMultipleSelection = false
    panel.prompt = "Choose"
    panel.message = "Choose the synced folder for your vaults."
    guard panel.runModal() == .OK, let url = panel.url else { return }
    sync.setFolder(url)
    dismiss()
  }
}
