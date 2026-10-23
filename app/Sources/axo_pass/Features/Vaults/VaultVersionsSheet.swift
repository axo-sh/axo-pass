import AxoPassFFI
import SwiftUI

/// Previous versions of one vault. A version is the vault file as it was
/// before a save. Versions are kept for up to 30 days.
struct VaultVersionsSheet: View {
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let vaultKey: String
  let vaultName: String

  @State private var versions: [RetainedVersionInfo]? = nil
  @State private var errorMessage: String? = nil
  @State private var confirmingRestore: RetainedVersionInfo? = nil
  @State private var confirmingErase = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Previous Versions of \(vaultName)").font(.headline)

      Group {
        if let versions {
          if versions.isEmpty {
            Text("No previous versions")
              .foregroundStyle(.secondary)
              .frame(maxWidth: .infinity, maxHeight: .infinity)
          } else {
            List(versions, id: \.name) { version in
              row(version)
            }
          }
        } else {
          ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
        }
      }
      .frame(height: 280)

      Text(
        "A copy of the vault is kept before each save. Copies from the last hour and the last copy of each day are kept for up to 30 days."
      )
      .font(.caption)
      .foregroundStyle(.secondary)

      if let errorMessage {
        Text(errorMessage)
          .font(.caption)
          .foregroundStyle(.red)
          .textSelection(.enabled)
      }

      HStack {
        Button("Erase All…", role: .destructive) { confirmingErase = true }
          .disabled(versions?.isEmpty ?? true)
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(20)
    .frame(width: 480)
    .task { await load() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .confirmationDialog(
      "Restore this version?",
      isPresented: Binding(
        get: { confirmingRestore != nil }, set: { if !$0 { confirmingRestore = nil } }),
      presenting: confirmingRestore
    ) { version in
      Button("Restore") { restore(version) }
    } message: { _ in
      Text(
        "The vault is replaced with this version. The current vault is kept as a previous version.")
    }
    .confirmationDialog(
      "Erase every previous version of \(vaultName)?",
      isPresented: $confirmingErase
    ) {
      Button("Erase All", role: .destructive) { erase() }
    } message: {
      Text("The vault itself is unchanged. This cannot be undone.")
    }
  }

  private func row(_ version: RetainedVersionInfo) -> some View {
    HStack {
      Text(
        "Replaced "
          + Date(timeIntervalSince1970: TimeInterval(version.savedAt)).formatted()
      )
      .font(.callout)
      Spacer(minLength: 0)
      Button("Restore…") { confirmingRestore = version }
        .controlSize(.small)
    }
    .padding(.vertical, 4)
  }

  private func load() async {
    do {
      versions = try await model.vaultVersions(vaultKey)
    } catch {
      versions = []
      errorMessage = String(describing: error)
    }
  }

  private func restore(_ version: RetainedVersionInfo) {
    errorMessage = nil
    Task {
      errorMessage = await failureMessage {
        try await model.restoreVaultVersion(vaultKey: vaultKey, name: version.name)
      }
      await load()
    }
  }

  private func erase() {
    errorMessage = nil
    Task {
      errorMessage = await failureMessage {
        _ = try await model.eraseVaultVersions(vaultKey)
      }
      await load()
    }
  }
}
