import AxoPassFFI
import SwiftUI

/// Previous versions of one vault. A version is the vault file as it was
/// before a save. Versions are kept for up to 30 days. A vault file that fails
/// to load can be replaced with a version too.
struct VaultVersionsSheet: View {
  @Environment(VaultsModel.self) private var model
  @Environment(SyncModel.self) private var sync
  @Environment(\.dismiss) private var dismiss

  let vaultKey: String
  let vaultName: String

  @State private var versions: [RetainedVersionInfo]? = nil
  /// Whether the vault file fails to load. Nil until checked.
  @State private var refused: Bool? = nil
  @State private var errorMessage: String? = nil
  @State private var confirmingRestore: RetainedVersionInfo? = nil
  @State private var confirmingErase = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("History of \(vaultName)").font(.headline)

      if refused == true {
        Label(
          "This vault file failed to load. Restore a previous version to replace it. The file that failed is kept aside.",
          systemImage: "exclamationmark.triangle.fill"
        )
        .font(.callout)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
      }

      if let versions {
        if versions.isEmpty {
          Text("No previous versions").foregroundStyle(.secondary)
        } else {
          // The list is as tall as its rows, and scrolls past the maximum height.
          ViewThatFits(in: .vertical) {
            versionList(versions)
            ScrollView { versionList(versions) }
          }
          .frame(maxHeight: 280)
        }
      } else {
        ProgressView().frame(maxWidth: .infinity, minHeight: 80)
      }

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
    .task { await start() }
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
      Text(restoreMessage)
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

  /// Text of the restore confirmation. The sync state of a vault file that
  /// fails to load cannot be read.
  private var restoreMessage: String {
    if refused == true {
      return
        "The vault file that failed to load is replaced with this version and kept aside. If the vault syncs, the differences are recorded as edits on every Mac."
    }
    if sync.state(vaultKey)?.isOn == true {
      return
        "The vault is replaced with this version. The current vault is kept as a previous version. The vault syncs, so the differences are recorded as edits on every Mac."
    }
    return
      "The vault is replaced with this version. The current vault is kept as a previous version."
  }

  private func versionList(_ versions: [RetainedVersionInfo]) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      ForEach(versions, id: \.name) { version in
        row(version)
        if version.name != versions.last?.name { Divider() }
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  private func row(_ version: RetainedVersionInfo) -> some View {
    HStack {
      Text(
        "Current until "
          + Date(timeIntervalSince1970: TimeInterval(version.savedAt)).formatted()
      )
      .font(.callout)
      Spacer(minLength: 0)
      Button("Restore…") { confirmingRestore = version }
        .controlSize(.small)
        .disabled(refused == nil)
    }
    .padding(.vertical, 8)
  }

  /// List the versions, and check whether the vault file loads.
  private func start() async {
    await load()
    refused = await model.loadFailure(vaultKey) != nil
  }

  private func load() async {
    do {
      versions = try await model.vaultVersions(vaultKey)
    } catch {
      versions = []
      errorMessage = error.userMessage
    }
  }

  private func restore(_ version: RetainedVersionInfo) {
    errorMessage = nil
    let refused = self.refused == true
    Task {
      errorMessage = await failureMessage {
        do {
          try await model.restoreVaultVersion(
            vaultKey: vaultKey, name: version.name, refused: refused)
        } catch FfiError.AuthExpired {
          // The app locked, which closes the sheet.
          return
        }
        self.refused = false
        await sync.reload(vaultKey)
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
