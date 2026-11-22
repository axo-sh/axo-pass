import AppKit
import AxoPassFFI
import SwiftUI

/// Text of the move of the vault files on new hardware, shown before pairing
/// or a recovery kit moves them.
let newHardwareMoveMessage =
  "Pairing or a recovery kit first moves every vault file on this Mac to the unreadable folder in the Axo Pass data folder. The moved files open only on the Mac that made them, and Settings › Vaults lists them."

/// Sidebar text of a key state with a notice. Nil for a key state with none.
func keyStateTitle(_ state: KeyStateInfo?) -> String? {
  switch state {
  case .newHardware: return "Vaults from another Mac"
  case .signingKeyLost: return "Signing key lost"
  case .keychainError: return "Keychain error"
  case .normal, .noVaultFiles, nil: return nil
  }
}

/// Key state of this Mac: the synced vaults on new hardware with pairing and
/// the recovery kit, the re-sign after signing key loss, or the keychain
/// error.
struct KeyStateSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  @State private var confirmingResign = false
  @State private var isWorking = false
  @State private var resigned: ResignedInfo? = nil
  @State private var error: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      if let resigned {
        resignedStep(resigned)
      } else {
        switch sync.keyState {
        case .newHardware: newHardwareStep
        case .signingKeyLost: signingKeyLostStep
        case .keychainError(let message): keychainErrorStep(message)
        case .normal, .noVaultFiles, nil: normalStep
        }
      }
    }
    .padding(20)
    .frame(width: 520)
    .task { await sync.reloadKeyState() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .confirmationDialog("Sign every vault again?", isPresented: $confirmingResign) {
      Button("Sign Again") { resign() }
    } message: {
      Text(
        "Axo Pass creates a new signing key and signs every vault file and previous version again. Sign again only if you are the only person who could change the vault files while the key was missing. A synced vault then stops syncing until you pair with another device or use its recovery kit."
      )
    }
  }

  // MARK: - New hardware

  private var newHardwareStep: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Vaults from Another Mac").font(.headline)

      Text(
        "This Mac does not have the keys that open its vault files. This happens after a backup or a Migration Assistant copy from another Mac, since the keys never leave the Mac that made them."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      if sync.newHardwareVaults.isEmpty {
        Text("Vaults on this Mac do not sync.")
          .foregroundStyle(.secondary)
      } else {
        Text(
          "These vaults sync. Pair with a device that syncs them, or use their recovery kits, to add them to this Mac:"
        )
        .fixedSize(horizontal: false, vertical: true)
        VStack(alignment: .leading, spacing: 4) {
          ForEach(sync.newHardwareVaults, id: \.vaultId) { vault in
            Text(syncedVaultName(vault))
          }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      }

      Text("A vault that does not sync cannot be opened on this Mac.")
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)

      Label(newHardwareMoveMessage, systemImage: "exclamationmark.triangle.fill")
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)

      HStack {
        Button("Pair with Another Device…") { sync.sheet = .pair(root: sync.folder, join: nil) }
        Button("Use a Recovery Kit…") { sync.sheet = .kitImport(root: sync.folder, join: nil) }
        Spacer()
        Button("Close") { dismiss() }
          .keyboardShortcut(.cancelAction)
      }
    }
  }

  /// Name of a synced vault by the listed vault of its id, marked as
  /// unverified, or its short id.
  private func syncedVaultName(_ vault: SyncedVaultInfo) -> String {
    guard let listed = model.vaults.first(where: { $0.id == vault.vaultId }) else {
      return "Vault \(vault.vaultId)"
    }
    return "\(listed.name ?? listed.key) (unverified)"
  }

  // MARK: - Signing key lost

  private var signingKeyLostStep: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Signing Key Lost").font(.headline)

      Text(
        "The signing key of this Mac is missing from the keychain, so every vault fails its check and stays closed. The encryption key of this Mac is present, so the vaults can be signed again with a new key."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      if let error { SyncErrorLabel(message: error) }

      HStack {
        if isWorking { ProgressView().controlSize(.small) }
        Spacer()
        Button("Close") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Sign Again…") { confirmingResign = true }
          .keyboardShortcut(.defaultAction)
          .disabled(isWorking)
      }
    }
  }

  private func resign() {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        resigned = try await sync.resign()
      } catch {
        self.error = error.userMessage
      }
    }
  }

  private func resignedStep(_ resigned: ResignedInfo) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Vaults Signed Again").font(.headline)

      Text(
        resigned.signed == 1
          ? "1 file was signed again with the new key."
          : "\(resigned.signed) files were signed again with the new key."
      )
      .fixedSize(horizontal: false, vertical: true)

      if !resigned.skipped.isEmpty {
        Text("These files were not signed again and still cannot be opened:")
          .fixedSize(horizontal: false, vertical: true)
        ScrollView {
          VStack(alignment: .leading, spacing: 4) {
            ForEach(resigned.skipped, id: \.self) { path in
              Text(path)
                .font(.callout.monospaced())
                .lineLimit(1)
                .truncationMode(.middle)
                .help(path)
                .textSelection(.enabled)
            }
          }
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(8)
        }
        .frame(maxHeight: 140)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      }

      HStack {
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  // MARK: - Other states

  private func keychainErrorStep(_ message: String) -> some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Keychain Error").font(.headline)

      Text(
        "Axo Pass cannot read its keys from the keychain, so every vault stays closed. Axo Pass did not create a key or change a file."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      SyncErrorLabel(message: message)

      HStack {
        Spacer()
        Button("Close") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Check Again") { Task { await sync.reloadKeyState() } }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  private var normalStep: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Keys of This Mac").font(.headline)
      Text("Keys are in the keychain.")
        .foregroundStyle(.secondary)
      HStack {
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
  }
}

/// Vault files moved to `unreadable/` on new hardware, by unverified name,
/// with Show in Finder for each file.
struct MovedVaultsSheet: View {
  let moved: [MovedVaultInfo]

  @Environment(\.dismiss) private var dismiss

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Moved Vault Files").font(.headline)

      Text(
        "This Mac could not open these vault files, so they were moved aside. They open only on the Mac that made them."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      ScrollView {
        VStack(alignment: .leading, spacing: 8) {
          ForEach(moved, id: \.path) { vault in
            HStack(spacing: 8) {
              VStack(alignment: .leading, spacing: 2) {
                Text("\(vault.name ?? vault.key) (unverified)")
                Text(vault.path)
                  .font(.caption.monospaced())
                  .foregroundStyle(.secondary)
                  .lineLimit(1)
                  .truncationMode(.middle)
                  .help(vault.path)
              }
              Spacer(minLength: 0)
              Button("Show in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: vault.path)])
              }
              .controlSize(.small)
            }
          }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
      }
      .frame(maxHeight: 280)
      .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))

      HStack {
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(20)
    .frame(width: 520)
  }
}
