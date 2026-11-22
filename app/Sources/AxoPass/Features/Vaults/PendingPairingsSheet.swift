import AxoPassFFI
import SwiftUI

/// Pairing of this Mac as the new Mac, and the pairing requests in the synced
/// folder. A request from another Mac shows its id and age, since its computer
/// name is unknown before a code matches. A request older than the pairing
/// expiry cannot be live, so it is deleted at once. A younger one asks first.
struct PendingPairingsSheet: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let root: SyncRootInfo

  /// Age in seconds past which a request is expired. Matches the 15 minutes
  /// that the pairing of the new Mac runs.
  private static let expirySeconds: UInt64 = 15 * 60

  @State private var requests: [PairingRequestInfo]? = nil
  @State private var error: String? = nil
  @State private var isWorking = false
  @State private var confirming: PairingRequestInfo? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Pending Pairings").font(.headline)

      ScrollView {
        VStack(alignment: .leading, spacing: 16) {
          thisMacSection
          folderSection
        }
        .frame(maxWidth: .infinity, alignment: .leading)
      }
      .frame(maxHeight: 400)

      if let error { SyncErrorLabel(message: error) }

      HStack {
        if isWorking { ProgressView().controlSize(.small) }
        Spacer()
        Button("Refresh") { Task { await load() } }
          .disabled(isWorking)
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(20)
    .frame(width: 520)
    .task { await load() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .onChange(of: sync.activePairing == nil) { Task { await load() } }
    .confirmationDialog(
      "Delete this request?",
      isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
      presenting: confirming
    ) { request in
      Button("Delete Request", role: .destructive) { delete(request) }
    } message: { _ in
      Text(
        "Another device may still be pairing with it. That device has to start the pairing again.")
    }
  }

  // MARK: - This Mac

  private var thisMacSection: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text("This Mac").font(.subheadline.weight(.semibold))
      if let pairing = sync.activePairing {
        VStack(alignment: .leading, spacing: 6) {
          ForEach(pairing.vaultIds(), id: \.self) { vaultId in
            HStack(alignment: .firstTextBaseline, spacing: 8) {
              Text(vaultName(vaultId))
              Spacer(minLength: 8)
              Text(importText(vaultId))
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(3)
                .multilineTextAlignment(.trailing)
              if case .failed? = sync.imports[vaultId] {
                Button("Retry") { sync.retryImport(vaultId) }
                  .controlSize(.small)
              }
            }
          }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        HStack {
          Button("Show Code") { sync.sheet = .pair(root: root, join: nil) }
          Button("Cancel Pairing", role: .destructive) { sync.cancelPairing() }
        }
      } else {
        let pending = sync.imports.filter { $0.value.isPending || isFailed($0.value) }
        if pending.isEmpty {
          Text("No pairing runs on this Mac.").foregroundStyle(.secondary)
        } else {
          VStack(alignment: .leading, spacing: 6) {
            ForEach(pending.keys.sorted(), id: \.self) { vaultId in
              HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(vaultName(vaultId))
                Spacer(minLength: 8)
                Text(importText(vaultId))
                  .font(.callout)
                  .foregroundStyle(.secondary)
                  .lineLimit(3)
                  .multilineTextAlignment(.trailing)
                if isFailed(pending[vaultId]) {
                  Button("Retry") { sync.retryImport(vaultId) }
                    .controlSize(.small)
                }
              }
            }
          }
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(8)
          .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
      }
    }
  }

  private func isFailed(_ progress: VaultImportProgress?) -> Bool {
    if case .failed? = progress { return true }
    return false
  }

  private func vaultName(_ vaultId: String) -> String {
    var key: String? = model.vaultKey(id: vaultId)
    if case .imported(let vaultKey)? = sync.imports[vaultId] { key = vaultKey }
    if let key, let vault = model.vaults.first(where: { $0.key == key }) {
      return vault.name ?? vault.key
    }
    return key ?? "Vault \(vaultId)"
  }

  private func importText(_ vaultId: String) -> String {
    switch sync.imports[vaultId] {
    case nil: return "Waiting for the other device to share"
    case .paired?: return "Received"
    case .waiting?: return "Waiting for files from the other device"
    case .awaitingKey(let message)?, .blocked(let message)?: return message
    case .imported?: return "Ready"
    case .failed(let message)?: return "Failed: \(message)"
    }
  }

  // MARK: - Requests in the folder

  private var ownRequestId: String? { sync.activePairing?.requestId() }

  private var folderSection: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text("Requests in the synced folder").font(.subheadline.weight(.semibold))
      Text(rootDescription(root))
        .font(.caption.monospaced())
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .truncationMode(.middle)
      if let requests {
        if requests.isEmpty {
          Text("No requests.").foregroundStyle(.secondary)
        } else {
          VStack(alignment: .leading, spacing: 6) {
            ForEach(requests, id: \.requestId) { request in
              requestRow(request)
            }
          }
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(8)
          .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
      } else {
        HStack(spacing: 8) {
          ProgressView().controlSize(.small)
          Text("Reading the folder…").foregroundStyle(.secondary)
        }
      }
    }
  }

  private func requestRow(_ request: PairingRequestInfo) -> some View {
    let own = request.requestId == ownRequestId
    return HStack(alignment: .firstTextBaseline, spacing: 8) {
      VStack(alignment: .leading, spacing: 2) {
        Text(own ? "This Mac" : "Another device")
        Text(String(request.requestId.prefix(8)))
          .font(.caption.monospaced())
          .foregroundStyle(.secondary)
      }
      Spacer(minLength: 8)
      Text(ageText(request.ageSeconds) + (isExpired(request) ? ", expired" : ""))
        .font(.callout)
        .foregroundStyle(.secondary)
      if !own {
        Button("Delete", role: .destructive) {
          if isExpired(request) { delete(request) } else { confirming = request }
        }
        .controlSize(.small)
        .disabled(isWorking)
      }
    }
  }

  private func isExpired(_ request: PairingRequestInfo) -> Bool {
    request.ageSeconds >= Self.expirySeconds
  }

  private func ageText(_ seconds: UInt64) -> String {
    switch seconds {
    case ..<60: return "\(seconds) s ago"
    case ..<3600: return "\(seconds / 60) min ago"
    case ..<86400: return "\(seconds / 3600) h ago"
    default: return "\(seconds / 86400) d ago"
    }
  }

  private func load() async {
    error = nil
    do {
      requests = try await sync.pairingRequestList(root: root)
    } catch {
      self.error = error.userMessage
    }
  }

  private func delete(_ request: PairingRequestInfo) {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        try await sync.deletePairingRequest(root: root, requestId: request.requestId)
        await load()
      } catch {
        self.error = error.userMessage
      }
    }
  }
}
