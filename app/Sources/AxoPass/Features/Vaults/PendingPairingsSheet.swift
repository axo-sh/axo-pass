import AxoPassFFI
import SwiftUI

/// Pairing requests in the synced folder. A request shows its age, since its
/// computer name is unknown before a code matches. A request older than the pairing
/// expiry cannot be live, so it is deleted immediately. A younger one asks first.
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
        folderSection
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

  // MARK: - Requests in the folder

  private var ownRequestId: String? { sync.activePairing?.requestId() }

  private var folderSection: some View {
    VStack(alignment: .leading, spacing: 8) {
      if let requests {
        if requests.isEmpty {
          Text("No requests.").foregroundStyle(.secondary)
        } else {
          VStack(alignment: .leading, spacing: 6) {
            ForEach(
              requests.filter { $0.requestId == ownRequestId }
                + requests.filter { $0.requestId != ownRequestId },
              id: \.requestId
            ) { request in
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
      Text(
        (own ? "This Mac, " : "")
          + ageText(request.ageSeconds) + (isExpired(request) ? ", expired" : "")
      )
      .help("Request id: \(request.requestId)")
      Spacer(minLength: 8)
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
