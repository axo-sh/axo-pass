import AxoPassFFI
import CryptoKit
import SwiftUI

struct VaultDetailView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    if let item = model.selectedItem {
      CredentialList(item: item)
    } else {
      ContentUnavailableView("Select an item", systemImage: "list.bullet.rectangle")
    }
  }
}

private struct CredentialList: View {
  @Environment(VaultsModel.self) private var model
  let item: ItemInfo

  @State private var secrets: [String: SymmetricKey] = [:]
  @State private var errors: [String: String] = [:]
  @State private var revealing: Set<String> = []
  @State private var isEditing: Bool = false

  var body: some View {
    ScrollView {
      VStack(spacing: 0) {
        Text(item.title)
          .font(.title2)
          .fontWeight(.bold)
          .padding(.horizontal, 20)
          .padding(.vertical, 0)
          .frame(maxWidth: .infinity, alignment: .leading)

        InsetGroupedSection {
          if item.credentials.isEmpty {
            Text("No credentials")
              .foregroundStyle(.secondary)
              .padding(8)
              .frame(maxWidth: .infinity, alignment: .leading)
          } else {
            VStack(spacing: 8) {
              ForEach(Array(item.credentials.enumerated()), id: \.element.key) { index, cred in
                if index > 0 {
                  Divider()
                }
                CredentialRow(
                  cred: cred,
                  secret: secrets[cred.key],
                  error: errors[cred.key],
                  isRevealing: revealing.contains(cred.key),
                  isEditing: isEditing,
                  onReveal: { Task { await reveal(cred) } },
                  onHide: { hide(cred) },
                  onCopy: { copy(cred) }
                )
              }
            }.padding(0)
          }
        }
        .padding()
        .padding(.top, 0)
      }
    }
    .safeAreaInset(edge: .top) {
      HStack(spacing: 8) {
        Spacer()
        Button(allRevealed ? "Hide All" : "Reveal All") {
          if allRevealed {
            hideAll()
          } else {
            Task { await revealAll() }
          }
        }
        .buttonStyle(.bordered)
        // .controlSize(.small)
        .disabled(!revealing.isEmpty)

        Button(isEditing ? "Done" : "Edit") {
          isEditing.toggle()
        }
        .buttonStyle(.bordered)
        // .controlSize(.small)
      }
      .padding(.horizontal)
      .padding(.vertical, 8)
      .background(.ultraThinMaterial)
    }
    .ignoresSafeArea(edges: [.top, .bottom])
    .onChange(of: item.key) {
      secrets = [:]
      errors = [:]
      revealing = []
      isEditing = false
    }
  }

  private var allRevealed: Bool {
    !item.credentials.isEmpty && item.credentials.allSatisfy { secrets[$0.key] != nil }
  }

  private func revealAll() async {
    await withTaskGroup(of: Void.self) { group in
      for cred in item.credentials where secrets[cred.key] == nil && !revealing.contains(cred.key) {
        group.addTask { await reveal(cred) }
      }
    }
  }

  private func hideAll() {
    secrets = [:]
  }

  private func reveal(_ cred: CredentialInfo) async {
    revealing.insert(cred.key)
    errors.removeValue(forKey: cred.key)
    do {
      secrets[cred.key] = try await model.credentialSecret(
        itemKey: item.key, credKey: cred.key
      )
    } catch {
      errors[cred.key] = String(describing: error)
    }
    revealing.remove(cred.key)
  }

  private func hide(_ cred: CredentialInfo) {
    secrets.removeValue(forKey: cred.key)
  }

  private func copy(_ cred: CredentialInfo) {
    guard let secret = secrets[cred.key] else { return }
    secret.withUnsafeBytes { ptr in
      guard let str = String(bytes: ptr, encoding: .utf8) else { return }
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(str, forType: .string)
    }
  }
}
