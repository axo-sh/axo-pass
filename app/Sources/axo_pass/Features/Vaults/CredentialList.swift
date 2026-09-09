import AxoPassFFI
import CryptoKit
import SwiftUI

/// Inset applied to each credential row. The drop indicator is offset by this
/// much to reach the row edge where the separator is drawn.
let credentialRowInset: CGFloat = 8

struct CredentialList: View {
  @Environment(VaultsModel.self) var model
  let item: ItemInfo
  let vaultKey: String

  @State var secrets: [String: SymmetricKey] = [:]
  @State var errors: [String: String] = [:]
  @State var revealing: Set<String> = []
  @State var isEditing: Bool = false
  @State private var showingNewCredentialSheet = false
  // Local override of credential order while a drag-reorder is pending its
  // reload. Cleared once the model returns the credentials in the new order.
  @State var pendingOrder: [String]? = nil
  // Where a drag would currently insert, for the drop indicator.
  @State var dropTarget: DropTarget? = nil

  var body: some View {
    List {
      Section {
        header
          .listRowSeparator(.hidden)
          .listRowInsets(EdgeInsets(top: 8, leading: 4, bottom: 16, trailing: 4))
      }
      Section {
        if item.credentials.isEmpty {
          Text("No credentials")
            .foregroundStyle(.secondary)
        } else {
          ForEach(displayCredentials, id: \.key) { cred in
            reorderableRow(cred)
              .listRowInsets(
                EdgeInsets(
                  top: credentialRowInset, leading: credentialRowInset,
                  bottom: credentialRowInset, trailing: credentialRowInset
                )
              )
              .listRowSeparator(.hidden)
          }
          endDropZone
            .listRowSeparator(.hidden)
            .listRowInsets(
              EdgeInsets(
                top: 0, leading: credentialRowInset, bottom: 0, trailing: credentialRowInset
              )
            )
        }
      }
    }
    .listStyle(.inset)
    .animation(.snappy(duration: 0.2), value: displayCredentials.map(\.key))
    .animation(.easeInOut(duration: 0.1), value: dropTarget)
    .overlay {
      if isEditing {
        RoundedRectangle(cornerRadius: 6)
          .strokeBorder(.tint, lineWidth: 2)
          .padding(8)
          .allowsHitTesting(false)
      }
    }
    .navigationTitle(item.title)
    .toolbar {
      ToolbarItemGroup(placement: .primaryAction) {
        // Push the item actions to the trailing edge of the toolbar.
        Spacer()

        if !isEditing, hasConcealed {
          Button(allRevealed ? "Hide All" : "Reveal All") {
            if allRevealed {
              hideAll()
            } else {
              Task { await revealAll() }
            }
          }
          .disabled(!revealing.isEmpty)
        }

        Button(isEditing ? "Done" : "Edit") {
          if isEditing {
            isEditing = false
            hideAll()
          } else {
            // Editing resubmits each credential's value along with its title,
            // so reveal everything before the edit forms appear.
            Task {
              await revealAll()
              isEditing = true
            }
          }
        }
        .disabled(!revealing.isEmpty)

        Button {
          showingNewCredentialSheet = true
        } label: {
          Label("Add Credential", systemImage: "plus")
        }
      }
    }
    .onChange(of: item.key) {
      secrets = [:]
      errors = [:]
      revealing = []
      isEditing = false
      pendingOrder = nil
    }
    .onChange(of: item.credentials.map(\.key)) {
      // The reload after a reorder delivers the persisted order; drop the
      // local override so the two cannot diverge.
      pendingOrder = nil
    }
    .sheet(isPresented: $showingNewCredentialSheet) {
      NewCredentialSheet { key, title, value, kind in
        await model.addOrUpdateCredential(
          vaultKey: vaultKey, itemKey: item.key, credKey: key, title: title, value: value,
          kind: kind
        )
      }
    }
  }

  private var header: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "lock.fill")
        .font(.system(size: 26))
        .foregroundStyle(.tint)
        .frame(width: 34)
      VStack(alignment: .leading, spacing: 2) {
        Text(item.title).font(.title2).fontWeight(.semibold)
        Text(item.key)
          .font(.callout)
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
      }
    }
  }

  @ViewBuilder
  func credentialRowBody(_ cred: CredentialInfo) -> some View {
    CredentialRow(
      cred: cred,
      secret: secrets[cred.key],
      error: errors[cred.key],
      isRevealing: revealing.contains(cred.key),
      isEditing: isEditing,
      onReveal: { Task { await reveal(cred) } },
      onHide: { hide(cred) },
      onCopy: { await copy(cred) },
      onSave: { newKey, newTitle, newValue, newKind in
        Task {
          await save(
            cred, newKey: newKey, newTitle: newTitle, newValue: newValue, newKind: newKind
          )
        }
      },
      onQuickSaveValue: { newValue in
        Task { await quickSaveValue(cred, newValue: newValue) }
      },
      onDelete: { Task { await delete(cred) } }
    )
  }
}
