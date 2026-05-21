import SwiftUI
import AxoPassFFI

struct ContentView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    @Bindable var model = model
    NavigationSplitView {
      VaultsSidebar(selection: $model.selectedKey)
    } detail: {
      VaultDetail(vault: model.selectedVault)
    }
    .navigationTitle("Vaults")
    .toolbar {
      ToolbarItem {
        Button {
          model.reload()
        } label: {
          Label("Reload", systemImage: "arrow.clockwise")
        }
      }
    }
  }
}

private struct VaultsSidebar: View {
  @Environment(VaultsModel.self) private var model
  @Binding var selection: String?

  var body: some View {
    Group {
      if let err = model.loadError {
        ContentUnavailableView(
          "Couldn't load vaults",
          systemImage: "exclamationmark.triangle",
          description: Text(err)
        )
      } else if model.vaults.isEmpty {
        ContentUnavailableView(
          "No vaults",
          systemImage: "lock.rectangle.stack",
          description: Text("Create a vault with the axo-pass CLI to see it here.")
        )
      } else {
        List(selection: $selection) {
          ForEach(model.vaults, id: \.key) { vault in
            VStack(alignment: .leading, spacing: 2) {
              Text(vault.name ?? vault.key)
                .font(.body)
              if vault.name != nil {
                Text(vault.key)
                  .font(.caption)
                  .foregroundStyle(.secondary)
              }
            }
            .tag(vault.key)
          }
        }
      }
    }
    .navigationSplitViewColumnWidth(min: 200, ideal: 240)
  }
}

private struct VaultDetail: View {
  let vault: VaultInfo?

  var body: some View {
    if let vault {
      VStack(alignment: .leading, spacing: 16) {
        Text(vault.name ?? vault.key)
          .font(.title)
        LabeledContent("Key", value: vault.key)
        if let name = vault.name {
          LabeledContent("Name", value: name)
        }
        Spacer()
      }
      .padding()
      .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    } else {
      ContentUnavailableView(
        "No vault selected",
        systemImage: "sidebar.left"
      )
    }
  }
}
