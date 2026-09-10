import AxoPassFFI
import SwiftUI

/// The Keychain window: a read-only inventory of the saved generic passwords
/// and the managed Secure Enclave keys, opened from Help ▸ Keychain.
struct KeychainWindow: View {
  @State private var model = KeychainModel()
  @State private var section: Section = .passwords
  @State private var passwordSelection: SavedPasswordRow.ID? = nil
  @State private var keySelection: ManagedKeyRow.ID? = nil
  @State private var showInspector = false
  @Environment(VaultsModel.self) private var vaults
  @Environment(\.dismiss) private var dismiss

  private enum Section: String, CaseIterable, Identifiable {
    case passwords
    case keys

    var id: String { rawValue }

    var label: String {
      switch self {
      case .passwords: return "Saved Passwords"
      case .keys: return "Managed Keys"
      }
    }
  }

  private var selectedPassword: SavedPasswordRow? {
    model.passwords.first { $0.id == passwordSelection }
  }

  private var selectedKey: ManagedKeyRow? {
    model.managedKeys.first { $0.id == keySelection }
  }

  var body: some View {
    NavigationStack {
      content
        .navigationTitle("Keychain")
        .toolbar { toolbarContent }
        .inspector(isPresented: $showInspector) {
          inspector
            .inspectorColumnWidth(min: 280, ideal: 340, max: 460)
        }
    }
    .task { await model.reload() }
    .onChange(of: passwordSelection) { _, newValue in
      if newValue != nil { showInspector = true }
    }
    .onChange(of: keySelection) { _, newValue in
      if newValue != nil { showInspector = true }
    }
    // The inventory is only available unlocked, so locking takes the window down.
    .onChange(of: vaults.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .overlay(alignment: .bottom) {
      if let error = model.loadError {
        Text(error)
          .font(.callout)
          .foregroundStyle(.red)
          .padding(8)
          .background(.regularMaterial, in: .rect(cornerRadius: 8))
          .padding()
      }
    }
  }

  @ViewBuilder
  private var content: some View {
    switch section {
    case .passwords:
      Table(model.passwords, selection: $passwordSelection) {
        TableColumn("Type", value: \.typeText)
          .width(min: 90, ideal: 110)
        TableColumn("Account", value: \.account)
        TableColumn("Key ID", value: \.keyId)
      }
    case .keys:
      Table(model.managedKeys, selection: $keySelection) {
        TableColumn("Label", value: \.label)
        TableColumn("SHA256") { Text($0.fingerprintSha256).font(.system(.body, design: .monospaced)) }
      }
    }
  }

  @ViewBuilder
  private var inspector: some View {
    switch section {
    case .passwords:
      SavedPasswordInspector(row: selectedPassword)
    case .keys:
      ManagedKeyInspector(row: selectedKey)
    }
  }

  @ToolbarContentBuilder
  private var toolbarContent: some ToolbarContent {
    ToolbarItemGroup(placement: .primaryAction) {
      Picker("Section", selection: $section) {
        ForEach(Section.allCases) { Text($0.label).tag($0) }
      }
      .pickerStyle(.segmented)

      Button {
        Task { await model.reload() }
      } label: {
        Label("Refresh", systemImage: "arrow.clockwise")
      }
      .disabled(model.isLoading)

      Button {
        showInspector.toggle()
      } label: {
        Label("Details", systemImage: "sidebar.right")
      }
    }
  }
}

private struct SavedPasswordInspector: View {
  let row: SavedPasswordRow?

  var body: some View {
    if let row {
      ScrollView {
        VStack(alignment: .leading, spacing: 8) {
          InsetGroupedSection {
            LabeledContent("Type", value: row.typeText)
            LabeledContent("Account", value: row.account)
            LabeledContent("Key ID", value: row.keyId)
          }
        }
        .labeledContentStyle(.inspectorField(labelWidth: 92))
        .textSelection(.enabled)
        .padding()
      }
    } else {
      ContentUnavailableView("No Password Selected", systemImage: "key")
    }
  }
}

private struct ManagedKeyInspector: View {
  let row: ManagedKeyRow?

  var body: some View {
    if let row {
      ScrollView {
        VStack(alignment: .leading, spacing: 8) {
          InsetGroupedSection {
            LabeledContent("Label", value: row.label)
            LabeledContent("SHA256", value: row.fingerprintSha256)
            LabeledContent("MD5", value: row.fingerprintMd5)
          }
          if let openssh = row.publicKeyOpenssh {
            InsetGroupedSection {
              LabeledContent("Public Key", value: openssh)
            }
          }
        }
        .labeledContentStyle(.inspectorField(labelWidth: 92))
        .textSelection(.enabled)
        .padding()
      }
    } else {
      ContentUnavailableView("No Key Selected", systemImage: "key.horizontal")
    }
  }
}
