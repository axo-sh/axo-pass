import AppKit
import AxoPassFFI
import SwiftUI

struct AgePane: View {
  @Bindable var model: AgeModel
  @State private var showingGenerateSheet = false
  @State private var showingHelp = false

  var body: some View {
    List(selection: $model.selectedRecipient) {
      if let err = model.loadError {
        Label(err, systemImage: "exclamationmark.triangle")
          .font(.caption)
          .foregroundStyle(.red)
      } else if model.keys.isEmpty {
        Text("No age keys found").foregroundStyle(.secondary)
      } else {
        ForEach(model.keys) { key in
          AgeKeyRow(key: key)
            .tag(key.recipient)
            .contextMenu {
              Button("Delete", role: .destructive) {
                Task { await model.deleteKey(name: key.name) }
              }
            }
        }
      }
    }
    .paneBackground()
    .navigationTitle("Age")
    .navigationSplitViewColumnWidth(min: 200, ideal: 260)
    .toolbar {
      ToolbarItem {
        Button {
          showingGenerateSheet = true
        } label: {
          Label("New Key", systemImage: "plus")
        }
      }
      ToolbarItem {
        Button {
          Task { await model.reload() }
        } label: {
          Label("Reload", systemImage: "arrow.clockwise")
        }
      }
      ToolbarItem {
        Button {
          showingHelp = true
        } label: {
          Label("How to use", systemImage: "questionmark.circle")
        }
      }
    }
    .sheet(isPresented: $showingGenerateSheet) {
      AgeGenerateSheet { name in
        await model.generateKey(name: name)
      }
    }
    .sheet(isPresented: $showingHelp) {
      AgeHelpSheet(keyName: model.selectedKey?.name)
    }
    .task { await model.reload() }
  }
}

extension AgeKeyEntry: Identifiable {
  public var id: String { recipient }
}

/// Explains what age keys are for and how to encrypt and decrypt with the
/// `ap age` CLI. Key management lives in this pane; file operations do not.
private struct AgeHelpSheet: View {
  /// The selected key's name, substituted into the example commands. Falls back
  /// to a `<name>` placeholder when no key is selected.
  var keyName: String?

  @Environment(\.dismiss) private var dismiss

  private var name: String { keyName ?? "<name>" }

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      HStack {
        Text("Using Age Keys").font(.headline)
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
      .padding(.bottom, 12)

      ScrollView {
        VStack(alignment: .leading, spacing: 14) {
          Text(
            "age encrypts a file to one or more recipients. Anyone can encrypt with a recipient's public key; only the matching secret key decrypts. Secret keys are held in your keychain and never leave this machine."
          )
          .fixedSize(horizontal: false, vertical: true)

          step(
            "Create a key", "Use New Key here, or run the command below in a terminal.",
            command: "ap age keygen <name>")
          step(
            "Share your recipient",
            "Select a key and choose Copy Recipient. Others encrypt to that age1… string.")
          step(
            "Encrypt a file",
            "Pass -r more than once for multiple recipients, or -r age1… for someone else's key.",
            command: "ap age encrypt -r \(name) secrets.txt > secrets.txt.age")
          step(
            "Decrypt a file", "Touch ID unlocks the secret key.",
            command: "ap age decrypt -r \(name) secrets.txt.age > secrets.txt")

          Text("Every keygen, delete, encrypt and decrypt is written to the audit log.")
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
      }
    }
    .padding(20)
    .frame(width: 420, height: 420)
  }

  private func step(_ title: String, _ body: String, command: String? = nil) -> some View {
    VStack(alignment: .leading, spacing: 5) {
      Text(title).fontWeight(.semibold)
      Text(body)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
      if let command {
        Text(command)
          .font(.system(.body, design: .monospaced))
          .textSelection(.enabled)
          .fixedSize(horizontal: false, vertical: true)
          .padding(.vertical, 6)
          .padding(.horizontal, 8)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      }
    }
  }
}

private struct AgeKeyRow: View {
  let key: AgeKeyEntry

  var body: some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(key.name).fontWeight(.semibold).lineLimit(1)
      Text(key.recipient)
        .font(.system(.caption, design: .monospaced))
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .truncationMode(.middle)
    }
    .padding(.vertical, 3)
  }
}
