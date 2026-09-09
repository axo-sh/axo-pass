import AppKit
import AxoPassFFI
import SwiftUI

struct AgeKeyDetailView: View {
  @Bindable var model: AgeModel

  var body: some View {
    Group {
      if let key = model.selectedKey {
        AgeKeyDetail(model: model, key: key)
      } else {
        ContentUnavailableView("Select a key", systemImage: "lock.rectangle.stack")
      }
    }
    .paneBackground()
  }
}

private struct AgeKeyDetail: View {
  @Bindable var model: AgeModel
  let key: AgeKeyEntry

  @State private var recentEvents: [AuditLogRow] = []
  @State private var copiedRecipient = false
  @State private var showingDeleteConfirmation = false

  private static let recentEventCount: UInt32 = 5

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 0) {
        header
        badges.padding(.top, 10).padding(.bottom, 16)

        sectionTitle("Recipient")
        InsetGroupedSection {
          CharWrappingText(text: key.recipient, dimsOuterFields: true)
            .frame(maxWidth: .infinity, alignment: .leading)
        }

        sectionTitle("Details")
        InsetGroupedSection {
          VStack(spacing: 8) {
            InspectorRow("Name", value: key.name)
            Divider()
            PassphraseField(
              label: "Secret Key",
              charWraps: true,
              hasSaved: true,
              reveal: { await model.revealSecret(name: key.name) },
              save: {},
              remove: { showingDeleteConfirmation = true }
            )
          }
        }

        if !recentEvents.isEmpty {
          sectionTitle("Recent Activity")
          InsetGroupedSection { activityTable }
        }
      }
      .padding()
    }
    .labeledContentStyle(.inspectorField)
    .navigationTitle(key.name)
    .task(id: key.recipient) {
      recentEvents = await model.recentEvents(name: key.name, limit: Self.recentEventCount)
    }
    .onChange(of: key.recipient) { copiedRecipient = false }
    .confirmationDialog(
      "Delete \(key.name)?", isPresented: $showingDeleteConfirmation, titleVisibility: .visible
    ) {
      Button("Delete", role: .destructive) {
        Task { await model.deleteKey(name: key.name) }
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text("The secret identity is removed from the keychain and cannot be recovered.")
    }
  }

  // MARK: - Header

  private var header: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "lock.rectangle.stack.fill")
        .font(.system(size: 26))
        .foregroundStyle(.tint)
        .frame(width: 34)
      VStack(alignment: .leading, spacing: 2) {
        Text(key.name).font(.title2).fontWeight(.semibold)
      }
      Spacer(minLength: 12)
      Button(copiedRecipient ? "Copied" : "Copy Recipient") { copyRecipient() }
    }
  }

  private var badges: some View {
    HStack(spacing: 8) {
      KeyBadge(text: "X25519", size: .regular)
    }
  }

  private var activityTable: some View {
    Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
      GridRow {
        columnHeader("Action")
        columnHeader("Caller")
        columnHeader("Outcome")
        columnHeader("When").gridColumnAlignment(.trailing)
      }
      Divider().gridCellColumns(4)
      ForEach(recentEvents) { event in
        GridRow {
          Text(actionLabel(event.action))
          Text(event.callerText)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.middle)
          Text(event.outcomeText)
            .foregroundStyle(event.record.outcome == .succeeded ? Color.secondary : .orange)
          Text(event.timeText)
            .foregroundStyle(.secondary)
        }
        .font(.callout)
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  // MARK: - Rows

  private func sectionTitle(_ text: String) -> some View {
    Text(text.uppercased())
      .font(.caption)
      .fontWeight(.semibold)
      .foregroundStyle(.secondary)
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(.bottom, 4)
  }

  private func columnHeader(_ text: String) -> some View {
    Text(text.uppercased())
      .font(.caption2)
      .fontWeight(.semibold)
      .foregroundStyle(.secondary)
  }

  private func actionLabel(_ action: String) -> String {
    switch action {
    case "age.key_create": return "Key created"
    case "age.key_delete": return "Key deleted"
    case "age.encrypt": return "Encrypted"
    case "age.decrypt": return "Decrypted"
    default: return action
    }
  }

  // MARK: - Actions

  private func copyRecipient() {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(key.recipient, forType: .string)
    copiedRecipient = true
  }
}
