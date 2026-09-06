import AxoPassFFI
import SwiftUI

/// The Audit Log window: an append-only view of every use of a key or secret,
/// opened from Help ▸ Audit Log.
struct AuditLogWindow: View {
  @State private var model = AuditLogModel()
  @State private var selection: AuditLogRow.ID? = nil
  @State private var showInspector = false
  @Environment(VaultsModel.self) private var vaults
  @Environment(\.dismiss) private var dismiss

  private var selectedRow: AuditLogRow? {
    model.events.first { $0.id == selection }
  }

  var body: some View {
    NavigationStack {
      table
        .navigationTitle("Audit Log")
        .searchable(text: $model.query, prompt: "Search caller, subject, or message")
        .toolbar { toolbarContent }
        .inspector(isPresented: $showInspector) {
          AuditEventInspector(row: selectedRow)
            .inspectorColumnWidth(min: 280, ideal: 340, max: 460)
        }
    }
    .task { await model.reload() }
    .onChange(of: selection) { _, newValue in
      if newValue != nil { showInspector = true }
    }
    // The log is only available unlocked, so locking takes the window down.
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

  private var table: some View {
    Table(model.events, selection: $selection) {
      TableColumn("Time") { Text($0.timeText).monospacedDigit() }
        .width(min: 130, ideal: 160)
      TableColumn("Action") { Text($0.action).font(.system(.body, design: .monospaced)) }
        .width(min: 120, ideal: 150)
      TableColumn("Subject", value: \.subjectText)
      TableColumn("Caller", value: \.callerText)
      TableColumn("Outcome") { row in
        Text(row.outcomeText)
          .foregroundStyle(color(for: row.record.outcome))
      }
      .width(min: 100, ideal: 120)
    }
    .contextMenu(forSelectionType: AuditLogRow.ID.self) { _ in
      Button("Reveal Log in Finder") { model.revealInFinder() }
    }
    .onAppear { paginateIfNeeded() }
    .onChange(of: selection) { _, _ in paginateIfNeeded() }
  }

  @ToolbarContentBuilder
  private var toolbarContent: some ToolbarContent {
    ToolbarItemGroup(placement: .primaryAction) {
      Picker("Source", selection: $model.source) {
        Text("All sources").tag(AuditSourceKind?.none)
        Text("SSH agent").tag(AuditSourceKind?.some(.agent))
        Text("pinentry").tag(AuditSourceKind?.some(.pinentry))
        Text("App").tag(AuditSourceKind?.some(.app))
        Text("CLI").tag(AuditSourceKind?.some(.cli))
        Text("askpass").tag(AuditSourceKind?.some(.askpass))
      }

      Picker("Events", selection: $model.actionGroup) {
        ForEach(AuditActionGroup.allCases) { Text($0.label).tag($0) }
      }

      Button {
        Task { await model.reload() }
      } label: {
        Label("Refresh", systemImage: "arrow.clockwise")
      }
      .disabled(model.isLoading)

      Button {
        model.revealInFinder()
      } label: {
        Label("Reveal in Finder", systemImage: "folder")
      }

      Button {
        showInspector.toggle()
      } label: {
        Label("Details", systemImage: "sidebar.right")
      }
    }
  }

  /// Load the next page once the user reaches the tail of what is loaded.
  private func paginateIfNeeded() {
    guard let selection, model.hasMore, !model.isLoading else { return }
    if let index = model.events.firstIndex(where: { $0.id == selection }),
      index >= model.events.count - 20
    {
      Task { await model.loadMore() }
    }
  }

  private func color(for outcome: AuditOutcomeKind) -> Color {
    switch outcome {
    case .succeeded: return .green
    case .cancelled: return .secondary
    case .denied, .failed: return .orange
    }
  }
}

/// A left-aligned label/value row with a fixed-width label column. Values wrap
/// onto multiple lines and stay flush left, unlike the default centered
/// `LabeledContent` layout in a narrow inspector.
private struct AuditFieldStyle: LabeledContentStyle {
  func makeBody(configuration: Configuration) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 8) {
      configuration.label
        .foregroundStyle(.secondary)
        .frame(width: 92, alignment: .leading)
      configuration.content
        .frame(maxWidth: .infinity, alignment: .leading)
        .multilineTextAlignment(.leading)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

/// The detail pane: full provenance chain and the action-specific detail map
/// for the selected row.
private struct AuditEventInspector: View {
  let row: AuditLogRow?

  var body: some View {
    if let row {
      ScrollView {
        VStack(alignment: .leading, spacing: 16) {
          InsetGroupedSection {
            LabeledContent("Time", value: row.timeText)
            LabeledContent("Source", value: row.sourceText)
            LabeledContent("Action", value: row.action)
            LabeledContent("Outcome", value: row.outcomeText)
            if let message = row.record.message, !message.isEmpty {
              LabeledContent("Message", value: message)
            }
          }

          if row.record.subjectId != nil || row.record.subjectLabel != nil {
            InsetGroupedSection {
              if let kind = row.subjectKindText { LabeledContent("Kind", value: kind) }
              if let id = row.record.subjectId { LabeledContent("Subject", value: id) }
              if let label = row.record.subjectLabel {
                LabeledContent("Label", value: label)
              }
              if let fp = row.record.subjectFingerprint {
                LabeledContent("Fingerprint", value: fp)
              }
            }
          }

          InsetGroupedSection {
            LabeledContent("Caller", value: row.callerText)
            LabeledContent("Chain", value: row.chainText)
            if let pid = row.record.actorPid {
              LabeledContent("PID", value: String(pid))
            }
            if let exe = row.record.actorExecutable {
              LabeledContent("Executable", value: exe)
            }
            if let bundle = row.record.actorBundleId {
              LabeledContent("Bundle ID", value: bundle)
            }
            if let team = row.record.actorTeamId {
              LabeledContent("Team ID", value: team)
            }
          }

          if !row.detailPairs.isEmpty {
            InsetGroupedSection {
              ForEach(row.detailPairs, id: \.0) { key, value in
                LabeledContent(key, value: value)
              }
            }
          }
        }
        .labeledContentStyle(AuditFieldStyle())
        .textSelection(.enabled)
        .padding()
      }
    } else {
      ContentUnavailableView("No Event Selected", systemImage: "list.bullet.rectangle")
    }
  }
}
