import AxoPassFFI
import SwiftUI

/// Explains the Audit Log filters and lists every action the log records.
struct AuditHelpSheet: View {
  /// Every audit action, grouped by category in display order.
  let actions: [AuditActionInfo]

  @Environment(\.dismiss) private var dismiss

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      HStack {
        Text("About the Audit Log").font(.headline)
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
      .padding(.bottom, 12)

      ScrollView {
        VStack(alignment: .leading, spacing: 20) {
          Text(
            "The audit log records every use of a key or secret and every change to keys and vaults. It names what was used and who asked. Secret values are never recorded."
          )
          .fixedSize(horizontal: false, vertical: true)

          filters
          requesters
          actionTable
        }
        .padding(.bottom, 4)
      }
    }
    .padding(20)
    .frame(width: 720, height: 640)
  }

  // MARK: - Filters

  private static let filterTerms = [
    Term(
      "All, Access, Changes",
      "Access shows uses of a key or secret, such as signing, decrypting, or reading a credential. Changes shows edits to keys, vaults, items, and credentials. All also shows locking and unlocking, SSH agent start and stop, SSH session binds, pinentry messages, approvals, and rejected requests."
    ),
    Term(
      "Category",
      "Shows one kind of subject. Each category matches the first part of the action name, such as ssh or credential. Grants are the auth actions."
    ),
    Term("Requester", "Shows events asked for by one kind of process. See Requesters below."),
    Term("Search", "Matches the caller, the subject, the subject label, and the message."),
  ]

  private var filters: some View {
    section("Filters") {
      GroupedTable(Self.filterTerms, id: \.title) { TermRow(term: $0) }
    }
  }

  private var requesters: some View {
    section("Requesters") {
      Text(
        "Requester is who asked for an event. Recorded by is the process that wrote it. A request from the CLI, a browser, or AutoFill is served by the app, so the app records it."
      )
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
      GroupedTable(AuditRequesterKind.allCases, id: \.self) { requester in
        TermRow(term: Term(requester.label, requester.helpText))
      }
    }
  }

  // MARK: - Actions

  private var actionTable: some View {
    section("Actions") {
      ForEach(AuditCategory.allCases, id: \.self) { category in
        let rows = actions.filter { $0.category == category }
        if !rows.isEmpty {
          VStack(alignment: .leading, spacing: 6) {
            Text(category.label)
              .font(.subheadline)
              .fontWeight(.semibold)
              .foregroundStyle(.secondary)
              .padding(.leading, tableInset)
            GroupedTable(rows, id: \.action) { ActionRow(row: $0) }
          }
          .padding(.bottom, 8)
        }
      }
    }
  }

  // MARK: - Layout

  private func section(
    _ title: String, @ViewBuilder content: () -> some View
  ) -> some View {
    VStack(alignment: .leading, spacing: 10) {
      Text(title).font(.title3).fontWeight(.semibold)
      content()
    }
  }
}

/// Horizontal inset of table rows, dividers, and table captions.
private let tableInset: CGFloat = 10

/// Rows in a rounded, bordered box, separated by dividers.
private struct GroupedTable<Data: RandomAccessCollection, ID: Hashable, RowContent: View>: View {
  let data: Data
  let id: KeyPath<Data.Element, ID>
  let row: (Data.Element) -> RowContent

  init(
    _ data: Data, id: KeyPath<Data.Element, ID>,
    @ViewBuilder row: @escaping (Data.Element) -> RowContent
  ) {
    self.data = data
    self.id = id
    self.row = row
  }

  var body: some View {
    VStack(spacing: 0) {
      let firstID = data.first?[keyPath: id]
      ForEach(data, id: id) { element in
        if element[keyPath: id] != firstID {
          Divider().padding(.leading, tableInset)
        }
        row(element)
          .padding(.vertical, 7)
          .padding(.horizontal, tableInset)
      }
    }
    .background(.quinary, in: RoundedRectangle(cornerRadius: 8))
    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.separator))
  }
}

/// A named explanation, such as a filter or a requester.
private struct Term {
  let title: String
  let body: String

  init(_ title: String, _ body: String) {
    self.title = title
    self.body = body
  }
}

/// One row of a term table: the name, then its explanation.
private struct TermRow: View {
  static let titleWidth: CGFloat = 150

  let term: Term

  var body: some View {
    HStack(alignment: .firstTextBaseline, spacing: 12) {
      Text(term.title)
        .font(.callout)
        .fontWeight(.semibold)
        .frame(width: Self.titleWidth, alignment: .leading)
      Text(term.body)
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
  }
}

/// One row of the action table. Column widths are fixed so the columns line
/// up across categories.
private struct ActionRow: View {
  static let actionWidth: CGFloat = 230
  static let kindWidth: CGFloat = 64

  let row: AuditActionInfo

  var body: some View {
    HStack(alignment: .firstTextBaseline, spacing: 12) {
      Text(row.action)
        .font(.system(.callout, design: .monospaced))
        .textSelection(.enabled)
        .frame(width: Self.actionWidth, alignment: .leading)
      KindBadge(kind: row.kind)
        .frame(width: Self.kindWidth, alignment: .leading)
      Text(row.description)
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
  }
}

/// Action kind as a tinted capsule.
private struct KindBadge: View {
  let kind: AuditActionKind

  var body: some View {
    Text(kind.label)
      .font(.caption)
      .fontWeight(.medium)
      .foregroundStyle(color)
      .padding(.horizontal, 6)
      .padding(.vertical, 1)
      .background(color.opacity(0.15), in: Capsule())
  }

  private var color: Color {
    switch kind {
    case .access: return .blue
    case .change: return .orange
    case .other: return .secondary
    }
  }
}

extension AuditActionKind {
  var label: String {
    switch self {
    case .access: return "Access"
    case .change: return "Change"
    case .other: return "Other"
    }
  }
}

extension AuditRequesterKind {
  /// Requester explanation for the help sheet.
  fileprivate var helpText: String {
    switch self {
    case .app: return "You, in the Axo Pass app."
    case .cli: return "An ap command, such as ap read, ap exec, or ap ssh-agent start."
    case .browser: return "The Axo Pass browser extension."
    case .autofill: return "AutoFill, for passwords and passkeys in apps and Safari."
    case .sshClient:
      return "A process using an SSH key through the SSH agent or askpass, such as ssh or git."
    case .gpgClient:
      return "A process using a GPG key through gpg-agent and pinentry, such as gpg or git."
    case .other: return "Any other process, such as one the app refused to serve."
    }
  }
}
