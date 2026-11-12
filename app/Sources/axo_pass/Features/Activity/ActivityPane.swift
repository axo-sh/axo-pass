import AppKit
import AxoPassFFI
import SwiftUI

/// Activity page. Lists uses of keys, credentials, and logins from the audit
/// log, grouped by day, newest first. Filter chips limit the list to browser
/// fills, the CLI, SSH, or GPG. A row opens its key or item if the audit event
/// recorded enough to find it.
struct ActivityPane: View {
  let sshModel: SshModel
  let gpgModel: GpgModel

  @Environment(VaultsModel.self) private var vaults
  @Environment(IssuesModel.self) private var issues
  @Environment(\.openWindow) private var openWindow
  @State private var model = ActivityModel()

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 0) {
        header
        filterChips
        content
      }
      .padding(.horizontal, 32)
      .padding(.bottom, 32)
    }
    .paneBackground()
    .navigationTitle("Activity")
    .task { await model.reload() }
    // Uses happen while the app is in the background, so read them again on
    // each activation.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      Task { await model.reload() }
    }
  }

  /// Page title with a button that opens the Audit Log window.
  private var header: some View {
    HStack(alignment: .firstTextBaseline) {
      Text("Activity")
        .font(.largeTitle)
        .fontWeight(.bold)
      Spacer()
      Button("Audit Log") { openWindow(id: AxoPassApp.auditWindowID) }
        .help("Show every audit event, including changes")
    }
    .padding(.top, 4)
  }

  private var filterChips: some View {
    HStack(spacing: 8) {
      ForEach(ActivityFilter.allCases, id: \.self) { filter in
        ActivityChip(title: filter.label, isSelected: model.filter == filter) {
          model.filter = filter
        }
      }
    }
    .padding(.top, 16)
  }

  @ViewBuilder
  private var content: some View {
    if let error = model.loadError {
      TodaySectionHeader("Activity")
      TodayCard { TodayNoteRow(error, color: .red) }
    } else if model.events.isEmpty {
      if !model.isLoading {
        TodaySectionHeader("Activity")
        TodayCard { TodayNoteRow("No activity recorded.") }
      }
    } else {
      ForEach(days, id: \.day) { group in
        TodaySectionHeader(dayTitle(group.day))
        TodayCard {
          ForEach(Array(group.events.enumerated()), id: \.element.id) { index, event in
            if index > 0 {
              Divider()
            }
            row(event)
          }
        }
      }
      if model.hasMore {
        Button("Show More") { Task { await model.loadMore() } }
          .disabled(model.isLoading)
          .frame(maxWidth: .infinity)
          .padding(.top, 16)
      }
    }
  }

  // MARK: - Rows

  @ViewBuilder
  private func row(_ event: ActivityEvent) -> some View {
    let status = ActivityStyle.status(event)
    let content = HStack(spacing: 12) {
      Text(event.date?.formatted(date: .omitted, time: .shortened) ?? "")
        .foregroundStyle(.secondary)
        .monospacedDigit()
        .frame(width: 64, alignment: .leading)
      TodayIcon(
        symbol: UsedTodayStyle.symbol(event.displayKind),
        color: UsedTodayStyle.color(event.displayKind))
      Text(ActivityStyle.sentence(event))
        .lineLimit(1)
        .truncationMode(.tail)
      Spacer(minLength: 12)
      Text(status.text)
        .foregroundStyle(status.color)
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
    .contentShape(.rect)

    let opener = SubjectOpener(
      vaults: vaults, issues: issues, sshModel: sshModel, gpgModel: gpgModel)
    if opener.canOpen(event.ref) {
      Button {
        opener.open(event.ref)
      } label: {
        content
      }
      .buttonStyle(.plain)
      .help(opener.help(event.ref))
    } else {
      content
    }
  }

  // MARK: - Days

  /// Events grouped by the start of their day, newest day first. Events come
  /// newest first.
  private var days: [(day: Date, events: [ActivityEvent])] {
    var groups: [(day: Date, events: [ActivityEvent])] = []
    for event in model.events {
      let day = Calendar.current.startOfDay(for: event.date ?? .distantPast)
      if let last = groups.indices.last, groups[last].day == day {
        groups[last].events.append(event)
      } else {
        groups.append((day, [event]))
      }
    }
    return groups
  }

  private func dayTitle(_ day: Date) -> String {
    let calendar = Calendar.current
    if calendar.isDateInToday(day) { return "Today" }
    if calendar.isDateInYesterday(day) { return "Yesterday" }
    if calendar.isDate(day, equalTo: .now, toGranularity: .year) {
      return day.formatted(.dateTime.weekday(.wide).month(.wide).day())
    }
    return day.formatted(.dateTime.weekday(.wide).month(.wide).day().year())
  }
}

/// Capsule filter button. The selected chip is filled.
private struct ActivityChip: View {
  let title: String
  let isSelected: Bool
  let action: () -> Void

  var body: some View {
    Button(action: action) {
      Text(title)
        .padding(.horizontal, 12)
        .padding(.vertical, 5)
        .foregroundStyle(isSelected ? Color(nsColor: .windowBackgroundColor) : .secondary)
        .background(
          isSelected ? AnyShapeStyle(.primary) : AnyShapeStyle(.quaternary), in: Capsule()
        )
        .contentShape(Capsule())
    }
    .buttonStyle(.plain)
  }
}

/// Presentation of an activity row.
private enum ActivityStyle {
  /// Outcome label and color. A successful use shows its past-tense verb.
  static func status(_ event: ActivityEvent) -> (text: String, color: Color) {
    switch event.record.outcome {
    case .denied: return ("Denied", .red)
    case .cancelled: return ("Cancelled", .secondary)
    case .failed: return ("Failed", .orange)
    case .succeeded: return (verb(event.action), .green)
    }
  }

  private static func verb(_ action: String) -> String {
    switch action {
    case "ssh.sign": return "Signed"
    case "ssh.passphrase", "gpg.passphrase": return "Supplied"
    case "gpg.confirm": return "Confirmed"
    case "age.decrypt": return "Decrypted"
    case "age.encrypt": return "Encrypted"
    case "vault.exported": return "Exported"
    case "credential.read": return "Read"
    case "credential.exec": return "Passed"
    case "credential.inject": return "Injected"
    case "passkey.asserted": return "Signed in"
    case "login.fill", "login.totp": return "Filled"
    default: return "Allowed"
    }
  }

  /// Row text, such as "github.com key signed for git to github.com". Subject
  /// and programs are in the primary color. Programs are monospaced. Uses
  /// that did not succeed read as requests.
  static func sentence(_ event: ActivityEvent) -> AttributedString {
    let phrase = phrase(event)
    var text = AttributedString(event.label)
    text += secondary(" \(phrase.verb)")
    let program = phrase.isBrowser ? event.browser ?? event.caller : event.caller
    if let program {
      text += secondary(" \(phrase.preposition) ")
      var name = AttributedString(program)
      if !phrase.isBrowser || event.browser == nil { name.font = .body.monospaced() }
      text += name
    }
    if event.displayKind == .sshKey, let host = event.host {
      text += secondary(" to ")
      text += AttributedString(host)
    }
    return text
  }

  /// Verb after the subject and preposition before the program. `isBrowser`
  /// is true if the program is the browser that asked for the fill.
  private static func phrase(
    _ event: ActivityEvent
  ) -> (verb: String, preposition: String, isBrowser: Bool) {
    if event.record.outcome != .succeeded { return ("requested", "by", false) }
    switch event.action {
    case "login.fill": return ("filled", "in", true)
    case "login.totp": return ("one-time code filled", "in", true)
    case "passkey.asserted": return ("passkey sign-in", "in", true)
    case "ssh.sign": return ("signed", "for", false)
    case "ssh.passphrase", "gpg.passphrase": return ("passphrase", "for", false)
    case "gpg.confirm": return ("confirmed", "for", false)
    case "age.decrypt": return ("decrypted", "by", false)
    case "age.encrypt": return ("encrypted", "by", false)
    case "vault.exported": return ("exported", "by", false)
    case "credential.read": return ("read", "by", false)
    case "credential.exec": return ("passed", "to", false)
    case "credential.inject": return ("injected", "by", false)
    default: return ("used", "by", false)
    }
  }

  private static func secondary(_ string: String) -> AttributedString {
    var text = AttributedString(string)
    text.foregroundColor = .secondary
    return text
  }
}
