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
  /// First event ids of merged runs that are expanded.
  @State private var expanded: Set<String> = []

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
      Task { await model.reload(clearing: false) }
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
          ForEach(Array(collapsed(group.events).enumerated()), id: \.element[0].id) {
            index, events in
            if index > 0 {
              Divider()
            }
            row(events)
            if events.count > 1, expanded.contains(events[0].id) {
              VStack(alignment: .leading, spacing: 0) {
                let showsHosts = Set(events.compactMap(\.host)).count > 1
                ForEach(Self.minutes(events), id: \.[0].id) { minute in
                  childRow(minute, showsHosts: showsHosts)
                }
              }
              .padding(.top, -4)
              .padding(.bottom, 6)
            }
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
  private func row(_ events: [ActivityEvent]) -> some View {
    let event = events[0]
    let opener = SubjectOpener(
      vaults: vaults, issues: issues, sshModel: sshModel, gpgModel: gpgModel)
    let content = HStack(spacing: 12) {
      Text(Self.time(event))
        .foregroundStyle(.secondary)
        .monospacedDigit()
        .frame(width: Self.timeWidth, alignment: .leading)
      TodayIcon(
        symbol: UsedTodayStyle.symbol(event.displayKind),
        color: UsedTodayStyle.color(event.displayKind))
      HStack(spacing: 6) {
        Text(opener.title(event.ref, label: event.label))
          .lineLimit(1)
          .truncationMode(.middle)
          .layoutPriority(1)
        if let tag = opener.keyTag(event.ref) {
          KeyIdTag(text: tag)
        }
        Text(ActivityStyle.predicate(events))
          .lineLimit(1)
          .truncationMode(.tail)
      }
      if events.count > 1 {
        Text("\(events.count)")
          .font(.caption)
          .monospacedDigit()
          .foregroundStyle(.secondary)
          .padding(.horizontal, 6)
          .padding(.vertical, 1)
          .background(.quaternary, in: Capsule())
          .fixedSize()
      }
      Spacer(minLength: 12)
      if let status = ActivityStyle.status(event) {
        Text(status.text)
          .foregroundStyle(status.color)
      }
      // Chevron width is reserved on every row so statuses line up.
      Image(systemName: expanded.contains(event.id) ? "chevron.down" : "chevron.right")
        .font(.caption)
        .foregroundStyle(.secondary)
        .frame(width: 12)
        .opacity(events.count > 1 ? 1 : 0)
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
    .contentShape(.rect)

    if events.count > 1 {
      Button {
        if !expanded.insert(event.id).inserted { expanded.remove(event.id) }
      } label: {
        content
      }
      .buttonStyle(.plain)
      .help(expanded.contains(event.id) ? "Hide details" : "Show details")
    } else {
      opening(event, content)
    }
  }

  /// Compact row of the events of one minute in an expanded run. Time is
  /// aligned with the parent sentence. Status is aligned with the parent
  /// status. Hosts are listed if `showsHosts` is true.
  private func childRow(_ events: [ActivityEvent], showsHosts: Bool) -> some View {
    let event = events[0]
    var hosts: [String] = []
    for host in events.compactMap(\.host) where !hosts.contains(host) { hosts.append(host) }
    let content = HStack(spacing: 12) {
      Text(Self.time(event))
        .monospacedDigit()
        .frame(width: Self.timeWidth, alignment: .leading)
      let noun = event.record.outcome == .succeeded ? "signature" : "request"
      Text(events.count == 1 ? "1 \(noun)" : "\(events.count) \(noun)s")
        .monospacedDigit()
      if showsHosts, !hosts.isEmpty {
        Text("to \(hosts.joined(separator: ", "))")
          .lineLimit(1)
          .truncationMode(.tail)
      }
      Spacer(minLength: 12)
      if let status = ActivityStyle.status(event) {
        Text(status.text)
          .foregroundStyle(status.color)
      }
      // Chevron width of the parent row, so statuses line up.
      Color.clear.frame(width: 12, height: 1)
    }
    .font(.callout)
    .foregroundStyle(.secondary)
    .padding(.leading, 14 + Self.timeWidth + 12 + 28 + 12)
    .padding(.trailing, 14)
    .padding(.vertical, 3)
    .contentShape(.rect)
    return opening(event, content)
  }

  /// Content wrapped in a button that opens the event subject, if it can be
  /// found.
  @ViewBuilder
  private func opening(_ event: ActivityEvent, _ content: some View) -> some View {
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

  /// Events of a run split into runs with the same displayed minute.
  private static func minutes(_ events: [ActivityEvent]) -> [[ActivityEvent]] {
    var groups: [[ActivityEvent]] = []
    for event in events {
      if let last = groups.last?.first, time(last) == time(event) {
        groups[groups.count - 1].append(event)
      } else {
        groups.append([event])
      }
    }
    return groups
  }

  private static let timeWidth: CGFloat = 64

  private static func time(_ event: ActivityEvent) -> String {
    event.date?.formatted(date: .omitted, time: .shortened) ?? ""
  }

  // MARK: - Days

  /// Events with runs of matching SSH signatures merged. A run has the same
  /// key, program, and outcome with no other event between. Each run is
  /// listed newest first.
  private func collapsed(_ events: [ActivityEvent]) -> [[ActivityEvent]] {
    var runs: [[ActivityEvent]] = []
    for event in events {
      if let last = runs.last?.first, event.action == "ssh.sign",
        last.action == event.action, last.label == event.label, last.caller == event.caller,
        last.record.outcome == event.record.outcome
      {
        runs[runs.count - 1].append(event)
      } else {
        runs.append([event])
      }
    }
    return runs
  }

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
  /// Outcome label and color. Nil for a successful use, since the sentence
  /// already states it.
  static func status(_ event: ActivityEvent) -> (text: String, color: Color)? {
    switch event.record.outcome {
    case .denied: return ("Denied", .red)
    case .cancelled: return ("Cancelled", .secondary)
    case .failed: return ("Failed", .orange)
    case .succeeded: return nil
    }
  }

  /// Row text after the subject title, such as "signed for git to
  /// github.com". Programs and hosts are in the primary color. Programs are
  /// monospaced. Uses that did not succeed read as requests.
  static func predicate(_ events: [ActivityEvent]) -> AttributedString {
    let event = events[0]
    let phrase = phrase(event)
    var text = secondary(phrase.verb)
    let caller = event.caller.flatMap {
      UsedTodayStyle.showsCaller($0, kind: event.kind) ? $0 : nil
    }
    let program = phrase.isBrowser ? event.browser ?? caller : caller
    if let program {
      text += secondary(" \(phrase.preposition) ")
      var name = AttributedString(program)
      if !phrase.isBrowser || event.browser == nil { name.font = .body.monospaced() }
      text += name
    }
    if event.displayKind == .sshKey {
      var hosts: [String] = []
      for host in events.compactMap(\.host) where !hosts.contains(host) { hosts.append(host) }
      if hosts.count == 1 {
        text += secondary(" to ")
        text += AttributedString(hosts[0])
      } else if hosts.count > 1 {
        text += secondary(" to \(hosts.count) hosts")
      }
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
    case "ssh.key_add": return ("added to agent", "by", false)
    case "ssh.passphrase", "gpg.passphrase": return ("unlocked", "by", false)
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
