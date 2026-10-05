import AuthenticationServices
import SwiftUI

/// What the extension shows inside the AutoFill popover.
struct CredentialListView: View {
  @Bindable var model: CredentialListModel
  @State private var filter = ""

  var body: some View {
    VStack(spacing: 0) {
      header
      Divider()
      content
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    .frame(minWidth: 340, minHeight: 380)
  }

  private var header: some View {
    HStack(spacing: 8) {
      Image(systemName: "lock.shield")
        .foregroundStyle(.tint)
      VStack(alignment: .leading, spacing: 1) {
        Text("Axo Pass")
          .font(.headline)
        if let host = model.host {
          Text(host)
            .font(.caption)
            .foregroundStyle(.secondary)
        }
      }
      Spacer()
      Button("Cancel") { model.onCancel?() }
        .keyboardShortcut(.cancelAction)
    }
    .padding(12)
  }

  @ViewBuilder
  private var content: some View {
    switch model.state {
    case .loading:
      message(
        icon: "touchid", title: "Waiting for Axo Pass",
        detail: "Confirm the request in the Axo Pass window to unlock your vaults.",
        showsProgress: true)

    case .filling(let account):
      message(
        icon: "touchid", title: "Filling \(account)",
        detail: "Confirm the request in the Axo Pass window.", showsProgress: true)

    case .list(let items):
      list(items)

    case .appUnavailable:
      message(
        icon: "bolt.horizontal.circle", title: "Axo Pass is not running",
        detail: "Open Axo Pass, then try again.",
        action: ("Open Axo Pass", { model.onOpenApp?() }))

    case .failed(let detail):
      message(
        icon: "exclamationmark.triangle", title: "Could not reach your vaults",
        detail: detail, action: ("Try Again", { model.retry() }))

    case .configuration(let onDone):
      configuration(onDone: onDone)
    }
  }

  private func list(_ logins: LoginList) -> some View {
    let matches = filtered(logins.matches)
    let others = filtered(logins.others)
    let site = model.host ?? "this site"
    let noun = model.purpose == .oneTimeCode ? "one-time codes" : "logins"
    return VStack(spacing: 0) {
      if logins.matches.isEmpty && logins.others.isEmpty {
        message(
          icon: "key.slash", title: "No matching \(noun)",
          detail: model.host.map { "Nothing in your vaults matches \($0)." }
            ?? "AutoFill did not say which site this is for.")
      } else {
        List {
          Section {
            if logins.matches.isEmpty {
              Text("No \(noun) saved for \(site).")
                .font(.callout)
                .foregroundStyle(.white)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity, minHeight: 56)
                .padding(8)
                .background(.white.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                .overlay(
                  RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(.white.opacity(0.3), lineWidth: 1)
                )
                .listRowSeparator(.hidden)
            }
            ForEach(matches) { item in loginButton(item) }
          } header: {
            Text("Matches for \(site)")
          }
          if !logins.others.isEmpty {
            Section {
              ForEach(others) { item in loginButton(item) }
            } header: {
              Text("All logins")
            }
          }
        }
        .listStyle(.inset)
        .searchable(text: $filter, prompt: "Filter")
      }
    }
  }

  private func loginButton(_ item: Login) -> some View {
    Button {
      model.onSelect?(item)
    } label: {
      row(item)
    }
    .buttonStyle(.plain)
  }

  private func row(_ item: Login) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(item.title)
        .fontWeight(.medium)
      Text(item.accountName)
        .font(.caption)
        .foregroundStyle(.secondary)
      Text(item.reason)
        .font(.caption2)
        .foregroundStyle(.tertiary)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(.vertical, 3)
    .contentShape(Rectangle())
  }

  private func filtered(_ items: [Login]) -> [Login] {
    let needle = filter.trimmingCharacters(in: .whitespaces).lowercased()
    guard !needle.isEmpty else { return items }
    return items.filter {
      $0.title.lowercased().contains(needle)
        || $0.accountName.lowercased().contains(needle)
        || ($0.matched?.host.lowercased().contains(needle) ?? false)
    }
  }

  private func configuration(onDone: @escaping () -> Void) -> some View {
    VStack(spacing: 12) {
      Image(systemName: "checkmark.circle")
        .font(.system(size: 36))
        .foregroundStyle(.tint)
      Text("Axo Pass is ready to fill passwords")
        .font(.headline)
      Text("Your vaults stay locked. Axo Pass asks you to confirm each fill.")
        .font(.subheadline)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
      Button("Done", action: onDone)
        .keyboardShortcut(.defaultAction)
    }
    .padding(24)
  }

  private func message(
    icon: String, title: String, detail: String, showsProgress: Bool = false,
    action: (String, () -> Void)? = nil
  ) -> some View {
    VStack(spacing: 10) {
      if showsProgress {
        ProgressView()
          .controlSize(.small)
      } else {
        Image(systemName: icon)
          .font(.system(size: 30))
          .foregroundStyle(.secondary)
      }
      Text(title)
        .font(.headline)
      Text(detail)
        .font(.subheadline)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
      if let action {
        Button(action.0, action: action.1)
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(24)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}
