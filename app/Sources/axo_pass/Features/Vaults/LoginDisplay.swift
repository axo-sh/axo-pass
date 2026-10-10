import AxoPassFFI
import SwiftUI

extension ItemInfo {
  /// The credential filled as the password, when the item has one.
  var passwordCredential: CredentialInfo? { credentials.first { $0.role == "password" } }

  /// The credential filled as the account name, when the item has one.
  var usernameCredential: CredentialInfo? { credentials.first { $0.role == "username" } }

  /// The credential the one-time code is generated from, when the item has one.
  var totpCredential: CredentialInfo? { credentials.first { $0.role == "totp" } }

  /// Whether the item is shown as a login, with the login card and websites.
  /// An item with a passkey or a website but no password role is still a login.
  var isLogin: Bool {
    passwordCredential != nil || category == "login" || !websites.isEmpty
      || !passkeyCredentials.isEmpty
  }

  /// The hosts the item belongs to: its website hosts, then the relying
  /// parties of its passkeys, without duplicates.
  var siteHosts: [String] {
    var hosts = websiteHosts
    for rp in passkeyCredentials.compactMap(\.passkey?.rpId) where !hosts.contains(rp) {
      hosts.append(rp)
    }
    return hosts
  }

  /// The relying parties of the item's passkeys, without duplicates.
  var passkeySites: [String] {
    var sites: [String] = []
    for rp in passkeyCredentials.compactMap(\.passkey?.rpId) where !sites.contains(rp) {
      sites.append(rp)
    }
    return sites
  }

  /// Passkey relying parties that none of the item's websites covers, so
  /// AutoFill would not offer the login's password there.
  var uncoveredPasskeySites: [String] {
    passkeySites.filter { rp in !websiteHosts.contains(where: { hostsOverlap($0, rp) }) }
  }

  /// Where the item's passkeys are offered on `host`. A passkey is offered on
  /// its relying party and that party's subdomains, whatever the websites say.
  func passkeyCoverage(of host: String) -> PasskeyCoverage {
    let sites = passkeySites
    if sites.contains(where: { host == $0 || host.hasSuffix(".\($0)") }) { return .whole }
    if let narrower = sites.first(where: { $0.hasSuffix(".\(host)") }) {
      return .subdomain(narrower)
    }
    return .none
  }

  /// Other logins in `items` that look like the same site, by the last two
  /// labels of their hosts. This is a suggestion only; it does not apply the
  /// Public Suffix List.
  func mergeCandidates(in items: [ItemInfo]) -> [ItemInfo] {
    let sites = Set(siteHosts.map(siteKey(of:)))
    guard isLogin, !sites.isEmpty else { return [] }
    return items.filter { other in
      other.key != key && other.isLogin
        && !sites.isDisjoint(with: other.siteHosts.map(siteKey(of:)))
    }
  }

  /// The hosts of the item's websites, in stored order, without duplicates.
  var websiteHosts: [String] {
    var hosts: [String] = []
    for website in websites {
      if let host = displayHost(of: website.url), !hosts.contains(host) {
        hosts.append(host)
      }
    }
    return hosts
  }

  /// What the item list shows under the title: the account name and the first
  /// website, or a credential count for an item that is neither.
  var subtitle: String {
    let parts = [username, siteHosts.first].compactMap { $0 }.filter { !$0.isEmpty }
    if !parts.isEmpty { return parts.joined(separator: " · ") }
    return "\(credentials.count) credential\(credentials.count == 1 ? "" : "s")"
  }

  /// Whether `query` appears in the title, the username, or a website host.
  func matches(searchQuery query: String) -> Bool {
    let query = query.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !query.isEmpty else { return true }
    let fields = [title, key, username ?? ""] + websiteHosts
    return fields.contains { $0.localizedCaseInsensitiveContains(query) }
  }

  /// The item's passkeys.
  var passkeyCredentials: [CredentialInfo] { credentials.filter { $0.kind.kind == "passkey" } }

  /// The credentials below the login card: everything except the role
  /// credentials and the passkeys, which a login shows in the card.
  var listCredentials: [CredentialInfo] {
    guard isLogin else { return credentials }
    return credentials.filter { $0.role == nil && $0.kind.kind != "passkey" }
  }

  /// Whether another passkey on the item has the same site and account as
  /// `cred`. A site keeps only one, so the other is likely unused.
  func hasDuplicate(of cred: CredentialInfo) -> Bool {
    guard let info = cred.passkey else { return false }
    return passkeyCredentials.contains { other in
      other.key != cred.key && other.passkey?.rpId == info.rpId
        && other.passkey?.username == info.username
    }
  }

  /// Credentials that could hold the password: not a passkey, one-time code, or
  /// unknown kind.
  var passwordCandidates: [CredentialInfo] {
    credentials.filter { !["passkey", "totp", "unknown"].contains($0.kind.kind) }
  }
}

/// The host of a stored website, which is a URL or a bare domain, without a
/// leading `www.`.
func displayHost(of website: String) -> String? {
  let trimmed = website.trimmingCharacters(in: .whitespacesAndNewlines)
  guard !trimmed.isEmpty else { return nil }
  let withScheme = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
  guard var host = URL(string: withScheme)?.host(percentEncoded: false), !host.isEmpty else {
    return nil
  }
  host = host.lowercased()
  if host.hasPrefix("www.") { host.removeFirst(4) }
  return host
}

/// Whether a login's passkeys are offered on a website.
enum PasskeyCoverage: Equatable {
  /// A passkey's relying party is the host or a parent of it.
  case whole
  /// Only on this subdomain of the host, a passkey's relying party.
  case subdomain(String)
  case none
}

/// The last two labels of a host, so `a.example.com` and `example.com` share a
/// key. Hosts under a multi-label suffix such as `co.uk` share one too.
func siteKey(of host: String) -> String {
  host.split(separator: ".").suffix(2).joined(separator: ".")
}

/// Whether one host equals the other or is a subdomain of it.
func hostsOverlap(_ a: String, _ b: String) -> Bool {
  a == b || a.hasSuffix(".\(b)") || b.hasSuffix(".\(a)")
}

/// The page to open for a stored website.
func openableURL(for website: String) -> URL? {
  let trimmed = website.trimmingCharacters(in: .whitespacesAndNewlines)
  guard !trimmed.isEmpty else { return nil }
  return URL(string: trimmed.contains("://") ? trimmed : "https://\(trimmed)")
}

/// A letter on a color derived from the site, standing in for a favicon. No
/// favicon is fetched, since that would send the list of sites to the network.
struct Monogram: View {
  let title: String
  /// The first website host, or nil for an item with none.
  let host: String?
  var size: CGFloat = 28

  var body: some View {
    Text(letter)
      .font(.system(size: size / 2, weight: .semibold, design: .rounded))
      .foregroundStyle(.white)
      .frame(width: size, height: size)
      .background(color, in: RoundedRectangle(cornerRadius: size / 4))
      .accessibilityHidden(true)
  }

  private var letter: String {
    title.first(where: { $0.isLetter || $0.isNumber }).map { String($0).uppercased() } ?? "?"
  }

  /// The hue comes from the last two labels of the host, so `a.example.com` and
  /// `b.example.com` share a color. This is not the registrable domain: a host
  /// under `co.uk` shares a color with other `co.uk` hosts, which only affects
  /// the color.
  private var color: Color {
    let seed = (host ?? title).split(separator: ".").suffix(2).joined(separator: ".")
    var hash: UInt64 = 5381
    for byte in seed.lowercased().utf8 { hash = (hash &* 33) &+ UInt64(byte) }
    return Color(hue: Double(hash % 360) / 360, saturation: 0.45, brightness: 0.62)
  }
}
