#if DEBUG
  import AxoPassFFI
  import Foundation

  /// Placeholder content for marketing screenshots, shown while
  /// `DevOverrides.showMarketingContent` is on. Compiled into debug builds only.
  enum MarketingContent {
    /// Vaults listed in the sidebar.
    static let vaults: [VaultInfo] = [
      VaultInfo(key: "personal", name: "Personal", id: nil),
      VaultInfo(key: "work", name: "Work", id: nil),
      VaultInfo(key: "infrastructure", name: "Infrastructure", id: nil),
    ]

    /// Status chips on Today, as label and help text.
    static let statusChecks: [(label: String, help: String)] = [
      ("Sync", "2 vaults synced"),
      ("Shell", "ap set up in zsh"),
      ("AutoFill", "AutoFill on"),
      ("SSH agent", "SSH agent running"),
      ("SSH", "SSH uses Axo Pass"),
      ("GPG", "gpg uses Axo Pass"),
    ]

    /// Entries of the "Used today" card. Not tied to a vault, so the rows do
    /// not open anything.
    static func usedToday() -> [UsedTodayEntry] {
      [
        entry(
          .sshKey, "SHA256:Zk3p9QmT7vLxW2aRn5Hc", "GitHub", count: 24, minutesAgo: 3,
          callers: ["git", "ssh"], actions: ["ssh.sign"]),
        entry(
          .credential, "aws-production", "AWS production", count: 12, minutesAgo: 18,
          callers: ["terraform"], actions: ["credential.exec"]),
        entry(
          .login, "github.com", "github.com", count: 6, minutesAgo: 41,
          callers: ["Safari"], actions: ["login.fill", "login.totp"]),
        entry(
          .credential, "stripe-api-key", "Stripe API key", count: 5, minutesAgo: 75,
          callers: ["node"], actions: ["credential.env"]),
        entry(
          .sshKey, "SHA256:Bv7dY1sKq0EoUj4mTf8N", "Staging server", count: 4, minutesAgo: 96,
          callers: ["ssh"], actions: ["ssh.sign"]),
        entry(
          .ageIdentity, "backups", "Backups", count: 3, minutesAgo: 140,
          callers: ["restic"], actions: ["age.decrypt"]),
        entry(
          .login, "figma.com", "figma.com", count: 2, minutesAgo: 190,
          callers: [], actions: ["passkey.asserted"]),
      ]
    }

    private static func entry(
      _ kind: UsedTodayKind, _ subjectId: String, _ label: String, count: Int, minutesAgo: Int,
      callers: [String], actions: [String]
    ) -> UsedTodayEntry {
      UsedTodayEntry(
        kind: kind, subjectId: subjectId, label: label, count: count, callers: callers,
        actions: actions, lastUsed: Date.now.addingTimeInterval(-Double(minutesAgo) * 60),
        vaultId: nil, vaultKey: nil, itemId: nil, hasName: true)
    }
  }
#endif
