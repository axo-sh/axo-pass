# Axo Pass

The Touch ID secrets manager for macOS dev environments.

[Download the latest release DMG here.](https://github.com/octavore/axo-pass/releases)

## Features

- Unlock SSH and GPG keys with Touch ID instead of entering passwords
- Protect API tokens and passwords with Secure Enclave encryption
- Inject secrets into files and env variables
- Autofill credentials and passkeys in your browser (Safari/Chrome/Firefox)
- Serverless syncing in shared folders or storage you control
- Global hot-keyed command palette
- Use `age` encryption with keys stored in Secure Enclave
- Audit logs
- 1Password/Apple Passwords import
- Full-featured command-line interface
- Free and open source

[Roadmap →](https://axo.sh)

## Screenshots

![Screenshot 1](https://axo.sh/assets/screenshot-1.jpg)

![Screenshot 2](https://axo.sh/assets/screenshot-2.jpg)

## Setup

Download latest version of Axo Pass from [here](https://github.com/octavore/axo-pass/releases) and move it to your Applications folder to install the app. First-time users will be prompted to set up a vault and some common integrations.

Axo Pass provides an `ap` command which allows you to interact with your vault from the command-line. It also integrates with SSH and GPG natively. The app provides helpers for setting up these integrations; this section is mainly useful for understanding how to do it yourself manually.

### `ap` command

Run the following to make the `ap` command available in your shell.

```shell
ln -s "/Applications/Axo Pass.app/Contents/MacOS/ap" /usr/local/bin/ap
```

To set up SSH agent and askpass configureation in zsh, as well as shell completions, add the following to `~/.zshrc`:

```shell
source <(ap shellenv zsh)
```

#### Example commands

```shell
# vault commands
ap vault list
ap item list [--vault <vault>]
ap item get [OPTIONS] <ITEM_REFERENCE>
ap item read [OPTIONS] <ITEM_REFERENCE>...
ap item set [OPTIONS] <ITEM_REFERENCE> [SECRET_VALUE]
# commands for reading secrets
ap read [--delimiter|-d <DELIMITER>] <ITEM_REFERENCE>...
ap inject [--input|-i <PATH>] [--output|-o <PATH>]
ap exec [--env-file|-e <PATH>]... -- <COMMAND>...
ap env --env-file|-e <PATH>...
# age commands
ap age encrypt --recipient|-r <RECIPIENT> [PATH]
ap age decrypt --recipient|-r <RECIPIENT> [PATH]
ap age keygen <NAME> [SHOW]
ap age recipients
ap age delete <RECIPIENT>
# misc
ap info
```

### SSH Integration

Use `ap shellenv zsh` (see above) to automatically configure SSH integration. The shellenv integration uses a zsh `preexec` hook to automatically fall back to the system ssh agent if Axo Pass is not available.

Otherwise, you can add the following to your shell configuration (e.g. `.zshrc` or `.bashrc`):

```shell
# ~/.zshrc or ~/.bashrc
export SSH_AUTH_SOCK="$HOME/Library/Application Support/Axo Pass/agent.sock"
export SSH_ASKPASS="/Applications/Axo Pass.app/Contents/Resources/ap-ssh-askpass"
export SSH_ASKPASS_REQUIRE=force
```

And for non-shell environments, you can add the following to your SzSH config file at `~/.ssh/config`:

```shell
Host *
  IdentityAgent "~/Library/Application Support/Axo Pass/agent.sock"
```

### SSH keys

Axo Pass supports several different ssh key storage locations. Using ssh keys stored by Axo Pass requires approval with Touch ID or your password, except where noted below.

| Key                               | Private key location               | Approval                              | Allowed Apps |
| --------------------------------- | ---------------------------------- | ------------------------------------- | ------------ |
| Secure Enclave key                | Secure Enclave, cannot be exported | Every use, enforced by Axo Pass       | Yes          |
| Secure Enclave key, user presence | Secure Enclave, cannot be exported | Every use, enforced by Secure Enclave | No           |
| Vault SSH key                     | Vault, agent memory if auto-loaded | Vault prompt; every use once loaded   | Yes          |
| Auto-loaded `~/.ssh` key          | `~/.ssh` folder                    | Every use                             | Yes          |
| Key added with `ssh-add -c`       | Agent memory                       | Every use                             | No           |
| Key added with `ssh-add`          | Agent memory                       | Never                                 | N/A          |

**Secure Enclave keys.** Create one with "Create Key" in the SSH pane. The public key is written to `~/.ssh/id_se_<id>.pub`. A User Presence key can be created by holding `option` in the Create Key window, which will force the Secure Enclave to request authentication on each use of the key (this disables the Allowed App feature on this key, because Axo Pass will no longer be able to manage access itself).

**Vault keys.** These are stored in your vault and can be synced and backed up with your vault. With auto-load on, the first use will prompt for vault access; the agent then holds the decrypted key like an auto-loaded `~/.ssh` key (subsequent usage will prompt for approval). With auto-load off, the agent does not holds the key and all uses will prompt for vault access.

**`~/.ssh` keys.** Selected `~/.ssh` can be auto-loaded, where the first use of the key will automatically read the key file. If passphrase-protected, Axo Pass will prompt you to unlock the key file. The decrypted key stays in the agent until it restarts or you remove it with `ssh-add -D`. Each subsequent use will still ask for approval.

**`ssh-add -c`.** A key added with `-c` (i.e. confirm) will ask for approval on each use, superseding any Allowed App configuration.

**Allowed Apps.** When an app asks to sign, the prompt offers to "Allow <App> to use this key for" a customizable duration. While the grant lasts, that app can sign with the key without prompting. See and remove grants under Allowed Apps in the key's details. Limitations:

- An app is identified by its team ID and bundle ID.
- Anything the app runs, such as git hooks, can also use the key.
- Only signed apps with a team ID can be allowed. Apple's apps, including Terminal.app, do not have a team ID, so `ssh` from Terminal.app always prompts.
- Every process in the request must have a verified code signature.
- Grants are stored in Axo Pass's data protection keychain, which other processes cannot edit.
- For keys held by the agent, grants apply only while auto-load is on, whether or not the app is locked. Grants do not apply while auto-load is off, but they are not automatically cleared.
- For vault keys with auto-load on, grants apply while the agent holds the key, whether or not the app is locked. For other vault keys, grants apply only while Axo Pass is unlocked. If Axo Pass is locked, the grant doesn't apply and a prompt will be displayed.

### GPG Integration

Add the following to `~/.gnupg/gpg-agent.conf`:

```shell
pinentry-program /Applications/Axo Pass.app/Contents/Resources/ap-pinentry
```

### `age` encryption

See the `ap` section above.

## Vault Spec

Vault files are stored as JSON in `~/Library/Application Support/Axo Pass/vaults`. Each vault is encrypted by a `file_key`, which is an AES-256 GCM key that is itself encrypted by an [ECIES key stored in the Secure Enclave](https://developer.apple.com/documentation/security/keys).

More precisely, `file_key` is used to encrypt credential and metadata values in the file. Values are base64 encoded, start with a 96-bit nonce, and the path of the value is used as additional authenticated data. This design was inspired by [SOPS](https://github.com/getsops/sops).

Below is an example of a vault json file.

```jsonc
{
  "id": "<uuid>",
  "name": "Axo Pass",
  "file_key": "<base64 ciphertext>", // Base64-encoded key encrypted by user's vault-encryption-key
  // map of items
  "items": {
    "github-api": {
      "id": "<uuid>",
      "title": "GitHub API",
      // map of credentials
      "credentials": {
        "token": {
          "id": "<uuid>", // VaultItemCredential UUID
          "title": "Personal Access Token",
          "value": "<base64 ciphertext>" // Secret value encrypted by file key
        }
      }
    }
  }
}
```

## Development

Todo. This app requires codesigning (and notarization for distribution), and Touch ID will not work without codesigning. If you're interested in hacking on this, reach out to me (octavore) on the Discord.
