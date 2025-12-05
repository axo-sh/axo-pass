# [Axo Pass](https://axo.sh)

The Touch ID secrets manager for macOS dev environments.

## Features

- Unlock GPG and SSH keys with Touch ID instead of entering passwords
- Protect API tokens and passwords with Secure Enclave encryption
- Inject secrets into files and env variables
- Use `age` encryption with keys stored in Secure Enclave
- Full-featured command-line interface
- Free and open source

## Quickstart

[Download the latest release DMG here.](https://github.com/octavore/axo-pass/releases)

### GPG Integration

Add the following to `~/.gnupg/gpg-agent.conf`:

```
pinentry-program /Applications/Axo Pass.app/Contents/bin/ap-pinentry
```

### SSH Integration

Add the following to your shell configuration (e.g. `.zshrc` or `.bashrc`):

```shell
export SSH_ASKPASS="/Applications/Axo Pass.app/Contents/bin/ap-ssh-askpass"
export SSH_ASKPASS_REQUIRE=force
```

### `age` encryption

See the `ap` section below.

## `ap` command

Run the following to make the `ap` command available in your shell.

```shell
ln -s "/Applications/Axo\ Pass.app/Contents/bin/ap" /usr/local/bin/ap
```

```
Usage: ap vault list
       ap item list [--vault <vault>]
       ap item get [OPTIONS] <ITEM_REFERENCE>
       ap item read [OPTIONS] <ITEM_REFERENCE>
       ap item set [OPTIONS] <ITEM_REFERENCE> [SECRET_VALUE]
       ap read <ITEM_REFERENCE>
       ap inject [--input|-i <PATH>] [--output|-o <PATH>]
       ap age encrypt --recipient|-r <RECIPIENT> [PATH]
       ap age decrypt --recipient|-r <RECIPIENT> [PATH]
       ap age keygen <RECIPIENT> [--show]
       ap age recipients
       ap age delete <RECIPIENT>
       ap info
```

## Vault Spec

Vault files are stored as JSON in `~/Library/Application Support/Axo Pass/vaults`.
Each vault has a `file_key`, which is a AES-256 GCM key encrypted with by an
[ECIES key stored in the Secure Enclave](https://developer.apple.com/documentation/security/keys).

This file key is used to encrypt credential values in the file. Credential values are base64 encoded,
start with a 96-bit nonce, and the path of credential is used as additional authenticated data. This
design was inspired by [SOPS](https://github.com/getsops/sops).

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
