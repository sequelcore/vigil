# Publishing Setup Guide

This guide documents how to set up Maven Central publishing for Sequel Java packages.

## Overview

Publishing to Maven Central requires:
1. Sonatype account with verified namespace
2. GPG key for signing packages
3. Credentials stored in Doppler

## 1. Create Sonatype Account

1. Go to [central.sonatype.com](https://central.sonatype.com)
2. Click **Sign In** (top right) → **Continue with GitHub**
3. Authorize with your GitHub account

## 2. Verify Namespace

For `io.github.sequelcore` (organization namespace):

1. Go to **Namespaces** in your Sonatype account
2. Click **Add Namespace** → Enter `io.github.sequelcore`
3. You'll receive a **verification code** (e.g., `ABCD1234`)
4. Create a **public repo** in the GitHub org with that exact name:
   ```
   github.com/sequelcore/ABCD1234
   ```
5. Back in Sonatype → Click **Verify Namespace**
6. Wait a few minutes for verification
7. Delete the verification repo (optional)

Note: Personal namespaces (`io.github.yourusername`) are auto-verified when signing in with GitHub.

## 3. Generate Publish Token

1. Go to [central.sonatype.com/account](https://central.sonatype.com/account)
2. Click **Generate User Token**
3. Enter:
   - **Token Name:** `sequelcore-publish` (reusable for all packages)
   - **Expiration:** `Does not expire`
4. Save the generated `username` and `password`

Add to Doppler (`sequel-core/prd`):
- `MAVEN_USERNAME` → generated username
- `MAVEN_PASSWORD` → generated password

## 4. Generate GPG Key

GPG is required to sign packages. Maven Central verifies signatures to ensure package authenticity.

### Install GPG

Windows:
```bash
winget install GnuPG.GnuPG
# Restart terminal after installation
```

macOS:
```bash
brew install gnupg
```

Linux:
```bash
sudo apt install gnupg
```

### Generate Key Pair

```bash
gpg --full-generate-key
```

When prompted:
- **Key type:** `1` (RSA and RSA)
- **Key size:** `4096`
- **Expiration:** `0` (does not expire)
- **Real name:** `Sequel`
- **Email:** Your email (same as GitHub)
- **Passphrase:** Create a strong one, save it securely

Example output:
```
pub   rsa4096 2025-12-11 [SC]
      91CFA3FCB2FCBA80EDBC578BFC8968F7AD13056D
uid   sequel <your@email.com>
sub   rsa4096 2025-12-11 [E]
```

The long hex string is your **Key ID**.

### Export Private Key

```bash
gpg --armor --export-secret-keys YOUR_KEY_ID
```

This outputs the private key as text. Copy the entire output (including `-----BEGIN PGP PRIVATE KEY BLOCK-----` and `-----END...`).

Add to Doppler (`sequel-core/prd`):
- `GPG_PRIVATE_KEY` → entire exported key
- `GPG_PASSPHRASE` → passphrase from key generation

### Publish Public Key to Keyserver

```bash
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
```

This allows Maven Central to verify your signatures.

## 5. Doppler Secrets Summary

After setup, `sequel-core/prd` should have:

| Key | Description |
|-----|-------------|
| `MAVEN_USERNAME` | Sonatype token username |
| `MAVEN_PASSWORD` | Sonatype token password |
| `GPG_PRIVATE_KEY` | Full private key (armored) |
| `GPG_PASSPHRASE` | GPG key passphrase |

## How Signing Works

1. **Private key** (in Doppler) signs the JAR during publish
2. **Public key** (on keyserver) lets Maven Central verify the signature
3. Maven Central fetches public key from keyserver and validates
4. Valid signature → package published. Invalid → rejected.

This ensures packages genuinely come from Sequel, preventing malicious impersonation.

## Publishing Commands

### Manual (local)
```bash
doppler run --project sequel-core --config prd -- ./gradlew publish
```

### Automated (GitHub Actions)
Publishing triggers automatically when creating a GitHub release. The workflow uses secrets from Doppler/GitHub Secrets.

## Troubleshooting

### GPG not found
Restart terminal after installing GPG, or add to PATH manually.

### Signature verification failed
Ensure public key was uploaded to keyserver:
```bash
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
```

### Namespace not verified
Check that the verification repo exists and is public in the correct GitHub org.

### Token expired
Generate a new token at [central.sonatype.com/account](https://central.sonatype.com/account) and update Doppler.
