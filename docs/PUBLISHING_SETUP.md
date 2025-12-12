# Publishing Setup Guide

This guide documents how to set up Maven Central publishing for Sequel Java packages.

## Overview

Publishing to Maven Central requires:
1. Sonatype account with verified namespace
2. GPG key for signing packages
3. Credentials stored in Doppler
4. Gradle plugin: `com.vanniktech.maven.publish`

## 1. Create Sonatype Account

1. Go to [central.sonatype.com](https://central.sonatype.com)
2. Click **Sign In** (top right) -> **Continue with GitHub**
3. Authorize with your GitHub account

## 2. Verify Namespace

For `io.github.sequelcore` (organization namespace):

1. Go to **Namespaces** in your Sonatype account
2. Click **Add Namespace** -> Enter `io.github.sequelcore`
3. You'll receive a **verification code** (e.g., `ABCD1234`)
4. Create a **public repo** in the GitHub org with that exact name
5. Back in Sonatype -> Click **Verify Namespace**
6. Delete the verification repo after verification

## 3. Generate Publish Token

1. Go to [central.sonatype.com/account](https://central.sonatype.com/account)
2. Click **Generate User Token**
3. Enter:
   - **Token Name:** `sequelcore-publish`
   - **Expiration:** `Does not expire`
4. Save the generated `username` and `password`

Add to Doppler (`sequel-core/prd`):
- `MAVEN_USERNAME` -> generated username
- `MAVEN_PASSWORD` -> generated password

## 4. Generate GPG Key

### Install GPG

```bash
# Windows
winget install GnuPG.GnuPG

# macOS
brew install gnupg

# Linux
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
- **Email:** Your email
- **Passphrase:** Create a strong one

### Export Private Key

```bash
gpg --armor --export-secret-keys YOUR_KEY_ID
```

Add to Doppler (`sequel-core/prd`):
- `GPG_PRIVATE_KEY` -> entire exported key (including BEGIN/END lines)
- `GPG_PASSPHRASE` -> passphrase from key generation

### Publish Public Key

```bash
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
```

## 5. Doppler Secrets Summary

| Key | Description |
|-----|-------------|
| `MAVEN_USERNAME` | Central Portal token username |
| `MAVEN_PASSWORD` | Central Portal token password |
| `GPG_PRIVATE_KEY` | Full private key (armored) |
| `GPG_PASSPHRASE` | GPG key passphrase |

## 6. Gradle Configuration

The project uses `com.vanniktech.maven.publish` plugin:

```kotlin
plugins {
    id("com.vanniktech.maven.publish") version "0.30.0"
}

mavenPublishing {
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL, automaticRelease = true)
    signAllPublications()

    coordinates("io.github.sequelcore", "vigil-spring-boot-starter", "1.0.0")

    pom {
        name.set("Vigil")
        description.set("JWT authentication starter for Spring Boot")
        // ... other POM details
    }
}
```

## 7. CI/CD Workflow

GitHub Actions workflow (`.github/workflows/publish.yml`) handles publishing on tags.

The workflow:
1. Fetches secrets from Doppler via `dopplerhq/secrets-fetch-action`
2. Maps secrets to Gradle properties:
   - `MAVEN_USERNAME` -> `ORG_GRADLE_PROJECT_mavenCentralUsername`
   - `MAVEN_PASSWORD` -> `ORG_GRADLE_PROJECT_mavenCentralPassword`
   - `GPG_PRIVATE_KEY` -> `ORG_GRADLE_PROJECT_signingInMemoryKey`
   - `GPG_PASSPHRASE` -> `ORG_GRADLE_PROJECT_signingInMemoryKeyPassword`
3. Runs `./gradlew publishAllPublicationsToMavenCentralRepository`

## 8. Publishing a Release

1. Update version in `build.gradle.kts`
2. Commit: `git commit -m "release: bump version to X.Y.Z"`
3. Create tag: `git tag vX.Y.Z`
4. Push: `git push origin main --tags`
5. GitHub Actions publishes to Maven Central automatically

## Troubleshooting

### GPG not found
Restart terminal after installing GPG.

### Signature verification failed
Ensure public key was uploaded:
```bash
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
```

### 401 Unauthorized
- Verify token is valid at [central.sonatype.com/account](https://central.sonatype.com/account)
- Regenerate if expired

### 404 Not Found (old OSSRH URLs)
OSSRH was deprecated. Use `com.vanniktech.maven.publish` with `CENTRAL_PORTAL`.
