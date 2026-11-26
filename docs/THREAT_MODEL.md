# Threat Model

## Assets

- Plaintext files and filenames.
- Archive encryption keys and recovery secrets.
- Encrypted NCT archives.
- Carrier images and transport manifests.
- Integrity and authenticity metadata.

## In-scope threats

- An attacker obtains a stored encrypted archive.
- An attacker modifies, truncates, reorders, or duplicates archive or transport data.
- An attacker supplies malformed images, manifests, or archive files.
- An attacker attempts password guessing against a stolen archive.
- A carrier is recompressed or otherwise modified during ordinary file handling.

## Out-of-scope or limited-protection threats

- A compromised operating system, malware, keyloggers, or memory extraction while unlocked.
- An attacker with access to plaintext or keys during a legitimate unlocked session.
- Traffic analysis and detection of steganographic content.
- Guaranteed undetectability: no image carrier mode can promise that hidden data cannot be detected.
- Secure deletion on SSDs, cloud-synced folders, backups, or journaling filesystems.

## Security goals

- Confidentiality from authenticated encryption.
- Tamper detection and authenticity at the cryptographic container layer.
- Safe parsing with explicit size and resource limits.
- Clear failure on authentication errors.
- No plaintext extraction before complete authentication of the relevant content.
- Recovery mechanisms that detect missing or corrupt parts rather than silently guessing.

## Assumptions to validate

- Passwords are sufficiently strong.
- OS cryptographic randomness is available.
- Cryptographic dependencies and versions are reviewed.
- The user keeps recovery material separate from the archive.
