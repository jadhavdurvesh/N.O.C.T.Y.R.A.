# NOCTYRA Desktop

The primary graphical application for NOCTYRA. Built with Tauri 2, React, TypeScript and the shared Rust security core.

## Run the application

Prerequisites: Rust stable (edition 2024 / Rust 1.85+), Node.js 22+, npm, and the platform prerequisites for Tauri 2.

From this directory:

```powershell
npm install
npm run tauri dev
```

This opens the native desktop window. You do not need to invoke the CLI for normal operations.

## Workspaces

- **Secure vault** — encrypt/decrypt a file or directory tree using a passphrase. NCT v2 streaming is used for new archives; legacy NCT v1 files remain readable.
- **Image carrier** — conceal an already-encrypted NCT archive inside a PNG/BMP image, or extract and integrity-check an embedded archive.
- **CONSTELLATION** — split an encrypted NCT archive into transfer parts and reassemble selected parts. Every part is required in this initial GUI workflow; Reed-Solomon recovery manifests and signed sender trust management are not yet exposed in the UI.
- **Recovery keys** — generate an independent 256-bit offline recovery key and encrypt/decrypt an archive with it.

All file processing occurs in the local Rust backend. There is no account service or network upload. The frontend reports operation completion but does not currently expose percentage-based progress.

## Security notes and limitations

- This is an experimental development build and has not undergone an independent security audit.
- Image LSB steganography does not guarantee undetectability. Resizing, filtering, recompression or lossy formats can destroy embedded data.
- The recovery-key workflow is a separate credential mode. It does not yet add a second key-wrapping slot to an existing password-protected archive.
- Recovery-key files contain the full decryption credential. Keep them offline, restrict access, and maintain a separate backup.
- Passwords pass through the desktop IPC boundary. The backend uses zeroizing buffers where practical, but complete memory erasure across the webview/runtime cannot be guaranteed.
- The desktop bundler is intentionally disabled until native packaging, signing, icons, update policy and platform hardening are reviewed.

Do not use this development build as the sole protection for high-value sensitive data.
