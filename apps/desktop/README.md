# NOCTYRA Desktop

The primary graphical application for NOCTYRA. Built with Tauri 2, React, TypeScript and the shared Rust security core.

## Run locally

Prerequisites: Rust stable (edition 2024 / Rust 1.85+), Node.js 22+, npm, Microsoft C++ Build Tools and WebView2 on Windows, or the platform prerequisites for Tauri 2.

```powershell
cd apps/desktop
npm install
npm run tauri dev
```

The desktop application provides graphical workflows; normal file operations do not require the CLI.

## Build a Windows installer

On a Windows development machine with Rust, Node.js 22+, Visual Studio C++ Build Tools, WebView2 and NSIS installed:

```powershell
cd apps/desktop
npm install
npm run tauri -- icon src-tauri/icons/noctyra.svg
npm run build:windows
```

The NSIS installer is written to:

`target/release/bundle/nsis/`

The GitHub Actions workflow **NOCTYRA Windows Desktop Installer** also builds the Windows installer on pushes affecting the desktop/core code and on manual dispatch. Its successful run uploads a downloadable artifact named **NOCTYRA-Windows-Installer** (retained for 30 days). This is an unsigned development installer; Windows SmartScreen may show an unknown-publisher warning.

## Workspaces

- **Vault** — encrypt/decrypt a file or directory tree using a passphrase. NCT v2 streaming is used for new archives; legacy NCT v1 files remain readable.
- **Image studio** — conceal an already-encrypted NCT archive inside a PNG/BMP image, or extract and integrity-check an embedded archive. The current single-image codec has a 16 MiB payload limit.
- **CONSTELLATION** — split an encrypted NCT archive into raw transfer parts and reassemble selected parts. Every part is required in this GUI workflow; multi-image carrier orchestration, Reed-Solomon recovery and signed sender trust management are not yet exposed in the UI.
- **Recovery** — generate an independent 256-bit offline recovery key and encrypt/decrypt an archive with it.
- **Drag and drop** — drop files onto the active workspace to populate its source selection.

All file processing occurs in the local Rust backend. There is no account service or network upload. The interface currently shows indeterminate operation activity; it does not yet expose measured percentage progress or cancellation.

## Security notes

- This is an experimental development build and has not undergone an independent security audit.
- Image LSB steganography does not guarantee undetectability. Resizing, filtering, recompression or lossy formats can destroy embedded data.
- The recovery-key workflow is a separate credential mode. It does not yet add a second key-wrapping slot to an existing password-protected archive.
- Recovery-key files contain the full decryption credential. Keep them offline, restrict access, and maintain a separate backup.
- Passwords pass through the desktop IPC boundary. The backend uses zeroizing buffers where practical, but complete memory erasure across the webview/runtime cannot be guaranteed.
- The Windows installer produced by CI is not code-signed. Verify its source and checksum before installing.

Do not use this development build as the sole protection for high-value sensitive data.
