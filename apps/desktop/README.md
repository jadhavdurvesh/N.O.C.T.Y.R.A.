# NOCTYRA Desktop

Tauri 2 + React + TypeScript desktop shell for Windows, Linux, and macOS.

## Development

From this directory:

```powershell
npm install
npm run tauri dev
```

The Rust backend uses the shared NOCTYRA core for archive encryption and decryption. File dialogs are provided by the Tauri dialog plugin.

## Current scope

- Local file selection.
- Password-prompt UI with confirmation during encryption.
- NCT v2 streaming file encryption and authenticated decryption; v1 file archives remain readable.
- Temporary sibling output and no-clobber publication after final authentication.
- New directory operations use NCT v2/NMF2 streaming; legacy NMF1 directory archives remain readable through the buffered compatibility path.
- No network upload or account service.

## Limitations

This is an early development shell. It is not audited. Password strings pass through the desktop IPC boundary and are cleared from the UI after an operation, but complete memory erasure across the webview/runtime cannot be guaranteed. Streaming single-file and directory archives are implemented as experimental v2 drafts. Carrier images, CONSTELLATION, recovery keys, and signed release packages are future milestones.

The Tauri bundle is disabled in the initial config until packaging and platform-specific hardening are reviewed.
