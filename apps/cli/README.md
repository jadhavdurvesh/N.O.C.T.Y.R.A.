# NOCTYRA CLI

Initial local file encryption/decryption interface.

## Usage

From repository root:

```powershell
cargo run -p noctyra-cli -- encrypt .\input.bin .\archive.nct
cargo run -p noctyra-cli -- decrypt .\archive.nct .\recovered.bin
```

The program prompts for the password without echoing it. Encryption asks for confirmation. Single-file operations use NCT v2 streaming encryption with 1 MiB independently compressed and authenticated chunks. Decryption supports both NCT v1 and v2. Outputs are written to temporary files and published only after complete authentication, without overwriting existing destinations.

## Directory commands

```powershell
cargo run -p noctyra-cli -- encrypt-dir .\\my-folder .\\folder.nct
cargo run -p noctyra-cli -- decrypt-dir .\\folder.nct .\\restored-folder
```

Directory extraction requires a destination path that does not already exist. The archive preserves nested files and empty directories. Symbolic links and special filesystem objects are rejected. The initial tree format stores the complete directory payload in memory and is limited to 1 GiB.

## Current limitations
- Directory archives still use the buffered NCT v1 tree representation and are limited to 1 GiB.
- No image carriers or CONSTELLATION packet splitting yet.
- No recovery-key mechanism yet.
- Not independently audited; do not rely on it as the sole protection for critical data.
