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

Directory extraction requires a destination path that does not already exist. New directory archives use NCT v2/NMF2: file contents are streamed, including large files, while preserving nested files and empty directories. Extraction authenticates and stages the complete stream before creating the destination. Symbolic links and special filesystem objects are rejected. The legacy NMF1 directory format remains readable and is buffered.

## Staging recovery

An interrupted extraction may leave a marked private staging directory beside the destination. After confirming no NOCTYRA extraction is currently running in that parent directory, remove marked staging directories older than 24 hours with:

```powershell
cargo run -p noctyra-cli -- cleanup-staging .\\
```

The cleanup command only considers directories carrying the NOCTYRA staging prefix and exact marker file. It does not touch arbitrary folders. Do not run it while an extraction is active.

## Current limitations
- Legacy NMF1 directory archives remain buffered; new directory archives use NMF2 streaming.
- No image carriers or CONSTELLATION packet splitting yet.
- No recovery-key mechanism yet.
- Not independently audited; do not rely on it as the sole protection for critical data.
