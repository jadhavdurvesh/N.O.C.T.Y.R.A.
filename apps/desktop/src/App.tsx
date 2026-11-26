import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { Activity, ArrowDownToLine, ArrowUpFromLine, CheckCircle2, FileLock2, FileText, Fingerprint, FolderLock, KeyRound, LockKeyhole, ShieldCheck, ShieldEllipsis, TriangleAlert } from "lucide-react";

type Mode = "encrypt" | "decrypt" | "encrypt-dir" | "decrypt-dir";
const isDirectoryMode = (mode: Mode) => mode.endsWith("-dir");
const isEncryption = (mode: Mode) => mode.startsWith("encrypt");

function App() {
  const [mode, setMode] = useState<Mode>("encrypt");
  const [inputPath, setInputPath] = useState("");
  const [outputPath, setOutputPath] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);

  function changeMode(next: Mode) {
    setMode(next); setInputPath(""); setOutputPath(""); setPassword(""); setConfirmation(""); setMessage("");
  }
  async function chooseInput() {
    const selected = await open({ multiple: false, directory: isDirectoryMode(mode) });
    if (typeof selected === "string") { setInputPath(selected); setOutputPath(""); setMessage(""); }
  }
  async function chooseOutput() {
    const selected = await save({
      defaultPath: mode === "decrypt-dir" ? "recovered-folder" : isEncryption(mode) ? "archive.nct" : "recovered-file",
    });
    if (selected) setOutputPath(selected);
  }
  async function runOperation() {
    setMessage(""); setError(false);
    if (!inputPath || !outputPath || !password) { setError(true); setMessage("Select both paths and enter your password."); return; }
    if (isEncryption(mode) && password !== confirmation) { setError(true); setMessage("Password confirmation does not match."); return; }
    setBusy(true);
    try {
      const commands: Record<Mode, string> = { encrypt: "encrypt_file", decrypt: "decrypt_file", "encrypt-dir": "encrypt_directory", "decrypt-dir": "decrypt_directory" };
      await invoke(commands[mode], { inputPath, outputPath, password });
      setMessage(mode === "encrypt" || mode === "encrypt-dir" ? "Encrypted NCT archive created successfully." : mode === "decrypt-dir" ? "Archive authenticated and directory recovered." : "Archive authenticated and file recovered.");
      setPassword(""); setConfirmation("");
    } catch (cause) { setError(true); setMessage(String(cause)); }
    finally { setBusy(false); setPassword(""); setConfirmation(""); }
  }

  const operationLabel = mode === "encrypt-dir" ? "ENCRYPT DIRECTORY" : mode === "decrypt-dir" ? "RECOVER DIRECTORY" : mode === "encrypt" ? "ENCRYPT FILE" : "RECOVER FILE";
  return (
    <main className="shell">
      <aside className="rail"><div className="brand-mark"><span>N</span></div><div className="rail-line" /><div className="rail-status"><span className="status-dot" /> LOCAL</div><div className="rail-bottom">NCT / 001</div></aside>
      <section className="workspace">
        <header className="topbar">
          <div className="brand-lockup"><div className="eyebrow">PRIVATE INFORMATION SECURITY SYSTEM</div><div className="wordmark">NOCTYRA<span className="wordmark-dot">.</span></div></div>
          <div className="top-meta"><span className="system-state"><span className="status-dot" /> CORE READY</span><span className="version">BUILD 0.1.0 / LOCAL</span></div>
        </header>
        <div className="content">
          <div className="section-heading"><div><div className="eyebrow">SECURE ARCHIVE OPERATIONS / 01</div><h1>Data protection <span>terminal</span></h1><p>Protect individual files or complete directory trees in authenticated NCT archives.</p></div><div className="seal"><ShieldCheck size={23} /><span>AUTHENTICATED<br />ENCRYPTION</span></div></div>
          <div className="status-strip"><div><Activity size={15} /><span>LOCAL PROCESSING</span></div><div><Fingerprint size={15} /><span>ARGON2ID</span></div><div><LockKeyhole size={15} /><span>XCHACHA20-POLY1305</span></div><div className="status-ready"><span className="status-dot" /> READY</div></div>
          <section className="operation-card">
            <div className="card-head"><div><div className="eyebrow">OPERATION SELECTOR</div><h2>Choose operation</h2></div><span className="index">NCT / 01—04</span></div>
            <div className="mode-switch mode-switch-four">
              <button className={mode === "encrypt" ? "mode active" : "mode"} onClick={() => changeMode("encrypt")}><LockKeyhole size={17} /><span><b>Encrypt file</b><small>Single file</small></span></button>
              <button className={mode === "decrypt" ? "mode active" : "mode"} onClick={() => changeMode("decrypt")}><ShieldEllipsis size={17} /><span><b>Decrypt file</b><small>Recover one file</small></span></button>
              <button className={mode === "encrypt-dir" ? "mode active" : "mode"} onClick={() => changeMode("encrypt-dir")}><FolderLock size={17} /><span><b>Encrypt folder</b><small>Complete directory</small></span></button>
              <button className={mode === "decrypt-dir" ? "mode active" : "mode"} onClick={() => changeMode("decrypt-dir")}><FileLock2 size={17} /><span><b>Recover folder</b><small>Restore directory tree</small></span></button>
            </div>
            <div className="form-grid">
              <div className="field full"><label>01 / {isDirectoryMode(mode) ? "SOURCE DIRECTORY" : "SOURCE FILE"}</label><div className="path-control">{isDirectoryMode(mode) ? <FolderLock size={17} /> : <FileText size={17} />}<span className={inputPath ? "path-value" : "path-placeholder"}>{inputPath || (isDirectoryMode(mode) ? "No source directory selected" : "No source file selected")}</span><button className="browse" onClick={chooseInput}>BROWSE</button></div></div>
              <div className="field full"><label>02 / {mode === "decrypt-dir" ? "NEW DESTINATION DIRECTORY" : "DESTINATION"}</label><div className="path-control"><FileLock2 size={17} /><span className={outputPath ? "path-value" : "path-placeholder"}>{outputPath || (mode === "decrypt-dir" ? "Choose a new folder path" : "Choose output location")}</span><button className="browse" onClick={chooseOutput}>SELECT</button></div></div>
              <div className="field"><label>03 / PASSPHRASE</label><div className="input-control"><KeyRound size={16} /><input type="password" autoComplete="new-password" placeholder="Enter a strong passphrase" value={password} onChange={e => setPassword(e.target.value)} /></div></div>
              {isEncryption(mode) && <div className="field"><label>04 / CONFIRM PASSPHRASE</label><div className="input-control"><KeyRound size={16} /><input type="password" autoComplete="new-password" placeholder="Re-enter passphrase" value={confirmation} onChange={e => setConfirmation(e.target.value)} /></div></div>}
            </div>
            <div className="notice"><TriangleAlert size={16} /><span>NOCTYRA cannot recover a forgotten password. Folder archives reject symbolic links and special files. Keep independent backups of important originals.</span></div>
            <button className="execute" disabled={busy} onClick={runOperation}>{busy ? <span className="spinner" /> : isEncryption(mode) ? <ArrowUpFromLine size={18} /> : <ArrowDownToLine size={18} />}{busy ? "PROCESSING" : operationLabel}</button>
            {message && <div className={error ? "result error" : "result success"}>{error ? <TriangleAlert size={17} /> : <CheckCircle2 size={17} />}<span>{message}</span></div>}
          </section>
          <div className="bottom-grid"><div className="info-card"><div className="info-icon"><ShieldCheck size={18} /></div><div><b>Authenticated encryption</b><p>Modified archives and incorrect passwords are rejected before plaintext is returned.</p></div></div><div className="info-card"><div className="info-icon"><Fingerprint size={18} /></div><div><b>Local-first processing</b><p>Selected files and folders are processed by the local Rust core, not uploaded to a server.</p></div></div></div>
          <footer><span>NOCTYRA CORE / DEVELOPMENT BUILD</span><span>FORMAT NCT v1 / v2 DRAFT <i>•</i> NOT YET AUDITED</span></footer>
        </div>
      </section>
    </main>
  );
}
export default App;
