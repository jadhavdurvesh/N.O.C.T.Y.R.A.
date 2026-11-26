import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { Activity, ArrowDownToLine, ArrowUpFromLine, CheckCircle2, FileLock2, FileText, Fingerprint, KeyRound, LockKeyhole, ShieldCheck, ShieldEllipsis, TriangleAlert } from "lucide-react";

type Mode = "encrypt" | "decrypt";

function App() {
  const [mode, setMode] = useState<Mode>("encrypt");
  const [inputPath, setInputPath] = useState("");
  const [outputPath, setOutputPath] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);

  async function chooseInput() {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected === "string") {
      setInputPath(selected);
      setOutputPath("");
      setMessage("");
    }
  }

  async function chooseOutput() {
    const selected = await save({
      defaultPath: mode === "encrypt" ? "archive.nct" : "recovered-file",
    });
    if (selected) setOutputPath(selected);
  }

  async function runOperation() {
    setMessage("");
    setError(false);
    if (!inputPath || !outputPath || !password) {
      setError(true);
      setMessage("Select both paths and enter your password.");
      return;
    }
    if (mode === "encrypt" && password !== confirmation) {
      setError(true);
      setMessage("Password confirmation does not match.");
      return;
    }
    setBusy(true);
    try {
      const command = mode === "encrypt" ? "encrypt_file" : "decrypt_file";
      await invoke(command, {
        inputPath,
        outputPath,
        password,
      });
      setMessage(mode === "encrypt"
        ? "Encrypted archive created successfully."
        : "Archive authenticated and file recovered.");
      setPassword("");
      setConfirmation("");
    } catch (cause) {
      setError(true);
      setMessage(String(cause));
    } finally {
      setBusy(false);
      setPassword("");
      setConfirmation("");
    }
  }

  return (
    <main className="shell">
      <aside className="rail">
        <div className="brand-mark"><span>N</span></div>
        <div className="rail-line" />
        <div className="rail-status"><span className="status-dot" /> LOCAL</div>
        <div className="rail-bottom">NCT / 001</div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div className="brand-lockup">
            <div className="eyebrow">PRIVATE INFORMATION SECURITY SYSTEM</div>
            <div className="wordmark">NOCTYRA<span className="wordmark-dot">.</span></div>
          </div>
          <div className="top-meta">
            <span className="system-state"><span className="status-dot" /> CORE READY</span>
            <span className="version">BUILD 0.1.0 / LOCAL</span>
          </div>
        </header>

        <div className="content">
          <div className="section-heading">
            <div>
              <div className="eyebrow">SECURE ARCHIVE OPERATIONS / 01</div>
              <h1>Data protection <span>terminal</span></h1>
              <p>Encrypt files into authenticated NCT archives or recover their original contents.</p>
            </div>
            <div className="seal"><ShieldCheck size={23} /><span>AUTHENTICATED<br />ENCRYPTION</span></div>
          </div>

          <div className="status-strip">
            <div><Activity size={15} /><span>LOCAL PROCESSING</span></div>
            <div><Fingerprint size={15} /><span>ARGON2ID</span></div>
            <div><LockKeyhole size={15} /><span>XCHACHA20-POLY1305</span></div>
            <div className="status-ready"><span className="status-dot" /> READY</div>
          </div>

          <section className="operation-card">
            <div className="card-head">
              <div>
                <div className="eyebrow">OPERATION SELECTOR</div>
                <h2>Choose operation</h2>
              </div>
              <span className="index">NCT / 01—02</span>
            </div>

            <div className="mode-switch">
              <button className={mode === "encrypt" ? "mode active" : "mode"} onClick={() => { setMode("encrypt"); setMessage(""); }}>
                <LockKeyhole size={17} /><span><b>Encrypt</b><small>Create protected archive</small></span>
              </button>
              <button className={mode === "decrypt" ? "mode active" : "mode"} onClick={() => { setMode("decrypt"); setMessage(""); }}>
                <ShieldEllipsis size={17} /><span><b>Decrypt</b><small>Authenticate and recover</small></span>
              </button>
            </div>

            <div className="form-grid">
              <div className="field full">
                <label>01 / SOURCE FILE</label>
                <div className="path-control">
                  <FileText size={17} />
                  <span className={inputPath ? "path-value" : "path-placeholder"}>{inputPath || "No source file selected"}</span>
                  <button className="browse" onClick={chooseInput}>BROWSE</button>
                </div>
              </div>

              <div className="field full">
                <label>02 / DESTINATION</label>
                <div className="path-control">
                  <FileLock2 size={17} />
                  <span className={outputPath ? "path-value" : "path-placeholder"}>{outputPath || "Choose output location"}</span>
                  <button className="browse" onClick={chooseOutput}>SELECT</button>
                </div>
              </div>

              <div className="field">
                <label>03 / PASSPHRASE</label>
                <div className="input-control"><KeyRound size={16} /><input type="password" autoComplete="new-password" placeholder="Enter a strong passphrase" value={password} onChange={e => setPassword(e.target.value)} /></div>
              </div>

              {mode === "encrypt" && <div className="field">
                <label>04 / CONFIRM PASSPHRASE</label>
                <div className="input-control"><KeyRound size={16} /><input type="password" autoComplete="new-password" placeholder="Re-enter passphrase" value={confirmation} onChange={e => setConfirmation(e.target.value)} /></div>
              </div>}
            </div>

            <div className="notice"><TriangleAlert size={16} /><span>NOCTYRA cannot recover a forgotten password. Keep a secure independent backup of important originals.</span></div>

            <button className="execute" disabled={busy} onClick={runOperation}>
              {busy ? <span className="spinner" /> : mode === "encrypt" ? <ArrowUpFromLine size={18} /> : <ArrowDownToLine size={18} />}
              {busy ? "PROCESSING" : mode === "encrypt" ? "INITIALIZE ENCRYPTION" : "AUTHENTICATE & DECRYPT"}
            </button>

            {message && <div className={error ? "result error" : "result success"}>
              {error ? <TriangleAlert size={17} /> : <CheckCircle2 size={17} />}
              <span>{message}</span>
            </div>}
          </section>

          <div className="bottom-grid">
            <div className="info-card">
              <div className="info-icon"><ShieldCheck size={18} /></div>
              <div><b>Authenticated encryption</b><p>Modified archives and incorrect passwords are rejected before plaintext is returned.</p></div>
            </div>
            <div className="info-card">
              <div className="info-icon"><Fingerprint size={18} /></div>
              <div><b>Local-first processing</b><p>Selected file contents are processed by the local Rust core, not uploaded to a server.</p></div>
            </div>
          </div>

          <footer><span>NOCTYRA CORE / DEVELOPMENT BUILD</span><span>FORMAT NCT v1 DRAFT <i>•</i> NOT YET AUDITED</span></footer>
        </div>
      </section>
    </main>
  );
}

export default App;
