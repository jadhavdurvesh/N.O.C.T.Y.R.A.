import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  Activity, ArrowDownToLine, ArrowUpFromLine, CheckCircle2, FileLock2, FileText,
  Fingerprint, FolderLock, KeyRound, LockKeyhole, ShieldCheck, ShieldEllipsis,
  TriangleAlert, Image, Network, KeySquare, Layers3, FolderOpen, RefreshCw,
  CopyCheck, ScanLine, ShieldAlert
} from "lucide-react";

type Section = "vault" | "images" | "transfer" | "recovery";
type Mode = "encrypt" | "decrypt" | "encrypt-dir" | "decrypt-dir";
const isDirectoryMode = (mode: Mode) => mode.endsWith("-dir");
const isEncryption = (mode: Mode) => mode.startsWith("encrypt");

async function chooseFile(title: string, extensions?: string[]) {
  const result = await open({ title, multiple: false, directory: false, filters: extensions ? [{ name: "Supported files", extensions }] : undefined });
  return typeof result === "string" ? result : "";
}
async function chooseSave(title: string, defaultPath: string, filters?: string[]) {
  return await save({ title, defaultPath, filters: filters ? [{ name: "NOCTYRA files", extensions: filters }] : undefined }) || "";
}

function App() {
  const [section, setSection] = useState<Section>("vault");
  const [mode, setMode] = useState<Mode>("encrypt");
  const [inputPath, setInputPath] = useState("");
  const [outputPath, setOutputPath] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);
  const [archivePath, setArchivePath] = useState("");
  const [carrierPath, setCarrierPath] = useState("");
  const [transferParts, setTransferParts] = useState<string[]>([]);
  const [partSize, setPartSize] = useState("4194304");
  const [recoveryKeyPath, setRecoveryKeyPath] = useState("");
  const [recoveryInputPath, setRecoveryInputPath] = useState("");
  const [recoveryOutputPath, setRecoveryOutputPath] = useState("");

  function clearStatus() { setMessage(""); setError(false); }
  function reportError(cause: unknown) { setError(true); setMessage(String(cause)); }
  async function execute<T>(task: () => Promise<T>, success: (result: T) => string) {
    clearStatus(); setBusy(true);
    try { const result = await task(); setMessage(success(result)); }
    catch (cause) { reportError(cause); }
    finally { setBusy(false); }
  }
  function navigate(next: Section) { setSection(next); clearStatus(); }
  function changeMode(next: Mode) {
    setMode(next); setInputPath(""); setOutputPath(""); setPassword(""); setConfirmation(""); clearStatus();
  }
  async function pickVaultInput() {
    const path = await open({ multiple: false, directory: isDirectoryMode(mode), title: "Select source" });
    if (typeof path === "string") { setInputPath(path); setOutputPath(""); clearStatus(); }
  }
  async function pickVaultOutput() {
    const path = await chooseSave("Choose destination", mode === "decrypt-dir" ? "recovered-folder" : isEncryption(mode) ? "archive.nct" : "recovered-file", isEncryption(mode) ? ["nct"] : undefined);
    if (path) setOutputPath(path);
  }
  async function runVault() {
    clearStatus();
    if (!inputPath || !outputPath || !password) { reportError("Select the source and destination, then enter your passphrase."); return; }
    if (isEncryption(mode) && password !== confirmation) { reportError("Passphrase confirmation does not match."); return; }
    await execute(async () => {
      const commands: Record<Mode, string> = { encrypt: "encrypt_file", decrypt: "decrypt_file", "encrypt-dir": "encrypt_directory", "decrypt-dir": "decrypt_directory" };
      await invoke(commands[mode], { inputPath, outputPath, password });
      setPassword(""); setConfirmation("");
      return true;
    }, () => isEncryption(mode) ? "Encrypted NCT archive created successfully." : "Archive authenticated and recovered successfully.");
  }
  async function runConceal(destination: string) {
    if (!archivePath || !carrierPath || !destination) { reportError("Choose an encrypted NCT archive, a PNG/BMP carrier and an output image."); return; }
    await execute(() => invoke<number>("conceal_archive", { archivePath, carrierPath, outputPath: destination }), n => `Encrypted archive embedded successfully (${n.toLocaleString()} bytes).`);
  }
  async function runReveal(destination: string) {
    if (!carrierPath || !destination) { reportError("Choose a carrier image and an output NCT archive path."); return; }
    await execute(() => invoke<number>("reveal_archive", { carrierPath, outputPath: destination }), n => `Embedded NCT archive extracted and integrity-checked (${n.toLocaleString()} bytes).`);
  }
  async function runSplit(destination: string) {
    if (!archivePath || !destination) { reportError("Choose an encrypted NCT archive and a new transfer folder destination."); return; }
    const size = Number(partSize);
    if (!Number.isSafeInteger(size) || size < 1024 || size > 8 * 1024 * 1024) { reportError("Part size must be between 1 KiB and 8 MiB."); return; }
    await execute(() => invoke<string[]>("constellation_split", { archivePath, outputDirectory: destination, fragmentBytes: size }), paths => `Transfer prepared: ${paths.length} authenticated integrity-checked parts created.`);
  }
  async function pickParts() {
    const result = await open({ title: "Select all parts from one NOCTYRA transfer", multiple: true, filters: [{ name: "NOCTYRA transfer parts", extensions: ["ncfr"] }] });
    if (Array.isArray(result)) { setTransferParts(result); clearStatus(); }
  }
  async function runJoin(destination: string) {
    if (!transferParts.length || !destination) { reportError("Select transfer parts and an output NCT archive path."); return; }
    await execute(() => invoke<number>("constellation_join", { fragmentPaths: transferParts, outputPath: destination }), n => `Transfer reassembled and archive digest verified (${n.toLocaleString()} bytes).`);
  }
  async function createRecoveryKey() {
    const path = await chooseSave("Save offline recovery key", "NOCTYRA-recovery.key", ["key"]);
    if (!path) return;
    await execute(() => invoke("generate_recovery_key", { outputPath: path }), () => { setRecoveryKeyPath(path); return "A new 256-bit recovery key was created. Store a separate offline backup."; });
  }
  async function runRecoveryKey(encrypt: boolean) {
    if (!recoveryInputPath || !recoveryOutputPath || !recoveryKeyPath) { reportError("Select the input file, output path and recovery-key file."); return; }
    await execute(() => invoke(encrypt ? "encrypt_file_with_recovery_key" : "decrypt_file_with_recovery_key", { inputPath: recoveryInputPath, outputPath: recoveryOutputPath, keyPath: recoveryKeyPath }), () => encrypt ? "Archive encrypted with the independent recovery key." : "Archive authenticated and recovered using the recovery key.");
  }

  const nav = [
    { id: "vault" as const, label: "Secure vault", icon: LockKeyhole, detail: "Encrypt / decrypt" },
    { id: "images" as const, label: "Image carrier", icon: Image, detail: "Conceal / extract" },
    { id: "transfer" as const, label: "Constellation", icon: Network, detail: "Split / reassemble" },
    { id: "recovery" as const, label: "Recovery keys", icon: KeySquare, detail: "Offline credentials" },
  ];
  const operationLabel = mode === "encrypt-dir" ? "ENCRYPT DIRECTORY" : mode === "decrypt-dir" ? "RECOVER DIRECTORY" : mode === "encrypt" ? "ENCRYPT FILE" : "RECOVER FILE";

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-mark"><span>N</span></div>
        <div className="sidebar-caption">WORKSPACE</div>
        <nav>{nav.map(item => <button key={item.id} className={section === item.id ? "nav-item selected" : "nav-item"} onClick={() => navigate(item.id)}><item.icon size={17}/><span><b>{item.label}</b><small>{item.detail}</small></span></button>)}</nav>
        <div className="sidebar-bottom"><span className="status-dot"/> LOCAL ONLY <small>NOCTYRA / 0.1.0</small></div>
      </aside>
      <section className="workspace">
        <header className="topbar">
          <div className="brand-lockup"><div className="eyebrow">PRIVATE INFORMATION SECURITY SYSTEM</div><div className="wordmark">NOCTYRA<span className="wordmark-dot">.</span></div></div>
          <div className="top-meta"><span className="system-state"><span className="status-dot"/>{busy ? "OPERATION RUNNING" : "LOCAL CORE READY"}</span><span className="version">DESKTOP / DEVELOPMENT BUILD</span></div>
        </header>
        <div className="content">
          <div className="section-heading"><div><div className="eyebrow">NOCTYRA WORKSPACE / {nav.findIndex(n => n.id === section) + 1}</div><h1>{section === "vault" ? "Secure your data" : section === "images" ? "Image carrier laboratory" : section === "transfer" ? "Constellation transfer" : "Recovery credentials"} <span>{section === "vault" ? "vault" : section === "images" ? "concealment" : section === "transfer" ? "protocol" : "management"}</span></h1><p>{section === "vault" ? "Protect files and directory trees with authenticated encryption." : section === "images" ? "Embed already-encrypted archives into PNG or BMP carrier images." : section === "transfer" ? "Prepare multi-part encrypted transfers and reassemble received parts." : "Create and use an independent offline recovery credential."}</p></div><div className="seal"><ShieldCheck size={23}/><span>LOCAL<br/>PROCESSING</span></div></div>
          <div className="status-strip"><div><Activity size={15}/><span>LOCAL PROCESSING</span></div><div><Fingerprint size={15}/><span>ARGON2ID</span></div><div><LockKeyhole size={15}/><span>XCHACHA20-POLY1305</span></div><div className="status-ready"><span className="status-dot"/>{busy ? "WORKING" : "READY"}</div></div>

          {section === "vault" && <section className="operation-card">
            <div className="card-head"><div><div className="eyebrow">SECURE ARCHIVE OPERATIONS</div><h2>Choose operation</h2></div><span className="index">NCT / 01—04</span></div>
            <div className="mode-switch mode-switch-four">
              <button className={mode === "encrypt" ? "mode active" : "mode"} onClick={() => changeMode("encrypt")}><LockKeyhole size={17}/><span><b>Encrypt file</b><small>Single file</small></span></button>
              <button className={mode === "decrypt" ? "mode active" : "mode"} onClick={() => changeMode("decrypt")}><ShieldEllipsis size={17}/><span><b>Decrypt file</b><small>Recover one file</small></span></button>
              <button className={mode === "encrypt-dir" ? "mode active" : "mode"} onClick={() => changeMode("encrypt-dir")}><FolderLock size={17}/><span><b>Encrypt folder</b><small>Directory tree</small></span></button>
              <button className={mode === "decrypt-dir" ? "mode active" : "mode"} onClick={() => changeMode("decrypt-dir")}><FileLock2 size={17}/><span><b>Recover folder</b><small>Restore tree</small></span></button>
            </div>
            <div className="form-grid">
              <div className="field full"><label>01 / {isDirectoryMode(mode) ? "SOURCE DIRECTORY" : "SOURCE FILE"}</label><div className="path-control"><FolderOpen size={17}/><span className={inputPath ? "path-value" : "path-placeholder"}>{inputPath || "Select source"}</span><button className="browse" onClick={pickVaultInput}>BROWSE</button></div></div>
              <div className="field full"><label>02 / DESTINATION</label><div className="path-control"><FileLock2 size={17}/><span className={outputPath ? "path-value" : "path-placeholder"}>{outputPath || "Choose output location"}</span><button className="browse" onClick={pickVaultOutput}>SELECT</button></div></div>
              <div className="field"><label>03 / PASSPHRASE</label><div className="input-control"><KeyRound size={16}/><input type="password" autoComplete="new-password" placeholder="Enter a strong passphrase" value={password} onChange={e => setPassword(e.target.value)}/></div></div>
              {isEncryption(mode) && <div className="field"><label>04 / CONFIRM PASSPHRASE</label><div className="input-control"><KeyRound size={16}/><input type="password" autoComplete="new-password" placeholder="Re-enter passphrase" value={confirmation} onChange={e => setConfirmation(e.target.value)}/></div></div>}
            </div>
            <div className="notice"><TriangleAlert size={16}/><span>Forgotten passphrases cannot be recovered. Decryption publishes output only after archive authentication. Keep independent backups of important originals.</span></div>
            <button className="execute" disabled={busy} onClick={runVault}>{busy ? <span className="spinner"/> : isEncryption(mode) ? <ArrowUpFromLine size={18}/> : <ArrowDownToLine size={18}/>} {busy ? "PROCESSING" : operationLabel}</button>
          </section>}

          {section === "images" && <section className="operation-card">
            <div className="card-head"><div><div className="eyebrow">REVERSIBLE IMAGE CARRIER</div><h2>Conceal or extract an encrypted archive</h2></div><span className="index">PNG / BMP</span></div>
            <div className="workflow-grid">
              <div className="workflow-panel"><div className="workflow-icon"><ScanLine size={20}/></div><h3>Conceal archive</h3><p>Choose an existing NCT archive and a PNG/BMP cover image. NOCTYRA checks capacity before embedding.</p>
                <div className="field"><label>ENCRYPTED NCT ARCHIVE</label><div className="path-control"><FileLock2 size={16}/><span className={archivePath ? "path-value" : "path-placeholder"}>{archivePath || "No archive selected"}</span><button className="browse" onClick={async()=>{const p=await chooseFile("Select encrypted NCT archive",["nct"]);if(p){setArchivePath(p);clearStatus();}}}>SELECT</button></div></div>
                <div className="field"><label>CARRIER IMAGE</label><div className="path-control"><Image size={16}/><span className={carrierPath ? "path-value" : "path-placeholder"}>{carrierPath || "No PNG/BMP selected"}</span><button className="browse" onClick={async()=>{const p=await chooseFile("Select PNG or BMP carrier",["png","bmp"]);if(p){setCarrierPath(p);clearStatus();}}}>SELECT</button></div></div>
                <button className="execute" disabled={busy} onClick={async()=>{const p=await chooseSave("Save concealed image","NOCTYRA-concealed.png",["png"]);if(p){setOutputPath(p);await runConceal(p);}}}><Image size={17}/> CONCEAL INTO IMAGE</button>
              </div>
              <div className="workflow-panel"><div className="workflow-icon"><CopyCheck size={20}/></div><h3>Extract archive</h3><p>Extracts the embedded payload and checks its integrity. You still need the archive passphrase to decrypt it.</p>
                <div className="field"><label>CARRIER IMAGE</label><div className="path-control"><Image size={16}/><span className={carrierPath ? "path-value" : "path-placeholder"}>{carrierPath || "No PNG/BMP selected"}</span><button className="browse" onClick={async()=>{const p=await chooseFile("Select concealed PNG or BMP",["png","bmp"]);if(p){setCarrierPath(p);clearStatus();}}}>SELECT</button></div></div>
                <button className="execute secondary-action" disabled={busy} onClick={async()=>{const p=await chooseSave("Save extracted NCT archive","extracted.nct",["nct"]);if(p){setOutputPath(p);await runReveal(p);}}}><ArrowDownToLine size={17}/> EXTRACT NCT ARCHIVE</button>
              </div>
            </div>
            <div className="notice"><ShieldAlert size={16}/><span>Steganography does not encrypt data or guarantee that hidden data is undetectable. This single-image codec supports up to 16 MiB per payload. Use lossless PNG/BMP files; resizing, filters and social-media recompression can destroy embedded data. Always encrypt before concealing.</span></div>
          </section>}

          {section === "transfer" && <section className="operation-card">
            <div className="card-head"><div><div className="eyebrow">CONSTELLATION / FRAGMENT TRANSPORT</div><h2>Move encrypted archives in parts</h2></div><span className="index">NCFR / v1</span></div>
            <div className="workflow-grid">
              <div className="workflow-panel"><div className="workflow-icon"><Layers3 size={20}/></div><h3>Prepare a transfer</h3><p>Split an encrypted NCT archive into independently integrity-checked parts for separate delivery.</p>
                <div className="field"><label>ENCRYPTED NCT ARCHIVE</label><div className="path-control"><FileLock2 size={16}/><span className={archivePath ? "path-value" : "path-placeholder"}>{archivePath || "No archive selected"}</span><button className="browse" onClick={async()=>{const p=await chooseFile("Select encrypted NCT archive",["nct"]);if(p){setArchivePath(p);clearStatus();}}}>SELECT</button></div></div>
                <div className="field"><label>PART SIZE</label><div className="input-control"><Layers3 size={16}/><select value={partSize} onChange={e=>setPartSize(e.target.value)}><option value="1048576">1 MiB</option><option value="2097152">2 MiB</option><option value="4194304">4 MiB</option><option value="8388608">8 MiB</option></select></div></div>
                <button className="execute" disabled={busy} onClick={async()=>{const p=await chooseSave("Choose new transfer folder path","NOCTYRA-Transfer");if(p){setOutputPath(p);await runSplit(p);}}}><Network size={17}/> PREPARE TRANSFER PARTS</button>
              </div>
              <div className="workflow-panel"><div className="workflow-icon"><RefreshCw size={20}/></div><h3>Reassemble a transfer</h3><p>Select all received parts from the same transfer. Missing, duplicated, mixed or corrupted parts are rejected.</p>
                <div className="field"><label>RECEIVED PARTS / {transferParts.length} SELECTED</label><div className="path-control"><Layers3 size={16}/><span className={transferParts.length ? "path-value" : "path-placeholder"}>{transferParts.length ? transferParts.map(p=>p.split(/[\\/]/).pop()).join(", ") : "No transfer parts selected"}</span><button className="browse" onClick={pickParts}>SELECT</button></div></div>
                <button className="execute secondary-action" disabled={busy} onClick={async()=>{const p=await chooseSave("Save reassembled NCT archive","reassembled.nct",["nct"]);if(p){setOutputPath(p);await runJoin(p);}}}><ArrowDownToLine size={17}/> REASSEMBLE ARCHIVE</button>
              </div>
            </div>
            <div className="notice"><TriangleAlert size={16}/><span>CONSTELLATION fragmentation is not erasure-coded recovery. Every fragment is required in this first desktop workflow. Send the decryption passphrase through a separate trusted channel.</span></div>
          </section>}

          {section === "recovery" && <section className="operation-card">
            <div className="card-head"><div><div className="eyebrow">OFFLINE KEY CREDENTIAL</div><h2>Independent recovery key</h2></div><span className="index">256-BIT</span></div>
            <p className="panel-intro">Create a random 256-bit key file and use it as a separate credential for NCT archives. This mode is independent from passphrase-based encryption.</p>
            <div className="recovery-key-banner"><KeySquare size={24}/><div><b>{recoveryKeyPath ? "Recovery key selected" : "No recovery key selected"}</b><small>{recoveryKeyPath || "Generate a new key or select an existing 32-byte key file."}</small></div><button className="browse" onClick={async()=>{const p=await chooseFile("Select 32-byte recovery key",["key"]);if(p){setRecoveryKeyPath(p);clearStatus();}}}>SELECT KEY</button></div>
            <button className="execute secondary-action" disabled={busy} onClick={createRecoveryKey}><KeyRound size={17}/> GENERATE OFFLINE RECOVERY KEY</button>
            <div className="divider-line"/>
            <div className="form-grid">
              <div className="field full"><label>INPUT FILE OR NCT ARCHIVE</label><div className="path-control"><FileText size={16}/><span className={recoveryInputPath ? "path-value" : "path-placeholder"}>{recoveryInputPath || "Select input file"}</span><button className="browse" onClick={async()=>{const p=await chooseFile("Select file or archive");if(p)setRecoveryInputPath(p);}}>SELECT</button></div></div>
              <div className="field full"><label>OUTPUT PATH</label><div className="path-control"><FileLock2 size={16}/><span className={recoveryOutputPath ? "path-value" : "path-placeholder"}>{recoveryOutputPath || "Choose output location"}</span><button className="browse" onClick={async()=>{const p=await chooseSave("Choose output path","recovery-output.nct",["nct"]);if(p)setRecoveryOutputPath(p);}}>SELECT</button></div></div>
            </div>
            <div className="button-row"><button className="execute" disabled={busy} onClick={()=>runRecoveryKey(true)}><LockKeyhole size={17}/> ENCRYPT WITH RECOVERY KEY</button><button className="execute secondary-action" disabled={busy} onClick={()=>runRecoveryKey(false)}><ShieldCheck size={17}/> DECRYPT WITH RECOVERY KEY</button></div>
            <div className="notice"><TriangleAlert size={16}/><span>Anyone with this key can decrypt archives encrypted with it. Store it offline, keep a separate backup, and never transmit it alongside the encrypted archive. This is a separate credential mode, not yet a second unlock slot on the same archive.</span></div>
          </section>}

          {message && <div className={error ? "result error" : "result success"}>{error ? <TriangleAlert size={17}/> : <CheckCircle2 size={17}/>}<span>{message}</span></div>}
          <div className="bottom-grid"><div className="info-card"><div className="info-icon"><ShieldCheck size={18}/></div><div><b>Authenticated operations</b><p>Encrypted archives are verified before recovered output is published.</p></div></div><div className="info-card"><div className="info-icon"><Fingerprint size={18}/></div><div><b>Local-first processing</b><p>Files and keys are handled by the local Rust core, not uploaded to a server.</p></div></div></div>
          <footer><span>NOCTYRA CORE / DEVELOPMENT BUILD</span><span>NCT v1 / v2 <i>•</i> NOT YET AUDITED</span></footer>
        </div>
      </section>
    </main>
  );
}
export default App;
