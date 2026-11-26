import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  Activity, ArrowDownToLine, ArrowRight, ArrowUpRight, Check, CheckCircle2,
  ChevronRight, CircleHelp, CloudOff, FileArchive, FileImage, FileKey2,
  FileLock2, FileText, Fingerprint, Folder, FolderLock, KeyRound, Layers3,
  LockKeyhole, Menu, Network, RefreshCw, ScanLine, Shield, ShieldAlert,
  ShieldCheck, Sparkles, Upload, X
} from "lucide-react";

type Section = "vault" | "images" | "transfer" | "recovery";
type Mode = "encrypt" | "decrypt" | "encrypt-dir" | "decrypt-dir";
const isDirectoryMode = (mode: Mode) => mode.endsWith("-dir");
const isEncryption = (mode: Mode) => mode.startsWith("encrypt");

async function chooseFile(title: string, extensions?: string[]) {
  const result = await open({ title, multiple: false, directory: false, filters: extensions ? [{ name: "Supported files", extensions }] : undefined });
  return typeof result === "string" ? result : "";
}
async function chooseSave(title: string, defaultPath: string, extensions?: string[]) {
  return await save({ title, defaultPath, filters: extensions ? [{ name: "NOCTYRA files", extensions }] : undefined }) || "";
}
function fileName(path: string) { return path.split(/[\\\\/]/).pop() || path; }

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
    const path = await open({ multiple: false, directory: isDirectoryMode(mode), title: "Choose source" });
    if (typeof path === "string") { setInputPath(path); setOutputPath(""); clearStatus(); }
  }
  async function pickVaultOutput() {
    const path = await chooseSave("Save output", mode === "decrypt-dir" ? "recovered-folder" : isEncryption(mode) ? "archive.nct" : "recovered-file", isEncryption(mode) ? ["nct"] : undefined);
    if (path) setOutputPath(path);
  }
  async function runVault() {
    clearStatus();
    if (!inputPath || !outputPath || !password) { reportError("Choose a source and destination, then enter your passphrase."); return; }
    if (isEncryption(mode) && password !== confirmation) { reportError("The passphrase confirmation does not match."); return; }
    await execute(async () => {
      const commands: Record<Mode, string> = { encrypt: "encrypt_file", decrypt: "decrypt_file", "encrypt-dir": "encrypt_directory", "decrypt-dir": "decrypt_directory" };
      await invoke(commands[mode], { inputPath, outputPath, password });
      setPassword(""); setConfirmation("");
      return true;
    }, () => isEncryption(mode) ? "Your encrypted archive is ready." : "Authentication passed. Your recovered output is ready.");
  }
  async function runConceal(destination: string) {
    if (!archivePath || !carrierPath || !destination) { reportError("Choose an encrypted archive, a PNG/BMP image and an output location."); return; }
    await execute(() => invoke<number>("conceal_archive", { archivePath, carrierPath, outputPath: destination }), n => `Encrypted payload embedded (${n.toLocaleString()} bytes).`);
  }
  async function runReveal(destination: string) {
    if (!carrierPath || !destination) { reportError("Choose a carrier image and an output archive path."); return; }
    await execute(() => invoke<number>("reveal_archive", { carrierPath, outputPath: destination }), n => `Payload extracted and integrity-checked (${n.toLocaleString()} bytes).`);
  }
  async function runSplit(destination: string) {
    if (!archivePath || !destination) { reportError("Choose an encrypted archive and a new transfer folder."); return; }
    const size = Number(partSize);
    if (!Number.isSafeInteger(size) || size < 1024 || size > 8 * 1024 * 1024) { reportError("Part size must be between 1 KiB and 8 MiB."); return; }
    await execute(() => invoke<string[]>("constellation_split", { archivePath, outputDirectory: destination, fragmentBytes: size }), paths => `Transfer prepared: ${paths.length} integrity-checked parts created.`);
  }
  async function pickParts() {
    const result = await open({ title: "Select all parts from one transfer", multiple: true, filters: [{ name: "NOCTYRA transfer parts", extensions: ["ncfr"] }] });
    if (Array.isArray(result)) { setTransferParts(result); clearStatus(); }
  }
  async function runJoin(destination: string) {
    if (!transferParts.length || !destination) { reportError("Select transfer parts and an output archive path."); return; }
    await execute(() => invoke<number>("constellation_join", { fragmentPaths: transferParts, outputPath: destination }), n => `Transfer reassembled and archive digest verified (${n.toLocaleString()} bytes).`);
  }
  async function createRecoveryKey() {
    const path = await chooseSave("Save offline recovery key", "NOCTYRA-recovery.key", ["key"]);
    if (!path) return;
    await execute(() => invoke("generate_recovery_key", { outputPath: path }), () => { setRecoveryKeyPath(path); return "A new 256-bit recovery key was created. Store a separate offline backup."; });
  }
  async function runRecoveryKey(encrypt: boolean) {
    if (!recoveryInputPath || !recoveryOutputPath || !recoveryKeyPath) { reportError("Select the input, output and recovery-key files."); return; }
    await execute(() => invoke(encrypt ? "encrypt_file_with_recovery_key" : "decrypt_file_with_recovery_key", { inputPath: recoveryInputPath, outputPath: recoveryOutputPath, keyPath: recoveryKeyPath }), () => encrypt ? "Archive encrypted with the independent recovery key." : "Archive authenticated and recovered using the recovery key.");
  }

  const nav = [
    { id: "vault" as const, label: "Vault", sub: "Encrypt & decrypt", icon: LockKeyhole, number: "01" },
    { id: "images" as const, label: "Image studio", sub: "Hide & reveal", icon: ScanLine, number: "02" },
    { id: "transfer" as const, label: "Constellation", sub: "Transfer system", icon: Network, number: "03" },
    { id: "recovery" as const, label: "Recovery", sub: "Offline keys", icon: FileKey2, number: "04" },
  ];
  const current = nav.find(n => n.id === section)!;
  const title = section === "vault" ? "Your private space." : section === "images" ? "Beyond the visible." : section === "transfer" ? "Every piece has a place." : "Access, safeguarded.";
  const subtitle = section === "vault" ? "Protect the things that matter with a private, local-first vault." : section === "images" ? "Conceal an encrypted archive inside an ordinary image." : section === "transfer" ? "Break an archive into verified parts. Reassemble it when it arrives." : "Create an independent offline key for a separate recovery path.";

  return (
    <main className="noctyra-app">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-symbol"><span>N</span><i /></div>
          <div><div className="brand-name">NOCTYRA<span>.</span></div><div className="brand-caption">PRIVATE BY DESIGN</div></div>
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav className="side-nav">
          {nav.map(item => <button key={item.id} className={section === item.id ? "nav-link active" : "nav-link"} onClick={() => navigate(item.id)}>
            <span className="nav-icon"><item.icon size={17}/></span><span className="nav-copy"><b>{item.label}</b><small>{item.sub}</small></span><span className="nav-number">{item.number}</span>
          </button>)}
        </nav>
        <div className="sidebar-spacer"/>
        <div className="privacy-card"><div className="privacy-icon"><ShieldCheck size={17}/></div><div><b>Your files stay yours.</b><p>Processing happens on this device. No cloud account required.</p></div><span className="privacy-glow"/></div>
        <div className="sidebar-footer"><span className="online-dot"/><span>LOCAL CORE</span><span className="footer-version">v0.1.0</span></div>
      </aside>

      <section className="main-panel">
        <header className="topbar">
          <div className="breadcrumb"><span>NOCTYRA</span><ChevronRight size={13}/><b>{current.label}</b></div>
          <div className="topbar-right"><div className="local-pill"><span className="online-dot"/>{busy ? "SECURE OPERATION" : "ALL SYSTEMS LOCAL"}</div><div className="avatar-mark"><Shield size={16}/></div></div>
        </header>

        <div className="page-content">
          <section className="hero">
            <div className="hero-copy">
              <div className="eyebrow"><span className="eyebrow-line"/>{current.number} / NOCTYRA WORKSPACE</div>
              <h1>{title}</h1>
              <p>{subtitle}</p>
            </div>
            <div className="hero-art" aria-hidden="true">
              <div className="orb orb-one"/><div className="orb orb-two"/><div className="orb-core"><div className="orb-glyph">N</div></div>
              <div className="orbit orbit-a"/><div className="orbit orbit-b"/><div className="orbit-dot dot-a"/><div className="orbit-dot dot-b"/>
              <div className="art-label">END-TO-END <span>•</span> LOCAL</div>
            </div>
          </section>

          <section className="trust-row">
            <div className="trust-item"><span className="trust-icon"><Fingerprint size={15}/></span><span><b>ARGON2ID</b><small>KEY DERIVATION</small></span></div>
            <div className="trust-separator"/>
            <div className="trust-item"><span className="trust-icon"><LockKeyhole size={15}/></span><span><b>XCHACHA20</b><small>AUTHENTICATED ENCRYPTION</small></span></div>
            <div className="trust-separator"/>
            <div className="trust-item"><span className="trust-icon"><CloudOff size={15}/></span><span><b>OFFLINE FIRST</b><small>NO UPLOADS</small></span></div>
            <div className="trust-end"><span className="online-dot"/>{busy ? "WORKING" : "READY"}</div>
          </section>

          {section === "vault" && <section className="work-card">
            <div className="card-topline"><div><span className="section-kicker">SECURE VAULT</span><h2>What would you like to do?</h2><p>Choose an operation to get started. Your original files are never modified.</p></div><div className="card-index">01 <span>/</span> 04</div></div>
            <div className="mode-grid">
              <button className={mode === "encrypt" ? "mode-card chosen" : "mode-card"} onClick={() => changeMode("encrypt")}><span className="mode-icon"><LockKeyhole size={19}/></span><span className="mode-text"><b>Encrypt a file</b><small>Seal a single file into an .nct archive</small></span><span className="mode-arrow"><ArrowUpRight size={16}/></span></button>
              <button className={mode === "decrypt" ? "mode-card chosen" : "mode-card"} onClick={() => changeMode("decrypt")}><span className="mode-icon"><ShieldCheck size={19}/></span><span className="mode-text"><b>Decrypt an archive</b><small>Verify and recover your original file</small></span><span className="mode-arrow"><ArrowUpRight size={16}/></span></button>
              <button className={mode === "encrypt-dir" ? "mode-card chosen" : "mode-card"} onClick={() => changeMode("encrypt-dir")}><span className="mode-icon"><FolderLock size={19}/></span><span className="mode-text"><b>Protect a folder</b><small>Encrypt a complete directory tree</small></span><span className="mode-arrow"><ArrowUpRight size={16}/></span></button>
              <button className={mode === "decrypt-dir" ? "mode-card chosen" : "mode-card"} onClick={() => changeMode("decrypt-dir")}><span className="mode-icon"><Folder size={19}/></span><span className="mode-text"><b>Restore a folder</b><small>Recover a previously encrypted tree</small></span><span className="mode-arrow"><ArrowUpRight size={16}/></span></button>
            </div>
            <div className="form-divider"/>
            <div className="form-title"><div><span className="section-kicker">CONFIGURE OPERATION</span><h3>{mode === "encrypt" ? "Encrypt a file" : mode === "decrypt" ? "Decrypt an archive" : mode === "encrypt-dir" ? "Encrypt a folder" : "Restore a folder"}</h3></div><span className="secure-tag"><ShieldCheck size={13}/> PRIVATE SESSION</span></div>
            <div className="file-flow">
              <div className="file-step"><div className="step-label"><span>01</span>{isDirectoryMode(mode) ? "SOURCE FOLDER" : "SOURCE FILE"}</div><button className={inputPath ? "drop-card has-file" : "drop-card"} onClick={pickVaultInput}><span className="drop-icon">{inputPath ? isDirectoryMode(mode) ? <Folder size={21}/> : <FileText size={21}/> : <Upload size={21}/>}</span><span className="drop-copy"><b>{inputPath ? fileName(inputPath) : "Choose a file to protect"}</b><small>{inputPath ? inputPath : "Browse your device to select a source"}</small></span><span className="drop-action">{inputPath ? "CHANGE" : "BROWSE"}</span></button></div>
              <div className="flow-connector"><ArrowRight size={16}/></div>
              <div className="file-step"><div className="step-label"><span>02</span>OUTPUT DESTINATION</div><button className={outputPath ? "drop-card has-file" : "drop-card"} onClick={pickVaultOutput}><span className="drop-icon"><FileArchive size={21}/></span><span className="drop-copy"><b>{outputPath ? fileName(outputPath) : "Choose where to save"}</b><small>{outputPath ? outputPath : isEncryption(mode) ? "Your encrypted .nct archive" : "Your recovered output"}</small></span><span className="drop-action">{outputPath ? "CHANGE" : "SELECT"}</span></button></div>
            </div>
            <div className="passphrase-grid">
              <label className="input-field"><span className="step-label"><span>03</span> PASSPHRASE</span><span className="input-shell"><KeyRound size={16}/><input type="password" autoComplete="new-password" placeholder="Enter a strong passphrase" value={password} onChange={e => setPassword(e.target.value)}/></span></label>
              {isEncryption(mode) && <label className="input-field"><span className="step-label"><span>04</span> CONFIRM PASSPHRASE</span><span className="input-shell"><KeyRound size={16}/><input type="password" autoComplete="new-password" placeholder="Confirm your passphrase" value={confirmation} onChange={e => setConfirmation(e.target.value)}/></span></label>}
            </div>
            <div className="card-action-row"><div className="safety-note"><ShieldAlert size={15}/><span>Keep your passphrase safe. It cannot be recovered if lost.</span></div><button className="primary-button" disabled={busy} onClick={runVault}>{busy ? <span className="spinner"/> : isEncryption(mode) ? <LockKeyhole size={17}/> : <ArrowDownToLine size={17}/>}<span>{busy ? "Processing securely…" : isEncryption(mode) ? "Encrypt securely" : "Verify & recover"}</span><ArrowRight size={16}/></button></div>
          </section>}

          {section === "images" && <section className="work-card">
            <div className="card-topline"><div><span className="section-kicker">IMAGE CARRIER STUDIO</span><h2>Keep the message out of sight.</h2><p>Start with an encrypted archive. The image is a carrier, not a replacement for encryption.</p></div><div className="card-index">PNG <span>/</span> BMP</div></div>
            <div className="studio-grid">
              <div className="studio-card"><div className="studio-visual conceal-visual"><div className="visual-image"><FileImage size={39}/><span>IMAGE</span></div><div className="visual-lock"><LockKeyhole size={17}/></div><div className="visual-pulse"/></div><div className="studio-heading"><div><h3>Conceal archive</h3><p>Embed an encrypted .nct archive into a lossless image.</p></div><span className="studio-number">01</span></div>
                <div className="mini-field"><span>ENCRYPTED ARCHIVE</span><button onClick={async()=>{const p=await chooseFile("Select encrypted NCT archive",["nct"]);if(p){setArchivePath(p);clearStatus();}}}><FileArchive size={15}/>{archivePath ? fileName(archivePath) : "Choose .nct archive"}<ChevronRight size={14}/></button></div>
                <div className="mini-field"><span>CARRIER IMAGE</span><button onClick={async()=>{const p=await chooseFile("Select PNG or BMP carrier",["png","bmp"]);if(p){setCarrierPath(p);clearStatus();}}}><FileImage size={15}/>{carrierPath ? fileName(carrierPath) : "Choose PNG or BMP"}<ChevronRight size={14}/></button></div>
                <button className="primary-button full-button" disabled={busy} onClick={async()=>{const p=await chooseSave("Save concealed image","NOCTYRA-concealed.png",["png"]);if(p)await runConceal(p);}}>Conceal into image <ArrowRight size={16}/></button>
              </div>
              <div className="studio-card"><div className="studio-visual reveal-visual"><div className="reveal-frame"><ScanLine size={37}/><span>SCAN CARRIER</span></div><div className="reveal-rays"/></div><div className="studio-heading"><div><h3>Reveal archive</h3><p>Extract and validate an embedded NOCTYRA payload.</p></div><span className="studio-number">02</span></div>
                <div className="mini-field"><span>CARRIER IMAGE</span><button onClick={async()=>{const p=await chooseFile("Select concealed PNG or BMP",["png","bmp"]);if(p){setCarrierPath(p);clearStatus();}}}><FileImage size={15}/>{carrierPath ? fileName(carrierPath) : "Choose concealed image"}<ChevronRight size={14}/></button></div>
                <div className="mini-field"><span>OUTPUT ARCHIVE</span><div className="mini-static"><FileArchive size={15}/> Extracted .nct archive</div></div>
                <button className="primary-button full-button" disabled={busy} onClick={async()=>{const p=await chooseSave("Save extracted NCT archive","extracted.nct",["nct"]);if(p)await runReveal(p);}}>Extract archive <ArrowRight size={16}/></button>
              </div>
            </div>
            <div className="inline-warning"><ShieldAlert size={16}/><span>Steganography cannot guarantee undetectability. This single-image codec supports up to 16 MiB per payload. Image resizing or lossy recompression can destroy embedded data.</span></div>
          </section>}

          {section === "transfer" && <section className="work-card">
            <div className="card-topline"><div><span className="section-kicker">CONSTELLATION / TRANSPORT</span><h2>Send it in pieces. Rebuild it intact.</h2><p>Prepare integrity-checked fragments for transfer through your chosen channel.</p></div><div className="card-index">NCFR <span>/</span> V1</div></div>
            <div className="constellation-art"><div className="constellation-node main-node"><ShieldCheck size={22}/><b>ENCRYPTED</b><small>ARCHIVE</small></div><div className="constellation-lines"><i/><i/><i/><i/><i/></div><div className="constellation-parts">{[1,2,3,4,5].map(n=><span key={n} className={transferParts.length ? "part-node lit" : "part-node"}>{String(n).padStart(2,"0")}</span>)}</div><div className="constellation-caption">ONE ARCHIVE <span>→</span> VERIFIED FRAGMENTS</div></div>
            <div className="transfer-grid">
              <div className="transfer-panel"><span className="section-kicker">01 / PREPARE</span><h3>Fragment an archive</h3><p>Select your encrypted archive and choose a fragment size.</p><button className="file-select" onClick={async()=>{const p=await chooseFile("Select encrypted NCT archive",["nct"]);if(p){setArchivePath(p);clearStatus();}}}><FileArchive size={17}/><span><b>{archivePath ? fileName(archivePath) : "Select encrypted archive"}</b><small>{archivePath || "NCT file"}</small></span><ChevronRight size={15}/></button><label className="select-label">FRAGMENT SIZE<select value={partSize} onChange={e=>setPartSize(e.target.value)}><option value="1048576">1 MiB</option><option value="2097152">2 MiB</option><option value="4194304">4 MiB</option><option value="8388608">8 MiB</option></select></label><button className="primary-button full-button" disabled={busy} onClick={async()=>{const p=await chooseSave("Choose new transfer folder","NOCTYRA-Transfer");if(p)await runSplit(p);}}>Prepare transfer <ArrowRight size={16}/></button></div>
              <div className="transfer-panel"><span className="section-kicker">02 / REASSEMBLE</span><h3>Rebuild received parts</h3><p>Select all parts belonging to the same transfer. Order does not matter.</p><button className="file-select" onClick={pickParts}><Layers3 size={17}/><span><b>{transferParts.length ? transferParts.length + " parts selected" : "Select transfer parts"}</b><small>{transferParts.length ? transferParts.map(fileName).slice(0,3).join(", ") : "Multiple .ncfr files"}</small></span><ChevronRight size={15}/></button><div className="part-count"><span>PARTS SELECTED</span><b>{String(transferParts.length).padStart(2,"0")}</b></div><button className="primary-button full-button" disabled={busy || !transferParts.length} onClick={async()=>{const p=await chooseSave("Save reassembled archive","reassembled.nct",["nct"]);if(p)await runJoin(p);}}>Reassemble archive <ArrowRight size={16}/></button></div>
            </div>
            <div className="inline-warning"><ShieldAlert size={16}/><span>This first GUI transfer workflow requires every fragment. Reed-Solomon recovery and signed sender verification are not yet connected to this screen.</span></div>
          </section>}

          {section === "recovery" && <section className="work-card">
            <div className="card-topline"><div><span className="section-kicker">OFFLINE CREDENTIALS</span><h2>A second path to your data.</h2><p>Create a separate 256-bit key and keep it somewhere safe, offline and independent.</p></div><div className="card-index">256 <span>/</span> BIT</div></div>
            <div className="key-hero"><div className="key-art"><div className="key-ring"/><div className="key-core"><KeyRound size={30}/></div><div className="key-orbit orbit-left"/><div className="key-orbit orbit-right"/></div><div className="key-summary"><span className="section-kicker">RECOVERY KEY STATUS</span><h3>{recoveryKeyPath ? "Key selected" : "No recovery key yet"}</h3><p>{recoveryKeyPath ? fileName(recoveryKeyPath) : "Generate a new key or select an existing 32-byte key file."}</p><div className="key-actions"><button className="primary-button" disabled={busy} onClick={createRecoveryKey}><KeyRound size={16}/> Generate key</button><button className="quiet-button" onClick={async()=>{const p=await chooseFile("Select 32-byte recovery key",["key"]);if(p){setRecoveryKeyPath(p);clearStatus();}}}>Choose existing key</button></div></div></div>
            <div className="form-divider"/>
            <div className="form-title"><div><span className="section-kicker">USE YOUR RECOVERY KEY</span><h3>Encrypt or recover a file</h3></div><span className="secure-tag"><ShieldCheck size={13}/> OFFLINE CREDENTIAL</span></div>
            <div className="recovery-form"><div className="mini-field"><span>INPUT FILE / ARCHIVE</span><button onClick={async()=>{const p=await chooseFile("Select input file or archive");if(p)setRecoveryInputPath(p);}}><FileText size={15}/>{recoveryInputPath ? fileName(recoveryInputPath) : "Choose input"}<ChevronRight size={14}/></button></div><div className="mini-field"><span>OUTPUT LOCATION</span><button onClick={async()=>{const p=await chooseSave("Choose output path","recovery-output.nct",["nct"]);if(p)setRecoveryOutputPath(p);}}><FileArchive size={15}/>{recoveryOutputPath ? fileName(recoveryOutputPath) : "Choose output"}<ChevronRight size={14}/></button></div></div>
            <div className="button-pair"><button className="primary-button" disabled={busy} onClick={()=>runRecoveryKey(true)}><LockKeyhole size={16}/> Encrypt with key <ArrowRight size={15}/></button><button className="secondary-button" disabled={busy} onClick={()=>runRecoveryKey(false)}><ShieldCheck size={16}/> Decrypt with key <ArrowRight size={15}/></button></div>
            <div className="inline-warning"><ShieldAlert size={16}/><span>Anyone with this key can decrypt archives encrypted with it. This is a separate credential mode, not yet a second unlock slot for an existing passphrase archive.</span></div>
          </section>}

          {message && <div className={error ? "result-banner error" : "result-banner success"}>{error ? <ShieldAlert size={17}/> : <CheckCircle2 size={17}/>}<span>{message}</span><button onClick={clearStatus} aria-label="Dismiss message"><X size={15}/></button></div>}
          {busy && <div className="operation-progress"><div className="progress-copy"><span className="online-dot"/>SECURE OPERATION IN PROGRESS</div><div className="progress-track"><span/></div><small>Keep NOCTYRA open until this operation finishes. No progress percentage is available from this backend yet.</small></div>}
          <footer className="app-footer"><span>NOCTYRA <i>•</i> BUILT FOR PRIVACY</span><span><span className="online-dot"/> LOCAL PROCESSING <i>•</i> DEVELOPMENT BUILD</span></footer>
        </div>
      </section>
    </main>
  );
}
export default App;
