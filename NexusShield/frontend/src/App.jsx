import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertCircle, ArrowDownRight, ArrowUpRight, Bell, Check, Clock3,
  FileText, Fingerprint, Globe2, LoaderCircle, LockKeyhole,
  Menu, MessageSquareWarning, Search, Send, Shield, ShieldCheck, Sparkles,
  Upload, X,
} from "lucide-react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Sidebar from "./components/Sidebar.jsx";
import RiskResult from "./components/RiskResult.jsx";
import { api } from "./services/api.js";

const titles = {
  overview: ["Security overview", "Your personal threat intelligence at a glance."],
  message: ["Message scanner", "Check suspicious SMS, chat messages, and email text."],
  url: ["URL scanner", "Inspect a link's structure without opening it."],
  email: ["Email analyzer", "Review message language and sender details."],
  documents: ["Document intelligence", "Search only the documents you choose to index."],
  history: ["Scan history", "Review or clear your locally recorded analysis history."],
  education: ["Security guide", "Practical steps to reduce your exposure to common scams."],
  settings: ["Privacy settings", "Choose what NEXUS SHIELD stores on this device."],
};

export default function App() {
  const [active, setActive] = useState("overview");
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [notes, setNotes] = useState([]);
  const [documents, setDocuments] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [result, setResult] = useState(null);
  const [message, setMessage] = useState("");
  const [url, setUrl] = useState("");
  const [email, setEmail] = useState({ subject: "", body: "", sender: "", reply_to: "", link_text: "" });
  const [docQuery, setDocQuery] = useState("");
  const [docResults, setDocResults] = useState(null);
  const [docBusy, setDocBusy] = useState(false);
  const [includeContent, setIncludeContent] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [nextStats, nextHistory, nextSettings, nextNotes, nextDocuments] = await Promise.all([
        api.stats(), api.history(), api.settings(), api.notes(), api.documents(),
      ]);
      setStats(nextStats);
      setHistory(Array.isArray(nextHistory) ? nextHistory : nextHistory.items || nextHistory.records || []);
      setIncludeContent(nextSettings.save_scan_content);
      setNotes(nextNotes);
      setDocuments(nextDocuments);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }, []);
  useEffect(() => { refresh(); }, [refresh]);

  const navigate = (id) => { setActive(id); setResult(null); setError(""); setMobileOpen(false); };
  const runScan = async (scan) => {
    setError("");
    setResult(null);
    setBusy(true);
    try {
      const value = await scan();
      setResult(value);
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };
  const showToast = (text) => { setToast(text); window.setTimeout(() => setToast(""), 2800); };
  const saveContentPreference = async (checked) => {
    setError("");
    try {
      const saved = await api.updateSettings({ save_scan_content: checked });
      setIncludeContent(saved.save_scan_content);
      showToast("Privacy preference saved locally.");
    } catch (err) {
      setError(err.message);
    }
  };
  const riskCounts = useMemo(() => ({
    high: stats?.high_risk_scans || 0,
    medium: stats?.suspicious_scans || 0,
    low: stats?.low_risk_scans || 0,
  }), [stats]);
  const scansTotal = stats?.total_scans ?? stats?.total ?? history.length;
  const trend = stats?.trend || stats?.daily_scans || [];
  const highCount = Number(riskCounts.high || riskCounts.High || 0) + Number(riskCounts.critical || riskCounts.Critical || 0);

  return (
    <div className="app-shell">
      <Sidebar active={active} onNavigate={navigate} />
      <main className="main-area">
        <header className="topbar">
          <button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileOpen(!mobileOpen)}><Menu size={20} /></button>
          <div className="breadcrumbs"><span>Workspace</span><span className="crumb-separator">/</span><strong>{titles[active][0]}</strong></div>
          <div className="topbar-actions"><span className="local-status"><span className="status-dot" /> System operational</span><button className="icon-button" aria-label="Refresh dashboard" onClick={refresh}><Bell size={18} /></button><div className="avatar">NS</div></div>
        </header>
        {mobileOpen && <div className="mobile-sidebar"><button className="icon-button close-menu" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X /></button><Sidebar active={active} onNavigate={navigate} /></div>}
        <div className="page-content">
          <div className="page-title-row"><div><span className="eyebrow">NEXUS SHIELD <span className="title-divider">/</span> {active.toUpperCase()}</span><h1>{titles[active][0]}</h1><p>{titles[active][1]}</p></div>{active === "overview" && <button className="primary-button" onClick={() => navigate("message")}><Sparkles size={16} /> New analysis</button>}</div>
          {error && <div className="error-banner"><AlertCircle size={17} /><span>{error}</span><button onClick={() => { setError(""); refresh(); }}>Retry</button></div>}
          {active === "overview" && <Overview stats={stats} total={scansTotal} highCount={highCount} riskCounts={riskCounts} trend={trend} history={history} navigate={navigate} />}
          {active === "message" && <div className="content-grid"><section className="panel scan-panel"><PanelHeader icon={<MessageSquareWarning />} title="Analyze a message" text="Paste message content to check for common social-engineering signals."/><form onSubmit={(e) => { e.preventDefault(); runScan(() => api.analyzeMessage(message, includeContent)); }}><label htmlFor="message">Message content</label><textarea id="message" rows="8" maxLength="12000" value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Paste a suspicious text, chat message, or email body..." required /><div className="input-meta"><span>Do not paste passwords, OTPs, or other secrets.</span><span>{message.length}/12000</span></div><button className="primary-button wide" disabled={busy || !message.trim()}>{busy ? <LoaderCircle className="spin" size={17} /> : <Search size={17} />}{busy ? "Analyzing..." : "Analyze message"}</button></form><div className="privacy-hint"><LockKeyhole size={15} /> {includeContent ? "Full content will be saved with scans." : "Scans are stored without full message text by default."}</div></section><div className="results-column">{result ? <RiskResult result={result} /> : <EmptyState icon={<ShieldCheck />} title="Your analysis will appear here" text="We look for indicators, not certainty. Review evidence before taking action." />}</div></div>}
          {active === "url" && <div className="content-grid"><section className="panel scan-panel"><PanelHeader icon={<Globe2 />} title="Inspect a URL" text="Analyze the link's shape and hostname. The URL is never visited."/><form onSubmit={(e) => { e.preventDefault(); runScan(() => api.analyzeUrl(url, includeContent)); }}><label htmlFor="url">URL to inspect</label><div className="input-with-icon"><Globe2 size={17} /><input id="url" type="text" maxLength="2048" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/path" required /></div><div className="url-warning"><AlertCircle size={15} /> Never open suspicious links to “test” them. HTTPS encrypts a connection but does not prove a site is trustworthy.</div><button className="primary-button wide" disabled={busy || !url.trim()}>{busy ? <LoaderCircle className="spin" size={17} /> : <Search size={17} />}{busy ? "Analyzing..." : "Analyze URL"}</button></form><div className="privacy-hint"><LockKeyhole size={15} /> {includeContent ? "The submitted URL will be saved with scans." : "URLs are not saved in full by default."}</div></section><div className="results-column">{result ? <RiskResult result={result} /> : <EmptyState icon={<Globe2 />} title="Link inspection results" text="No network or reputation lookup will be performed." />}</div></div>}
          {active === "email" && <div className="content-grid"><section className="panel scan-panel"><PanelHeader icon={<Send />} title="Review an email" text="Check the email language and compare its sender details."/><form onSubmit={(e) => { e.preventDefault(); runScan(() => api.analyzeEmail(email, includeContent)); }}><label htmlFor="subject">Subject <span className="optional">optional</span></label><input id="subject" value={email.subject} onChange={(e) => setEmail({ ...email, subject: e.target.value })} maxLength="300" placeholder="Email subject" /><label htmlFor="sender">Sender address <span className="optional">optional, unverified</span></label><input id="sender" type="text" value={email.sender} onChange={(e) => setEmail({ ...email, sender: e.target.value })} maxLength="320" placeholder="sender@example.com" /><label htmlFor="reply-to">Reply-to address <span className="optional">optional</span></label><input id="reply-to" type="text" value={email.reply_to} onChange={(e) => setEmail({ ...email, reply_to: e.target.value })} maxLength="320" placeholder="reply@example.com" /><label htmlFor="email-body">Email body</label><textarea id="email-body" rows="6" maxLength="12000" value={email.body} onChange={(e) => setEmail({ ...email, body: e.target.value })} placeholder="Paste the email body..." /><label htmlFor="link-text">Link text or URL <span className="optional">optional</span></label><input id="link-text" value={email.link_text} onChange={(e) => setEmail({ ...email, link_text: e.target.value })} maxLength="2048" placeholder="Text displayed for a link" /><button className="primary-button wide" disabled={busy || !email.body.trim()}>{busy ? <LoaderCircle className="spin" size={17} /> : <Search size={17} />}{busy ? "Analyzing..." : "Analyze email"}</button></form><div className="privacy-hint"><LockKeyhole size={15} /> {includeContent ? "Full email content will be saved with scans." : "Scans are stored without full email text by default."}</div></section><div className="results-column">{result ? <RiskResult result={result} /> : <EmptyState icon={<Send />} title="Email findings will appear here" text="Sender identity is not verified by this local analysis." />}</div></div>}
          {active === "documents" && <Documents documents={documents} refresh={refresh} docQuery={docQuery} setDocQuery={setDocQuery} docResults={docResults} setDocResults={setDocResults} docBusy={docBusy} setDocBusy={setDocBusy} showToast={showToast} setError={setError} />}
          {active === "history" && <History history={history} refresh={refresh} showToast={showToast} setError={setError} />}
          {active === "education" && <Education />}
          {active === "settings" && <Settings includeContent={includeContent} saveContentPreference={saveContentPreference} notes={notes} refresh={refresh} showToast={showToast} setError={setError} />}
          <footer className="page-footer"><span><ShieldCheck size={14} /> Private by default. Built for awareness, not guarantees.</span><span>Analysis is an estimate, not a security certification.</span></footer>
        </div>
      </main>
      {toast && <div className="toast"><Check size={16} />{toast}</div>}
    </div>
  );
}

function PanelHeader({ icon, title, text }) {
  return <div className="panel-header"><div className="panel-icon">{icon}</div><div><h2>{title}</h2><p>{text}</p></div></div>;
}

function EmptyState({ icon, title, text }) {
  return <div className="empty-state"><div className="empty-icon">{icon}</div><h3>{title}</h3><p>{text}</p><span className="empty-dash" /></div>;
}

function Overview({ stats, total, highCount, riskCounts, trend, history, navigate }) {
  const chartData = trend.map((point) => ({ date: point.date || point.day || "", scans: point.count ?? point.scans ?? 0 }));
  const recent = history.slice(0, 5);
  const dist = [
    ["High", riskCounts.high || riskCounts.High || 0, "high"],
    ["Medium", riskCounts.medium || riskCounts.Medium || 0, "medium"],
    ["Low", riskCounts.low || riskCounts.Low || 0, "low"],
  ];
  return <>
    <div className="stats-grid">
      <StatCard label="Total analyses" value={total} note="All-time local scans" icon={<Fingerprint />} accent="cyan" />
      <StatCard label="High-risk findings" value={highCount} note="Review before acting" icon={<AlertCircle />} accent="orange" />
      <StatCard label="Indexed documents" value={stats?.indexed_documents ?? stats?.document_count ?? 0} note="Available for local search" icon={<FileText />} accent="purple" />
      <StatCard label="Analysis engine" value="Active" note="Rule-based baseline" icon={<ShieldCheck />} accent="green" />
    </div>
    <div className="dashboard-grid">
      <section className="panel chart-panel"><div className="section-heading"><div><h2>Scan activity</h2><p>Recent analysis volume recorded locally</p></div><span className="chart-tag">RECENT</span></div>
        {chartData.length ? <ResponsiveContainer width="100%" height={220}><AreaChart data={chartData} margin={{ top: 10, right: 8, left: -18, bottom: 0 }}><defs><linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#19c8d8" stopOpacity={0.3} /><stop offset="100%" stopColor="#19c8d8" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#1d2d40" strokeDasharray="4 5" vertical={false} /><XAxis dataKey="date" tick={{ fill: "#718399", fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "#718399", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: "#101d2d", border: "1px solid #26394d", borderRadius: 8, color: "#e8f0f8" }} /><Area type="monotone" dataKey="scans" stroke="#19c8d8" strokeWidth={2} fill="url(#scanGradient)" /></AreaChart></ResponsiveContainer> : <div className="chart-empty"><Clock3 size={20} /><span>Scan activity will appear as you use the analyzers.</span></div>}
      </section>
      <section className="panel risk-panel"><div className="section-heading"><div><h2>Risk distribution</h2><p>Based on recorded scan results</p></div><Shield size={17} /></div><div className="distribution">{dist.map(([label, value, tone]) => <div className="distribution-row" key={label}><div className={`dist-icon ${tone}`}><span /></div><span className="dist-label">{label}</span><div className="dist-track"><span className={tone} style={{ width: `${total ? Math.min(100, (Number(value) / Number(total)) * 100) : 0}%` }} /></div><strong>{value}</strong></div>)}</div><div className="risk-footnote"><AlertCircle size={14} /> Risk levels represent matched indicators—not confirmed incidents.</div></section>
    </div>
    <section className="panel recent-panel"><div className="section-heading"><div><h2>Recent findings</h2><p>Your latest scans</p></div><button className="text-button" onClick={() => navigate("history")}>View history <ArrowUpRight size={15} /></button></div><HistoryTable items={recent} onEmpty={() => navigate("message")} /></section>
    <section className="safety-banner"><div className="safety-icon"><ShieldCheck size={22} /></div><div><strong>Pause before you act.</strong><p>Urgent requests for money, passwords, or one-time codes deserve independent verification.</p></div><button onClick={() => navigate("education")}>Explore safety guide <ArrowDownRight size={16} /></button></section>
  </>;
}

function StatCard({ label, value, note, icon, accent }) {
  return <div className="stat-card"><div className={`stat-icon ${accent}`}>{icon}</div><span className="stat-label">{label}</span><strong className="stat-value">{value}</strong><span className="stat-note">{note}</span></div>;
}

function HistoryTable({ items, onEmpty }) {
  if (!items.length) return <div className="history-empty"><span>No scans recorded yet.</span><button className="text-button" onClick={onEmpty}>Run your first analysis <ArrowUpRight size={14} /></button></div>;
  return <div className="table-scroll"><table><thead><tr><th>TYPE</th><th>SUMMARY</th><th>RISK</th><th>DATE</th></tr></thead><tbody>{items.map((item, i) => {
    const type = item.scan_type || item.type || item.analysis_type || "Scan";
    const rawLevel = String(item.risk_level || item.verdict || "unknown").toLowerCase();
    const level = rawLevel === "suspicious" ? "medium" : rawLevel.replace("_risk", "");
    return <tr key={item.id || `${type}-${i}`}><td><span className="type-cell"><span className={`type-dot ${level}`} />{type}</span></td><td className="summary-cell">{item.summary || item.input_preview || item.target || item.subject || "Analysis completed"}</td><td><span className={`risk-badge ${level}`}>{level}</span></td><td className="date-cell">{formatDate(item.created_at || item.timestamp)}</td></tr>;
  })}</tbody></table></div>;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function Documents({ documents, refresh, docQuery, setDocQuery, docResults, setDocResults, docBusy, setDocBusy, showToast, setError }) {
  const [fileBusy, setFileBusy] = useState(false);
  async function upload(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (!/\.(txt|pdf)$/i.test(file.name)) { setError("Only TXT and PDF documents are accepted."); return; }
    setFileBusy(true); setError("");
    try {
      const uploaded = await api.uploadDocument(file);
      await refresh();
      showToast(uploaded.message || `${uploaded.filename} indexed locally.`);
    } catch (err) { setError(err.message); } finally { setFileBusy(false); }
  }
  async function removeDocument(id) {
    setError("");
    try {
      await api.deleteDocument(id);
      await refresh();
      showToast("Indexed document deleted.");
    } catch (err) { setError(err.message); }
  }
  async function search(event) {
    event.preventDefault();
    if (!docQuery.trim()) { setError("Enter a question or search phrase."); return; }
    setError(""); setDocResults(null); setDocBusy(true);
    try { setDocResults(await api.searchDocuments(docQuery)); } catch (err) { setError(err.message); } finally { setDocBusy(false); }
  }
  const matches = Array.isArray(docResults) ? docResults : docResults?.results || docResults?.passages || [];
  return <div className="doc-layout"><section className="panel doc-intro"><PanelHeader icon={<FileText />} title="Local knowledge base" text="Upload files you are authorized to use. Text is extracted and indexed on this device."/><div className="upload-zone"><input id="document-file" type="file" accept=".txt,.pdf,text/plain,application/pdf" onChange={upload} disabled={fileBusy} /><div className="upload-icon">{fileBusy ? <LoaderCircle className="spin" /> : <Upload />}</div><strong>{fileBusy ? "Indexing document..." : "Choose a document to index"}</strong><span>TXT or PDF · processed locally</span><label className="secondary-button" htmlFor="document-file">{fileBusy ? "Please wait" : "Browse files"}</label></div><div className="doc-safety"><LockKeyhole size={15} /><span>Documents are untrusted reference material—not instructions for the application.</span></div><div className="indexed-documents"><h3>Indexed documents <span>{documents.length}</span></h3>{documents.length ? documents.map((doc) => <div className="indexed-document" key={doc.id}><FileText size={14} /><div><strong>{doc.filename}</strong><span>{formatDate(doc.created_at)}</span></div><button className="icon-button" aria-label={`Delete ${doc.filename}`} onClick={() => removeDocument(doc.id)}><X size={15} /></button></div>) : <p>No documents indexed. Your uploaded documents can be removed here.</p>}</div></section><section className="panel doc-search"><PanelHeader icon={<Search />} title="Search your documents" text="Ask a question or enter keywords to find relevant passages."/><form className="doc-search-form" onSubmit={search}><input value={docQuery} onChange={(e) => setDocQuery(e.target.value)} maxLength="500" placeholder="e.g. What does my bank say about reporting fraud?" /><button className="primary-button" disabled={docBusy}>{docBusy ? <LoaderCircle className="spin" size={17} /> : <Search size={17} />}{docBusy ? "Searching" : "Search"}</button></form>{docResults && <div className="doc-results">{matches.length ? matches.map((item, index) => <article className="passage-card" key={item.id || index}><div><FileText size={14} /><strong>{item.filename || item.source || "Local document"}</strong>{(item.page || item.page_number) && <span>Page {item.page || item.page_number}</span>}</div><p>{item.text || item.content || item.passage || item.snippet || "No passage text was returned."}</p></article>) : <p className="no-evidence">No matching evidence was found. The indexed documents may not contain enough information to answer this.</p>}</div>}</section></div>;
}

function History({ history, refresh, showToast, setError }) {
  const [clearing, setClearing] = useState(false);
  async function clear() {
    if (!window.confirm("Delete all recorded scan history? This cannot be undone.")) return;
    setClearing(true); setError("");
    try { await api.clearHistory(); await refresh(); showToast("Scan history cleared."); } catch (err) { setError(err.message); } finally { setClearing(false); }
  }
  return <section className="panel history-panel"><div className="section-heading"><div><h2>Recorded analyses</h2><p>Stored locally; full message content is not saved by default.</p></div><button className="danger-button" onClick={clear} disabled={clearing || !history.length}>{clearing ? <LoaderCircle className="spin" size={15} /> : <X size={15} />}{clearing ? "Clearing" : "Clear history"}</button></div><HistoryTable items={history} onEmpty={() => {}} /></section>;
}

function Education() {
  const guidance = [
    ["Suspicious messages", "Slow down when a message creates urgency. Verify the request through a known, independent contact channel—not by replying to the message."],
    ["Unsafe links", "Check the full hostname before entering information. Avoid shortened or unexpected links. HTTPS encrypts traffic but does not establish that a site is legitimate."],
    ["Impersonation", "Caller ID, display names, and sender addresses can be spoofed. Contact the organization using a number or website you already trust."],
    ["Credentials and payment", "Never share passwords, one-time codes, or recovery phrases. Do not pay unexpected fees or move money based only on a message."],
    ["Attachments", "Do not open unexpected files. This tool does not execute or detonate attachments; use your organization's approved security process."],
    ["If you already responded", "Contact your bank or service provider using an official channel, change affected credentials from a trusted device, and report the incident to the relevant authority."],
  ];
  return <div className="education-grid">{guidance.map(([title, body], i) => <article className="panel education-card" key={title}><div className="edu-number">0{i + 1}</div><div><h2>{title}</h2><p>{body}</p></div></article>)}</div>;
}

function Settings({ includeContent, saveContentPreference, notes, refresh, showToast, setError }) {
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  async function saveNote(event) {
    event.preventDefault();
    if (!draft.trim()) { setError("Enter a note before saving."); return; }
    setSaving(true); setError("");
    try {
      await api.createNote(draft.trim());
      setDraft("");
      await refresh();
      showToast("Security note saved on this device.");
    } catch (err) { setError(err.message); } finally { setSaving(false); }
  }
  async function deleteNote(id) {
    setError("");
    try { await api.deleteNote(id); await refresh(); showToast("Security note deleted."); }
    catch (err) { setError(err.message); }
  }
  return <div className="settings-layout">
    <section className="panel settings-panel"><PanelHeader icon={<LockKeyhole />} title="Data and privacy" text="Your scans are processed locally by the backend you run. No third-party API is required."/><div className="setting-row"><div><strong>Allow full submitted content in scan history</strong><p>{includeContent ? "Enabled. Full content is stored only when an individual scan also opts in. Turn this off to prevent future content retention." : "Off by default. Enable only if you want to retain content; each scan also sends an explicit opt-in."}</p></div><button className={`toggle ${includeContent ? "on" : ""}`} role="switch" aria-checked={includeContent} onClick={() => saveContentPreference(!includeContent)}><span /></button></div><div className="setting-row"><div><strong>External reputation checks</strong><p>Unavailable in this MVP. URLs are never automatically visited and content is not sent to external services.</p></div><span className="unavailable-label">NOT CONNECTED</span></div><div className="setting-row"><div><strong>Local document index</strong><p>Documents you upload are available for on-device keyword search.</p></div><span className="enabled-label"><span className="status-dot" /> ENABLED</span></div></section>
    <section className="panel settings-panel"><PanelHeader icon={<ShieldCheck />} title="Approved security notes" text="Save only context you explicitly choose to remember. Avoid passwords, one-time codes, and other secrets."/><form onSubmit={saveNote}><label htmlFor="security-note">New note</label><textarea id="security-note" rows="3" maxLength="2000" value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="For example: My bank's official fraud-reporting phone number is saved in my contacts."/><div className="note-form-footer"><span>{draft.length}/2000 · stored in local SQLite</span><button className="primary-button" disabled={saving || !draft.trim()}>{saving ? <LoaderCircle className="spin" size={16} /> : <Check size={16} />}{saving ? "Saving" : "Save note"}</button></div></form><div className="saved-notes">{notes.length ? notes.map((item) => <article className="saved-note" key={item.id}><p>{item.note}</p><div><span>{formatDate(item.created_at)}</span><button className="icon-button" aria-label="Delete security note" onClick={() => deleteNote(item.id)}><X size={15} /></button></div></article>) : <p className="saved-notes-empty">No approved notes saved.</p>}</div></section>
    <section className="notice-card"><ShieldCheck size={20} /><div><strong>Your data, your choice</strong><p>Delete recorded scans from the history page, saved notes here, and indexed documents from Document Intelligence.</p></div></section>
  </div>;
}
