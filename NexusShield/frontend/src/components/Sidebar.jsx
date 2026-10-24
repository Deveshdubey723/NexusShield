import {
  Activity, BookOpen, FileSearch, History, LayoutDashboard, Link2,
  Mail, MessageSquareWarning, Settings, Shield, ShieldCheck,
} from "lucide-react";

const items = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "message", label: "Message scanner", icon: MessageSquareWarning },
  { id: "url", label: "URL scanner", icon: Link2 },
  { id: "email", label: "Email analyzer", icon: Mail },
  { id: "documents", label: "Document intelligence", icon: FileSearch },
  { id: "history", label: "Scan history", icon: History },
  { id: "education", label: "Security guide", icon: BookOpen },
  { id: "settings", label: "Privacy settings", icon: Settings },
];

export default function Sidebar({ active, onNavigate }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark"><Shield size={21} /></div>
        <div><strong>NEXUS<span>SHIELD</span></strong><small>PERSONAL THREAT INTELLIGENCE</small></div>
      </div>
      <div className="workspace-label">WORKSPACE</div>
      <nav aria-label="Main navigation">
        {items.map(({ id, label, icon: Icon }) => (
          <button key={id} className={`nav-item ${active === id ? "active" : ""}`} onClick={() => onNavigate(id)}>
            <Icon size={18} strokeWidth={1.8} /><span>{label}</span>
            {id === "overview" && active === id && <span className="nav-indicator" />}
          </button>
        ))}
      </nav>
      <div className="sidebar-bottom">
        <div className="local-badge"><span className="status-dot" /><span>LOCAL ANALYSIS ACTIVE</span></div>
        <p><ShieldCheck size={15} /> Your content stays on this device.</p>
        <div className="sidebar-version"><Activity size={14} /> NEXUS SHIELD <span>v1.0</span></div>
      </div>
    </aside>
  );
}
