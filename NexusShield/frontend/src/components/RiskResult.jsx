import { AlertTriangle, ArrowRight, CheckCircle2, Info, ShieldAlert } from "lucide-react";

export default function RiskResult({ result }) {
  if (!result) return null;
  const level = (result.risk_level || "unknown").toLowerCase();
  const isLow = level === "low";
  const isMedium = level === "medium";
  const Icon = isLow ? CheckCircle2 : isMedium ? Info : AlertTriangle;
  const signals = result.detected_signals || [];
  const actions = result.recommended_actions || [];

  return (
    <section className={`result-card risk-${level}`} aria-live="polite">
      <div className="result-heading">
        <div className="result-icon"><Icon size={22} /></div>
        <div className="result-title"><span className="eyebrow">ANALYSIS COMPLETE</span><h3>{level} risk indicators detected</h3></div>
        <div className="score-pill"><strong>{result.risk_score ?? "—"}</strong><small> / 100</small></div>
      </div>
      <div className="score-track"><span style={{ width: `${Math.min(100, Math.max(0, Number(result.risk_score) || 0))}%` }} /></div>
      <p className="result-explanation">{result.explanation || "No explanation was provided."}</p>
      {signals.length > 0 && <div className="result-section"><h4>Detected signals</h4><div className="signal-list">{signals.map((signal, i) => <span className="signal-chip" key={`${signal}-${i}`}><ShieldAlert size={13} />{typeof signal === "string" ? signal : signal.name || signal.type}</span>)}</div></div>}
      {result.evidence?.length > 0 && <div className="result-section"><h4>Evidence</h4><ul className="evidence-list">{result.evidence.map((item, i) => <li key={i}>{typeof item === "string" ? item : item.description || item.text || JSON.stringify(item)}</li>)}</ul></div>}
      {actions.length > 0 && <div className="result-section"><h4>Recommended next steps</h4><ul className="action-list">{actions.map((action, i) => <li key={i}><ArrowRight size={14} />{typeof action === "string" ? action : action.text || action.action}</li>)}</ul></div>}
      {result.analysis_limitations?.length > 0 && <div className="limit-note"><Info size={15} /><div><strong>Limitations</strong><ul>{result.analysis_limitations.map((item, i) => <li key={i}>{item}</li>)}</ul></div></div>}
      <div className="disclaimer-inline">Indicators are not proof of fraud. No automated system can guarantee that a message or website is safe.</div>
    </section>
  );
}
