import React, { useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  Clock3,
  FileImage,
  Link2,
  Mail,
  Menu,
  MessageSquareText,
  RotateCcw,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Upload,
  X,
} from "lucide-react";

const analyzers = [
  {
    title: "URL Analyzer",
    description: "Check suspicious links before clicking. Detect phishing domains, redirect tricks, and unsafe patterns.",
    href: "/analyze/url",
    icon: Link2,
    tone: "blue",
  },
  {
    title: "Screenshot Analyzer",
    description: "Upload screenshots of suspicious messages, pop-ups, or websites for scam-awareness guidance.",
    href: "/analyze/screenshot",
    icon: FileImage,
    tone: "purple",
  },
  {
    title: "SMS Analyzer",
    description: "Paste suspicious SMS messages to identify phishing, fake rewards, OTP scams, and impersonation.",
    href: "/analyze/sms",
    icon: MessageSquareText,
    tone: "green",
  },
  {
    title: "Email Analyzer",
    description: "Analyze email subject, sender, and body content for phishing, fraud, and social engineering.",
    href: "/analyze/email",
    icon: Mail,
    tone: "orange",
  },
  {
    title: "Cyber AI Assistant",
    description: "Ask cybersecurity questions in plain language. Get practical guidance on staying safe online.",
    href: "/assistant",
    icon: Bot,
    tone: "cyan",
  },
];

const safetyTips = [
  {
    icon: "🔗",
    title: "Hover Before You Click",
    text: "Preview the destination of a link before opening it. If the address looks unfamiliar or misspelled, don't click.",
    tag: "URLs",
  },
  {
    icon: "🔐",
    title: "Never Share OTPs",
    text: "Legitimate services will never ask you to tell them a one-time password. Keep OTPs private, even from callers.",
    tag: "Authentication",
  },
  {
    icon: "⚠️",
    title: "Urgency is a Red Flag",
    text: "Messages that pressure you to act immediately or threaten account closure are a common scam tactic.",
    tag: "Social engineering",
  },
  {
    icon: "📧",
    title: "Verify Sender Email Domains",
    text: "Check the complete address. Scammers often imitate a familiar brand with a slightly altered domain.",
    tag: "Email",
  },
  {
    icon: "💰",
    title: "Too Good to Be True",
    text: "Unexpected prizes, lottery wins, or giveaways are suspicious—especially if you must pay or share details to claim them.",
  },
  {
    icon: "🛡️",
    title: "Use Two-Factor Authentication",
    text: "Enable 2FA on important accounts. It adds a layer of protection if a password is exposed.",
  },
];

const urlExamples = [
  "https://www.google.com",
  "https://free-prize-claim.example/winner",
  "http://192.168.1.1/login",
  "https://paypa1-secure-verify.tk/account",
  "https://amazon-support-help-login.xyz/update",
];

const smsExamples = [
  {
    label: "Prize Scam",
    text: "Congratulations! You've been selected as our lucky winner. Claim your prize now at bit.ly/claim-reward",
  },
  {
    label: "Bank Fraud",
    text: "URGENT: Your bank account has been suspended. Verify your details immediately: http://bank-verify-alert.xyz",
  },
  {
    label: "OTP Scam",
    text: "A support agent needs the verification code sent to your phone. Reply with your OTP to keep your account active.",
  },
  {
    label: "Likely Safe",
    text: "Your order has been shipped and will arrive tomorrow. Track your delivery in the retailer's official app.",
  },
];

const emailExamples = {
  phishing: {
    subject: "URGENT: Your account has been suspended",
    sender: "security@paypa1-account-check.tk",
    body: "We detected unusual activity. Your account will be permanently closed in 24 hours. Verify your identity now to restore access.",
    links: "http://paypa1-account-check.tk/verify",
  },
  prize: {
    subject: "You've won our monthly cash giveaway!",
    sender: "rewards@winner-claim-now.xyz",
    body: "You have been selected to receive a cash reward. Pay the small processing fee today to claim your prize.",
    links: "https://winner-claim-now.xyz/redeem",
  },
  safe: {
    subject: "Your monthly statement is ready",
    sender: "statements@example.com",
    body: "Your monthly statement is now available. Sign in through the official app or type the known website address into your browser.",
    links: "",
  },
};

const assistantSuggestions = [
  "What is phishing?",
  "OTP scam explained",
  "Password safety",
  "Common scam types",
  "How to stay safe",
];

function getRoute() {
  const path = window.location.pathname.replace(/\/+$/, "") || "/";
  return path;
}

function analyzeText(text, extra = "") {
  const content = `${text} ${extra}`.toLowerCase();
  const checks = [
    { pattern: /urgent|immediately|act now|within \d+ hours|account.{0,20}(suspend|close|block)/i, reason: "Creates urgency or threatens account access to pressure a quick response." },
    { pattern: /otp|one.time password|verification code|pin number/i, reason: "Mentions a verification code or secret that should never be shared with another person." },
    { pattern: /prize|winner|giveaway|lottery|claim.{0,20}(reward|gift|cash)/i, reason: "Uses an unexpected prize or reward as a reason to click or share information." },
    { pattern: /password|bank details|credit card|ssn|social security|cvv/i, reason: "Requests or references sensitive personal or financial information." },
    { pattern: /bit\.ly|tinyurl|t\.co|shorturl|free-gift|claim-now/i, reason: "Contains a shortened or promotional link that hides the final destination." },
    { pattern: /paypa[l1]|amaz[o0]n|micr[o0]soft|googl[e3]|\.tk\b|\.ml\b|\.xyz\b|\.top\b/i, reason: "Contains a possible brand lookalike or an uncommon domain ending." },
    { pattern: /pay.{0,20}(fee|shipping|tax)|processing fee/i, reason: "Asks for a payment to release a prize, account, or delivery." },
  ];
  const reasons = checks.filter((check) => check.pattern.test(content)).map((check) => check.reason);
  const severity = reasons.length >= 3 ? "high" : reasons.length > 0 ? "caution" : "low";
  return {
    severity,
    reasons: reasons.length ? reasons : ["No common scam patterns were detected in the provided content. This does not guarantee that it is safe."],
  };
}

function analyzeUrl(value) {
  const candidate = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  let url;
  try {
    url = new URL(candidate);
  } catch {
    return { severity: "high", reasons: ["This does not look like a valid web address. Avoid opening unexpected or malformed links."] };
  }

  const host = url.hostname.toLowerCase();
  const reasons = [];
  const suspiciousTlds = /\.(tk|ml|ga|cf|gq|xyz|top|click|work)$/i;
  const knownBrandLookalikes = /(paypa[l1]|amaz[o0]n|g[o0]{2}gle|micr[o0]soft|app[l1]e)/i;
  const officialBrandDomain = /(^|\.)((paypal|amazon|google|microsoft|apple)\.com)$/i.test(host);
  if (url.protocol !== "https:") reasons.push("The address does not use HTTPS encryption.");
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) reasons.push("The link points directly to an IP address instead of a recognizable domain.");
  if (suspiciousTlds.test(host)) reasons.push("The domain uses an uncommon top-level ending frequently seen in throwaway links.");
  if (/\.example$/i.test(host)) reasons.push("The .example domain is reserved for documentation and testing, not a public website.");
  if (knownBrandLookalikes.test(host) && !officialBrandDomain) reasons.push("The domain may imitate a well-known brand with a lookalike spelling.");
  if (/login|verify|secure|account|update|support/i.test(`${host}${url.pathname}`) && !officialBrandDomain) reasons.push("The address combines account or verification wording with a domain that is not clearly the official service.");
  if (/free[-\s]?(?:prize|gift)|\bprize\b/i.test(`${host}${url.pathname}`)) reasons.push("Uses free-prize or gift wording commonly used to bait people into clicking.");
  if (/\bwinner\b|\bclaim\b/i.test(`${host}${url.pathname}`)) reasons.push("Uses winner or claim wording to encourage an unexpected reward claim.");
  if (url.username || url.password) reasons.push("The link contains embedded sign-in information, which can be used to disguise its destination.");
  const severity = reasons.length >= 3 ? "high" : reasons.length ? "caution" : "low";
  return {
    severity,
    reasons: reasons.length ? reasons : ["No common URL warning patterns were detected. HTTPS encrypts a connection but does not prove a site is trustworthy. Check the domain carefully and use official apps or saved bookmarks."],
  };
}

function Header() {
  const [open, setOpen] = useState(false);
  return (
    <header className="site-header">
      <div className="header-inner">
        <a className="brand" href="/" aria-label="ScamLens home">
          <span className="brand-icon"><Shield size={23} /></span>
          <span>ScamLens</span>
        </a>
        <nav className={open ? "main-nav nav-open" : "main-nav"} aria-label="Main navigation">
          <a href="/analyze/url">URL</a>
          <a href="/analyze/screenshot">Screenshot</a>
          <a href="/analyze/sms">SMS</a>
          <a href="/analyze/email">Email</a>
          <a href="/assistant">AI Assistant</a>
          <a href="/">Dashboard</a>
        </nav>
        <button className="menu-toggle" aria-label={open ? "Close menu" : "Toggle menu"} onClick={() => setOpen((value) => !value)}>
          {open ? <X size={23} /> : <Menu size={23} />}
        </button>
      </div>
    </header>
  );
}

function Footer() {
  return (
    <footer className="site-footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <span className="brand-icon"><Shield size={21} /></span>
          <span><b>ScamLens</b><small>Detect. Understand. Stay Safe.</small></span>
        </div>
        <div className="footer-disclaimer"><ShieldCheck size={20} /><p>ScamLens provides <strong>educational analysis only</strong> — results are assessments, not guarantees. Always verify suspicious content through official channels. Never share OTPs, passwords, or PINs with anyone.</p></div>
        <small className="copyright">© 2026 ScamLens. For awareness only.</small>
      </div>
    </footer>
  );
}

function Notice({ children }) {
  return <div className="notice"><ShieldCheck size={20} /><p>{children}</p></div>;
}

function AnalyzerHeading({ icon: Icon, title, description }) {
  return <div className="page-heading"><span className="page-icon"><Icon size={25} /></span><div><h1>{title}</h1><p>{description}</p></div></div>;
}

function AnalysisResult({ result, title = "Analysis" }) {
  if (!result) return null;
  const details = {
    high: { label: "High risk indicators", icon: ShieldAlert },
    caution: { label: "Use caution", icon: AlertTriangle },
    low: { label: "No obvious warning signs", icon: CheckCircle2 },
  }[result.severity];
  const Icon = details.icon;
  return (
    <section className={`analysis-result result-${result.severity}`} aria-live="polite">
      <div className="result-heading"><span><Icon size={21} /></span><div><small>{title}</small><h2>{details.label}</h2></div></div>
      <ul>{result.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
      <p className="result-footnote">This pattern-based check is educational, not a security guarantee. When in doubt, contact the organization through a trusted channel.</p>
    </section>
  );
}

function HomePage() {
  const [history, setHistory] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("scamlens-history") || "[]");
    } catch {
      return [];
    }
  });
  return (
    <>
      <main className="home-main">
        <section className="home-hero">
          <div className="hero-art" aria-label="Cybersecurity illustration">
            <div className="art-grid" />
            <div className="art-orbit orbit-one" />
            <div className="art-orbit orbit-two" />
            <span className="art-shield"><ShieldCheck size={76} strokeWidth={1.25} /></span>
            <span className="art-node node-one"><Link2 size={20} /></span>
            <span className="art-node node-two"><Mail size={19} /></span>
            <span className="art-node node-three"><MessageSquareText size={19} /></span>
            <span className="art-caption"><i /> THREAT AWARENESS · ONLINE</span>
          </div>
          <div className="hero-copy">
            <div className="eyebrow"><ShieldCheck size={16} /> AI-Powered Scam Detection Platform</div>
            <h1>Detect. Understand.<br /><span>Stay Safe.</span></h1>
            <p>ScamLens helps students and everyday internet users analyze suspicious URLs, screenshots, SMS messages, and emails — with clear, jargon-free explanations.</p>
            <div className="hero-actions"><a className="button button-primary" href="/analyze/url"><Shield size={17} /> Start Analyzing <ArrowRight size={17} /></a><a className="button button-secondary" href="/assistant"><Bot size={18} /> Ask AI Assistant</a></div>
            <div className="hero-trust"><ShieldCheck size={15} /> Private by design <span /> Educational guidance, not guarantees</div>
          </div>
        </section>

        <section className="analyzers-section">
          <div className="section-title"><div><span className="section-kicker">YOUR FIRST LINE OF DEFENSE</span><h2>Choose Your Analyzer</h2><p>Select the type of suspicious content you want to check.</p></div><span className="section-decoration"><Sparkles size={16} /> Scam awareness made simple</span></div>
          <div className="analyzer-grid">
            {analyzers.map(({ title, description, href, icon: Icon, tone }) => (
              <a className="analyzer-card" href={href} key={title}>
                <span className={`analyzer-icon ${tone}`}><Icon size={22} /></span><span className="card-arrow"><ArrowRight size={17} /></span>
                <h3>{title}</h3><p>{description}</p><span className="card-link">Analyze Now <ArrowRight size={15} /></span>
              </a>
            ))}
          </div>
        </section>

        <section className="home-lower">
          <div className="history-card">
            <div className="lower-heading"><span className="lower-icon"><Clock3 size={19} /></span><div><h2>Recent Analyses</h2><p>Your latest checks, stored on this device.</p></div></div>
            {history.length ? <div className="history-list">{history.slice(0, 4).map((item, index) => <div className="history-item" key={`${item.date}-${index}`}><span className={`history-dot ${item.severity}`} /><span><b>{item.title}</b><small>{item.value}</small></span><time>{item.date}</time></div>)}</div> : <div className="empty-history"><span className="empty-icon"><SearchIcon /></span><strong>No analyses yet.</strong><p>Your recent analysis history will appear here.</p></div>}
          </div>
          <div className="tips-section">
            <div className="lower-heading"><span className="lower-icon mint"><ShieldCheck size={19} /></span><div><h2>Cyber Safety Tips</h2><p>Small habits make a big difference.</p></div></div>
            <div className="tips-grid">{safetyTips.map((tip) => <article className="tip-card" key={tip.title}><div className="tip-title"><span>{tip.icon}</span><h3>{tip.title}</h3></div><p>{tip.text}</p>{tip.tag && <small>{tip.tag}</small>}</article>)}</div>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}

function SearchIcon() {
  return <CircleHelp size={23} />;
}

function rememberAnalysis(title, value, severity) {
  try {
    const current = JSON.parse(localStorage.getItem("scamlens-history") || "[]");
    const entry = { title, value: value.slice(0, 90), severity, date: new Date().toLocaleDateString(undefined, { month: "short", day: "numeric" }) };
    localStorage.setItem("scamlens-history", JSON.stringify([entry, ...current].slice(0, 10)));
  } catch {
    // The current analysis remains available even when browser storage is disabled.
  }
}

function UrlPage() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const submit = (event) => {
    event.preventDefault();
    if (!url.trim()) return;
    const analysis = analyzeUrl(url.trim());
    setResult({ ...analysis, value: url.trim() });
    rememberAnalysis("URL Analyzer", url.trim(), analysis.severity);
  };
  return (
    <AnalyzerLayout>
      <AnalyzerHeading icon={Link2} title="URL Analyzer" description="Check suspicious links for phishing, impersonation, and unsafe patterns" />
      <Notice>This analyzer examines URL structure and patterns. It is an <strong>educational tool</strong>, not a real-time threat database. Results are assessments — not guarantees. Never enter sensitive data on a site you don't fully trust.</Notice>
      <section className="form-card">
        <form onSubmit={submit}>
          <label htmlFor="url-input">Enter URL to analyze</label>
          <div className="input-action"><input id="url-input" type="text" value={url} onChange={(e) => { setUrl(e.target.value); setResult(null); }} placeholder="https://example.com/suspicious-page" autoComplete="url" /><button className="button button-primary" type="submit" disabled={!url.trim()}><Sparkles size={17} /> Analyze</button></div>
        </form>
        <div className="examples"><p>Try an example:</p><div>{urlExamples.map((sample) => <button type="button" key={sample} onClick={() => { setUrl(sample); setResult(null); }}>{sample}</button>)}</div></div>
      </section>
      {result && <AnalysisResult result={result} title={result.value} />}
    </AnalyzerLayout>
  );
}

function SmsPage() {
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const submit = (event) => {
    event.preventDefault();
    const analysis = analyzeText(message);
    setResult(analysis);
    rememberAnalysis("SMS Analyzer", message, analysis.severity);
  };
  return (
    <AnalyzerLayout>
      <AnalyzerHeading icon={MessageSquareText} title="SMS Analyzer" description="Paste suspicious SMS messages to detect phishing, scams, and fraud" />
      <Notice><strong>Never share real OTPs, passwords, PINs, or CVVs</strong> — not here, not anywhere. This tool analyzes message content only. Remove personal details before pasting a message.</Notice>
      <section className="form-card">
        <form onSubmit={submit}>
          <div className="label-row"><label htmlFor="sms-input">Paste SMS message</label><span>{message.length}/2000</span></div>
          <textarea id="sms-input" maxLength={2000} value={message} onChange={(e) => { setMessage(e.target.value); setResult(null); }} placeholder="Paste the suspicious SMS here... e.g., 'Your account has been suspended. Click here to verify...'" rows={6} />
          <button className="button button-primary form-submit" type="submit" disabled={!message.trim()}><Sparkles size={17} /> Analyze SMS</button>
        </form>
        <div className="examples"><p>Try an example SMS</p><div className="example-cards">{smsExamples.map((example) => <button type="button" key={example.label} onClick={() => { setMessage(example.text); setResult(null); }}><b>{example.label}</b><span>{example.text}</span></button>)}</div></div>
      </section>
      {result && <AnalysisResult result={result} title="SMS pattern check" />}
    </AnalyzerLayout>
  );
}

function EmailPage() {
  const [values, setValues] = useState({ subject: "", sender: "", body: "", links: "" });
  const [result, setResult] = useState(null);
  const [showHelp, setShowHelp] = useState(false);
  const update = (key, value) => { setValues((current) => ({ ...current, [key]: value })); setResult(null); };
  const loadExample = (type) => { setValues(emailExamples[type]); setResult(null); };
  const submit = (event) => {
    event.preventDefault();
    const analysis = analyzeText(`${values.subject} ${values.sender} ${values.body}`, values.links);
    setResult(analysis);
    rememberAnalysis("Email Analyzer", values.subject || values.sender || "Email content", analysis.severity);
  };
  return (
    <AnalyzerLayout>
      <AnalyzerHeading icon={Mail} title="Email Analyzer" description="Analyze email content for phishing, fraud, and social engineering" />
      <Notice>Do not paste real passwords, OTPs, or card numbers into any analyzer. Paste only the email text you received. Results are <strong>pattern-based assessments</strong>, not real-time threat intelligence.</Notice>
      <section className="form-card">
        <button className="disclosure" type="button" aria-expanded={showHelp} onClick={() => setShowHelp((value) => !value)}>What should I analyze? <ChevronDown size={17} className={showHelp ? "rotated" : ""} /></button>
        {showHelp && <p className="help-copy">Look for mismatched sender domains, unexpected links, unusual requests for payment or personal information, and messages that pressure you to act quickly. Remove private information before pasting.</p>}
        <form onSubmit={submit} className="stacked-form">
          <label>Subject Line<input value={values.subject} onChange={(e) => update("subject", e.target.value)} placeholder="e.g., URGENT: Your account has been suspended" /></label>
          <label>Sender Address<input type="text" value={values.sender} onChange={(e) => update("sender", e.target.value)} placeholder="e.g., support@paypal-secure.ml or no-reply@example.com" /></label>
          <label>Email Body<textarea value={values.body} onChange={(e) => update("body", e.target.value)} placeholder="Paste the email content here..." rows={5} /></label>
          <label>Links Found in Email (one per line)<textarea value={values.links} onChange={(e) => update("links", e.target.value)} placeholder={"https://example.com/verify\nhttp://suspicious-link.tk"} rows={3} /></label>
          <button className="button button-primary form-submit" type="submit" disabled={!Object.values(values).some((value) => value.trim())}><Sparkles size={17} /> Analyze Email</button>
        </form>
        <div className="examples"><p>Load an example email</p><div className="example-buttons"><button type="button" onClick={() => loadExample("phishing")}>Phishing Email</button><button type="button" onClick={() => loadExample("prize")}>Prize Scam</button><button type="button" onClick={() => loadExample("safe")}>Safe Email</button></div></div>
      </section>
      {result && <AnalysisResult result={result} title="Email pattern check" />}
    </AnalyzerLayout>
  );
}

function ScreenshotPage() {
  const fileInput = useRef(null);
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState("");
  const [text, setText] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!file) {
      setPreview("");
      return undefined;
    }
    const objectUrl = URL.createObjectURL(file);
    setPreview(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [file]);
  const acceptFile = (selected) => {
    if (!selected) return;
    if (!/^image\/(png|jpeg|webp)$/i.test(selected.type)) {
      setError("Choose a PNG, JPG, JPEG, or WEBP image.");
      return;
    }
    setFile(selected);
    setError("");
    setResult(null);
  };
  const submit = (event) => {
    event.preventDefault();
    const analysis = analyzeText(text);
    setResult(analysis);
    rememberAnalysis("Screenshot Analyzer", file?.name || text, analysis.severity);
  };
  return (
    <AnalyzerLayout>
      <AnalyzerHeading icon={FileImage} title="Screenshot Analyzer" description="Upload screenshots of suspicious messages, pop-ups, or websites" />
      <Notice>Text extraction is not available in this demo. Upload a screenshot, then paste its visible text below for a pattern check. Image contents are not sent to a server.</Notice>
      <section className="form-card screenshot-form">
        <input ref={fileInput} type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(event) => acceptFile(event.target.files?.[0])} />
        <button className="upload-zone" type="button" onClick={() => fileInput.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); acceptFile(event.dataTransfer.files?.[0]); }}>
          {file ? <img src={preview} alt="Selected screenshot preview" /> : <><span className="upload-icon"><Upload size={25} /></span><strong>Upload Screenshot</strong><span>Drag &amp; drop or click to browse</span><small>Supported: PNG, JPG, JPEG, WEBP</small></>}
        </button>
        {file && <div className="selected-file"><span><FileImage size={17} /> {file.name}</span><button type="button" onClick={() => { setFile(null); setResult(null); if (fileInput.current) fileInput.current.value = ""; }}>Remove</button></div>}
        {error && <p className="field-error">{error}</p>}
        <form onSubmit={submit} className="stacked-form screenshot-text-form">
          <label>Text visible in the screenshot<textarea value={text} onChange={(event) => { setText(event.target.value); setResult(null); }} placeholder="Paste or type the message shown in the image..." rows={5} /></label>
          <button className="button button-primary form-submit" type="submit" disabled={!text.trim()}><Sparkles size={17} /> Analyze Text</button>
        </form>
      </section>
      {result && <AnalysisResult result={result} title="Screenshot text pattern check" />}
    </AnalyzerLayout>
  );
}

function assistantReply(question) {
  const value = question.toLowerCase();
  if (/otp|one.time|verification code/.test(value)) return "An OTP is a one-time code that helps verify your identity. Never share it with a caller, texter, or person claiming to be support—even if they know your name or say your account is at risk. If you shared one, contact the service through its official app or website immediately.";
  if (/password|passphrase|login/.test(value)) return "Use a unique, long password for every account. A password manager can create and store them securely. Turn on two-factor authentication, and never enter your password after following an unexpected message link—open the official app or type the known address yourself.";
  if (/type|common|scam/.test(value)) return "Common scams include phishing links, fake delivery notices, impersonation calls, romance and investment fraud, prize offers, and requests for OTPs or urgent payments. Watch for pressure, secrecy, unusual payment methods, and links or addresses that don't match the real organization.";
  if (/safe|protect|avoid/.test(value)) return "Pause before acting on an unexpected message. Verify requests using a phone number or website you find independently, keep software updated, use unique passwords and 2FA, and never share OTPs. If you clicked a link, don't enter details; close it and check your account through its official app.";
  return "Phishing is a form of fraud where someone impersonates a trusted person or organization to trick you into clicking a link, opening a file, or sharing private information. Check the sender and web address carefully, be cautious of urgency, and verify unexpected requests using an official contact method.";
}

function AssistantPage() {
  const [messages, setMessages] = useState([{ from: "assistant", text: "I'm your Cyber AI Assistant. I can help you understand online scams, phishing tactics, how to stay safe, and explain cybersecurity concepts in simple terms. What would you like to know?" }]);
  const [draft, setDraft] = useState("");
  const sendMessage = (text = draft) => {
    const prompt = text.trim();
    if (!prompt) return;
    setMessages((current) => [...current, { from: "user", text: prompt }, { from: "assistant", text: assistantReply(prompt) }]);
    setDraft("");
  };
  return (
    <>
      <main className="assistant-main">
        <section className="assistant-card">
          <div className="assistant-heading"><span className="assistant-avatar"><Bot size={23} /></span><div><h1>Cyber AI Assistant</h1><span className="online"><i /> Ready — ask about cybersecurity</span></div><button type="button" className="reset-chat" onClick={() => setMessages([])}><RotateCcw size={15} /> Reset</button></div>
          <div className="suggestions">{assistantSuggestions.map((suggestion) => <button type="button" key={suggestion} onClick={() => sendMessage(suggestion)}><Sparkles size={14} /> {suggestion}</button>)}</div>
          <div className="chat-window" aria-live="polite">
            {messages.map((message, index) => <div className={`chat-message ${message.from}`} key={`${index}-${message.text}`}><span className="chat-avatar">{message.from === "assistant" ? <Bot size={17} /> : <span>You</span>}</span><div className="chat-bubble"><p>{message.text}</p><small>{new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</small></div></div>)}
            {!messages.length && <div className="chat-empty">Start a new conversation using one of the prompts above.</div>}
          </div>
          <div className="assistant-note"><ShieldCheck size={15} /> Demo assistant with prepared educational guidance. For emergencies, contact official cybercrime authorities.</div>
          <form className="chat-form" onSubmit={(event) => { event.preventDefault(); sendMessage(); }}><input value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Ask about phishing, OTPs, scams, or online safety..." aria-label="Ask about phishing, OTPs, scams, or online safety..." /><button type="submit" aria-label="Send message" disabled={!draft.trim()}><Send size={18} /></button></form>
        </section>
      </main>
      <Footer />
    </>
  );
}

function AnalyzerLayout({ children }) {
  return <><main className="analyzer-main">{children}</main><Footer /></>;
}

function NotFound() {
  return <AnalyzerLayout><AnalyzerHeading icon={CircleHelp} title="Page not found" description="The page you are looking for may have moved." /><a className="button button-primary" href="/">Return to ScamLens <ArrowRight size={17} /></a></AnalyzerLayout>;
}

export default function App() {
  const route = getRoute();
  let page;
  if (route === "/") page = <HomePage />;
  else if (route === "/analyze/url") page = <UrlPage />;
  else if (route === "/analyze/sms") page = <SmsPage />;
  else if (route === "/analyze/email") page = <EmailPage />;
  else if (route === "/analyze/screenshot") page = <ScreenshotPage />;
  else if (route === "/assistant") page = <AssistantPage />;
  else page = <NotFound />;
  const analyzerNames = { url: "URL Analyzer", sms: "SMS Analyzer", email: "Email Analyzer", screenshot: "Screenshot Analyzer" };
  const routeKey = route.split("/").pop();
  const pageName = route === "/" ? "AI-Assisted Cyber Scam Detection & Awareness" : route === "/assistant" ? "Cyber AI Assistant" : analyzerNames[routeKey] || "Page Not Found";
  document.title = `ScamLens – ${pageName}`;
  return <div className="site-shell"><Header />{page}</div>;
}
