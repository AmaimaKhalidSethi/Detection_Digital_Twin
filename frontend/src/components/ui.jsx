export function Panel({ title, eyebrow, actions, children, className = "" }) {
  return (
    <section className={`rounded-lg border border-bg-800 bg-bg-900 ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between border-b border-bg-800 px-4 py-3">
          <div>
            {eyebrow && (
              <div className="font-mono text-[11px] uppercase tracking-widest text-slate-500">
                {eyebrow}
              </div>
            )}
            {title && <h2 className="text-sm font-medium text-slate-300">{title}</h2>}
          </div>
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Badge({ tone = "neutral", children }) {
  const tones = {
    neutral: "bg-bg-800 text-slate-300",
    signal: "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30",
    amber: "bg-fuchsia-500/15 text-fuchsia-400 border border-fuchsia-500/30",
    alert: "bg-rose-500/15 text-rose-400 border border-rose-500/30",
  };
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 font-mono text-[11px] ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function Button({ children, variant = "primary", className = "", ...props }) {
  const variants = {
    primary: "bg-cyan-500 text-bg-950 hover:bg-cyan-400",
    secondary: "bg-bg-800 text-slate-300 hover:bg-bg-800/70",
    danger: "bg-rose-500/15 text-rose-400 border border-rose-500/40 hover:bg-rose-500/25",
  };
  return (
    <button
      className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

export function EmptyState({ title, hint }) {
  return (
    <div className="rounded-md border border-dashed border-bg-800 px-6 py-10 text-center">
      <p className="text-sm text-slate-300">{title}</p>
      {hint && <p className="mt-1 font-mono text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

export function ErrorNote({ message }) {
  if (!message) return null;
  return (
    <div className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 font-mono text-xs text-rose-400">
      {message}
    </div>
  );
}
