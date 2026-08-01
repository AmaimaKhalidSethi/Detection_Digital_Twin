export function Panel({ title, eyebrow, actions, children, className = "" }) {
  return (
    <section className={`rounded-lg border border-graphite-700 bg-graphite-900 ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between border-b border-graphite-700 px-4 py-3">
          <div>
            {eyebrow && (
              <div className="font-mono text-[11px] uppercase tracking-widest text-graphite-400">
                {eyebrow}
              </div>
            )}
            {title && <h2 className="text-sm font-medium text-graphite-100">{title}</h2>}
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
    neutral: "bg-graphite-700 text-graphite-200",
    signal: "bg-signal-500/15 text-signal-400 border border-signal-500/30",
    amber: "bg-amber-500/15 text-amber-400 border border-amber-500/30",
    alert: "bg-alert-500/15 text-alert-400 border border-alert-500/30",
  };
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 font-mono text-[11px] ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function Button({ children, variant = "primary", className = "", ...props }) {
  const variants = {
    primary: "bg-signal-500 text-graphite-950 hover:bg-signal-400",
    secondary: "bg-graphite-700 text-graphite-100 hover:bg-graphite-600",
    danger: "bg-alert-500/15 text-alert-400 border border-alert-500/40 hover:bg-alert-500/25",
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
    <div className="rounded-md border border-dashed border-graphite-600 px-6 py-10 text-center">
      <p className="text-sm text-graphite-300">{title}</p>
      {hint && <p className="mt-1 font-mono text-xs text-graphite-500">{hint}</p>}
    </div>
  );
}

export function ErrorNote({ message }) {
  if (!message) return null;
  return (
    <div className="rounded-md border border-alert-500/40 bg-alert-500/10 px-3 py-2 font-mono text-xs text-alert-400">
      {message}
    </div>
  );
}
