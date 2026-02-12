/**
 * BOTCHA Dashboard CSS
 *
 * Light terminal aesthetic — black and white with offwhite background.
 * Borrows structural patterns from turbopuffer (dot shadows, hard borders,
 * layered box-shadows on buttons) but with BOTCHA's own identity.
 *
 * JetBrains Mono · #f5f3f0 bg · #1a1a1a text · black accent · square corners · dot shadows
 */

export const DASHBOARD_CSS = `
  /* ============ Reset ============ */
  * { margin: 0; padding: 0; box-sizing: border-box; }

  :root {
    /* ---- palette (black & white) ---- */
    --bg:          #f5f3f0;
    --bg-card:     #ffffff;
    --bg-raised:   #eae8e4;
    --text:        #1a1a1a;
    --text-muted:  #6b6b6b;
    --text-dim:    #a0a0a0;
    --accent:      #1a1a1a;
    --accent-dim:  #333333;
    --red:         #cc2222;
    --amber:       #b87a00;
    --green:       #1a8a2a;
    --border:      #ddd9d4;
    --border-bright: #c0bbb5;

    /* ---- type ---- */
    --font: 'JetBrains Mono', 'Courier New', monospace;

    /* ---- dot shadow (turbopuffer SVG pattern, black fill) ---- */
    --dot-shadow: url("data:image/svg+xml,%3Csvg width='7' height='13' viewBox='0 0 7 13' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M5.58984 12.2344V10.7051H6.52734V12.2344H5.58984ZM1.86328 12.2344V10.7051H2.79492V12.2344H1.86328ZM3.72656 10.0957V8.56641H4.6582V10.0957H3.72656ZM0 10.0957V8.56641H0.925781V10.0957H0ZM5.58984 7.95117V6.42188H6.52734V7.95117H5.58984ZM1.86328 7.95117V6.42188H2.79492V7.95117H1.86328ZM3.72656 5.8125V4.2832H4.6582V5.8125H3.72656ZM0 5.8125V4.2832H0.925781V5.8125H0ZM5.58984 3.66797V2.13867H6.52734V3.66797H5.58984ZM1.86328 3.66797V2.13867H2.79492V3.66797H1.86328ZM3.72656 1.5293V0H4.6582V1.5293H3.72656ZM0 1.5293V0H0.925781V1.5293H0Z' fill='%231a1a1a'/%3E%3C/svg%3E");
  }

  /* ============ Base ============ */
  html, body {
    height: 100%;
    font-family: var(--font);
    font-size: 14px;
    line-height: 1.6;
    background: var(--bg);
    color: var(--text);
    -webkit-font-smoothing: antialiased;
  }

  body { display: flex; flex-direction: column; }

  ::selection { background: var(--accent); color: #fff; }

  a { color: var(--accent); }
  a:hover { text-decoration: none; opacity: 0.65; }

  /* ============ Scanline overlay (subtle CRT feel) ============ */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0, 0, 0, 0.012) 2px,
      rgba(0, 0, 0, 0.012) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  /* ============ Dot shadow utility ============ */
  .dot-shadow { position: relative; }
  .dot-shadow::after {
    content: '';
    position: absolute;
    top: 0.5rem; left: 0.5rem;
    right: -0.5rem; bottom: -0.5rem;
    background-image: var(--dot-shadow);
    background-repeat: repeat;
    z-index: -1;
    pointer-events: none;
    opacity: 0.6;
  }

  /* ============ Navigation ============ */
  .dashboard-nav {
    background: var(--bg);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 100;
  }

  .nav-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0.75rem 1.5rem;
    display: flex;
    align-items: center;
    gap: 1.5rem;
  }

  .nav-logo {
    font-weight: 700;
    font-size: 0.875rem;
    color: var(--text);
    text-decoration: none;
    letter-spacing: 0.15em;
    text-transform: uppercase;
  }
  .nav-logo:hover { opacity: 1; }

  .nav-app-id {
    color: var(--text-muted);
    font-size: 0.75rem;
    margin-left: auto;
  }

  .nav-link {
    color: var(--text);
    text-decoration: none;
    font-size: 0.75rem;
    border: 1px solid var(--border-bright);
    padding: 0.25rem 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    transition: background 0.1s, color 0.1s;
  }
  .nav-link:hover {
    background: var(--accent);
    color: var(--bg);
    border-color: var(--accent);
    opacity: 1;
  }

  /* ============ Main content ============ */
  .dashboard-main {
    flex: 1;
    max-width: 1200px;
    width: 100%;
    margin: 0 auto;
    padding: 2rem 1.5rem;
  }

  /* ============ Card — primary container (Turbopuffer-style) ============ */
  .card {
    display: flex;
    flex-direction: column;
    margin-bottom: 1.5rem;
  }

  .card-header {
    margin-bottom: -1px; /* overlap the border */
    padding: 0;
  }

  .card-header h3 {
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    line-height: 1;
    color: var(--text);
    margin: 0;
  }

  .card-header h3 span {
    position: relative;
    z-index: 10;
    margin-left: -0.5rem;
    margin-right: -0.5rem;
    background: var(--bg);
    padding: 0 0.5rem;
  }

  .card-body {
    position: relative;
    border: 2px solid var(--border-bright);
  }

  .card-body::before {
    content: '';
    position: absolute;
    top: 0.5rem;
    left: 0.5rem;
    right: -0.5rem;
    bottom: -0.5rem;
    background-image: var(--dot-shadow);
    background-repeat: repeat;
    pointer-events: none;
    opacity: 0.6;
  }

  .card-inner {
    position: relative;
    z-index: 1;
    background: var(--bg-card);
    padding: 1.5rem;
  }

  /* Legacy fieldset support (deprecated — use .card instead) */
  fieldset {
    border: 2px solid var(--border-bright);
    border-radius: 0;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    background: var(--bg-card);
    position: relative;
    z-index: 0;
  }

  legend {
    padding: 0 0.5rem;
    font-size: 0.75rem;
    color: var(--text);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }

  /* ============ Dashboard grid ============ */
  .dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1.5rem;
    margin-bottom: 1.5rem;
  }

  /* ============ Stat cards ============ */
  .stat-card {
    display: flex; flex-direction: column; gap: 0.25rem;
    padding: 1rem;
    border: 1px solid var(--border);
    background: var(--bg-card);
  }

  .stat-card .stat-value {
    font-size: 2rem; font-weight: 700; line-height: 1;
    color: var(--text);
    font-variant-numeric: tabular-nums;
  }

  .stat-card .stat-label {
    font-size: 0.6875rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }

  .stat-card .stat-change { font-size: 0.75rem; font-weight: 500; }
  .stat-card .stat-change.positive { color: var(--green); }
  .stat-card .stat-change.negative { color: var(--red); }

  /* ============ Bar chart ============ */
  .bar-chart { width: 100%; }

  .bar-chart .bar-item { margin-bottom: 0.75rem; }

  .bar-chart .bar-label {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 0.125rem; font-size: 0.75rem;
  }
  .bar-chart .bar-name { color: var(--text); }
  .bar-chart .bar-value {
    color: var(--text-muted);
    font-weight: 700; font-variant-numeric: tabular-nums;
  }

  .bar-chart .bar {
    height: 18px;
    background: var(--accent);
    border-radius: 0;
    transition: width 0.3s ease;
    position: relative; overflow: hidden;
    opacity: 0.8;
  }
  .bar-chart .bar:hover { opacity: 1; }

  .bar-chart .bar-fill { height: 100%; background: var(--accent); }

  /* ============ Form controls ============ */
  input, select, textarea, button { font-family: var(--font); font-size: 0.875rem; }

  input[type="text"],
  input[type="email"],
  input[type="password"],
  input[type="number"],
  select,
  textarea {
    width: 100%;
    padding: 0.625rem 0.75rem;
    background: var(--bg);
    border: 1px solid var(--border-bright);
    border-radius: 0;
    color: var(--text);
  }

  input:focus, select:focus, textarea:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 1px var(--accent);
  }

  input::placeholder, textarea::placeholder { color: var(--text-dim); }

  label {
    display: block;
    margin-bottom: 0.375rem;
    font-size: 0.6875rem;
    color: var(--text-muted);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  .form-group { margin-bottom: 1.25rem; }

  /* ============ Buttons ============ */
  button, .button {
    display: inline-block;
    padding: 0.625rem 1.25rem;
    background: var(--accent);
    color: #fff;
    border: 1px solid var(--accent);
    border-radius: 0;
    font-weight: 700;
    cursor: pointer;
    text-decoration: none;
    text-align: center;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-size: 0.75rem;
    box-shadow:
      inset 1px 1px 0 rgba(255,255,255,0.15),
      inset -1px -1px 0 rgba(0,0,0,0.15),
      2px 2px 0 rgba(0,0,0,0.1);
    transition: box-shadow 0.1s, transform 0.1s;
  }
  button:hover, .button:hover {
    box-shadow:
      inset 1px 1px 0 rgba(255,255,255,0.1),
      inset -1px -1px 0 rgba(0,0,0,0.15),
      3px 3px 0 rgba(0,0,0,0.12);
    opacity: 1;
  }
  button:active, .button:active {
    transform: translate(1px, 1px);
    box-shadow: inset 1px 1px 3px rgba(0,0,0,0.25);
  }
  button:disabled, .button:disabled { opacity: 0.25; cursor: not-allowed; }

  button.secondary, .button.secondary {
    background: transparent;
    color: var(--text);
    border-color: var(--border-bright);
    box-shadow: 2px 2px 0 rgba(0,0,0,0.05);
  }
  button.secondary:hover, .button.secondary:hover {
    border-color: var(--accent);
    color: var(--accent);
    box-shadow: 2px 2px 0 rgba(0,0,0,0.1);
  }

  button.danger, .button.danger {
    background: var(--red);
    border-color: var(--red);
    color: #fff;
    box-shadow: 2px 2px 0 rgba(204,34,34,0.15);
  }
  button.danger:hover, .button.danger:hover {
    background: transparent;
    color: var(--red);
  }

  /* ============ Tables ============ */
  table { width: 100%; border-collapse: collapse; }

  thead { border-bottom: 1px solid var(--border-bright); }
  th {
    padding: 0.5rem 0.75rem; text-align: left;
    font-size: 0.6875rem; color: var(--text);
    font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.1em;
    background: var(--bg-raised);
  }

  td {
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.75rem;
    font-variant-numeric: tabular-nums;
  }

  tbody tr:hover { background: var(--bg-raised); }

  /* ============ Code ============ */
  code, pre {
    font-family: var(--font);
    background: var(--bg-raised);
    padding: 0.125rem 0.375rem;
    border-radius: 0;
    font-size: 0.75rem;
    border: 1px solid var(--border);
    color: var(--text);
  }
  pre { padding: 1rem; overflow-x: auto; border: 1px solid var(--border-bright); }
  pre code { background: none; padding: 0; border: none; }

  /* ============ Login layout ============ */
  .login-container {
    min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    padding: 2rem;
    background: var(--bg);
  }
  .login-box { width: 100%; max-width: 420px; }

  .login-header { text-align: center; margin-bottom: 2rem; }
  .login-header h1 {
    font-size: 1.5rem; font-weight: 700; color: var(--text);
    letter-spacing: 0.15em; text-transform: uppercase;
    margin-bottom: 0.25rem;
  }
  .login-header p { color: var(--text-muted); font-size: 0.75rem; }

  /* ============ htmx loading ============ */
  .htmx-indicator { opacity: 0; transition: opacity 0.15s; }
  .htmx-request .htmx-indicator { opacity: 1; }
  .htmx-request.htmx-swapping { opacity: 0.3; pointer-events: none; }

  /* ============ Skeleton — blinking cursor ============ */
  .skeleton {
    background: var(--bg-raised);
    border: 1px solid var(--border);
    position: relative;
    overflow: hidden;
  }
  .skeleton::after {
    content: '';
    position: absolute; left: 0; top: 0;
    width: 2px; height: 100%;
    background: var(--text);
    animation: cursor-blink 0.8s step-end infinite;
  }
  @keyframes cursor-blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0; }
  }

  .skeleton-text { height: 1rem; margin-bottom: 0.5rem; }
  .skeleton-heading { height: 1.5rem; width: 60%; margin-bottom: 1rem; }

  /* ============ Utilities ============ */
  .text-center { text-align: center; }
  .text-right  { text-align: right; }
  .text-muted  { color: var(--text-muted); }
  .text-dim    { color: var(--text-dim); }
  .text-success { color: var(--green); }
  .text-danger  { color: var(--red); }
  .text-warning { color: var(--amber); }

  .mb-0 { margin-bottom: 0; }
  .mb-1 { margin-bottom: 0.5rem; }
  .mb-2 { margin-bottom: 1rem; }
  .mb-3 { margin-bottom: 1.5rem; }
  .mb-4 { margin-bottom: 2rem; }
  .mt-0 { margin-top: 0; }
  .mt-1 { margin-top: 0.5rem; }
  .mt-2 { margin-top: 1rem; }
  .mt-3 { margin-top: 1.5rem; }
  .mt-4 { margin-top: 2rem; }

  /* ============ Period selector ============ */
  .period-selector button {
    font-size: 0.625rem;
    padding: 0.2rem 0.5rem;
  }

  /* ============ Responsive ============ */
  @media (max-width: 768px) {
    html, body { font-size: 13px; }
    .dashboard-main { padding: 1rem; }
    .nav-container { padding: 0.5rem 1rem; }
    .dashboard-grid { grid-template-columns: 1fr; gap: 1rem; }
    .card-inner { padding: 1rem; }
    .card { margin-bottom: 1rem; }
    fieldset { padding: 1rem; margin-bottom: 1rem; }
    .stat-card .stat-value { font-size: 1.75rem; }
    table { font-size: 0.625rem; }
    th, td { padding: 0.375rem 0.5rem; }
  }

  @media (max-width: 480px) {
    .nav-container { flex-wrap: wrap; }
    .nav-app-id { margin-left: 0; width: 100%; order: 3; }
  }

  /* ============ Alerts ============ */
  .alert {
    padding: 0.75rem 1rem;
    border-radius: 0;
    margin-bottom: 1.5rem;
    border: 1px solid var(--border-bright);
    font-size: 0.75rem;
    background: var(--bg-card);
  }
  .alert::before { font-weight: 700; margin-right: 0.5rem; }

  .alert-info { border-color: var(--border-bright); color: var(--text); }
  .alert-info::before { content: '>'; color: var(--text); }

  .alert-success { border-color: var(--green); color: var(--green); }
  .alert-success::before { content: '[ok]'; }

  .alert-warning { border-color: var(--amber); color: var(--amber); }
  .alert-warning::before { content: '[!!]'; }

  .alert-danger { border-color: var(--red); color: var(--red); }
  .alert-danger::before { content: '[ERR]'; }

  /* ============ Badges ============ */
  .badge {
    display: inline-block;
    padding: 0.125rem 0.375rem;
    font-size: 0.625rem; font-weight: 700;
    border-radius: 0;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border: 1px solid;
  }
  .badge-success { color: var(--green); border-color: var(--green); background: transparent; }
  .badge-danger  { color: var(--red); border-color: var(--red); background: transparent; }
  .badge-warning { color: var(--amber); border-color: var(--amber); background: transparent; }
  .badge-info    { color: #fff; border-color: var(--accent); background: var(--accent); }

  /* ============ Empty state ============ */
  .empty-state { text-align: center; padding: 3rem 1rem; color: var(--text-muted); }
  .empty-state-icon { font-size: 1.5rem; margin-bottom: 0.75rem; color: var(--text); font-weight: 700; }
  .empty-state-text { font-size: 0.8125rem; margin-bottom: 0.25rem; }
  .empty-state-subtext { font-size: 0.6875rem; color: var(--text-dim); }

  /* ============ Scrollbar ============ */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg-raised); }
  ::-webkit-scrollbar-thumb { background: var(--border-bright); }
  ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
`;
