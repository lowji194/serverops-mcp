import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const compiledCssPath = path.join(__dirname, 'dist', 'tailwind.css');

let cachedCss = null;

export function getCompiledCss() {
  if (cachedCss && process.env.NODE_ENV !== 'development') {
    return cachedCss;
  }
  try {
    if (fs.existsSync(compiledCssPath)) {
      cachedCss = fs.readFileSync(compiledCssPath, 'utf8');
      return cachedCss;
    }
  } catch {}
  return '';
}

export function escapeHtml(str) {
  return String(str || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function renderAuthorizePage({
  clientDisplayName,
  clientId,
  redirectUri,
  requestedScopes,
  hiddenFields,
  nonce,
  cancelUrl
}) {
  const hasAdmin = requestedScopes.includes('system:admin');

  const scopeBadges = requestedScopes.map(scope => {
    const isAdmin = scope === 'system:admin';
    const colorClass = isAdmin
      ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300 border-amber-300 dark:border-amber-700'
      : 'bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300 border-slate-200 dark:border-slate-700';

    return `<span class="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-medium border ${colorClass}">${escapeHtml(scope)}</span>`;
  }).join(' ');

  const hiddenInputsHtml = Object.entries(hiddenFields)
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join('\n');

  return `<!doctype html>
<html lang="en" class="h-full">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize Access — ServerOps MCP</title>
  <style nonce="${nonce}">${getCompiledCss()}</style>
</head>
<body class="h-full bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-sans antialiased flex flex-col justify-center py-12 sm:px-6 lg:px-8 selection:bg-emerald-500 selection:text-white">
  <div class="sm:mx-auto sm:w-full sm:max-w-md px-4">
    <!-- ServerOps Header / Branding -->
    <div class="text-center mb-6">
      <div class="inline-flex items-center justify-center w-12 h-12 rounded-2xl bg-emerald-600 text-white shadow-lg shadow-emerald-500/20 mb-3">
        <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" aria-hidden="true">
          <path stroke-linecap="round" stroke-linejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.75 5.25a3 3 0 012.4-1.2h7.7a3 3 0 012.4 1.2l2.1 3.3a4.5 4.5 0 01.9 2.7m-13.5 0a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zm10.5 0a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zm-10.5 6a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zm10.5 0a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z" />
        </svg>
      </div>
      <h1 class="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">ServerOps MCP</h1>
      <p class="mt-1 text-xs text-slate-500 dark:text-slate-400 font-medium">Privileged Linux Administration & Automation</p>
    </div>

    <!-- Main SaaS Card -->
    <div class="bg-white dark:bg-slate-900 py-8 px-6 shadow-xl shadow-slate-200/50 dark:shadow-none border border-slate-200/80 dark:border-slate-800 rounded-2xl sm:px-10">
      
      <!-- Client Identity Banner -->
      <div class="flex items-center gap-3.5 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200/60 dark:border-slate-700/60 mb-6">
        <div class="w-10 h-10 rounded-lg bg-emerald-100 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-400 flex items-center justify-center font-bold text-base shrink-0">
          ${escapeHtml(clientDisplayName.charAt(0).toUpperCase())}
        </div>
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-1.5">
            <h2 class="text-sm font-semibold text-slate-900 dark:text-white truncate">${escapeHtml(clientDisplayName)}</h2>
            <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-300">AI Client</span>
          </div>
          <p class="text-xs text-slate-500 dark:text-slate-400 truncate mt-0.5" title="${escapeHtml(clientId)}">${escapeHtml(clientId)}</p>
        </div>
      </div>

      <!-- Scope Request & Security Warnings -->
      <div class="space-y-4 mb-6">
        <div class="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
          The application is requesting access to administer server services and execute automation tools on your behalf.
        </div>

        ${hasAdmin ? `
        <div class="rounded-xl border border-amber-300 bg-amber-50 p-3.5 dark:border-amber-700/80 dark:bg-amber-950/30">
          <div class="flex items-start gap-3">
            <svg class="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
            <div class="text-xs text-amber-900 dark:text-amber-200">
              <span class="font-semibold">Privileged Root Scope Requested:</span>
              <p class="mt-0.5 leading-normal">
                Includes <code class="font-mono font-semibold">system:admin</code>. Destructive actions and command executions will still require explicit one-time confirmation.
              </p>
            </div>
          </div>
        </div>
        ` : ''}

        <!-- Collapsible Scopes Details -->
        <details class="group rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30">
          <summary class="flex cursor-pointer items-center justify-between p-3 text-xs font-medium text-slate-700 dark:text-slate-300 select-none">
            <span>Requested Scopes (${requestedScopes.length})</span>
            <svg class="h-4 w-4 transition-transform group-open:rotate-180 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
            </svg>
          </summary>
          <div class="p-3 pt-0 border-t border-slate-100 dark:border-slate-800/60 mt-1">
            <div class="flex flex-wrap gap-1.5 mt-2">
              ${scopeBadges}
            </div>
          </div>
        </details>
      </div>

      <!-- Password-Only Form (No Username Field) -->
      <form id="oauth-form" method="post" action="/oauth/authorize" class="space-y-4">
        ${hiddenInputsHtml}
        
        <div>
          <label for="password" class="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
            Owner Password
          </label>
          <div class="relative rounded-xl shadow-sm">
            <input
              type="password"
              id="password"
              name="password"
              autocomplete="current-password"
              required
              placeholder="Enter server owner password"
              class="block w-full rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-4 py-3 text-sm text-slate-900 dark:text-white placeholder-slate-400 focus:border-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 pr-12 transition"
            >
            <button
              type="button"
              id="toggle-password"
              aria-label="Toggle password visibility"
              class="absolute inset-y-0 right-0 flex items-center pr-3.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition"
            >
              <svg id="eye-icon" class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              </svg>
              <svg id="eye-slash-icon" class="w-5 h-5 hidden" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18" />
              </svg>
            </button>
          </div>
        </div>

        <button
          id="submit-btn"
          type="submit"
          class="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/40 shadow-lg shadow-emerald-600/20 active:scale-[0.99] transition"
        >
          <span>Authorize and Connect</span>
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3" />
          </svg>
        </button>

        ${cancelUrl ? `
        <div class="text-center pt-1">
          <a href="${escapeHtml(cancelUrl)}" class="text-xs text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition">
            Deny & Cancel Request
          </a>
        </div>
        ` : ''}
      </form>

      <!-- Status / Feedback Banner -->
      <div id="status-card" class="hidden mt-4 rounded-xl p-3.5 text-xs transition" role="status" aria-live="polite">
        <div class="flex items-start gap-2.5">
          <div id="status-spinner" class="hidden w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin shrink-0 mt-0.5"></div>
          <div id="status-content">
            <p id="status-title" class="font-semibold"></p>
            <p id="status-desc" class="mt-0.5 opacity-90"></p>
          </div>
        </div>
      </div>

    </div>

    <!-- Security Footer -->
    <div class="text-center mt-6 text-xs text-slate-400 dark:text-slate-500">
      <p>Protected by OAuth 2.1 & PKCE S256 with scoped administrator approvals.</p>
    </div>
  </div>

  <script nonce="${nonce}">
    const form = document.getElementById('oauth-form');
    const submitBtn = document.getElementById('submit-btn');
    const pwdInput = document.getElementById('password');
    const togglePwd = document.getElementById('toggle-password');
    const eyeIcon = document.getElementById('eye-icon');
    const eyeSlashIcon = document.getElementById('eye-slash-icon');
    const statusCard = document.getElementById('status-card');
    const statusSpinner = document.getElementById('status-spinner');
    const statusTitle = document.getElementById('status-title');
    const statusDesc = document.getElementById('status-desc');

    // Show/hide password toggle
    togglePwd.addEventListener('click', () => {
      const isPassword = pwdInput.type === 'password';
      pwdInput.type = isPassword ? 'text' : 'password';
      eyeIcon.classList.toggle('hidden', isPassword);
      eyeSlashIcon.classList.toggle('hidden', !isPassword);
      togglePwd.setAttribute('aria-pressed', isPassword ? 'true' : 'false');
    });

    function showStatus(type, title, desc) {
      statusCard.className = 'mt-4 rounded-xl p-3.5 text-xs transition';
      statusSpinner.classList.add('hidden');

      if (type === 'loading') {
        statusCard.classList.add('bg-slate-100', 'text-slate-800', 'dark:bg-slate-800', 'dark:text-slate-200', 'border', 'border-slate-200', 'dark:border-slate-700');
        statusSpinner.classList.remove('hidden');
      } else if (type === 'success') {
        statusCard.classList.add('bg-emerald-50', 'text-emerald-800', 'dark:bg-emerald-950/40', 'dark:text-emerald-300', 'border', 'border-emerald-300', 'dark:border-emerald-800');
      } else if (type === 'error') {
        statusCard.classList.add('bg-rose-50', 'text-rose-800', 'dark:bg-rose-950/40', 'dark:text-rose-300', 'border', 'border-rose-300', 'dark:border-rose-800');
      }
      statusTitle.textContent = title;
      statusDesc.textContent = desc || '';
      statusCard.classList.remove('hidden');
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      submitBtn.disabled = true;
      submitBtn.classList.add('opacity-70', 'cursor-wait');
      showStatus('loading', 'Authenticating...', 'Verifying owner password and generating authorization code.');

      try {
        const formData = new FormData(form);
        const body = new URLSearchParams(formData);

        const res = await fetch(form.action, {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
          },
          body: body.toString(),
          credentials: 'same-origin'
        });

        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ok || !data.redirect_url) {
          throw new Error(data.message || data.error_description || data.error || ('HTTP ' + res.status));
        }

        showStatus('success', 'Authorization Granted', 'Redirecting back to your application...');
        setTimeout(() => {
          window.location.assign(data.redirect_url);
        }, 400);

      } catch (err) {
        showStatus('error', 'Authentication Failed', err.message || 'Incorrect owner password. Please verify and try again.');
        submitBtn.disabled = false;
        submitBtn.classList.remove('opacity-70', 'cursor-wait');
      }
    });
  </script>
</body>
</html>`;
}
