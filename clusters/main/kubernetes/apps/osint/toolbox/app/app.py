import hmac
import os
import re
import secrets
import select
import signal
import subprocess
import threading
import time
from pathlib import Path
from flask import (Flask, Response, abort, jsonify, render_template_string,
                   request, send_from_directory, session, stream_with_context)

app = Flask(__name__)
# One Gunicorn worker is intentional: the search mutex is process-local.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,  # TLS is terminated by Traefik.
    MAX_CONTENT_LENGTH=4096,
)
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
RESULTS_DIR = DATA_DIR / "results"
PRIVATE_DIR = DATA_DIR / "blackbird"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
(PRIVATE_DIR / "logs").mkdir(parents=True, exist_ok=True)
(DATA_DIR / "work").mkdir(parents=True, exist_ok=True)

# Exports only; the /data tree itself is deliberately NOT web-accessible.
EXPORT_EXTENSIONS = {".txt", ".csv", ".pdf", ".json", ".xlsx"}
USERNAME_REGEX = re.compile(r"^[\w.-]{1,64}$", re.ASCII)
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
search_lock = threading.Lock()
active_search_guard = threading.Lock()
active_search = None  # Exactly one active search per single-worker Gunicorn process.
MAX_SEARCH_SECONDS = 600

HTML_TEMPLATE = r"""

<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<title>OSINT Toolbox</title>

<meta name="viewport" content="width=device-width, initial-scale=1">

<script>
(function () {
  let savedTheme = null;
  try { savedTheme = localStorage.getItem('osint-toolbox-theme'); } catch (_) {}
  document.documentElement.dataset.theme = savedTheme === 'light' ? 'light' : 'dark';
})();
</script>

<style>
:root {
  /* OLED-black theme is the default. */
  color-scheme: dark;
  --page: #000000;
  --surface: #000000;
  --field: #101010;
  --text: #f2f4f8;
  --muted: #aab3c2;
  --border: #292929;
  --accent: #6aa9ff;
  --accent-hover: #8abaff;
  --button: #216bd5;
  --button-hover: #1b59b3;
  --button-text: #ffffff;
  --log: #000000;
  --log-text: #d6e4f5;
  --shadow: none;
  --toggle-off: #343434;
  --toggle-on: #216bd5;
}
html[data-theme="light"] {
  color-scheme: light;
  --page: #f4f4f9;
  --surface: #ffffff;
  --field: #ffffff;
  --text: #202b3a;
  --muted: #526075;
  --border: #d8dee8;
  --accent: #005ecb;
  --accent-hover: #004c9e;
  --button: #0069d9;
  --button-hover: #0056b3;
  --button-text: #ffffff;
  --log: #f1f4f9;
  --log-text: #1b2736;
  --shadow: 0 2px 12px rgba(24, 35, 55, 0.07);
  --toggle-off: #c8d0db;
  --toggle-on: #0069d9;
}
* { box-sizing: border-box; }
html { background: var(--page); }
body {
  max-width: 940px;
  margin: 0 auto;
  padding: 32px 20px 56px;
  background: var(--page);
  color: var(--text);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  line-height: 1.5;
}
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  margin-bottom: 26px;
}
h1 { font-size: 1.8rem; letter-spacing: -0.025em; margin: 0; }
h2 { font-size: 1.14rem; margin: 0 0 16px; }
.card {
  background: var(--surface);
  padding: 22px;
  margin-bottom: 18px;
  border: 1px solid var(--border);
  border-radius: 12px;
  box-shadow: var(--shadow);
}
.field-label { display: block; margin: 14px 0 6px; font-weight: 600; }
input[type="text"], select {
  display: block;
  width: 100%;
  padding: 10px 12px;
  min-height: 42px;
  background: var(--field);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 7px;
  font: inherit;
}
input[type="text"]::placeholder { color: var(--muted); }
input:focus-visible, select:focus-visible, button:focus-visible, a:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 3px;
}
.checkboxes { display: flex; flex-wrap: wrap; gap: 12px 24px; margin-top: 17px; }
.checkbox-label { display: inline-flex; align-items: center; gap: 8px; cursor: pointer; }
.checkbox-label input { width: 16px; height: 16px; margin: 0; accent-color: var(--button); }
button {
  background: var(--button);
  color: var(--button-text);
  border: 0;
  border-radius: 7px;
  padding: 10px 20px;
  margin-top: 20px;
  min-height: 42px;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
}
button:hover { background: var(--button-hover); }
button:disabled { opacity: 0.5; cursor: not-allowed; }
.button-row { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; }
.button-row button { margin-top: 20px; }
.stop-button { background: #b4232e; color: #ffffff; }
.stop-button:hover:not(:disabled) { background: #921b25; }
html[data-theme="light"] .stop-button { background: #bb2532; }
html[data-theme="light"] .stop-button:hover:not(:disabled) { background: #981b28; }
pre {
  background: var(--log);
  color: var(--log-text);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  margin: 0;
  height: 300px;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 0.9rem;
}
ul { list-style: none; margin: 0; padding: 0; }
li {
  padding: 10px 0;
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
  overflow-wrap: anywhere;
}
li:last-child { border-bottom: 0; }
a { color: var(--accent); }
a:hover { color: var(--accent-hover); }
.theme-switch { display: inline-flex; align-items: center; gap: 12px; cursor: pointer; font-weight: 600; }
.theme-switch input { position: absolute; opacity: 0; width: 1px; height: 1px; }
.theme-switch__track {
  position: relative;
  display: inline-block;
  width: 48px;
  height: 27px;
  flex-shrink: 0;
  background: var(--toggle-off);
  border: 1px solid var(--border);
  border-radius: 999px;
  transition: background 160ms ease;
}
.theme-switch__track::after {
  content: "";
  position: absolute;
  left: 3px;
  top: 3px;
  width: 19px;
  height: 19px;
  background: #fff;
  border-radius: 50%;
  transition: transform 160ms ease;
}
.theme-switch input:checked + .theme-switch__track { background: var(--toggle-on); }
.theme-switch input:checked + .theme-switch__track::after { transform: translateX(21px); }
.theme-switch input:focus-visible + .theme-switch__track { outline: 2px solid var(--accent); outline-offset: 3px; }
@media (max-width: 520px) {
  body { padding: 22px 14px 40px; }
  h1 { font-size: 1.45rem; }
  .card { padding: 17px; }
}
@media (prefers-reduced-motion: reduce) {
  .theme-switch__track, .theme-switch__track::after { transition: none; }
}
</style>

</head>

<body>

<header class="header">
  <h1>OSINT Toolbox Control Panel</h1>
  <label class="theme-switch" for="themeToggle">
    <span>OLED dark</span>
    <input type="checkbox" id="themeToggle" role="switch" checked>
    <span class="theme-switch__track" aria-hidden="true"></span>
  </label>
</header>


<div class="card">

<h2>Run Tool</h2>

<form id="runForm">

<label class="field-label" for="tool">Select Tool:</label>

<select id="tool" name="tool">

<option value="sherlock">Sherlock (Username)</option>

<option value="blackbird">Blackbird (Username)</option>

<option value="blackbird_email">Blackbird (Email)</option>

<option value="ghunt">GHunt (Email)</option>

</select>



<label class="field-label" for="target" id="targetLabel">Target username:</label>

<input type="text" id="target" name="target" required autocomplete="off" placeholder="e.g. target_user">



<div class="checkboxes">
  <label class="checkbox-label"><input type="checkbox" id="csv_flag" name="csv"> Export CSV</label>
  <label class="checkbox-label"><input type="checkbox" id="pdf_flag" name="pdf"> Export PDF</label>
</div>



<div class="button-row">
  <button type="submit" id="submitBtn">Run Search</button>
  <button type="button" id="stopBtn" class="stop-button" disabled>Stop Search</button>
</div>

</form>

</div>



<div class="card">

<h2>Live Output</h2>

<pre id="output">Waiting for execution...</pre>

</div>



<div class="card">

<h2>Result Files (/data/results)</h2>

<ul id="fileList">Loading files...</ul>

</div>



<script>

const CSRF_TOKEN = {{ csrf_token | tojson }};
const themeToggle = document.getElementById('themeToggle');
themeToggle.checked = document.documentElement.dataset.theme !== 'light';
themeToggle.addEventListener('change', () => {
  const theme = themeToggle.checked ? 'dark' : 'light';
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem('osint-toolbox-theme', theme); } catch (_) {}
});

const form = document.getElementById('runForm');
const toolSelect = document.getElementById('tool');
const targetInput = document.getElementById('target');
const targetLabel = document.getElementById('targetLabel');

function updateTargetField() {
  const expectsEmail = toolSelect.value === 'blackbird_email' || toolSelect.value === 'ghunt';
  targetLabel.textContent = expectsEmail ? 'Target email:' : 'Target username:';
  targetInput.type = expectsEmail ? 'email' : 'text';
  targetInput.placeholder = expectsEmail ? 'e.g. name@example.com' : 'e.g. target_user';
  targetInput.value = '';
}
toolSelect.addEventListener('change', updateTargetField);
updateTargetField();

const outputPre = document.getElementById('output');

const submitBtn = document.getElementById('submitBtn');
const stopBtn = document.getElementById('stopBtn');
let searchInProgress = false;
let activeSearchId = null;
let stopRequested = false;
let stopSent = false;

async function sendStopRequest() {
  if (!activeSearchId || stopSent) return;
  stopSent = true;
  try {
    const response = await fetch('/api/stop', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN },
      body: JSON.stringify({ search_id: activeSearchId })
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      // The search can finish naturally between clicking Stop and this request.
      if (response.status === 404 || response.status === 409) return;
      throw new Error(detail.error || `Stop failed (HTTP ${response.status})`);
    }
  } catch (error) {
    outputPre.textContent += `Unable to stop search: ${error.message}\n`;
    stopSent = false;
    if (searchInProgress) stopBtn.disabled = false;
  }
}

stopBtn.addEventListener('click', async () => {
  if (!searchInProgress || stopRequested) return;
  stopRequested = true;
  stopBtn.disabled = true;
  outputPre.textContent += 'Stopping search...\n';
  // A click before the POST response arrives is queued until its search ID is known.
  await sendStopRequest();
});

const fileListUl = document.getElementById('fileList');



async function loadFiles() {
  try {
    const res = await fetch('/api/files', { credentials: 'same-origin' });
    if (!res.ok) throw new Error('Unable to load files');
    const files = await res.json();
    fileListUl.replaceChildren();
    if (!files.length) {
      const li = document.createElement('li');
      li.textContent = 'No result files found.';
      fileListUl.appendChild(li);
      return;
    }
    for (const filename of files) {
      const li = document.createElement('li');
      const label = document.createElement('span');
      label.textContent = filename; // Never parse filenames as HTML.
      const link = document.createElement('a');
      link.textContent = 'Download';
      link.href = '/api/download/' + filename.split('/').map(encodeURIComponent).join('/');
      link.rel = 'noopener noreferrer';
      li.append(label, link);
      fileListUl.appendChild(li);
    }
  } catch (error) {
    fileListUl.replaceChildren();
    const li = document.createElement('li');
    li.textContent = 'Error loading file list.';
    fileListUl.appendChild(li);
  }
}

// PDF export is supported by Blackbird; Sherlock supports CSV; GHunt has neither flag.
const csvFlag = document.getElementById('csv_flag');
const pdfFlag = document.getElementById('pdf_flag');
function updateExportFlags() {
  const isBlackbird = toolSelect.value === 'blackbird' || toolSelect.value === 'blackbird_email';
  csvFlag.disabled = toolSelect.value === 'ghunt';
  pdfFlag.disabled = !isBlackbird;
  if (csvFlag.disabled) csvFlag.checked = false;
  if (pdfFlag.disabled) pdfFlag.checked = false;
}
toolSelect.addEventListener('change', updateExportFlags);
updateExportFlags();

// POST is required for search execution. Fetch streams the SSE response.
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (searchInProgress) return;
  searchInProgress = true;
  activeSearchId = null;
  stopRequested = false;
  stopSent = false;
  submitBtn.disabled = true;
  stopBtn.disabled = false;
  outputPre.textContent = 'Initializing search...\n';
  try {
    const response = await fetch('/api/run', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN },
      body: JSON.stringify({
        tool: toolSelect.value,
        target: targetInput.value.trim(),
        csv: csvFlag.checked,
        pdf: pdfFlag.checked
      })
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || `Request failed (HTTP ${response.status})`);
    }
    activeSearchId = response.headers.get('X-Search-Id');
    if (!activeSearchId) throw new Error('Search ID missing from response');
    if (stopRequested) await sendStopRequest();
    if (!response.body) throw new Error('Streaming is unavailable in this browser');
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    function handleEvents() {
      const parts = buffer.split(/\r?\n\r?\n/);
      buffer = parts.pop();
      for (const block of parts) {
        const lines = block.split(/\r?\n/)
          .filter(line => line.startsWith('data:'))
          .map(line => line.slice(5).trimStart());
        if (lines.length) {
          outputPre.textContent += lines.join('\n') + '\n';
          outputPre.scrollTop = outputPre.scrollHeight;
        }
      }
    }
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      handleEvents();
    }
    buffer += decoder.decode();
    buffer += '\n\n';
    handleEvents();
  } catch (error) {
    outputPre.textContent += `Error: ${error.message}\n`;
  } finally {
    searchInProgress = false;
    activeSearchId = null;
    stopRequested = false;
    stopSent = false;
    submitBtn.disabled = false;
    stopBtn.disabled = true;
    await loadFiles();
  }
});

loadFiles();
setInterval(loadFiles, 10000); // Refresh file list every 10s

</script>

</body>

</html>

"""

@app.after_request
def safe_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/healthz")
def healthcheck():
    return Response("ok\n", mimetype="text/plain")

@app.get("/")
def index():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return render_template_string(HTML_TEMPLATE, csrf_token=session["csrf_token"])

def safe_export(path):
    # Reject symlinks, hidden files, traversals, and anything outside results.
    try:
        if not path.is_file() or path.is_symlink():
            return False
        if any(part.startswith(".") for part in path.relative_to(RESULTS_DIR).parts):
            return False
        if path.suffix.lower() not in EXPORT_EXTENSIONS:
            return False
        return path.resolve().is_relative_to(RESULTS_DIR.resolve())
    except (OSError, ValueError):
        return False

@app.get("/api/files")
def list_files():
    files = []
    try:
        for candidate in RESULTS_DIR.rglob("*"):
            if safe_export(candidate):
                files.append(candidate.relative_to(RESULTS_DIR).as_posix())
            if len(files) >= 500:
                break
    except OSError:
        pass
    return jsonify(sorted(files))

@app.get("/api/download/<path:filename>")
def download_file(filename):
    candidate = RESULTS_DIR / filename
    if not safe_export(candidate):
        abort(404)
    return send_from_directory(RESULTS_DIR, filename, as_attachment=True)

def sse(message):
    # Escape control characters so subprocess output cannot inject new SSE events.
    message = str(message).replace("\r", " ").replace("\n", " ")
    return f"data: {message}\n\n"

def has_valid_csrf():
    expected = session.get("csrf_token", "")
    supplied = request.headers.get("X-CSRF-Token", "")
    return bool(expected) and hmac.compare_digest(expected, supplied)


def stop_process_group(process):
    """Stop the full process group, including normal child subprocesses."""
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    # A child may outlive the parent; kill remaining members of its process group.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        app.logger.warning("OSINT process did not exit after SIGKILL")


@app.post("/api/stop")
def stop_tool():
    if not has_valid_csrf():
        return jsonify(error="CSRF token missing or invalid; refresh the page"), 403
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("search_id"), str):
        return jsonify(error="Expected search_id"), 400
    with active_search_guard:
        state = active_search
        if state is None or state["id"] != payload["search_id"]:
            return jsonify(error="Search has already finished or was not found"), 404
        if state["owner"] != session.get("search_owner"):
            return jsonify(error="Not allowed to stop this search"), 403
        state["cancel"].set()
    # The search streaming thread observes cancellation within approximately 0.5s.
    return jsonify(status="stopping"), 202


@app.post("/api/run")
def run_tool():
    global active_search
    if not has_valid_csrf():
        return jsonify(error="CSRF token missing or invalid; refresh the page"), 403
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Expected JSON request"), 400
    tool, target = payload.get("tool"), payload.get("target")
    csv, pdf = payload.get("csv") is True, payload.get("pdf") is True
    if not isinstance(target, str):
        return jsonify(error="Invalid target"), 400
    if tool not in {"sherlock", "blackbird", "blackbird_email", "ghunt"}:
        return jsonify(error="Unknown tool"), 400
    if tool in {"blackbird_email", "ghunt"}:
        if not EMAIL_REGEX.fullmatch(target) or len(target) > 254:
            return jsonify(error="Enter a valid email address"), 400
    elif not USERNAME_REGEX.fullmatch(target) or target.startswith("-"):
        return jsonify(error="Enter a valid username"), 400
    if tool == "ghunt" and (csv or pdf):
        return jsonify(error="GHunt export flags are not supported"), 400
    if tool == "sherlock" and pdf:
        return jsonify(error="Sherlock PDF export is not supported"), 400
    if not search_lock.acquire(blocking=False):
        return jsonify(error="Another search is already running"), 409

    if "search_owner" not in session:
        session["search_owner"] = secrets.token_urlsafe(32)
    state = {
        "id": secrets.token_urlsafe(24),
        "owner": session["search_owner"],
        "cancel": threading.Event(),
    }
    with active_search_guard:
        active_search = state

    def generate():
        global active_search
        process = None
        cancelled = False
        timed_out = False
        try:
            if tool == "sherlock":
                cmd = ["sherlock", target, "--output", str(RESULTS_DIR / f"{target}.txt"), "--no-color"]
                if csv:
                    cmd.append("--csv")
            elif tool in {"blackbird", "blackbird_email"}:
                cmd = ["blackbird", "-e" if tool == "blackbird_email" else "-u", target]
                if csv:
                    cmd.append("--csv")
                if pdf:
                    cmd.append("--pdf")
            else:
                cmd = ["ghunt", "email", target]
            if state["cancel"].is_set():
                yield sse("Search cancelled before starting.")
                return
            yield sse(f"Executing: {' '.join(cmd)}")
            if state["cancel"].is_set():
                yield sse("Search cancelled before starting.")
                return
            process = subprocess.Popen(
                cmd, cwd=str(DATA_DIR / "work"), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=0, start_new_session=True,
            )
            # Read nonblocking bytes: a tool writing without a newline cannot hang cancellation.
            fd = process.stdout.fileno()
            os.set_blocking(fd, False)
            pending = b""
            deadline = time.monotonic() + MAX_SEARCH_SECONDS
            last_heartbeat = time.monotonic()
            while True:
                now = time.monotonic()
                if state["cancel"].is_set():
                    cancelled = True
                    break
                if now >= deadline:
                    timed_out = True
                    break
                readable, _, _ = select.select([fd], [], [], 0.5)
                if readable:
                    try:
                        chunk = os.read(fd, 16384)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        if pending:
                            yield sse(pending.decode("utf-8", "replace")[:4096])
                        break
                    pending += chunk
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        yield sse(line.decode("utf-8", "replace")[:4096])
                    if len(pending) >= 65536:
                        yield sse(pending[:4096].decode("utf-8", "replace"))
                        pending = b""
                elif now - last_heartbeat >= 10:
                    yield ": heartbeat\n\n"
                    last_heartbeat = now
            if cancelled or timed_out:
                stop_process_group(process)
                yield sse("Search cancelled by user." if cancelled else "Search timed out and was stopped.")
            else:
                process.wait(timeout=5)
            yield sse(f"[Process finished with exit code {process.returncode}]")
        except Exception as exc:
            app.logger.exception("OSINT tool failed")
            yield sse(f"Search failed: {type(exc).__name__}")
        finally:
            if process is not None and process.poll() is None:
                stop_process_group(process)
            if process is not None and process.stdout:
                process.stdout.close()
            with active_search_guard:
                if active_search is state:
                    active_search = None
            search_lock.release()

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"X-Accel-Buffering": "no", "X-Search-Id": state["id"]},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
