(function () {
  const REPORTS_KEY = "cybershieldSavedReports";
  const CHAT_KEY = "cybershieldAiChatHistory";
  const currentPage = (window.location.pathname.split("/").pop() || "home2.html").toLowerCase();

  const pageToolMap = {
    "tool.html": ["whois", "rdap", "dns", "uptime"],
    "tool1.html": ["cve"],
    "tool2.html": ["vulnerability-analysis", "ip-threat-check", "domain-lookup-ip", "domain-asn-details", "email-header-analysis"],
    "toolhash.html": ["safe-link", "file-hashing", "ssl-analysis"],
    "toolhash-classic.html": ["safe-link", "file-hashing", "ssl-analysis"],
    "tools-lab.html": ["whois", "rdap", "dns", "uptime", "safe-link", "file-hashing", "ssl-analysis"],
    "urlscan.html": ["urlscan"],
    "threat-intel.html": ["threat-intel"],
    "analysis.html": [],
    "cases.html": [],
    "monitoring.html": [],
    "reports.html": []
  };

  const pageLabelMap = {
    "home2.html": "Command Center",
    "analysis.html": "Analysis Engine",
    "tools-lab.html": "Tools Lab",
    "tool.html": "OSINT Tools",
    "tool1.html": "CVE Scanner",
    "tool2.html": "Threat Lookup",
    "toolhash.html": "Security Utilities",
    "reports.html": "Reports",
    "cases.html": "Cases",
    "monitoring.html": "Monitoring",
    "urlscan.html": "URLScan Intelligence",
    "threat-intel.html": "Threat Intelligence"
  };

  const style = document.createElement("style");
  style.textContent = `
    .cyber-ai-launcher {
      position: fixed;
      right: 24px;
      bottom: 22px;
      z-index: 95;
      border: 0;
      border-radius: 999px;
      background:
        linear-gradient(135deg, rgba(14, 165, 233, 0.92), rgba(67, 56, 202, 0.96)),
        radial-gradient(circle at 20% 20%, rgba(255, 255, 255, 0.24), transparent 32%);
      color: #fff;
      box-shadow: 0 18px 44px rgba(37, 99, 235, 0.34);
      padding: 0.9rem 1.08rem;
      font-weight: 700;
      display: inline-flex;
      align-items: center;
      flex-direction: row;
      gap: 0.65rem;
      cursor: pointer;
      transition: transform 0.25s ease, box-shadow 0.25s ease;
    }
    .cyber-ai-launcher.panel-open {
      opacity: 0;
      pointer-events: none;
      transform: translateY(14px) scale(0.96);
    }
    .cyber-ai-launcher:hover {
      transform: translateY(-3px);
      box-shadow: 0 24px 58px rgba(37, 99, 235, 0.42);
    }
    .cyber-ai-launcher svg {
      transform: none;
    }
    .cyber-ai-overlay {
      position: fixed;
      inset: 0;
      background: linear-gradient(90deg, rgba(2, 6, 23, 0.18), rgba(2, 6, 23, 0.48));
      backdrop-filter: blur(3px);
      z-index: 92;
      display: none;
    }
    .cyber-ai-overlay.open {
      display: none;
    }
    .cyber-ai-panel {
      position: fixed;
      right: 0;
      top: 0;
      width: min(560px, calc(100vw - 18px));
      height: 100vh;
      min-height: 0;
      z-index: 96;
      border-radius: 28px 0 0 28px;
      overflow: hidden;
      background:
        radial-gradient(circle at 92% 10%, rgba(34, 211, 238, 0.14), transparent 28%),
        radial-gradient(circle at 14% 92%, rgba(99, 102, 241, 0.2), transparent 34%),
        linear-gradient(180deg, var(--cyber-ai-panel-bg, rgba(15, 23, 42, 0.98)), var(--cyber-ai-panel-bg2, rgba(2, 6, 23, 0.97)));
      color: var(--cyber-ai-text, #e5eefc);
      border-left: 1px solid var(--cyber-ai-line, rgba(125, 211, 252, 0.18));
      box-shadow: -30px 0 80px rgba(2, 6, 23, 0.35);
      display: none;
      backdrop-filter: blur(18px);
    }
    .cyber-ai-panel.open {
      display: grid;
      grid-template-rows: auto minmax(0, 1fr) auto auto;
    }
    html:not(.dark) .cyber-ai-panel {
      --cyber-ai-panel-bg: rgba(248, 250, 252, 0.97);
      --cyber-ai-panel-bg2: rgba(226, 232, 240, 0.96);
      --cyber-ai-text: #0f172a;
      --cyber-ai-muted: #475569;
      --cyber-ai-line: rgba(99, 102, 241, 0.18);
      box-shadow: -30px 0 80px rgba(15, 23, 42, 0.18);
    }
    .cyber-ai-header {
      padding: 1.15rem 1.2rem 1rem;
      background:
        radial-gradient(circle at top right, rgba(96, 165, 250, 0.24), transparent 40%),
        linear-gradient(135deg, rgba(15, 23, 42, 0.68), rgba(30, 41, 59, 0.52));
      border-bottom: 1px solid rgba(148, 163, 184, 0.14);
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 1rem;
      position: relative;
    }
    .cyber-ai-header::after {
      content: "";
      position: absolute;
      left: 1.2rem;
      right: 1.2rem;
      bottom: 0;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(34, 211, 238, 0.55), transparent);
    }
    .cyber-ai-title strong {
      display: block;
      font-size: 1.15rem;
      letter-spacing: 0.02em;
    }
    .cyber-ai-title p {
      margin: 0.3rem 0 0;
      color: var(--cyber-ai-muted, #cbd5e1);
      font-size: 0.84rem;
      line-height: 1.45;
      max-width: 28rem;
    }
    .cyber-ai-context {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.45rem;
      margin-bottom: 0.75rem;
    }
    .cyber-ai-context span {
      border-radius: 999px;
      border: 1px solid rgba(125, 211, 252, 0.18);
      background: rgba(14, 165, 233, 0.12);
      color: #a5f3fc;
      font-size: 0.68rem;
      font-weight: 800;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      padding: 0.32rem 0.58rem;
    }
    .cyber-ai-close {
      border: 0;
      border-radius: 9999px;
      width: 2rem;
      height: 2rem;
      background: rgba(99, 102, 241, 0.16);
      color: var(--cyber-ai-text, #e2e8f0);
      cursor: pointer;
      flex: 0 0 auto;
    }
    .cyber-ai-body {
      padding: 1rem 1.15rem;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 0.8rem;
      min-height: 0;
      max-height: none;
      background:
        linear-gradient(180deg, rgba(30, 41, 59, 0.2), transparent 24%);
    }
    .cyber-ai-message {
      border-radius: 18px;
      padding: 0.85rem 0.95rem;
      line-height: 1.55;
      font-size: 0.93rem;
      white-space: pre-wrap;
      max-width: 94%;
      box-shadow: 0 12px 24px rgba(2, 6, 23, 0.12);
    }
    .cyber-ai-message.user {
      background: rgba(37, 99, 235, 0.18);
      border: 1px solid rgba(96, 165, 250, 0.2);
      align-self: flex-end;
    }
    .cyber-ai-message.assistant {
      background:
        linear-gradient(180deg, rgba(30, 41, 59, 0.9), rgba(15, 23, 42, 0.86));
      border: 1px solid rgba(125, 211, 252, 0.13);
      align-self: flex-start;
    }
    html:not(.dark) .cyber-ai-message.assistant {
      background: rgba(255, 255, 255, 0.78);
      border-color: rgba(99, 102, 241, 0.18);
    }
    .cyber-ai-suggestions {
      padding: 0 1.15rem 0.9rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.55rem;
      border-top: 1px solid rgba(148, 163, 184, 0.1);
      background: rgba(15, 23, 42, 0.72);
    }
    html:not(.dark) .cyber-ai-suggestions {
      background: rgba(241, 245, 249, 0.72);
    }
    .cyber-ai-chip {
      margin-top: 0.75rem;
      border: 1px solid rgba(148, 163, 184, 0.22);
      background: rgba(51, 65, 85, 0.44);
      color: #e2e8f0;
      border-radius: 9999px;
      font-size: 0.76rem;
      padding: 0.42rem 0.78rem;
      cursor: pointer;
      transition: background 0.2s ease, border-color 0.2s ease;
    }
    html:not(.dark) .cyber-ai-chip {
      background: rgba(255, 255, 255, 0.78);
      color: #334155;
      border-color: rgba(99, 102, 241, 0.18);
    }
    .cyber-ai-chip:hover {
      background: rgba(59, 130, 246, 0.18);
      border-color: rgba(96, 165, 250, 0.35);
    }
    .cyber-ai-form {
      padding: 1rem 1.15rem 1.15rem;
      border-top: 1px solid rgba(148, 163, 184, 0.12);
      display: grid;
      gap: 0.75rem;
      background: rgba(15, 23, 42, 0.94);
    }
    html:not(.dark) .cyber-ai-form {
      background: rgba(248, 250, 252, 0.92);
    }
    .cyber-ai-textarea {
      width: 100%;
      resize: none;
      min-height: 118px;
      border-radius: 16px;
      border: 1px solid rgba(148, 163, 184, 0.2);
      background: rgba(15, 23, 42, 0.72);
      color: #f8fafc;
      padding: 0.9rem 1rem;
      outline: none;
      line-height: 1.5;
    }
    html:not(.dark) .cyber-ai-textarea {
      background: rgba(255, 255, 255, 0.86);
      color: #0f172a;
    }
    .cyber-ai-upload-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.6rem;
    }
    .cyber-ai-upload {
      border: 1px dashed rgba(125, 211, 252, 0.32);
      border-radius: 999px;
      background: rgba(14, 165, 233, 0.1);
      color: var(--cyber-ai-text, #e2e8f0);
      padding: 0.52rem 0.78rem;
      cursor: pointer;
      font-size: 0.8rem;
      font-weight: 700;
    }
    .cyber-ai-attachments {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .cyber-ai-attachment {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 999px;
      background: rgba(30, 41, 59, 0.44);
      padding: 0.32rem 0.45rem 0.32rem 0.35rem;
      font-size: 0.75rem;
    }
    html:not(.dark) .cyber-ai-attachment {
      background: rgba(255, 255, 255, 0.82);
    }
    .cyber-ai-attachment img {
      width: 26px;
      height: 26px;
      border-radius: 999px;
      object-fit: cover;
    }
    .cyber-ai-attachment button {
      border: 0;
      background: transparent;
      color: #ef4444;
      cursor: pointer;
      font-weight: 800;
    }
    .cyber-ai-textarea:focus {
      border-color: rgba(96, 165, 250, 0.5);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.18);
    }
    .cyber-ai-actions {
      display: flex;
      gap: 0.75rem;
      align-items: center;
      justify-content: space-between;
    }
    .cyber-ai-action-stack {
      display: flex;
      gap: 0.75rem;
      align-items: center;
    }
    .cyber-ai-actions button {
      border: 0;
      border-radius: 14px;
      padding: 0.8rem 1rem;
      font-weight: 600;
      cursor: pointer;
      min-width: 116px;
    }
    .cyber-ai-send {
      background: linear-gradient(135deg, #2563eb, #4f46e5);
      color: #fff;
      box-shadow: 0 12px 28px rgba(37, 99, 235, 0.22);
    }
    .cyber-ai-clear {
      background: rgba(226, 232, 240, 0.12);
      color: #e2e8f0;
    }
    html:not(.dark) .cyber-ai-clear {
      background: rgba(15, 23, 42, 0.08);
      color: #334155;
    }
    .cyber-ai-status {
      font-size: 0.75rem;
      color: var(--cyber-ai-muted, #cbd5e1);
      min-height: 1rem;
      line-height: 1.4;
      max-width: 280px;
    }
    @media (max-width: 768px) {
      .cyber-ai-launcher {
        right: 14px;
        bottom: 14px;
        padding: 0.85rem 1rem;
      }
      .cyber-ai-panel {
        right: 10px;
        left: 10px;
        top: 10px;
        width: auto;
        height: calc(100vh - 20px);
        min-height: 0;
        border-radius: 22px;
        border: 1px solid rgba(125, 211, 252, 0.2);
      }
      .cyber-ai-panel.open { grid-template-rows: auto minmax(0, 1fr) auto auto; }
      .cyber-ai-message {
        max-width: 100%;
      }
      .cyber-ai-actions {
        flex-direction: column;
        align-items: stretch;
      }
      .cyber-ai-action-stack {
        width: 100%;
      }
      .cyber-ai-actions button {
        width: 100%;
      }
    }
  `;
  document.head.appendChild(style);

  const launcher = document.createElement("button");
  launcher.className = "cyber-ai-launcher";
  launcher.type = "button";
  launcher.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width="20" height="20" aria-hidden="true">
      <path d="M12 2l7 3v6c0 5.25-3.44 9.92-7 11-3.56-1.08-7-5.75-7-11V5l7-3zm-2.25 8.5h1.5V12h1.5v-1.5h1.5V9h-1.5V7.5h-1.5V9h-1.5v1.5zM9 15.5h6V17H9v-1.5z"/>
    </svg>
    <span>AI Assistant</span>
  `;

  const overlay = document.createElement("div");
  overlay.className = "cyber-ai-overlay";

  const panel = document.createElement("section");
  panel.className = "cyber-ai-panel";
  panel.innerHTML = `
    <div class="cyber-ai-header">
      <div class="cyber-ai-title">
        <div class="cyber-ai-context">
          <span>Workspace Copilot</span>
          <span>${pageLabelMap[currentPage] || "CyberShield"}</span>
        </div>
        <strong>AI Findings Assistant</strong>
        <p>This assistant is part of the current investigation workspace. Use it to summarize findings, explain risk, identify gaps, and decide the next action.</p>
      </div>
      <button type="button" class="cyber-ai-close" aria-label="Minimize AI panel">×</button>
    </div>
    <div id="cyberAiBody" class="cyber-ai-body"></div>
    <div class="cyber-ai-suggestions">
      <button type="button" class="cyber-ai-chip" data-prompt="Summarize the latest report on this page.">Summarize latest finding</button>
      <button type="button" class="cyber-ai-chip" data-prompt="What should I investigate next based on the available evidence?">Next investigation step</button>
      <button type="button" class="cyber-ai-chip" data-prompt="Explain the current findings in simple language.">Explain simply</button>
    </div>
    <form id="cyberAiForm" class="cyber-ai-form">
      <textarea id="cyberAiInput" class="cyber-ai-textarea" placeholder="Ask about the current CVE, RDAP, DNS, IP, SSL, or saved report context..."></textarea>
      <div class="cyber-ai-upload-row">
        <button type="button" id="cyberAiAttach" class="cyber-ai-upload">Attach photo</button>
        <input id="cyberAiFileInput" type="file" accept="image/*" multiple hidden />
        <div id="cyberAiAttachments" class="cyber-ai-attachments"></div>
      </div>
      <div class="cyber-ai-actions">
        <div id="cyberAiStatus" class="cyber-ai-status"></div>
        <div class="cyber-ai-action-stack">
          <button type="button" id="cyberAiClear" class="cyber-ai-clear">Clear</button>
          <button type="submit" id="cyberAiSend" class="cyber-ai-send">Send</button>
        </div>
      </div>
    </form>
  `;

  document.body.appendChild(overlay);
  document.body.appendChild(launcher);
  const assistantHost = document.querySelector("[data-ai-assistant-host]") || document.querySelector("main") || document.body;
  assistantHost.appendChild(panel);

  const body = panel.querySelector("#cyberAiBody");
  const form = panel.querySelector("#cyberAiForm");
  const input = panel.querySelector("#cyberAiInput");
  const attachBtn = panel.querySelector("#cyberAiAttach");
  const fileInput = panel.querySelector("#cyberAiFileInput");
  const attachmentsBox = panel.querySelector("#cyberAiAttachments");
  const clearBtn = panel.querySelector("#cyberAiClear");
  const closeBtn = panel.querySelector(".cyber-ai-close");
  const status = panel.querySelector("#cyberAiStatus");
  let attachedImages = [];

  function openPanel() {
    panel.classList.add("open");
    launcher.classList.add("panel-open");
    window.setTimeout(() => input.focus(), 260);
  }

  function closePanel() {
    panel.classList.remove("open");
    launcher.classList.remove("panel-open");
  }

  function readChatHistory() {
    return JSON.parse(localStorage.getItem(CHAT_KEY) || "[]").slice(-10);
  }

  function writeChatHistory(history) {
    localStorage.setItem(CHAT_KEY, JSON.stringify(history.slice(-10)));
  }

  function addMessage(role, text, persist) {
    const node = document.createElement("div");
    node.className = `cyber-ai-message ${role}`;
    node.textContent = text;
    body.appendChild(node);
    body.scrollTop = body.scrollHeight;

    if (persist) {
      const history = readChatHistory();
      history.push({ role, text, createdAt: new Date().toISOString() });
      writeChatHistory(history);
    }
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return "unknown size";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function renderAttachments() {
    attachmentsBox.innerHTML = attachedImages.map((item, index) => `
      <span class="cyber-ai-attachment">
        <img src="${item.preview}" alt="">
        <span>${item.name.length > 22 ? `${item.name.slice(0, 19)}...` : item.name}</span>
        <button type="button" data-remove-attachment="${index}" aria-label="Remove ${item.name}">×</button>
      </span>
    `).join("");

    attachmentsBox.querySelectorAll("[data-remove-attachment]").forEach((button) => {
      button.addEventListener("click", () => {
        attachedImages.splice(Number(button.dataset.removeAttachment), 1);
        renderAttachments();
      });
    });
  }

  function readImageFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve({
        name: file.name,
        type: file.type || "image/*",
        size: file.size,
        preview: String(reader.result || "")
      });
      reader.onerror = () => reject(new Error(`Failed to read ${file.name}`));
      reader.readAsDataURL(file);
    });
  }

  function renderHistory() {
    body.innerHTML = "";
    const history = readChatHistory();
    if (!history.length) {
      addMessage("assistant", "I can explain your latest CyberShield findings and suggest what to check next.", false);
      return;
    }
    history.forEach((entry) => addMessage(entry.role, entry.text, false));
  }

  function inferRelevantReports() {
    const reports = JSON.parse(localStorage.getItem(REPORTS_KEY) || "[]");
    if (!reports.length) return [];

    const pageTools = pageToolMap[currentPage] || [];
    let relevant = reports;

    if (pageTools.length) {
      relevant = reports.filter((report) => pageTools.includes(report.tool));
    }

    if (!relevant.length && currentPage === "reports.html") {
      relevant = reports;
    }

    return relevant.slice(0, 4);
  }

  function compactValue(value, depth = 0) {
    if (value == null) return value;
    if (typeof value === "string") {
      return value.length > 420 ? `${value.slice(0, 420)}...` : value;
    }
    if (typeof value !== "object") return value;
    if (depth >= 3) {
      if (Array.isArray(value)) return value.slice(0, 4);
      return "[Truncated object]";
    }
    if (Array.isArray(value)) {
      return value.slice(0, 5).map((entry) => compactValue(entry, depth + 1));
    }
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 10)
        .map(([key, entry]) => [key, compactValue(entry, depth + 1)])
    );
  }

  function compactReportsForChat() {
    return inferRelevantReports().map((report) => ({
      id: report.id,
      tool: report.tool,
      query: report.query || null,
      fetchedAt: report.fetchedAt || null,
      savedAt: report.savedAt || null,
      report: compactValue(report.report)
    }));
  }

  async function readJsonSafe(response) {
    const contentType = response.headers.get("content-type") || "";
    const text = await response.text();
    if (!contentType.includes("application/json")) {
      throw new Error("Backend returned HTML instead of JSON. Restart the server and open the app through http://localhost:3000.");
    }
    return text ? JSON.parse(text) : {};
  }

  async function sendQuestion(question, attachments = []) {
    const attachmentText = attachments.length
      ? `\n\nAttached photo(s): ${attachments.map((item) => `${item.name} (${item.type}, ${formatBytes(item.size)})`).join(", ")}`
      : "";
    addMessage("user", `${question}${attachmentText}`, true);
    status.textContent = "CyberShield AI is analyzing the available evidence...";

    try {
      const response = await fetch("/api/ai/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question,
          page: currentPage,
          attachments: attachments.map((item) => ({
            name: item.name,
            type: item.type,
            size: item.size
          })),
          reports: compactReportsForChat(),
          history: readChatHistory().slice(-6).map((entry) => ({
            role: entry.role,
            text: typeof entry.text === "string" ? entry.text.slice(0, 500) : ""
          }))
        })
      });

      const payload = await readJsonSafe(response);
      if (!response.ok) {
        throw new Error(payload.error || "Failed to get an AI response.");
      }

      addMessage("assistant", payload.answer, true);
      status.textContent = `Answered by ${payload.provider || "ai"} / ${payload.model} at ${new Date(payload.timestamp).toLocaleTimeString()}.`;
    } catch (error) {
      addMessage("assistant", `I could not answer that right now: ${error.message}`, true);
      status.textContent = "The AI request failed.";
    }
  }

  launcher.addEventListener("click", () => {
    openPanel();
  });

  closeBtn.addEventListener("click", closePanel);
  overlay.addEventListener("click", closePanel);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const question = input.value.trim();
    if (!question && !attachedImages.length) {
      status.textContent = "Enter a question or attach a photo first.";
      return;
    }

    const attachments = attachedImages.slice();
    attachedImages = [];
    renderAttachments();
    input.value = "";
    await sendQuestion(question || "Review the attached photo in the context of this CyberShield workspace.", attachments);
  });

  clearBtn.addEventListener("click", () => {
    localStorage.removeItem(CHAT_KEY);
    attachedImages = [];
    renderAttachments();
    status.textContent = "Chat history cleared.";
    renderHistory();
  });

  attachBtn.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", async () => {
    const files = [...fileInput.files || []].filter((file) => file.type.startsWith("image/")).slice(0, 4);
    if (!files.length) {
      status.textContent = "Choose an image file to attach.";
      return;
    }

    try {
      const nextImages = await Promise.all(files.map(readImageFile));
      attachedImages = [...attachedImages, ...nextImages].slice(0, 4);
      renderAttachments();
      status.textContent = "Photo attached. Add a question and send when ready.";
    } catch (error) {
      status.textContent = error.message || "Failed to attach image.";
    } finally {
      fileInput.value = "";
    }
  });

  panel.querySelectorAll(".cyber-ai-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      input.value = chip.dataset.prompt || "";
      input.focus();
    });
  });

  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && panel.classList.contains("open")) {
      closePanel();
    }
  });

  renderHistory();
})();
