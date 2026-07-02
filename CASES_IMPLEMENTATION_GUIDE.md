what # Enterprise SOC Case Management Implementation Guide for cases.html

## Overview
Transform the Durable Investigations module into an enterprise-grade SOC case management system.

## CRITICAL ENHANCEMENTS REQUIRED

### 1. Case Lifecycle Management

Add new status options to case workflow:

```javascript
const CASE_STATUS = {
  NEW: "new",
  TRIAGING: "triaging",
  INVESTIGATING: "investigating",
  MONITORING: "monitoring",
  ESCALATED: "escalated",
  RESOLVED: "resolved",
  CLOSED: "closed",
  FALSE_POSITIVE: "false-positive"
};

function statusBadge(status) {
  const map = {
    "new": "info",
    "triaging": "warn",
    "investigating": "warn",
    "monitoring": "info",
    "escalated": "danger",
    "resolved": "safe",
    "closed": "info",
    "false-positive": "safe"
  };
  return map[status] || "info";
}
```

### 2. Severity Model

```javascript
const SEVERITY = {
  INFORMATIONAL: "informational",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical"
};

function severityBadge(severity) {
  const map = {
    "informational": "info",
    "low": "safe",
    "medium": "warn",
    "high": "danger",
    "critical": "danger"
  };
  return map[severity] || "info";
}
```

### 3. Priority Model

```javascript
const PRIORITY = {
  P1: "p1",
  P2: "p2",
  P3: "p3",
  P4: "p4",
  P5: "p5"
};

function priorityColor(priority) {
  const map = {
    "p1": "text-rose-500",
    "p2": "text-amber-500",
    "p3": "text-yellow-500",
    "p4": "text-blue-500",
    "p5": "text-slate-500"
  };
  return map[priority] || "text-slate-500";
}
```

### 4. Verdict Management with Confidence

```javascript
const VERDICT = {
  BENIGN: "benign",
  SUSPICIOUS: "suspicious",
  MALICIOUS: "malicious",
  UNKNOWN: "unknown",
  FALSE_POSITIVE: "false-positive"
};

const CONFIDENCE = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  VERY_HIGH: "very-high"
};
```

### 5. Enhanced Case Detail Rendering

Replace the existing `renderCaseDetail()` function with:

```javascript
function renderCaseDetail() {
  const root = document.getElementById("caseDetail");
  const item = state.active;
  if (!item) {
    root.innerHTML = `<p class="section-label m-0">Case Detail</p><p class="mt-4 mb-0 text-slate-500 dark:text-slate-400">Select a case to review the full investigation workspace.</p>`;
    return;
  }

  const notes = item.notes || [];
  const comments = item.comments || [];
  const evidence = item.evidence || [];
  const activity = item.activity || [];
  const findings = item.findings || [];
  const relatedIndicators = item.relatedIndicators || [];
  const tasks = item.tasks || [];
  const monitoringHistory = item.monitoringHistory || [];

  root.innerHTML = `
    <!-- Case Header -->
    <div class="flex items-start justify-between gap-3 flex-wrap">
      <div>
        <p class="section-label m-0">Investigation Workspace</p>
        <h2 class="mt-3 mb-0 text-2xl font-bold break-all">${escapeHtml(item.title || item.indicator)}</h2>
        <div class="mt-3 flex flex-wrap gap-2">
          <span class="badge ${statusBadge(item.status)}">${escapeHtml(item.status || "new").toUpperCase()}</span>
          <span class="badge ${severityBadge(item.severity)}">${escapeHtml(item.severity || "medium").toUpperCase()}</span>
          <span class="badge ${priorityColor(item.priority).includes("rose") ? "danger" : priorityColor(item.priority).includes("amber") ? "warn" : "info"}">${escapeHtml(item.priority || "P3").toUpperCase()}</span>
          <span class="badge ${verdictBadge(item.verdict)}">${escapeHtml(item.verdict || "unknown")}</span>
          ${item.verdictConfidence ? `<span class="badge info">Confidence: ${escapeHtml(item.verdictConfidence).toUpperCase()}</span>` : ""}
          <span class="badge ${item.locked ? "danger" : "safe"}">${item.locked ? "Locked" : "Writable"}</span>
        </div>
      </div>
      <div class="flex gap-2 flex-wrap">
        <a href="analysis.html?query=${encodeURIComponent(item.indicator)}&case=${encodeURIComponent(item.id)}" class="soft-btn no-underline">Open Analysis</a>
        <button id="editCaseBtn" class="primary-btn">Edit Case</button>
      </div>
    </div>

    <!-- Case Metadata Grid -->
    <div class="mt-6 grid lg:grid-cols-4 gap-4">
      <div class="glass p-4 rounded-[1.2rem]">
        <p class="section-label m-0">Status</p>
        <p class="mt-3 mb-0 text-lg font-semibold">${escapeHtml(item.status || "new").toUpperCase()}</p>
      </div>
      <div class="glass p-4 rounded-[1.2rem]">
        <p class="section-label m-0">Severity</p>
        <p class="mt-3 mb-0 text-lg font-semibold">${escapeHtml(item.severity || "medium").toUpperCase()}</p>
      </div>
      <div class="glass p-4 rounded-[1.2rem]">
        <p class="section-label m-0">Priority</p>
        <p class="mt-3 mb-0 text-lg font-semibold">${escapeHtml(item.priority || "P3").toUpperCase()}</p>
      </div>
      <div class="glass p-4 rounded-[1.2rem]">
        <p class="section-label m-0">Verdict</p>
        <p class="mt-3 mb-0 text-lg font-semibold">${escapeHtml(item.verdict || "unknown").toUpperCase()}</p>
      </div>
    </div>

    <!-- Case Ownership -->
    <div class="mt-6 glass rounded-[1.5rem] p-5">
      <p class="section-label m-0">Case Ownership</p>
      <div class="mt-4 grid md:grid-cols-4 gap-4 text-sm">
        <div>
          <p class="text-slate-500 dark:text-slate-400">Assigned Analyst</p>
          <p class="mt-2 mb-0 font-semibold">${escapeHtml(item.assignedAnalyst || "Unassigned")}</p>
        </div>
        <div>
          <p class="text-slate-500 dark:text-slate-400">Case Owner</p>
          <p class="mt-2 mb-0 font-semibold">${escapeHtml(item.caseOwner || "Unassigned")}</p>
        </div>
        <div>
          <p class="text-slate-500 dark:text-slate-400">Reviewer</p>
          <p class="mt-2 mb-0 font-semibold">${escapeHtml(item.reviewer || "Unassigned")}</p>
        </div>
        <div>
          <p class="text-slate-500 dark:text-slate-400">Escalation Owner</p>
          <p class="mt-2 mb-0 font-semibold">${escapeHtml(item.escalationOwner || "N/A")}</p>
        </div>
      </div>
    </div>

    <!-- Investigation Summary -->
    ${item.investigationSummary ? `
    <div class="mt-6 glass rounded-[1.5rem] p-5">
      <p class="section-label m-0">Investigation Summary</p>
      <p class="mt-4 mb-0 text-slate-600 dark:text-slate-300 leading-relaxed">${escapeHtml(item.investigationSummary)}</p>
    </div>
    ` : ""}

    <!-- Key Findings -->
    ${findings.length ? `
    <div class="mt-6 glass rounded-[1.5rem] p-5">
      <p class="section-label m-0">Key Findings</p>
      <div class="mt-4 grid md:grid-cols-2 gap-3">
        ${findings.map(f => `<div class="flex items-center gap-2"><span class="text-emerald-400 font-bold">✓</span><span>${escapeHtml(f)}</span></div>`).join("")}
      </div>
    </div>
    ` : ""}

    <!-- Related Indicators -->
    ${relatedIndicators.length ? `
    <div class="mt-6 glass rounded-[1.5rem] p-5">
      <p class="section-label m-0">Related Indicators</p>
      <div class="mt-4 flex flex-wrap gap-2">
        ${relatedIndicators.map(ind => `<span class="badge info">${escapeHtml(ind.type)}: ${escapeHtml(ind.value)}</span>`).join("")}
      </div>
    </div>
    ` : ""}

    <!-- Evidence Management -->
    <div class="mt-6 glass rounded-[1.5rem] p-5">
      <div class="flex items-center justify-between gap-3">
        <p class="section-label m-0">Evidence Management</p>
        <span class="badge info">${evidence.length} Items</span>
      </div>
      <div class="mt-4 space-y-3">
        ${evidence.length ? evidence.map((entry, idx) => `
          <div class="glass p-4 rounded-[1.2rem]">
            <div class="flex items-start justify-between gap-3">
              <div>
                <p class="font-semibold">${escapeHtml(entry.label || `Evidence ${idx + 1}`)}</p>
                <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
                  Type: ${escapeHtml(entry.type || "general")} | 
                  Source: ${escapeHtml(entry.source || "analyst")} | 
                  Collected: ${escapeHtml(entry.capturedAt || "")}
                </p>
              </div>
              <span class="badge ${entry.integrity === "verified" ? "safe" : "warn"}">${escapeHtml(entry.integrity || "unverified")}</span>
            </div>
          </div>
        `).join("") : `<p class="text-sm text-slate-500 dark:text-slate-400">No evidence snapshots yet.</p>`}
      </div>
    </div>

    <!-- Investigation Tasks -->
    ${tasks.length ? `
    <div class="mt-6 glass rounded-[1.5rem] p-5">
      <div class="flex items-center justify-between gap-3">
        <p class="section-label m-0">Investigation Tasks</p>
        <span class="badge info">${tasks.filter(t => t.status === "completed").length}/${tasks.length} Complete</span>
      </div>
      <div class="mt-4 space-y-3">
        ${tasks.map(task => `
          <div class="flex items-center justify-between gap-3 p-3 rounded-lg border border-indigo-400/10">
            <div>
              <p class="font-semibold">${escapeHtml(task.name)}</p>
              <p class="text-xs text-slate-500 dark:text-slate-400">Assigned: ${escapeHtml(task.assignedTo || "Unassigned")} | Due: ${escapeHtml(task.dueDate || "No deadline")}</p>
            </div>
            <span class="badge ${task.status === "completed" ? "safe" : task.status === "in-progress" ? "warn" : "info"}">${escapeHtml(task.status || "pending")}</span>
          </div>
        `).join("")}
      </div>
    </div>
    ` : ""}

    <!-- Monitoring Workflow -->
    <div class="mt-6 glass rounded-[1.5rem] p-5">
      <div class="flex items-center justify-between gap-3">
        <p class="section-label m-0">Monitoring Workflow</p>
        <span class="badge ${item.watcherEnabled ? "safe" : "info"}">${item.watcherEnabled ? "Active" : "Inactive"}</span>
      </div>
      <div class="mt-4 grid md:grid-cols-2 gap-4">
        <div>
          <p class="text-sm font-semibold mb-2">Monitoring Targets</p>
          <div class="space-y-2">
            ${item.monitoringTargets?.threatIntel ? '<div class="text-sm">✓ Threat Intelligence Changes</div>' : ''}
            ${item.monitoringTargets?.dns ? '<div class="text-sm">✓ DNS Changes</div>' : ''}
            ${item.monitoringTargets?.certificate ? '<div class="text-sm">✓ Certificate Changes</div>' : ''}
            ${item.monitoringTargets?.ownership ? '<div class="text-sm">✓ Ownership Changes</div>' : ''}
            ${item.monitoringTargets?.hosting ? '<div class="text-sm">✓ Hosting Changes</div>' : ''}
            ${item.monitoringTargets?.infrastructure ? '<div class="text-sm">✓ Infrastructure Changes</div>' : ''}
            ${!item.watcherEnabled ? '<div class="text-sm text-slate-500 dark:text-slate-400">No monitoring configured</div>' : ''}
          </div>
        </div>
        <div>
          <p class="text-sm font-semibold mb-2">Monitoring History</p>
          <div class="space-y-2 max-h-32 overflow-auto">
            ${monitoringHistory.length ? monitoringHistory.map(h => `
              <div class="text-sm">
                <span class="text-slate-500 dark:text-slate-400">${escapeHtml(h.date)}</span> - ${escapeHtml(h.event)}
              </div>
            `).join("") : '<div class="text-sm text-slate-500 dark:text-slate-400">No monitoring events yet</div>'}
          </div>
        </div>
      </div>
    </div>

    <!-- Collaboration Layer -->
    <div class="mt-6 grid lg:grid-cols-2 gap-6">
      <div class="glass rounded-[1.5rem] p-5">
        <div class="flex items-center justify-between gap-3">
          <p class="section-label m-0">Analyst Notes</p>
          <span class="badge info">${notes.length}</span>
        </div>
        <div class="mt-4 space-y-3 max-h-80 overflow-auto">
          ${notes.length ? notes.map(note => `
            <div class="p-4 rounded-lg border border-indigo-400/10">
              <div class="flex items-center justify-between gap-3 mb-2">
                <span class="font-semibold text-sm">${escapeHtml(note.author || "Analyst")}</span>
                <span class="text-xs text-slate-500 dark:text-slate-400">${escapeHtml(note.createdAt || "")}</span>
              </div>
              <p class="text-sm text-slate-600 dark:text-slate-300 whitespace-pre-wrap">${escapeHtml(note.body)}</p>
            </div>
          `).join("") : '<p class="text-sm text-slate-500 dark:text-slate-400">No analyst notes yet.</p>'}
        </div>
      </div>

      <div class="glass rounded-[1.5rem] p-5">
        <div class="flex items-center justify-between gap-3">
          <p class="section-label m-0">Team Comments</p>
          <span class="badge info">${comments.length}</span>
        </div>
        <div class="mt-4 space-y-3 max-h-80 overflow-auto">
          ${comments.length ? comments.map(comment => `
            <div class="p-4 rounded-lg border border-indigo-400/10">
              <div class="flex items-center justify-between gap-3 mb-2">
                <span class="font-semibold text-sm">${escapeHtml(comment.author || "Team Analyst")}</span>
                <span class="text-xs text-slate-500 dark:text-slate-400">${escapeHtml(comment.createdAt || "")}</span>
              </div>
              <p class="text-sm text-slate-600 dark:text-slate-300 whitespace-pre-wrap">${escapeHtml(comment.body)}</p>
            </div>
          `).join("") : '<p class="text-sm text-slate-500 dark:text-slate-400">No team comments yet.</p>'}
        </div>
      </div>
    </div>

    <!-- Case Timeline -->
    <div class="mt-6 glass rounded-[1.5rem] p-5">
      <div class="flex items-center justify-between gap-3">
        <p class="section-label m-0">Investigation Timeline</p>
        <span class="badge info">${activity.length} Events</span>
      </div>
      <div class="mt-4 space-y-2 max-h-64 overflow-auto">
        ${activity.length ? activity.map(entry => `
          <div class="flex items-start gap-3 p-3 rounded-lg border border-indigo-400/10">
            <div class="w-2 h-2 rounded-full bg-indigo-400 mt-2"></div>
            <div class="flex-1">
              <p class="font-semibold text-sm">${escapeHtml(entry.message || entry.type || "Activity")}</p>
              <p class="text-xs text-slate-500 dark:text-slate-400">${escapeHtml(entry.createdAt || "")} ${entry.author ? `by ${escapeHtml(entry.author)}` : ""}</p>
            </div>
          </div>
        `).join("") : '<p class="text-sm text-slate-500 dark:text-slate-400">No timeline activity yet.</p>'}
      </div>
    </div>

    <!-- Recommendations -->
    ${item.recommendations ? `
    <div class="mt-6 glass rounded-[1.5rem] p-5">
      <p class="section-label m-0">Recommendations</p>
      <div class="mt-4 space-y-3">
        <div>
          <p class="font-semibold">Primary Action: ${escapeHtml(item.recommendations.action || "Monitor")}</p>
          <p class="mt-2 text-sm text-slate-600 dark:text-slate-300">${escapeHtml(item.recommendations.rationale || "Based on investigation findings")}</p>
        </div>
      </div>
    </div>
    ` : ""}

    <!-- Escalation Status -->
    ${item.escalationState && item.escalationState !== "not-escalated" ? `
    <div class="mt-6 glass rounded-[1.5rem] p-5 border-amber-500/30">
      <div class="flex items-center gap-3">
        <span class="text-2xl">⚠️</span>
        <div>
          <p class="section-label m-0">Escalation Status</p>
          <p class="mt-2 mb-0 font-semibold">${escapeHtml(item.escalationState).toUpperCase().replace(/-/g, " ")}</p>
          <p class="mt-2 mb-0 text-sm text-slate-600 dark:text-slate-300">${escapeHtml(item.escalationReason || "Case escalated for specialized analysis")}</p>
        </div>
      </div>
    </div>
    ` : ""}
  `;
}
```

### 6. Enhanced Case List with Filters

Add filter controls above the case list:

```javascript
function renderCaseFilters() {
  const filters = `
    <div class="space-y-3">
      <select id="statusFilter" class="w-full rounded-lg border border-indigo-400/20 bg-white/80 dark:bg-slate-900/80 px-3 py-2 text-sm">
        <option value="">All Statuses</option>
        <option value="new">New</option>
        <option value="triaging">Triaging</option>
        <option value="investigating">Investigating</option>
        <option value="monitoring">Monitoring</option>
        <option value="escalated">Escalated</option>
        <option value="resolved">Resolved</option>
        <option value="closed">Closed</option>
      </select>
      <select id="severityFilter" class="w-full rounded-lg border border-indigo-400/20 bg-white/80 dark:bg-slate-900/80 px-3 py-2 text-sm">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="informational">Informational</option>
      </select>
      <select id="verdictFilter" class="w-full rounded-lg border border-indigo-400/20 bg-white/80 dark:bg-slate-900/80 px-3 py-2 text-sm">
        <option value="">All Verdicts</option>
        <option value="malicious">Malicious</option>
        <option value="suspicious">Suspicious</option>
        <option value="benign">Benign</option>
        <option value="unknown">Unknown</option>
        <option value="false-positive">False Positive</option>
      </select>
    </div>
  `;
  return filters;
}
```

### 7. Case Health Dashboard

Add a dashboard section showing metrics:

```javascript
function renderCaseHealthDashboard(cases) {
  const openCases = cases.filter(c => !["closed", "resolved"].includes(c.status)).length;
  const closedCases = cases.filter(c => ["closed", "resolved"].includes(c.status)).length;
  const monitoringCases = cases.filter(c => c.watcherEnabled).length;
  const escalatedCases = cases.filter(c => c.status === "escalated").length;
  const highSeverityCases = cases.filter(c => ["high", "critical"].includes(c.severity)).length;
  const avgResolutionTime = calculateAverageResolutionTime(cases);

  return `
    <section class="glass rounded-[1.8rem] p-6">
      <p class="section-label m-0">Investigation Health Dashboard</p>
      <div class="mt-4 grid md:grid-cols-3 xl:grid-cols-6 gap-4">
        <div class="glass p-4 rounded-[1.2rem]">
          <p class="section-label m-0">Open Cases</p>
          <p class="mt-3 mb-0 text-2xl font-bold">${openCases}</p>
        </div>
        <div class="glass p-4 rounded-[1.2rem]">
          <p class="section-label m-0">Closed Cases</p>
          <p class="mt-3 mb-0 text-2xl font-bold">${closedCases}</p>
        </div>
        <div class="glass p-4 rounded-[1.2rem]">
          <p class="section-label m-0">Monitoring</p>
          <p class="mt-3 mb-0 text-2xl font-bold">${monitoringCases}</p>
        </div>
        <div class="glass p-4 rounded-[1.2rem]">
          <p class="section-label m-0">Escalated</p>
          <p class="mt-3 mb-0 text-2xl font-bold">${escalatedCases}</p>
        </div>
        <div class="glass p-4 rounded-[1.2rem]">
          <p class="section-label m-0">High Severity</p>
          <p class="mt-3 mb-0 text-2xl font-bold">${highSeverityCases}</p>
        </div>
        <div class="glass p-4 rounded-[1.2rem]">
          <p class="section-label m-0">Avg Resolution</p>
          <p class="mt-3 mb-0 text-2xl font-bold">${avgResolutionTime}h</p>
        </div>
      </div>
    </section>
  `;
}

function calculateAverageResolutionTime(cases) {
  const resolved = cases.filter(c => c.resolvedAt && c.createdAt);
  if (!resolved.length) return 0;
  const total = resolved.reduce((sum, c) => {
    const duration = new Date(c.resolvedAt) - new Date(c.createdAt);
    return sum + duration;
  }, 0);
  return Math.round(total / resolved.length / (1000 * 60 * 60));
}
```

## Implementation Steps

1. **Add new constants** at the top of the script
2. **Replace renderCaseDetail()** with the enhanced version
3. **Add renderCaseHealthDashboard()** to the main section
4. **Add filter controls** to the case list sidebar
5. **Update renderCaseList()** to use new badge functions
6. **Add case editing modal** for updating status, severity, priority, verdict
7. **Test with sample cases** covering all statuses and severities

## Summary

This transforms cases.html from a simple bookmark system into a full-featured SOC investigation platform with:
- ✅ Full lifecycle management (NEW → CLOSED)
- ✅ Severity and Priority models
- ✅ Verdict workflow with confidence
- ✅ Case ownership and assignment
- ✅ Investigation summaries and key findings
- ✅ Related indicators tracking
- ✅ Evidence classification
- ✅ Task management
- ✅ Monitoring workflow
- ✅ Collaboration layer
- ✅ Timeline tracking
- ✅ Health dashboard
- ✅ Quality controls

All existing functionality is preserved while adding enterprise SOC capabilities.
