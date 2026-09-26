const $ = (id) => document.getElementById(id);
const api = async (path, options = {}) => {
  let response;
  try {
    response = await fetch(path, {headers: {"Content-Type": "application/json", ...(options.headers || {})}, ...options});
  } catch {
    // Browser fetch errors are otherwise exposed as the unhelpful "Failed to fetch".
    // All API calls here target this local service, so provide an actionable message.
    throw new Error("无法连接本地服务，请确认服务已启动后重试");
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail || data));
  return data;
};

const statusLabels = {success: "成功", failed: "失败", disabled: "已禁用", running: "进行中", pending: "待处理", queued: "排队中", cancelled: "已取消"};
const jobStepLabels = {queued: "等待执行", proxy: "获取代理", login: "登录授权", check_2fa: "检查 2FA", enroll_2fa: "申请密钥", activate_2fa: "激活 2FA", save_token: "保存 Token", save_totp: "保存 2FA 密钥", finished: "已完成"};
const selectedAccounts = new Set();
const accountSnapshot = new Map();
let accountListItems = [];
let accountQuotaMap = new Map();
const initialAccountParams = new URLSearchParams(window.location.search);
const initialAccountPage = Number(initialAccountParams.get("page"));
const initialAccountPageSize = Number(initialAccountParams.get("page_size"));
let accountSearchQuery = String(initialAccountParams.get("q") || "").slice(0, 200);
const validAccountStatuses = ["", "pending", "running", "success", "failed", "disabled"];
const initialAccountStatus = String(initialAccountParams.get("status") || "").toLowerCase();
let accountStatusFilter = validAccountStatuses.includes(initialAccountStatus) ? initialAccountStatus : "";
const initialProxyPage = Number(initialAccountParams.get("proxy_page"));
const initialProxyPageSize = Number(initialAccountParams.get("proxy_page_size"));
let accountGlobalTotal = 0;
let accountAuthorizedTotal = 0;
let accountSearchTimer = 0;
let accountRefreshSequence = 0;
const accountPagination = {
  page: Number.isInteger(initialAccountPage) && initialAccountPage > 0 ? initialAccountPage : 1,
  pageSize: [10, 20, 50, 100, 200, 500, 1000, 2000, 5000].includes(initialAccountPageSize) ? initialAccountPageSize : 20,
  total: 0,
  totalPages: 1,
  loading: false,
};
const proxyPagination = {
  page: Number.isInteger(initialProxyPage) && initialProxyPage > 0 ? initialProxyPage : 1,
  pageSize: [20, 50, 100, 200, 500, 1000, 2000, 5000].includes(initialProxyPageSize) ? initialProxyPageSize : 20,
  total: 0,
  totalPages: 1,
  loading: false,
};
let proxyListItems = [];
const activeReauthJobs = new Map();
const quotaProgressSnapshot = {running: false, active_account_ids: []};
const connectionModeSnapshot = {useProxy: false, total: 0, available: 0};
const operationState = {
  reauthBusy: false,
  reauthIds: new Set(),
  reauthTargetCount: 0,
  totpSetupBusy: false,
  totpSetupIds: new Set(),
  totpSetupTargetCount: 0,
  targetedReauthBusy: false,
  livenessBusy: false,
  livenessIds: new Set(),
  livenessTargetCount: 0,
  quotaBusy: false,
  quotaIds: new Set(),
  quotaTargetCount: 0,
  targetedQuotaBusy: false,
  cleanupDisabledBusy: false,
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"}[char]));
}

function formatCredit(value) {
  const number = Number(value || 0);
  return Number.isFinite(number) ? number.toLocaleString("zh-CN", {maximumFractionDigits: 2}) : "0";
}

function quotaTone(quota) {
  if (quota.credits_unlimited) return "purple";
  if (quota.status && quota.status !== "success") return "red";
  const value = Number(quota.credits_balance);
  if (quota.status === "success" && (quota.credits_has === false || quota.credits_has === 0 || quota.credits_has === "0")) return "red";
  if (!Number.isFinite(value)) return "neutral";
  if (value <= 0) return "red";
  // Keep the row badge in the same six tiers as the quota summary cards.
  if (value < 100) return "orange";
  if (value < 500) return "green";
  if (value < 1000) return "blue";
  return "gold";
}

function quotaDisplay(quota) {
  if (quota.credits_unlimited) return "无额度";
  if (quota.status && quota.status !== "success") return quota.http_status === 429 ? "429 限流" : "查询失败";
  if (quota.status === "success" && (quota.credits_has === false || quota.credits_has === 0 || quota.credits_has === "0") && quota.credits_balance == null) return "0";
  if (quota.credits_balance != null) return formatCredit(quota.credits_balance);
  return quota.status ? "未识别" : "待查询";
}

function planLabel(quota) {
  const explicit = String(quota.plan_label || "").trim();
  if (explicit) return explicit;
  const normalized = String(quota.plan_type || "").toLowerCase();
  if (normalized.includes("plus")) return "Plus";
  if (normalized.includes("free")) return "Free";
  if (normalized.includes("pro")) return "Pro";
  if (normalized.includes("team")) return "Team";
  if (normalized.includes("enterprise")) return "Enterprise";
  return "";
}

function planTone(label) {
  const normalized = String(label || "").toLowerCase();
  return ["free", "plus", "pro", "team", "enterprise"].includes(normalized) ? normalized : "unknown";
}

function formatPercent(value) {
  if (value === null || value === undefined || value === "") return "";
  const number = Number(value);
  if (!Number.isFinite(number)) return "";
  const rounded = Math.round(number * 10) / 10;
  return `${rounded}%`;
}

function formatResetAfter(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) return "";
  let remaining = Math.floor(value);
  const days = Math.floor(remaining / 86400);
  remaining %= 86400;
  const hours = Math.floor(remaining / 3600);
  remaining %= 3600;
  const minutes = Math.floor(remaining / 60);
  const parts = [];
  if (days) parts.push(`${days}d`);
  if (hours || days) parts.push(`${hours}h`);
  if (minutes || (!days && !hours)) parts.push(`${minutes}m`);
  return parts.join("");
}

function formatResetAt(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (number) => String(number).padStart(2, "0");
  return `${pad(date.getMonth() + 1)}/${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function renderJobs(jobs = {}) {
  const items = Array.isArray(jobs.items) ? jobs.items.slice(0, 20) : [];
  $("jobStats").textContent = `最近 ${items.length} 条`;
  $("jobs").innerHTML = items.length ? items.map((job) => {
    const status = String(job.status || "pending").toLowerCase();
    const operation = String(job.operation || "reauth").toLowerCase();
    const tone = ["success", "failed", "running", "pending", "cancelled"].includes(status) ? status : "pending";
    const icon = status === "success" ? "✓" : status === "failed" ? "×" : status === "running" ? "↻" : status === "cancelled" ? "−" : "…";
    const step = jobStepLabels[String(job.current_step || "").toLowerCase()] || String(job.current_step || "等待执行");
    const timeValue = job.finished_at || job.started_at || job.created_at;
    const time = formatResetAt(timeValue) || "—";
    const proxyEndpoint = String(job.proxy_endpoint || "").trim();
    const proxyState = String(job.proxy_state || "").trim().toLowerCase();
    let connection = "直连（未使用代理）";
    let connectionTone = "direct";
    if (job.use_proxy && proxyState === "claimed" && proxyEndpoint) {
      connection = `已使用代理 ${proxyEndpoint}`;
      connectionTone = "proxy";
    } else if (job.use_proxy && proxyState === "failed") {
      connection = "代理未领取成功";
      connectionTone = "failed";
    } else if (job.use_proxy && ["pending", "running"].includes(status)) {
      connection = "正在从代理池领取代理";
      connectionTone = "waiting";
    } else if (job.use_proxy) {
      connection = "代理池模式（旧任务未记录实际地址）";
      connectionTone = "waiting";
    }
    const error = job.error ? `<div class="job-error"><b>失败原因</b><span>${escapeHtml(job.error)}</span></div>` : "";
    const operationLabel = operation === "totp_setup" ? "开通 2FA" : "重新授权";
    return `<article class="job job-${tone}"><span class="job-icon" aria-hidden="true">${icon}</span><div class="job-account"><strong>${escapeHtml(job.email)}</strong><span class="job-operation">${operationLabel}</span><span class="job-connection job-connection-${connectionTone}">${escapeHtml(connection)}</span></div><div class="job-step"><span>当前步骤</span><strong>${escapeHtml(step)}</strong></div><span class="job-status job-status-${tone}">${escapeHtml(statusLabels[status] || status)}</span><time datetime="${escapeHtml(timeValue || "")}">${escapeHtml(time)}</time>${error}</article>`;
  }).join("") : `<div class="job-empty">暂无授权任务</div>`;
}

function quotaLimitTone(window) {
  if (window.limit_reached === true) return "red";
  const used = Number(window.used_percent);
  if (!Number.isFinite(used)) return "blue";
  const remaining = Math.max(0, Math.min(100, 100 - used));
  if (remaining <= 20) return "red";
  if (remaining <= 50) return "yellow";
  return "green";
}

function quotaLimitPercent(window) {
  if (window.limit_reached === true) return 100;
  const used = Number(window.used_percent);
  return Number.isFinite(used) ? Math.max(0, Math.min(100, used)) : null;
}

function quotaLimitDisplay(quota) {
  const windows = Array.isArray(quota.limit_windows) ? quota.limit_windows : [];
  const rows = windows.length ? windows : [{
    label: "主窗口",
    used_percent: quota.used_percent,
    remaining_display: quota.remaining_display,
    limit_display: quota.limit_display,
    reset_after_seconds: quota.reset_after_seconds,
    reset_at: quota.reset_at,
    limit_reached: false,
  }];
  return rows.map((window) => {
    const label = String(window.label || "限额");
    const used = quotaLimitPercent(window);
    const remaining = used == null ? null : Math.max(0, Math.min(100, 100 - used));
    const remainingText = remaining == null ? "" : formatPercent(remaining);
    const amount = window.remaining_display && window.limit_display
      ? `${window.remaining_display}/${window.limit_display}`
      : window.remaining_display || window.limit_display || "";
    const reset = formatResetAfter(window.reset_after_seconds) || formatResetAt(window.reset_at);
    const reached = window.limit_reached === true;
    const tone = quotaLimitTone(window);
    const details = [amount ? `剩余 ${amount}` : "", remaining == null ? "" : `剩余 ${remainingText}`].filter(Boolean).join(" · ");
    const title = [details, reset ? `重置 ${reset}` : ""].filter(Boolean).join(" · ");
    if (!details && !reset) return "";
    const progress = used == null
      ? `<span class="quota-progress-track quota-progress-unknown" aria-hidden="true"><span class="quota-progress-fill"></span></span>`
      : `<span class="quota-progress-track" role="progressbar" aria-label="${escapeHtml(label)} 剩余率" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${remaining}"><span class="quota-progress-fill quota-progress-${tone}" style="width:${remaining}%"></span></span>`;
    const metaMarkup = [
      reset ? `<span class="quota-reset">${escapeHtml(reset)}</span>` : "",
      remainingText ? `<span class="quota-remaining-percent">${escapeHtml(remainingText)}</span>` : "",
    ].filter(Boolean).join(" ");
    const amountMarkup = amount ? `<small class="quota-remaining-amount">剩余 ${escapeHtml(amount)}</small>` : "";
    return `<span class="quota-limit-item quota-limit-${tone}${reached ? " is-reached" : ""}" title="${escapeHtml(title)}"><span class="quota-limit-header"><b>${escapeHtml(label)}</b><strong>${metaMarkup || "—"}</strong></span>${progress}${amountMarkup}</span>`;
  }).filter(Boolean).join("") || "—";
}

function uploadStatusDisplay(account) {
  const statuses = account.upload_statuses || {};
  return [["cpa", "CPA"], ["sub2api", "Sub2API"]].map(([key, label]) => {
    const item = statuses[key] || {};
    const status = String(item.status || "pending").toLowerCase();
    const tone = status === "success" ? "success" : status === "failed" ? "failed" : "pending";
    const statusLabel = status === "success" ? "已上传" : status === "failed" ? "失败" : "未上传";
    const time = item.uploaded_at || item.last_attempt_at || "";
    return `<span class="upload-status upload-${tone}" title="${escapeHtml(time)}"><b>${label}</b>${statusLabel}</span>`;
  }).join("");
}

function accountStatusDisplay(account, activity = "") {
  if (activity === "reauth-running" || activity === "reauth-pending" || activity === "totp-running" || activity === "totp-pending" || activity === "quota") {
    const isQuota = activity === "quota";
    const isTotp = activity === "totp-running" || activity === "totp-pending";
    const label = isQuota ? "查询中" : isTotp ? activity === "totp-running" ? "开通 2FA 中" : "2FA 排队中" : activity === "reauth-running" ? "授权中" : "排队中";
    const tone = isQuota ? "querying" : isTotp ? "reauthing" : activity === "reauth-running" ? "reauthing" : "queued";
    const title = isQuota ? "正在查询额度，请稍候" : isTotp ? "正在开通 2FA，请稍候" : activity === "reauth-running" ? "正在重新授权，请稍候" : "已加入授权队列，等待线程处理";
    return `<span class="account-status account-status-${tone} account-status-busy" title="${title}"><span class="status-spinner" aria-hidden="true"></span>${label}</span>`;
  }
  const status = String(account.status || "pending").toLowerCase();
  const tone = ["success", "failed", "disabled", "running", "pending"].includes(status) ? status : "pending";
  const title = ["failed", "disabled"].includes(status) && account.last_error ? ` title="${escapeHtml(account.last_error)}"` : "";
  return `<span class="account-status account-status-${tone}"${title}>${escapeHtml(statusLabels[status] || "待处理")}</span>`;
}

function livenessStatusDisplay(account) {
  if (!account.has_token) return `<span class="liveness-status liveness-unavailable">未授权</span>`;
  const status = String(account.liveness_status || "unknown").toLowerCase();
  const labels = {
    valid: "有效",
    invalid: "已失效",
    forbidden: "权限受限",
    rate_limited: "限流",
    temporary_failed: "临时失败",
    unknown: "未验活",
  };
  const tone = ["valid", "invalid", "forbidden", "rate_limited", "temporary_failed", "unknown"].includes(status) ? status : "unknown";
  const details = [
    account.liveness_checked_at ? `检查于 ${account.liveness_checked_at}` : "",
    account.liveness_http_status ? `HTTP ${account.liveness_http_status}` : "",
    account.liveness_error_code || "",
  ].filter(Boolean).join(" · ");
  return `<span class="liveness-status liveness-${tone}"${details ? ` title="${escapeHtml(details)}"` : ""}>${labels[tone]}</span>`;
}

function applySettings(data = {}) {
  const settings = data.settings || {};
  const scheduler = data.scheduler || {};
  $("settingUseProxy").checked = Boolean(settings.use_proxy_default);
  updateReauthConnectionMode(settings);
  $("settingAutoCpa").checked = Boolean(settings.auto_upload_cpa);
  $("settingAutoSub2Api").checked = Boolean(settings.auto_upload_sub2api);
  $("forceUpload").checked = Boolean(settings.force_upload);
  $("settingScheduledLiveness").checked = Boolean(settings.scheduled_liveness_enabled);
  $("settingScheduledLivenessInterval").value = String(settings.scheduled_liveness_interval_minutes || 60);
  if (settings.worker_count) $("settingWorkerCount").value = String(settings.worker_count);
  $("settingCpaUrl").value = String(settings.cpa_api_url || "");
  $("settingCpaKey").value = "";
  $("settingCpaKey").placeholder = settings.cpa_management_key_configured ? "已配置，留空保持不变" : "请输入管理员密码";
  $("settingCpaTimeout").value = String(settings.cpa_api_timeout_seconds || 30);
  $("settingCpaStatus").textContent = settings.cpa_api_url && settings.cpa_management_key_configured ? "可上传" : settings.cpa_api_url ? "缺少密码" : "未配置";
  $("settingSub2ApiUrl").value = String(settings.sub2api_api_url || "");
  $("settingSub2ApiKey").value = "";
  $("settingSub2ApiKey").placeholder = settings.sub2api_admin_api_key_configured ? "已配置，留空保持不变" : "请输入管理员 API Key";
  $("settingSub2ApiGroupId").value = settings.sub2api_group_id ? String(settings.sub2api_group_id) : "";
  $("settingSub2ApiTimeout").value = String(settings.sub2api_api_timeout_seconds || 30);
  $("settingSub2ApiStatus").textContent = settings.sub2api_api_url && settings.sub2api_admin_api_key_configured ? "可上传" : settings.sub2api_api_url ? "缺少密钥" : "未配置";
  $("schedulerState").textContent = scheduler.running ? "执行中" : scheduler.enabled ? "已启用" : "已关闭";
  const lastRun = scheduler.last_run || {};
  const scheduleParts = [];
  if (scheduler.enabled) {
    scheduleParts.push(`每 ${scheduler.interval_minutes || settings.scheduled_liveness_interval_minutes || 60} 分钟执行`);
    if (scheduler.next_run_at) scheduleParts.push(`下次 ${formatResetAt(scheduler.next_run_at)}`);
  }
  if (lastRun.finished_at) {
    const resultLabel = lastRun.status === "failed" ? "失败" : "完成";
    scheduleParts.push(`上次 ${formatResetAt(lastRun.finished_at)} ${resultLabel}：检查 ${lastRun.checked || 0}，失效 ${lastRun.invalid || 0}，入队 ${lastRun.queued || 0}，临时失败 ${lastRun.temporary_failed || 0}`);
  }
  if (lastRun.error) scheduleParts.push(`错误：${lastRun.error}`);
  $("schedulerDetail").textContent = scheduleParts.join("；") || "启用后将按设定频率检查已有 Token。";
  $("settingsState").textContent = data.restart_required ? "线程数待重启" : "设置已生效";
}

function updateReauthConnectionMode(settings = null, stats = null) {
  if (settings) connectionModeSnapshot.useProxy = Boolean(settings.use_proxy_default);
  if (stats) {
    connectionModeSnapshot.total = Number(stats.total || 0);
    connectionModeSnapshot.available = Number(stats.available || 0);
  }
  const pill = $("reauthConnectionMode");
  if (!pill) return;
  pill.classList.remove("is-proxy", "is-direct", "is-unavailable");
  if (!connectionModeSnapshot.useProxy) {
    pill.textContent = "重新授权：直连";
    pill.classList.add("is-direct");
    pill.title = "当前设置未启用代理池，重新授权会直接连接目标服务";
  } else if (connectionModeSnapshot.available <= 0) {
    pill.textContent = `重新授权：代理池（可领取 0/${connectionModeSnapshot.total}）`;
    pill.classList.add("is-unavailable");
    pill.title = "当前已启用代理池，但没有可领取的代理，授权任务会失败并显示原因";
  } else {
    pill.textContent = `重新授权：代理池（可领取 ${connectionModeSnapshot.available}/${connectionModeSnapshot.total}）`;
    pill.classList.add("is-proxy");
    pill.title = "重新授权会从代理池领取代理；实际使用的脱敏地址会显示在最近任务中";
  }
  const button = $("reauthSelected");
  if (button) button.title = pill.title;
}

function renderQuotaSummary(summary = {}) {
  $("statAccountTotal").textContent = formatCredit(summary.account_total);
  $("statAuthorized").textContent = formatCredit(summary.authorized);
  $("statPending").textContent = formatCredit(summary.pending);
  $("statFailed").textContent = formatCredit(summary.failed);
  $("statTotalCredit").textContent = formatCredit(summary.total_credit);
  $("statEstimatedValue").textContent = `$${Number(summary.estimated_value || 0).toLocaleString("en-US", {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;
  const planCounts = summary.plan_counts || {};
  $("statFree").textContent = formatCredit(planCounts.free);
  $("statPlus").textContent = formatCredit(planCounts.plus);
  const allowedTones = new Set(["gold", "blue", "green", "orange", "red", "purple"]);
  $("quotaTiers").innerHTML = (summary.tiers || []).filter((tier) => tier.key !== "unlimited").map((tier) => {
    const tone = allowedTones.has(tier.tone) ? tier.tone : "blue";
    const description = tier.description ? `<span>${escapeHtml(tier.description)}</span>` : "";
    const label = tier.key === "zero" ? "无额度" : tier.label;
    return `<article class="quota-tier quota-tier-${tone}"><div><strong>${escapeHtml(label)}</strong>${description}</div><b>${formatCredit(tier.count)}</b></article>`;
  }).join("");
}

function schedulerRunLabel(status) {
  const normalized = String(status || "idle").toLowerCase();
  return normalized === "success" ? "完成" : normalized === "failed" ? "失败" : normalized === "running" ? "执行中" : "尚未执行";
}

function renderSchedulerWorkbench(scheduler = {}, settings = {}) {
  const state = $("workbenchSchedulerState");
  const meta = $("workbenchSchedulerMeta");
  const stats = $("workbenchSchedulerStats");
  const error = $("workbenchSchedulerError");
  if (!state || !meta || !stats || !error) return;
  const lastRun = scheduler.last_run || {};
  const enabled = Boolean(scheduler.enabled ?? settings.scheduled_liveness_enabled);
  const running = Boolean(scheduler.running);
  const failed = !running && String(lastRun.status || "").toLowerCase() === "failed";
  const stateLabel = running ? "执行中" : !enabled ? "已关闭" : failed ? "上次失败" : "已启用";
  const stateTone = running ? "running" : !enabled ? "disabled" : failed ? "failed" : "success";
  state.className = `soft-pill scheduler-workbench-state scheduler-workbench-state-${stateTone}`;
  state.textContent = stateLabel;

  const interval = Number(scheduler.interval_minutes || settings.scheduled_liveness_interval_minutes || 60);
  const metaParts = [];
  if (enabled) metaParts.push(`每 ${interval} 分钟执行`);
  if (running) metaParts.push("当前正在检查已有 Token");
  else if (enabled && scheduler.next_run_at) metaParts.push(`下次 ${formatResetAt(scheduler.next_run_at) || "待定"}`);
  else if (!enabled) metaParts.push("可在设置菜单中开启");
  meta.textContent = metaParts.join(" · ") || "启用后将按设定频率检查已有 Token。";

  const runTime = formatResetAt(lastRun.finished_at || lastRun.started_at) || "—";
  const runStatus = schedulerRunLabel(lastRun.status);
  const metrics = [
    ["上次检查", Number(lastRun.checked || 0), "次"],
    ["有效 Token", Number(lastRun.valid || 0), "个"],
    ["失效账号", Number(lastRun.invalid || 0), "个"],
    ["已入队授权", Number(lastRun.queued || 0), "个"],
    ["临时失败", Number(lastRun.temporary_failed || 0), "个"],
  ];
  stats.innerHTML = `<div class="scheduler-workbench-last-run"><span>最近执行</span><strong>${escapeHtml(runStatus)}</strong><time>${escapeHtml(runTime)}</time></div>${metrics.map(([label, value, suffix]) => `<div class="scheduler-workbench-stat"><span>${escapeHtml(label)}</span><strong>${formatCredit(value)}<small>${suffix}</small></strong></div>`).join("")}`;
  if (lastRun.error) {
    error.hidden = false;
    error.textContent = `最近一次执行错误：${String(lastRun.error)}`;
  } else {
    error.hidden = true;
    error.textContent = "";
  }
}

function accountActivity(accountId) {
  const id = String(accountId || "");
  const job = activeReauthJobs.get(id);
  if (job) {
    const operation = String(job.operation || "reauth").toLowerCase();
    if (operation === "totp_setup") return job.status === "running" ? "totp-running" : "totp-pending";
    return job.status === "running" ? "reauth-running" : "reauth-pending";
  }
  if (operationState.reauthIds.has(id)) return "reauth-pending";
  if (operationState.totpSetupIds.has(id)) return "totp-pending";
  if (operationState.quotaIds.has(id) || quotaProgressSnapshot.active_account_ids.includes(id)) return "quota";
  return "";
}

function refreshAccountActivityCells() {
  document.querySelectorAll(".account-row").forEach((row) => {
    const account = accountSnapshot.get(String(row.dataset.accountId || ""));
    const cell = row.querySelector(".account-status-cell");
    if (account && cell) cell.innerHTML = accountStatusDisplay(account, accountActivity(account.id));
  });
}

function syncAccountListUrl() {
  const url = new URL(window.location.href);
  url.searchParams.set("page", String(accountPagination.page));
  url.searchParams.set("page_size", String(accountPagination.pageSize));
  if (accountSearchQuery.trim()) url.searchParams.set("q", accountSearchQuery.trim());
  else url.searchParams.delete("q");
  if (accountStatusFilter) url.searchParams.set("status", accountStatusFilter);
  else url.searchParams.delete("status");
  url.searchParams.set("proxy_page", String(proxyPagination.page));
  url.searchParams.set("proxy_page_size", String(proxyPagination.pageSize));
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

function updateProxyPaginationControls() {
  const total = Math.max(0, Number(proxyPagination.total || 0));
  const totalPages = Math.max(1, Number(proxyPagination.totalPages || 1));
  const page = Math.min(totalPages, Math.max(1, Number(proxyPagination.page || 1)));
  const start = total ? ((page - 1) * proxyPagination.pageSize) + 1 : 0;
  const end = total ? Math.min(total, start + proxyListItems.length - 1) : 0;
  $("proxyPageSummary").textContent = total ? `显示 ${start}–${end}，共 ${total} 个代理` : "共 0 个代理";
  $("proxyPage").value = String(page);
  $("proxyPage").max = String(totalPages);
  $("proxyPageSize").value = String(proxyPagination.pageSize);
  $("proxyPageTotal").textContent = `/ ${totalPages} 页`;
  $("proxyPagePrev").disabled = proxyPagination.loading || page <= 1;
  $("proxyPageNext").disabled = proxyPagination.loading || page >= totalPages;
  syncAccountListUrl();
}

function renderProxyTable() {
  const proxyItems = [...proxyListItems];
  $("proxyRows").innerHTML = proxyItems.length
    ? proxyItems.map((proxy) => {
      const state = proxy.leased ? "租约中" : proxy.cooling_down ? "冷却中" : proxy.enabled ? "可用" : "已停用";
      const stateTone = state === "可用" ? "available" : state === "租约中" ? "leased" : state === "冷却中" ? "cooldown" : "disabled";
      const endpoint = String(proxy.endpoint || "");
      const protocol = endpoint.includes("://") ? endpoint.split("://", 1)[0].toUpperCase() : "HTTP";
      return `<tr><td class="proxy-endpoint">${escapeHtml(endpoint)}</td><td>${escapeHtml(protocol)}</td><td><span class="proxy-state proxy-state-${stateTone}">${state}</span></td><td>${Number(proxy.success_count || 0)}</td><td>${Number(proxy.failure_count || 0)}</td></tr>`;
    }).join("")
    : `<tr><td colspan="5"><div class="account-empty">暂无代理</div></td></tr>`;
  updateProxyPaginationControls();
}

function updateAccountPaginationControls() {
  const total = Math.max(0, Number(accountPagination.total || 0));
  const totalPages = Math.max(1, Number(accountPagination.totalPages || 1));
  const page = Math.min(totalPages, Math.max(1, Number(accountPagination.page || 1)));
  const start = total ? ((page - 1) * accountPagination.pageSize) + 1 : 0;
  const end = total ? Math.min(total, start + accountListItems.length - 1) : 0;
  $("accountPageSummary").textContent = total ? `显示 ${start}–${end}，共 ${total} 个账号` : "共 0 个账号";
  $("accountPage").value = String(page);
  $("accountPage").max = String(totalPages);
  $("accountPageSize").value = String(accountPagination.pageSize);
  $("accountPageTotal").textContent = `/ ${totalPages} 页`;
  $("accountPagePrev").disabled = accountPagination.loading || page <= 1;
  $("accountPageNext").disabled = accountPagination.loading || page >= totalPages;
  syncAccountListUrl();
}

function renderAccountTable() {
  const visibleAccounts = accountListItems;
  const query = accountSearchQuery.trim();
  const searchMeta = $("accountSearchMeta");
  if (searchMeta) searchMeta.textContent = query ? `匹配 ${accountPagination.total} 个` : `共 ${accountPagination.total} 个`;
  $("rows").innerHTML = visibleAccounts.map((account) => {
    const quota = accountQuotaMap.get(account.id) || {};
    const id = String(account.id || "");
    const quotaBadge = account.has_token
      ? `<span class="quota-badge quota-${quotaTone(quota)}">${escapeHtml(quotaDisplay(quota))}</span>`
      : "—";
    const plan = planLabel(quota);
    const planBadge = plan
      ? `<span class="plan-badge plan-${planTone(plan)}">${escapeHtml(plan)}</span>`
      : `<span class="plan-badge plan-unknown">未识别</span>`;
    const emailCell = `<div class="account-email">${escapeHtml(account.email)}</div><div class="account-plan">${planBadge}</div>`;
    const selectedClass = selectedAccounts.has(id) ? " is-selected" : "";
    return `<tr class="account-row${selectedClass}" data-account-id="${escapeHtml(id)}"><td><input type="checkbox" class="account-check" data-id="${escapeHtml(id)}" aria-label="选择 ${escapeHtml(account.email)}" ${selectedAccounts.has(id) ? "checked" : ""}></td><td class="account-email-cell">${emailCell}</td><td class="account-status-cell">${accountStatusDisplay(account, accountActivity(id))}</td><td>${livenessStatusDisplay(account)}</td><td class="upload-status-cell">${uploadStatusDisplay(account)}</td><td>${quotaBadge}</td><td class="quota-limit-cell">${quotaLimitDisplay(quota)}</td></tr>`;
  }).join("") || `<tr><td colspan="7"><div class="account-empty">${query ? "没有匹配的账号" : "暂无账号，请先点击“导入账号”"}</div></td></tr>`;
  document.querySelectorAll(".account-check").forEach((checkbox) => checkbox.addEventListener("change", () => {
    const id = String(checkbox.dataset.id || "");
    if (checkbox.checked) selectedAccounts.add(id); else selectedAccounts.delete(id);
    checkbox.closest("tr")?.classList.toggle("is-selected", checkbox.checked);
    updateAccountSelectionState();
  }));
  updateAccountSelectionState();
  updateAccountPaginationControls();
}

function renderAccounts(accounts, quotas, jobs, proxies, quotaProgress = {}) {
  accountListItems = Array.isArray(accounts.items) ? accounts.items : [];
  accountPagination.page = Math.max(1, Number(accounts.page || accountPagination.page));
  accountPagination.pageSize = Math.max(1, Number(accounts.page_size || accounts.limit || accountPagination.pageSize));
  accountPagination.total = Math.max(0, Number(accounts.total || 0));
  accountPagination.totalPages = Math.max(1, Number(accounts.total_pages || Math.ceil(accountPagination.total / accountPagination.pageSize) || 1));
  accountQuotaMap = new Map((quotas.items || []).map((item) => [item.account_id, item]));
  accountGlobalTotal = Math.max(0, Number(quotas.summary?.account_total || accounts.total || 0));
  accountAuthorizedTotal = Math.max(0, Number(quotas.summary?.authorized || 0));
  accountSnapshot.clear();
  accountListItems.forEach((account) => accountSnapshot.set(String(account.id || ""), account));
  activeReauthJobs.clear();
  (jobs.items || []).forEach((job) => {
    const status = String(job.status || "").toLowerCase();
    if (["pending", "running"].includes(status)) activeReauthJobs.set(String(job.account_id || ""), {...job, status});
  });
  quotaProgressSnapshot.running = Boolean(quotaProgress.running);
  quotaProgressSnapshot.active_account_ids = Array.isArray(quotaProgress.active_account_ids)
    ? quotaProgress.active_account_ids.map((id) => String(id))
    : quotaProgress.active_account_id ? [String(quotaProgress.active_account_id)] : [];
  renderQuotaSummary(quotas.summary || {});
  renderAccountTable();
  renderJobs(jobs);
  const stats = proxies.stats || {};
  updateReauthConnectionMode(null, stats);
  $("proxyStats").textContent = `代理 ${stats.total || 0} 个，可用 ${stats.available || 0} 个`;
  proxyListItems = Array.isArray(proxies.items) ? proxies.items : [];
  proxyPagination.page = Math.max(1, Number(proxies.page || proxyPagination.page));
  proxyPagination.pageSize = Math.max(1, Number(proxies.page_size || proxies.limit || proxyPagination.pageSize));
  proxyPagination.total = Math.max(0, Number(proxies.total ?? stats.total ?? 0));
  proxyPagination.totalPages = Math.max(1, Number(proxies.total_pages || Math.ceil(proxyPagination.total / proxyPagination.pageSize) || 1));
  renderProxyTable();
}

function updateAccountSelectionState() {
  const boxes = [...document.querySelectorAll(".account-check")];
  const selectAll = $("selectAllAccounts");
  if (selectAll) {
    selectAll.checked = boxes.length > 0 && boxes.every((box) => box.checked);
    selectAll.indeterminate = boxes.some((box) => box.checked) && !selectAll.checked;
    selectAll.disabled = boxes.length === 0;
  }
  const count = selectedAccounts.size;
  const hasAccounts = accountGlobalTotal > 0 || count > 0;
  $("selectionCount").textContent = count ? `已选择 ${count} 个账号` : "未选择账号";
  $("reauthSelected").textContent = operationState.reauthBusy
    ? `重新授权中（${operationState.reauthTargetCount}）`
    : count ? `重新授权选中（${count}）` : "重新授权全部";
  const reauthTotpButton = $("reauthTotp");
  if (reauthTotpButton) {
    reauthTotpButton.textContent = operationState.reauthBusy
      ? `2FA 重新授权中（${operationState.reauthTargetCount}）`
      : count ? `2FA 重新授权选中（${count}）` : "2FA 重新授权全部";
  }
  const setupTotpButton = $("setupTotp");
  if (setupTotpButton) {
    setupTotpButton.textContent = operationState.totpSetupBusy
      ? `开通 2FA 中（${operationState.totpSetupTargetCount}）`
      : count ? `开通选中账号 2FA（${count}）` : "开通 2FA";
  }
  $("quotaSelected").textContent = operationState.quotaBusy
    ? `刷新中（${operationState.quotaTargetCount}）`
    : count ? `刷新选中额度（${count}）` : "查询全部额度";
  $("livenessSelected").textContent = operationState.livenessBusy
    ? `验活中（${operationState.livenessTargetCount}）`
    : count ? `验活选中（${count}）` : "一键验活";
  const reauthButton = $("reauthSelected");
  const livenessButton = $("livenessSelected");
  const quotaButton = $("quotaSelected");
  const anyAccountOperationBusy = operationState.reauthBusy || operationState.totpSetupBusy || operationState.livenessBusy || operationState.quotaBusy || operationState.targetedReauthBusy || operationState.targetedQuotaBusy || operationState.cleanupDisabledBusy;
  reauthButton.disabled = !hasAccounts || anyAccountOperationBusy;
  if (reauthTotpButton) reauthTotpButton.disabled = !hasAccounts || anyAccountOperationBusy;
  if (setupTotpButton) setupTotpButton.disabled = !hasAccounts || anyAccountOperationBusy;
  livenessButton.disabled = !hasAccounts || anyAccountOperationBusy;
  quotaButton.disabled = !hasAccounts || anyAccountOperationBusy;
  reauthButton.classList.toggle("is-busy", operationState.reauthBusy);
  if (reauthTotpButton) {
    reauthTotpButton.classList.toggle("is-busy", operationState.reauthBusy);
    reauthTotpButton.setAttribute("aria-busy", String(operationState.reauthBusy));
  }
  if (setupTotpButton) {
    setupTotpButton.classList.toggle("is-busy", operationState.totpSetupBusy);
    setupTotpButton.setAttribute("aria-busy", String(operationState.totpSetupBusy));
  }
  livenessButton.classList.toggle("is-busy", operationState.livenessBusy);
  quotaButton.classList.toggle("is-busy", operationState.quotaBusy);
  reauthButton.setAttribute("aria-busy", String(operationState.reauthBusy));
  livenessButton.setAttribute("aria-busy", String(operationState.livenessBusy));
  quotaButton.setAttribute("aria-busy", String(operationState.quotaBusy));
  const retryReauthButton = $("retryFailedReauth");
  const retryQuotaButton = $("retryFailedQuota");
  if (retryReauthButton) {
    retryReauthButton.disabled = !hasAccounts || anyAccountOperationBusy;
    retryReauthButton.classList.toggle("is-busy", operationState.targetedReauthBusy);
    retryReauthButton.setAttribute("aria-busy", String(operationState.targetedReauthBusy));
  }
  if (retryQuotaButton) {
    retryQuotaButton.disabled = !hasAccounts || anyAccountOperationBusy;
    retryQuotaButton.classList.toggle("is-busy", operationState.targetedQuotaBusy);
    retryQuotaButton.setAttribute("aria-busy", String(operationState.targetedQuotaBusy));
  }
  const cleanupDisabledButton = $("clearDisabledAccounts");
  if (cleanupDisabledButton) {
    cleanupDisabledButton.disabled = !hasAccounts || anyAccountOperationBusy;
    cleanupDisabledButton.classList.toggle("is-busy", operationState.cleanupDisabledBusy);
    cleanupDisabledButton.setAttribute("aria-busy", String(operationState.cleanupDisabledBusy));
  }
  $("deleteSelected").disabled = count === 0 || anyAccountOperationBusy;
}

async function refreshData({showError = true} = {}) {
  const requestSequence = ++accountRefreshSequence;
  accountPagination.loading = true;
  proxyPagination.loading = true;
  updateAccountPaginationControls();
  updateProxyPaginationControls();
  try {
    const accountParams = new URLSearchParams({
      page: String(accountPagination.page),
      page_size: String(accountPagination.pageSize),
    });
    if (accountSearchQuery.trim()) accountParams.set("q", accountSearchQuery.trim());
    if (accountStatusFilter) accountParams.set("status", accountStatusFilter);
    const proxyParams = new URLSearchParams({
      page: String(proxyPagination.page),
      page_size: String(proxyPagination.pageSize),
    });
    const [accounts, quotas, jobs, proxies, quotaProgress, settingsData] = await Promise.all([api(`/api/accounts?${accountParams}`), api("/api/quotas?limit=5000"), api("/api/reauth/jobs"), api(`/api/proxies?${proxyParams}`), api("/api/quotas/progress"), api("/api/settings")]);
    if (requestSequence !== accountRefreshSequence) return true;
    renderAccounts(accounts, quotas, jobs, proxies, quotaProgress);
    renderSchedulerWorkbench(settingsData.scheduler || {}, settingsData.settings || {});
    $("health").textContent = "服务正常";
    return true;
  } catch (error) {
    if (requestSequence !== accountRefreshSequence) return false;
    $("health").textContent = "连接失败";
    if (showError) setAccountResult("actionResult", error.message);
    return false;
  } finally {
    if (requestSequence === accountRefreshSequence) {
      accountPagination.loading = false;
      proxyPagination.loading = false;
      updateAccountPaginationControls();
      updateProxyPaginationControls();
    }
  }
}

function setAccountResult(targetId, message) {
  // These three messages share one visual row. Clear the other slots so a
  // later account operation replaces the previous result instead of running
  // into it (for example, quota refresh followed by an upload).
  ["importResult", "actionResult", "exportResult"].forEach((id) => {
    $(id).textContent = id === targetId ? String(message || "") : "";
  });
}

function quotaRefreshMessage(label, result) {
  const refreshed = Array.isArray(result.results) ? result.results.length : 0;
  return `${label}：完成 ${refreshed} 个`;
}

async function refreshSettings() {
  try {
    applySettings(await api("/api/settings"));
  } catch (error) {
    $("settingsState").textContent = "读取失败";
    $("settingsResult").textContent = error.message;
  }
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => {
      const active = item === tab;
      item.classList.toggle("is-active", active);
      item.setAttribute("aria-selected", String(active));
    });
    document.querySelectorAll(".tab-panel").forEach((panel) => { panel.hidden = panel.dataset.panel !== tab.dataset.tab; });
    if (tab.dataset.tab === "settings") refreshSettings();
  });
});

const importDialog = $("importAccountsDialog");
$("openImportAccounts").onclick = () => { importDialog.showModal(); $("accountsText").focus(); };
$("closeImportAccounts").onclick = () => importDialog.close();
$("cancelImportAccounts").onclick = () => importDialog.close();
$("importAccounts").onclick = async () => {
  try {
    const result = await api("/api/accounts/import", {method: "POST", body: JSON.stringify({text: $("accountsText").value})});
    setAccountResult("importResult", `收到 ${result.received} 行，新增 ${result.created}，更新 ${result.updated}，无效 ${result.invalid}`);
    $("accountsText").value = "";
    importDialog.close();
    await refreshData();
  } catch (error) { setAccountResult("importResult", error.message); }
};
$("importProxies").onclick = async () => {
  try {
    const result = await api("/api/proxies/import", {method: "POST", body: JSON.stringify({text: $("proxyText").value})});
    $("proxyResult").textContent = `导入 ${result.imported} 个，重复 ${result.duplicates || 0} 个，无效 ${result.invalid}`;
    $("proxyText").value = "";
    await refreshData();
  } catch (error) { $("proxyResult").textContent = error.message; }
};
$("selectAllAccounts").onclick = (event) => {
  document.querySelectorAll(".account-check").forEach((checkbox) => {
    checkbox.checked = event.target.checked;
    const id = String(checkbox.dataset.id || "");
    if (checkbox.checked) selectedAccounts.add(id); else selectedAccounts.delete(id);
    checkbox.closest("tr")?.classList.toggle("is-selected", checkbox.checked);
  });
  updateAccountSelectionState();
};

$("accountSearch").addEventListener("input", (event) => {
  accountSearchQuery = String(event.target.value || "").slice(0, 200);
  accountPagination.page = 1;
  $("accountSearchMeta").textContent = "搜索中…";
  window.clearTimeout(accountSearchTimer);
  accountSearchTimer = window.setTimeout(() => refreshData(), 250);
});

$("accountStatusFilter").addEventListener("change", (event) => {
  accountStatusFilter = String(event.target.value || "").toLowerCase();
  accountPagination.page = 1;
  refreshData();
});

async function goToAccountPage(page) {
  const target = Math.min(accountPagination.totalPages, Math.max(1, Number(page) || 1));
  if (target === accountPagination.page && accountListItems.length) {
    updateAccountPaginationControls();
    return;
  }
  accountPagination.page = target;
  await refreshData();
}

$("accountPagePrev").onclick = () => goToAccountPage(accountPagination.page - 1);
$("accountPageNext").onclick = () => goToAccountPage(accountPagination.page + 1);
$("accountPageSize").onchange = async (event) => {
  accountPagination.pageSize = Number(event.target.value) || 20;
  accountPagination.page = 1;
  await refreshData();
};
$("accountPage").onchange = (event) => goToAccountPage(event.target.value);
$("accountPage").onkeydown = (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    event.target.blur();
  }
};

async function goToProxyPage(page) {
  const target = Math.min(proxyPagination.totalPages, Math.max(1, Number(page) || 1));
  if (target === proxyPagination.page && proxyListItems.length) {
    updateProxyPaginationControls();
    return;
  }
  proxyPagination.page = target;
  await refreshData();
}

$("proxyPagePrev").onclick = () => goToProxyPage(proxyPagination.page - 1);
$("proxyPageNext").onclick = () => goToProxyPage(proxyPagination.page + 1);
$("proxyPageSize").onchange = async (event) => {
  proxyPagination.pageSize = Number(event.target.value) || 20;
  proxyPagination.page = 1;
  await refreshData();
};
$("proxyPage").onchange = (event) => goToProxyPage(event.target.value);
$("proxyPage").onkeydown = (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    event.target.blur();
  }
};

async function runAccountAction(path) {
  const isReauth = path === "/api/reauth/queue" || path === "/api/reauth/queue-2fa";
  const isTotpReauth = path === "/api/reauth/queue-2fa";
  const kind = isReauth ? "reauth" : "quota";
  const busyKey = `${kind}Busy`;
  if (operationState[busyKey]) return;
  const selected = selectedAccounts.size > 0;
  const ids = selected
    ? [...selectedAccounts]
    : [...accountSnapshot.values()].filter((account) => kind !== "quota" || account.has_token).map((account) => String(account.id));
  const targetCount = selected ? ids.length : kind === "quota" ? accountAuthorizedTotal : isTotpReauth ? "已配置 2FA 的账号" : accountGlobalTotal;
  operationState[busyKey] = true;
  operationState[`${kind}Ids`] = new Set(ids);
  operationState[`${kind}TargetCount`] = targetCount;
  updateAccountSelectionState();
  refreshAccountActivityCells();
  const requestedConnection = connectionModeSnapshot.useProxy ? "代理池模式" : "直连模式";
  setAccountResult("actionResult", kind === "reauth"
    ? (isTotpReauth
      ? `正在以${requestedConnection}提交${selected ? ` ${targetCount} 个` : "全部已配置 2FA 的"}账号重新授权，请稍候…`
      : `正在以${requestedConnection}提交 ${targetCount} 个账号的重新授权，请稍候…`)
    : `正在查询 ${targetCount} 个账号的额度，请稍候…`);
  const body = selected ? {ids} : {};
  try {
    const result = await api(path, {method: "POST", body: JSON.stringify(body)});
    if (isReauth) {
      const label = isTotpReauth
        ? (selected ? "已提交选中 2FA 账号" : "已提交全部 2FA 账号")
        : (selected ? "已重新授权选中账号" : "已重新授权全部账号");
      const connection = result.use_proxy ? "代理池模式" : "直连模式";
      const skipped = Number(result.skipped || 0);
      const disabledSkipped = Number(result.disabled_skipped || 0);
      const skippedText = skipped ? `，跳过 ${skipped} 个${disabledSkipped ? `（已禁用 ${disabledSkipped} 个）` : ""}` : "";
      const matchedText = isTotpReauth ? `匹配 ${result.matched || 0} 个，` : "";
      setAccountResult("actionResult", `${label}（${connection}）：${matchedText}加入 ${result.queued || 0} 个，重复 ${result.duplicate || 0} 个${skippedText}`);
    } else {
      const label = selected ? "已刷新选中额度" : "额度查询完成";
      setAccountResult("actionResult", Array.isArray(result.results) && result.results.length
        ? quotaRefreshMessage(label, result)
        : "暂无已保存 OAuth Token，请先完成重新授权");
    }
    await refreshData();
  } catch (error) {
    setAccountResult("actionResult", error.message);
  } finally {
    operationState[busyKey] = false;
    operationState[`${kind}Ids`].clear();
    operationState[`${kind}TargetCount`] = 0;
    updateAccountSelectionState();
    refreshAccountActivityCells();
  }
}

async function runTotpSetupAction() {
  if (operationState.totpSetupBusy) return;
  const selected = selectedAccounts.size > 0;
  const ids = selected ? [...selectedAccounts] : [];
  operationState.totpSetupBusy = true;
  operationState.totpSetupIds = new Set(ids);
  operationState.totpSetupTargetCount = selected ? ids.length : "符合条件账号";
  updateAccountSelectionState();
  refreshAccountActivityCells();
  const requestedConnection = connectionModeSnapshot.useProxy ? "代理池模式" : "直连模式";
  setAccountResult("actionResult", `正在以${requestedConnection}提交${selected ? ` ${ids.length} 个` : "全部符合条件的"}账号开通 2FA，请稍候…`);
  try {
    const result = await api("/api/accounts/2fa/setup", {method: "POST", body: JSON.stringify(selected ? {ids} : {})});
    const skipped = Number(result.skipped || 0);
    const reasons = [];
    if (Number(result.already_configured || 0)) reasons.push(`已配置 ${result.already_configured} 个`);
    if (Number(result.no_password || 0)) reasons.push(`无密码 ${result.no_password} 个`);
    if (Number(result.disabled_skipped || 0)) reasons.push(`已禁用 ${result.disabled_skipped} 个`);
    const reasonText = skipped ? `，跳过 ${skipped} 个${reasons.length ? `（${reasons.join("，")}）` : ""}` : "";
    setAccountResult("actionResult", `已提交开通 2FA（${result.use_proxy ? "代理池模式" : "直连模式"}）：匹配 ${result.matched || 0} 个，加入 ${result.queued || 0} 个，重复 ${result.duplicate || 0} 个${reasonText}`);
    await refreshData();
  } catch (error) {
    setAccountResult("actionResult", error.message);
  } finally {
    operationState.totpSetupBusy = false;
    operationState.totpSetupIds.clear();
    operationState.totpSetupTargetCount = 0;
    updateAccountSelectionState();
    refreshAccountActivityCells();
  }
}

async function runLivenessAction() {
  if (operationState.livenessBusy) return;
  const selected = selectedAccounts.size > 0;
  const ids = selected ? [...selectedAccounts] : [];
  const targetCount = selected ? ids.length : accountAuthorizedTotal;
  operationState.livenessBusy = true;
  operationState.livenessIds = new Set(ids);
  operationState.livenessTargetCount = targetCount;
  updateAccountSelectionState();
  setAccountResult("actionResult", `正在验活 ${targetCount} 个账号，请稍候…`);
  try {
    const result = await api("/api/liveness/run", {method: "POST", body: JSON.stringify(selected ? {ids} : {})});
    if (result.skipped && result.status === "running") {
      setAccountResult("actionResult", "已有验活任务正在执行，请稍候再试");
    } else {
      setAccountResult("actionResult", `验活完成：检查 ${result.checked || 0} 个，有效 ${result.valid || 0} 个，失效 ${result.invalid || 0} 个，临时失败 ${result.temporary_failed || 0} 个，加入重新授权 ${result.queued || 0} 个`);
    }
    await refreshData();
  } catch (error) {
    setAccountResult("actionResult", error.message);
  } finally {
    operationState.livenessBusy = false;
    operationState.livenessIds.clear();
    operationState.livenessTargetCount = 0;
    updateAccountSelectionState();
  }
}

async function runTargetedAccountAction(path, label) {
  const isReauth = path === "/api/reauth/retry-failed";
  const busyKey = isReauth ? "targetedReauthBusy" : "targetedQuotaBusy";
  const button = $(isReauth ? "retryFailedReauth" : "retryFailedQuota");
  if (!button || button.disabled) return;
  operationState[busyKey] = true;
  updateAccountSelectionState();
  setAccountResult("actionResult", `${label}，请稍候…`);
  try {
    const result = await api(path, {method: "POST", body: "{}"});
    const matched = Number(result.matched || 0);
    if (isReauth) {
      setAccountResult("actionResult", `${label}：匹配 ${matched} 个，加入 ${result.queued || 0} 个，重复 ${result.duplicate || 0} 个`);
    } else {
      const completed = Array.isArray(result.results) ? result.results.length : 0;
      setAccountResult("actionResult", `${label}：匹配 ${matched} 个，完成 ${completed} 个`);
    }
    await refreshData();
  } catch (error) {
    setAccountResult("actionResult", error.message);
  } finally {
    operationState[busyKey] = false;
    updateAccountSelectionState();
  }
}

$("reauthSelected").onclick = () => runAccountAction("/api/reauth/queue").catch((error) => { setAccountResult("actionResult", error.message); });
$("reauthTotp").onclick = () => runAccountAction("/api/reauth/queue-2fa").catch((error) => { setAccountResult("actionResult", error.message); });
$("setupTotp").onclick = () => runTotpSetupAction().catch((error) => { setAccountResult("actionResult", error.message); });
$("livenessSelected").onclick = () => runLivenessAction().catch((error) => { setAccountResult("actionResult", error.message); });
$("quotaSelected").onclick = () => runAccountAction("/api/quotas/refresh").catch((error) => { setAccountResult("actionResult", error.message); });
$("retryFailedReauth").onclick = () => runTargetedAccountAction("/api/reauth/retry-failed", "重新授权失败账号");
$("retryFailedQuota").onclick = () => runTargetedAccountAction("/api/quotas/refresh-failed", "查询失败额度账号");
$("clearDisabledAccounts").onclick = async () => {
  if (operationState.cleanupDisabledBusy || !window.confirm("确定删除全部已禁用账号吗？相关 Token、额度和授权任务也会一并删除。")) return;
  operationState.cleanupDisabledBusy = true;
  updateAccountSelectionState();
  setAccountResult("actionResult", "正在清理已禁用账号，请稍候…");
  try {
    const result = await api("/api/accounts/disabled", {method: "DELETE"});
    selectedAccounts.clear();
    setAccountResult("actionResult", `已清理 ${result.deleted || 0} 个禁用账号`);
    await refreshData();
  } catch (error) {
    setAccountResult("actionResult", error.message);
  } finally {
    operationState.cleanupDisabledBusy = false;
    updateAccountSelectionState();
  }
};
$("deleteSelected").onclick = async () => {
  const ids = [...selectedAccounts];
  if (!ids.length || !window.confirm(`确定删除选中的 ${ids.length} 个账号吗？相关 Token、额度和授权任务也会删除。`)) return;
  try {
    const result = await api("/api/accounts", {method: "DELETE", body: JSON.stringify({ids})});
    selectedAccounts.clear();
    setAccountResult("actionResult", `已删除 ${result.deleted || 0} 个账号`);
    await refreshData();
  } catch (error) { setAccountResult("actionResult", error.message); }
};

async function downloadAccounts() {
  const format = String($("exportFormat")?.value || "cpa");
  const ids = [...selectedAccounts];
  const query = new URLSearchParams({format});
  const response = await fetch(`/api/accounts/export?${query}`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(ids.length ? {ids, format} : {format}),
  });
  if (!response.ok) throw new Error((await response.text()).slice(0, 300) || "导出失败");
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = match ? match[1] : `codex-${format}-export`;
  link.click();
  URL.revokeObjectURL(link.href);
  setAccountResult("exportResult", `已导出 ${blob.size} 字节`);
}

async function uploadAccounts(path, label) {
  const ids = [...selectedAccounts];
  const body = ids.length ? {ids} : {};
  const result = await api(path, {method: "POST", body: JSON.stringify(body)});
  const skipped = Number(result.skipped || 0);
  const skipText = skipped ? `，跳过已上传 ${skipped}` : "";
  const summary = `${label}完成：成功 ${result.uploaded || 0}，失败 ${result.failed || 0}${skipText}`;
  const refreshed = await refreshData({showError: false});
  setAccountResult("exportResult", refreshed ? summary : `${summary}（列表刷新失败，请稍后点击“查询全部额度”或刷新页面）`);
}
$("exportAccounts").onclick = () => downloadAccounts().catch((error) => { setAccountResult("exportResult", error.message); });
$("uploadCpa").onclick = () => uploadAccounts("/api/accounts/upload-cpa", "CPA 上传").catch((error) => { setAccountResult("exportResult", error.message); });
$("uploadSub2Api").onclick = () => uploadAccounts("/api/accounts/upload-sub2api", "Sub2API 上传").catch((error) => { setAccountResult("exportResult", error.message); });
$("saveSettings").onclick = async () => {
  try {
    const workerCount = Number($("settingWorkerCount").value);
    if (!Number.isInteger(workerCount) || workerCount < 1 || workerCount > 32) {
      throw new Error("授权线程数必须是 1 到 32 的整数");
    }
    const scheduledLivenessInterval = Number($("settingScheduledLivenessInterval").value);
    if (!Number.isInteger(scheduledLivenessInterval) || scheduledLivenessInterval < 5 || scheduledLivenessInterval > 10080) {
      throw new Error("验活执行频率必须是 5 到 10080 分钟的整数");
    }
    const cpaTimeout = Number($("settingCpaTimeout").value);
    const sub2apiTimeout = Number($("settingSub2ApiTimeout").value);
    if (!Number.isInteger(cpaTimeout) || cpaTimeout < 1 || cpaTimeout > 120 || !Number.isInteger(sub2apiTimeout) || sub2apiTimeout < 1 || sub2apiTimeout > 120) {
      throw new Error("上传超时必须是 1 到 120 的整数");
    }
    const sub2apiGroupIdRaw = $("settingSub2ApiGroupId").value.trim();
    const sub2apiGroupId = sub2apiGroupIdRaw === "" ? 0 : Number(sub2apiGroupIdRaw);
    if (!Number.isSafeInteger(sub2apiGroupId) || sub2apiGroupId < 0) {
      throw new Error("Sub2API 分组 ID 必须是正整数或留空");
    }
    const result = await api("/api/settings", {
      method: "PATCH",
      body: JSON.stringify({
        use_proxy_default: $("settingUseProxy").checked,
        auto_upload_cpa: $("settingAutoCpa").checked,
        auto_upload_sub2api: $("settingAutoSub2Api").checked,
        force_upload: $("forceUpload").checked,
        scheduled_liveness_enabled: $("settingScheduledLiveness").checked,
        scheduled_liveness_interval_minutes: scheduledLivenessInterval,
        worker_count: workerCount,
        cpa_api_url: $("settingCpaUrl").value.trim(),
        cpa_management_key: $("settingCpaKey").value.trim(),
        cpa_api_timeout_seconds: cpaTimeout,
        sub2api_api_url: $("settingSub2ApiUrl").value.trim(),
        sub2api_admin_api_key: $("settingSub2ApiKey").value.trim(),
        sub2api_api_timeout_seconds: sub2apiTimeout,
        sub2api_group_id: sub2apiGroupId,
      }),
    });
    applySettings(result);
    $("settingsResult").textContent = result.restart_required ? "设置已保存，请重启服务应用新的线程数" : "设置已保存";
  } catch (error) { $("settingsResult").textContent = error.message; }
};
$("accountSearch").value = accountSearchQuery;
$("accountStatusFilter").value = validAccountStatuses.includes(accountStatusFilter) ? accountStatusFilter : "";
$("accountPageSize").value = String(accountPagination.pageSize);
$("accountPage").value = String(accountPagination.page);
$("proxyPageSize").value = String(proxyPagination.pageSize);
$("proxyPage").value = String(proxyPagination.page);
refreshData();
refreshSettings();
setInterval(refreshData, 5000);
