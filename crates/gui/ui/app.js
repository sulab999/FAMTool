import { events, escapeHTML as esc, splitPath, matches, identitySource, settingPaths, dateParts, pageNumber, pageSummary, shouldAskAuditPermission, shouldOpenAuditPrivacy } from './format.js';
const $ = id => document.getElementById(id);
const invoke = (command, args = {}) => {
  if (!window.__TAURI__) return Promise.reject(new Error('请通过 Tauri 桌面应用打开此界面。'));
  return window.__TAURI__.core.invoke(command, args);
};
let snapshot = null, view = 'live', busy = false, refreshing = false, settingsDirty = false, detailRecord = null, liveRows = [];
let history = { rows: [], total: null, totalPages: 0, page: 0, pageSize: 200, scanned: 0, requestId: null, searching: false, loadingPage: false, generation: 0 };
let toastTimer;
function toast(message, failure = false) { $('toast').textContent = String(message); $('toast').classList.toggle('failure', failure); $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 5500); }
function setBusy(value) { busy = value; $('toggle-monitor').disabled = value || !snapshot?.writable; $('save-settings').disabled = value || !snapshot?.writable; $('delete-button').disabled = value || !snapshot?.writable; $('confirm-delete').disabled = value; $('cancel-delete').disabled = value; }
async function operation(work, message) { if (busy) return; setBusy(true); try { await work(); if (message) toast(message); } catch (error) { toast(error, true); } finally { setBusy(false); await refresh(); } }
const titles = { live: ['实时活动', 'LIVE ACTIVITY', '文件的每一次变化，都有迹可循。'], history: ['历史搜索', 'HISTORY SEARCH', '按时间和线索，找到你需要的记录。'], settings: ['监控设置', 'PREFERENCES', '设定监控范围，让记录更有用。'] };
function navigate(next) { view = next; for (const name of Object.keys(titles)) $(`view-${name}`).hidden = name !== next; document.querySelectorAll('[data-view]').forEach(b => b.classList.toggle('active', b.dataset.view === next)); const [title, eyebrow, description] = titles[next]; $('page-title').textContent = title; $('breadcrumb-current').textContent = title; $('eyebrow').textContent = eyebrow; $('page-description').textContent = description; if (next === 'live') renderLive(); }
function populateEvents(element) { element.innerHTML = '<option value="">全部事件</option>' + Object.entries(events).map(([value, label]) => `<option value="${value}">${label}</option>`).join(''); }
populateEvents($('live-event')); populateEvents($('history-event'));
let auditPermissionBusy = false, auditPromptSeen = false, auditRequested = false, auditPrivacyOpened = false, auditServicePolling = false, auditWatchUntil = 0, auditBannerDismissed = false;
const auditPromptKey = 'audit-permission-prompt-v1';
function auditDismissed() { try { return localStorage.getItem(auditPromptKey) === 'dismissed'; } catch { return false; } }
function rememberAuditPrompt() { try { localStorage.setItem(auditPromptKey, 'dismissed'); } catch {} auditPromptSeen = true; }
function openAuditPrompt() {
 if (auditPermissionBusy || busy || !snapshot?.writable) return;
 auditPromptSeen = true;
 if (!$('audit-permission-dialog').open) $('audit-permission-dialog').showModal();
}
function showAuditPermissionResult(result) {
 const message = `${result.message}${result.helper_path ? `\n辅助程序：${result.helper_path}` : ''}`;
 $('audit-permission-result').textContent = message;
 $('audit-dialog-result').textContent = message;
}
async function requestAuditEnable() {
 if (auditPermissionBusy || busy) return;
 auditPermissionBusy = true;
 $('audit-permission-confirm').disabled = true;
 $('audit-permission-later').disabled = true;
 $('audit-dialog-result').textContent = '正在检查签名及系统授权条件…';
 try {
   const result = await invoke('audit_enable');
   showAuditPermissionResult(result);
   rememberAuditPrompt();
   auditRequested = ['enabled', 'approval_required'].includes(result.state);
   auditWatchUntil = Date.now() + 120000;
   auditPrivacyOpened = false;
   if (auditRequested) { $('audit-permission-dialog').close(); $('setting-audit').checked = true; await refresh(); }
 } catch (error) { showAuditPermissionResult({ message: String(error) }); }
 finally { auditPermissionBusy = false; $('audit-permission-confirm').disabled = false; $('audit-permission-later').disabled = false; }
}
async function openAuditPrivacy() {
 try { const result = await invoke('audit_open_privacy'); $('audit-permission-result').textContent = result.message; }
 catch (error) { toast(error, true); }
}
$('audit-enable').onclick = openAuditPrompt;
$('audit-banner-close').onclick = () => { auditBannerDismissed = true; $('audit-banner').hidden = true; };
$('audit-pipe-start').onclick = () => operation(async () => {
  const r = await invoke('audit_pipe_launch');
  $('audit-permission-result').textContent = `审计辅助程序已以管理员启动。数秒后审计状态应显示“系统审计已连接”`;
}, 'OpenBSM 审计辅助程序已启动。');

$('audit-permission-confirm').onclick = requestAuditEnable;
$('audit-permission-later').onclick = () => { rememberAuditPrompt(); $('audit-permission-dialog').close(); };
$('audit-permission-dialog').addEventListener('cancel', event => { if (auditPermissionBusy) event.preventDefault(); else rememberAuditPrompt(); });
$('audit-privacy').onclick = openAuditPrivacy;
$('audit-service-stop').onclick = () => operation(async () => {
 const result = await invoke('audit_service_stop'); showAuditPermissionResult(result); if (result.state !== 'stopped') throw new Error(result.message); auditRequested = false; rememberAuditPrompt();
}, '后台审计服务已停用，普通文件监控继续运行。');
setInterval(async () => {
 if (!auditRequested || auditServicePolling || (document.hidden && Date.now() > auditWatchUntil)) return;
 auditServicePolling = true;
 try { const result = await invoke('audit_service_status'); if (snapshot?.audit?.state !== 'running') $('audit-permission-result').textContent = result.message; }
 catch (error) { $('audit-permission-result').textContent = String(error); }
 finally { auditServicePolling = false; }
}, 5000);
function renderAudit() {
 const a = snapshot.audit;
 if (!a) return;
 const labels = {running:'系统审计已连接',waiting:'等待审计辅助程序',connecting:'正在连接',disabled:'系统审计未启用',paused:'审计已暂停',unavailable:'系统审计不可用',disconnected:'审计连接断开',not_entitled:'缺少 Apple 审计授权',not_permitted:'缺少完全磁盘访问权限',not_privileged:'辅助程序需要 root',failed:'审计启动失败'};
 const title = labels[a.state] || a.state;
 $('audit-state').textContent = title;
 $('audit-status').textContent = `${a.message} · 已接收 ${a.received.toLocaleString()} 条系统审计记录`;
 $('audit-socket').textContent = `审计连接位置：${a.socket_path}`;
 $('audit-probe').disabled = !a.supported;
 $('audit-enable').disabled = !a.supported || !snapshot.writable || auditPermissionBusy;
 $('audit-pipe-start').disabled = !a.supported || !snapshot.writable || auditPermissionBusy;
 $('audit-privacy').disabled = !a.supported;
 $('audit-service-stop').disabled = !a.supported || !snapshot.writable || auditPermissionBusy;
 if (shouldAskAuditPermission(a, auditPromptSeen || auditDismissed(), busy) && snapshot.writable) openAuditPrompt();
 if (shouldOpenAuditPrivacy(a, auditRequested, auditPrivacyOpened)) { auditPrivacyOpened = true; openAuditPrivacy(); }
 if (a.state === 'running') { auditRequested = false; $('audit-permission-result').textContent = '系统审计已实际连接，辅助程序正以 root 接收事件。'; }
 if (a.state === 'running') auditBannerDismissed = false; // 真正连上时重新提示
 $('audit-banner').hidden = !a.enabled || auditBannerDismissed;
 $('audit-banner').classList.toggle('audit-ready', a.state === 'running');
 $('audit-banner-text').textContent = `${title}：${a.message}${a.state === 'running' ? '' : (snapshot.running ? '。普通文件监控继续运行。' : '。监控已暂停。')}`;
}
$('audit-probe').onclick = async () => {
 $('audit-probe').disabled = true;
 try { const result = await invoke('audit_probe'); $('audit-probe-result').textContent = `${result.message}（检查以当前普通用户身份执行）\n辅助程序：${result.helper_path}`; }
 catch (e) { $('audit-probe-result').textContent = String(e); }
 finally { $('audit-probe').disabled = !snapshot?.audit?.supported; }
};
function recordRow(r, index) { const { time, date } = dateParts(r.time); const { name, parent } = splitPath(r.path); const known = events[r.event] ? r.event : 'diagnostic'; const title = r.diagnostic ? `${r.diagnostic.code} · ${r.diagnostic.count} 次` : name; const sub = r.diagnostic?.message || parent; const user = r.actor?.user || r.owner || '—'; return `<tr tabindex="0" data-index="${index}" aria-label="查看 ${esc(title)}"><td><div class="time-text">${esc(time)}</div><div class="date-text">${esc(date)}</div></td><td><span class="pill event-${known}">${esc(events[r.event] || r.event)}</span>${r.audit ? '<span class="audit-tag">系统审计</span>' : ''}</td><td title="${esc(r.path)}"><div class="file-main">${esc(title || '—')}</div><div class="file-parent">${esc(sub)}</div></td><td class="cell-ellipsis" title="${esc(identitySource(r.actor?.source))}">${esc(r.actor?.application || '—')}</td><td class="cell-ellipsis" title="${esc(r.actor?.user ? '进程用户' : r.owner ? '文件属主，并非操作者' : '系统未提供')}">${esc(user)}</td><td class="chevron">›</td></tr>`; }
function renderLive() { if (!snapshot || view !== 'live') return; if ($('live-follow').checked) liveRows = snapshot.records.map(item => item.record); const rows = liveRows.filter(r => matches(r, $('live-text').value, $('live-event').value)); $('live-rows').innerHTML = rows.map(recordRow).join(''); $('live-rows')._records = rows; $('live-count').textContent = `${rows.length} 条`; $('live-empty').hidden = rows.length !== 0; $('live-summary').textContent = `显示 ${rows.length} 条 · 缓冲共 ${snapshot.buffered.toLocaleString()} 条`; }
function fillSettings() { if (!snapshot) return; const c = snapshot.config; $('setting-roots').value = c.roots.join('\n'); $('setting-excludes').value = c.excludes.join('\n'); $('setting-log').value = c.log_file; $('setting-retention').value = c.retention_days; $('setting-debounce').value = c.debounce_ms; $('setting-recursive').checked = c.recursive; $('setting-access').checked = c.track_access; $('setting-audit').checked = c.audit_enabled; $('setting-audit').disabled = !snapshot.audit?.supported; }
async function refresh() { if (refreshing) return; refreshing = true; try { snapshot = await invoke('snapshot'); $('connection').textContent = snapshot.running ? '监控运行中' : '监控已暂停'; $('connection').classList.toggle('running', snapshot.running); $('toggle-monitor').textContent = snapshot.running ? 'Ⅱ 暂停监控' : '▷ 开始监控'; setBusy(busy); renderAudit(); $('stat-received').textContent = snapshot.received.toLocaleString(); $('stat-buffered').textContent = snapshot.buffered.toLocaleString(); $('stat-retention').textContent = snapshot.config.retention_days; const error = snapshot.errors.at(-1); $('error-banner').hidden = !error; $('error-banner').textContent = error || ''; if (!settingsDirty) fillSettings(); if (!detailRecord && document.activeElement?.closest('tbody') === null) renderLive(); } catch (error) { $('connection').textContent = '连接异常'; $('connection').classList.remove('running'); $('error-banner').hidden = false; $('error-banner').textContent = String(error); } finally { refreshing = false; } }
function showDetail(r) { detailRecord = r; const fields = [['时间', new Date(r.time).toLocaleString('zh-CN', { hour12: false })], ['操作', events[r.event] || r.event], ['对象', ({ file: '文件', folder: '文件夹', monitor: '监控诊断' })[r.object] || r.object], ['文件路径', r.path], ...(r.from ? [['原路径', r.from]] : []), ['关联应用', r.actor?.application || '未知'], ['进程 ID', r.actor?.process_id ?? '未知'], ['进程用户', r.actor?.user || '未知'], ['文件属主', r.owner || '未知'], ['归因来源', identitySource(r.actor?.source)]]; if (r.audit) {
 const a = r.audit;
 const ref = p => p ? `${p.executable || '路径未知（进程可能已退出）'} · PID ${p.pid}` : '系统未提供';
 fields.push(['执行文件', a.executable], ['有效 UID', a.uid], ['真实 UID', a.real_uid], ['审计登录 UID', a.audit_uid], ['进程版本', a.pid_version], ['父进程', ref(a.parent)], ['责任进程', ref(a.responsible)], ['签名标识', a.signing_id || '未提供'], ['签名团队', a.team_id || '未提供'], ['系统审计序号', a.global_sequence]);
 } if (r.diagnostic) fields.push(['诊断代码', r.diagnostic.code], ['累计次数', r.diagnostic.count], ['首次发生', new Date(r.diagnostic.first_time).toLocaleString()], ['末次发生', new Date(r.diagnostic.last_time).toLocaleString()], ['诊断说明', r.diagnostic.message]); $('detail-content').innerHTML = `<span class="pill event-${events[r.event] ? r.event : 'diagnostic'}">${esc(events[r.event] || r.event)}</span><dl class="detail-list">${fields.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>`).join('')}</dl><div class="detail-note">${r.audit ? '执行进程来自 Endpoint Security 事件。父进程/责任进程路径通过审计令牌查询，退出后可能未知；责任进程不一定是直接父进程。' : '关联应用、进程用户及文件属主是不同信息。句柄关联与路径推断不代表确定的操作者。'}</div>`; $('reveal-file').hidden = Boolean(r.diagnostic) || !r.path; $('detail-dialog').showModal(); }
for (const id of ['live-rows', 'history-rows']) { $(id).addEventListener('click', event => { const row = event.target.closest('tr'); if (row) showDetail($(id)._records[Number(row.dataset.index)]); }); $(id).addEventListener('keydown', event => { if (event.key === 'Enter') { const row = event.target.closest('tr'); if (row) showDetail($(id)._records[Number(row.dataset.index)]); } }); }
$('close-detail').onclick = () => $('detail-dialog').close(); $('detail-dialog').addEventListener('close', () => { detailRecord = null; });
$('reveal-file').onclick = () => invoke('reveal_file', { path: detailRecord.path }).catch(e => toast(e, true));
document.querySelectorAll('[data-view]').forEach(b => b.onclick = () => navigate(b.dataset.view));
$('toggle-monitor').onclick = () => operation(() => invoke('set_monitoring', { running: !snapshot.running }));
$('open-storage').onclick = () => invoke('open_location', { which: 'logs' }).catch(e => toast(e, true));
$('clear-display').onclick = () => operation(async () => { await invoke('clear_display'); liveRows = []; snapshot.records = []; snapshot.buffered = 0; renderLive(); }, '仅清空显示，数据库记录保留。');
$('live-text').oninput = renderLive; $('live-event').onchange = renderLive; $('live-follow').onchange = renderLive;
function cancelHistory() {
  if (history.requestId) invoke('cancel_search', { requestId: history.requestId }).catch(() => {});
  history.generation++;
  history.searching = false;
  history.loadingPage = false;
}
function clearHistory() {
  cancelHistory();
  Object.assign(history, { rows: [], total: null, totalPages: 0, page: 0, scanned: 0, requestId: null });
  renderHistory();
  $('history-status').textContent = '设置条件，查找过去的文件活动';
}
function renderHistory() {
  $('history-rows').innerHTML = history.rows.map(recordRow).join('');
  $('history-rows')._records = history.rows;
  $('history-count').textContent = history.total === null ? (history.searching ? '统计中…' : '尚未完成搜索') : `共 ${history.total.toLocaleString()} 条`;
  $('history-empty').hidden = history.rows.length !== 0;
  const empty = $('history-empty');
  empty.querySelector('h3').textContent = history.searching ? '正在统计完整搜索结果' : history.total === 0 ? '没有找到匹配记录' : '从这里找回记录';
  empty.querySelector('p').textContent = history.searching ? '后台解密匹配中，可随时取消；监控继续运行。' : history.total === 0 ? '调整关键字或时间范围后再试。' : '按时间、文件路径或关联应用组合查询。';
  const pending = history.searching || history.loadingPage;
  const pageable = !pending && history.totalPages > 0;
  $('history-page-info').textContent = history.searching ? '总页数统计中…' : `第 ${history.page} / ${history.totalPages} 页`;
  $('history-prev').disabled = !pageable || history.page <= 1;
  $('history-next').disabled = !pageable || history.page >= history.totalPages;
  $('history-page-input').disabled = !pageable;
  $('history-page-input').max = String(Math.max(1, history.totalPages));
  $('history-page-input').value = history.page > 0 ? history.page : '';
  $('history-go').disabled = !pageable;
  $('search-button').disabled = pending;
  $('cancel-search').hidden = !pending;
}
function acceptHistoryPage(result) {
  Object.assign(history, { rows: result.records, total: result.total, totalPages: result.total_pages, page: result.page, pageSize: result.page_size, scanned: result.scanned });
  const range = pageSummary(result.total, result.page, result.page_size);
  $('history-status').textContent = `共找到 ${result.total.toLocaleString()} 条 · 共 ${result.total_pages.toLocaleString()} 页 · 本页显示 ${range.from.toLocaleString()}–${range.to.toLocaleString()} 条`;
  $('view-history').querySelector('.table-scroll').scrollTop = 0;
}
async function startHistorySearch(query) {
  clearHistory();
  const generation = history.generation;
  const id = crypto.randomUUID();
  history.requestId = id;
  history.searching = true;
  renderHistory();
  $('history-status').textContent = '正在搜索并统计总条数…';
  try {
    const result = await invoke('search_history', { request: { ...query, request_id: id, limit: 200 } });
    if (generation !== history.generation) return;
    acceptHistoryPage(result);
  } catch (error) {
    if (generation === history.generation) { $('history-status').textContent = String(error); toast(error, true); }
  } finally {
    if (generation === history.generation) { history.searching = false; renderHistory(); }
  }
}
async function goHistoryPage(value) {
  if (history.searching || history.loadingPage) return;
  const page = pageNumber(value, history.totalPages);
  if (page === null) { toast(`请输入 1–${history.totalPages} 之间的整数页码`, true); return; }
  if (page === history.page) return;
  const generation = history.generation;
  history.loadingPage = true;
  renderHistory();
  $('history-status').textContent = `正在读取第 ${page} 页…`;
  try {
    const result = await invoke('history_page', { requestId: history.requestId, page });
    if (generation !== history.generation) return;
    acceptHistoryPage(result);
  } catch (error) {
    if (generation === history.generation) {
      Object.assign(history, { rows: [], total: null, totalPages: 0, page: 0 });
      $('history-status').textContent = String(error);
      toast(error, true);
    }
  } finally {
    if (generation === history.generation) { history.loadingPage = false; renderHistory(); }
  }
}
$('history-form').onsubmit = event => {
  event.preventDefault();
  startHistorySearch({ text: $('history-text').value, event: $('history-event').value, application: $('history-app').value, user: $('history-user').value, since: $('history-since').value, until: $('history-until').value });
};
$('cancel-search').onclick = () => {
  clearHistory();
  $('history-status').textContent = '查询已取消，未完成的统计不会作为总数显示；请重新搜索。';
};
$('reset-history').onclick = () => { $('history-form').reset(); clearHistory(); };
$('history-next').onclick = () => goHistoryPage(history.page + 1);
$('history-prev').onclick = () => goHistoryPage(history.page - 1);
$('history-go').onclick = () => goHistoryPage($('history-page-input').value);
$('history-page-input').onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); goHistoryPage(event.currentTarget.value); } };
$('settings-form').oninput = () => { settingsDirty = true; };
$('reset-excludes').onclick = () => { $('setting-excludes').value = snapshot.defaults.excludes.join('\n'); settingsDirty = true; };
$('settings-form').onsubmit = event => { event.preventDefault(); operation(async () => { const config = { roots: settingPaths($('setting-roots').value), excludes: settingPaths($('setting-excludes').value), log_file: $('setting-log').value.trim(), debounce_ms: Number($('setting-debounce').value), track_access: $('setting-access').checked, recursive: $('setting-recursive').checked, retention_days: Number($('setting-retention').value), audit_enabled: $('setting-audit').checked }; await invoke('save_settings', { config }); settingsDirty = false; clearHistory(); }, '设置已保存并应用。'); };
function requestDelete() { if (busy || !snapshot?.writable) return; $('delete-path').textContent = `${snapshot.config.log_file}.store/events.sqlite3`; if (!$('delete-dialog').open) $('delete-dialog').showModal(); }
$('delete-button').onclick = requestDelete; $('cancel-delete').onclick = () => $('delete-dialog').close(); $('delete-dialog').addEventListener('cancel', event => { if (busy) event.preventDefault(); });
$('confirm-delete').onclick = () => operation(async () => { clearHistory(); const result = await invoke('delete_logs', { confirmation: 'DELETE_ALL_LOGS' }); $('delete-dialog').close(); liveRows = []; toast(`已删除 ${result.deleted.toLocaleString()} 条日志。${result.resume_error ? `恢复监控失败：${result.resume_error}` : '监控已恢复，之后显示的都是新产生的记录。'}`, Boolean(result.resume_error)); });
window.addEventListener('unhandledrejection', event => { toast(event.reason, true); });
if (window.__TAURI__) { await window.__TAURI__.event.listen('history-progress', event => { const p = event.payload; if (history.searching && p.request_id === history.requestId) { $('history-status').textContent = `已扫描 ${p.scanned.toLocaleString()} 条，已匹配 ${p.matched.toLocaleString()} 条；正在统计总数…`; } }); await window.__TAURI__.event.listen('navigate', event => navigate(event.payload)); await window.__TAURI__.event.listen('request-delete', requestDelete); await window.__TAURI__.event.listen('operation-error', event => toast(event.payload, true)); }
await refresh();
setInterval(() => { if ((!document.hidden || (auditRequested && Date.now() < auditWatchUntil)) && !busy) refresh(); }, 1200);
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
