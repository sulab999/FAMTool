export const events = { created: '创建', modified: '修改', renamed: '重命名', renamed_in: '移入', renamed_out: '移出', removed: '删除', accessed: '访问', diagnostic: '监控诊断' };
export const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
export function splitPath(path = '') { const pos = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')); return { name: path.slice(pos + 1) || path, parent: pos >= 0 ? path.slice(0, pos) || '/' : '' }; }
export function matches(record, text, event) { const q = text.trim().toLocaleLowerCase(); return (!event || event === record.event) && (!q || [record.path, record.from, record.actor?.application, record.actor?.user, record.owner, record.actor?.process_id, record.diagnostic?.code, record.diagnostic?.message, record.audit?.executable, record.audit?.parent?.executable, record.audit?.responsible?.executable].some(v => String(v ?? '').toLocaleLowerCase().includes(q))); }
export function identitySource(source = '') { source = String(source ?? ''); if (source === 'endpoint_security') return '系统审计：Endpoint Security 在操作发生时采集的执行进程'; if (source === 'bsm_auditpipe') return '系统审计：OpenBSM 审计管道在操作发生时采集的执行进程'; if (source === 'fanotify') return '系统审计：内核 fanotify 事件记录的执行进程'; if (source === 'security_log') return '系统审计：Windows 安全日志（4663/4660）记录的执行进程'; if (source.startsWith('path_inferred')) return '按路径推断（不是确定的操作者）'; if (source.startsWith('fd_scan')) return '文件句柄关联（不代表确定的写入者）'; if (source.startsWith('notify_process_id')) return '系统提供 PID，事件后查询进程身份'; return source || '系统未提供'; }
export function settingPaths(text) { return text.split(/\r?\n/).map(v => v.trim()).filter(Boolean); }
export function dateParts(value) { const d = new Date(value); return { time: d.toLocaleTimeString('zh-CN', { hour12: false }), date: d.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' }) }; }

export function pageNumber(value, totalPages) {
  const text = String(value ?? '').trim();
  if (!/^\d+$/.test(text)) return null;
  const page = Number(text);
  return Number.isSafeInteger(page) && page >= 1 && page <= totalPages ? page : null;
}
export function pageSummary(total, page, pageSize) {
  const totalPages = Math.ceil(total / pageSize);
  return { totalPages, from: total === 0 ? 0 : (page - 1) * pageSize + 1, to: Math.min(page * pageSize, total) };
}

export function shouldAskAuditPermission(audit, dismissed, busy) {
  return Boolean(audit?.enabled && audit?.supported && ['waiting','not_permitted','not_privileged','disconnected'].includes(audit.state) && !dismissed && !busy);
}
export function shouldOpenAuditPrivacy(audit, requested, opened) {
  return Boolean(requested && !opened && audit?.state === 'not_permitted');
}
// 诊断横幅同因去重:去掉“（累计 N 次…）”后缀后作为关闭键
export function errorKey(text) { return String(text ?? '').split('（')[0].trim(); }
export function shouldShowErrorBanner(error, dismissedKey) {
  return Boolean(error) && errorKey(error) !== dismissedKey;
}
