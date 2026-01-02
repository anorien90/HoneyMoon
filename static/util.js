export function escapeHtml(str) {
  if (!str) return '';
  const escapeMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return str.replace(/[&<>"']/g, m => escapeMap[m]);
}

export function truncate(str = '', len = 80) {
  if (str.length <= len) return str;
  return str.slice(0, len - 1) + '…';
}
