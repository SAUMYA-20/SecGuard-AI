function normalizeAuditUrl(rawUrl) {
  const value = typeof rawUrl === 'string' ? rawUrl.trim() : '';
  if (!value) return '';

  const withProtocol = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  const parsed = new URL(withProtocol);
  parsed.hash = '';
  parsed.search = '';
  parsed.username = '';
  parsed.password = '';

  const pathname = parsed.pathname === '/'
    ? '/'
    : parsed.pathname.replace(/\/+$/, '') || '/';

  return `${parsed.origin}${pathname}`;
}

module.exports = { normalizeAuditUrl };
