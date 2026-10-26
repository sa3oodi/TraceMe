/** Thin fetch wrapper. State-changing calls carry X-TraceMe, which the server requires as a CSRF defence. */
export async function api(path, { method = 'GET', body, signal } = {}) {
  const res = await fetch('/api' + path, {
    method, signal,
    headers: { 'X-TraceMe': '1', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) { document.dispatchEvent(new CustomEvent('tm-unauthorized')); throw new Error('Authentication required'); }
  if (res.status === 204) return null;
  let data = null;
  const text = await res.text();
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) throw new Error((data && data.error) || (typeof data === 'string' && data) || res.statusText);
  return data;
}
export const get = (p, o) => api(p, o);
export const post = (p, body, o) => api(p, { method: 'POST', body: body ?? {}, ...o });
export const put = (p, body) => api(p, { method: 'PUT', body });
export const del = p => api(p, { method: 'DELETE' });
