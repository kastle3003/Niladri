const API_BASE = '';

const api = {
  _token: () => localStorage.getItem('archive_token'),
  _headers: (extra = {}) => ({
    'Content-Type': 'application/json',
    ...(api._token() ? { Authorization: `Bearer ${api._token()}` } : {}),
    ...extra
  }),
  _handle: async (res) => {
    if (res.status === 401) {
      console.warn('[api] 401 on', res.url, '→ clearing token & redirecting to sign-in');
      localStorage.removeItem('archive_token');
      localStorage.removeItem('archive_user');
      window.location.href = '/index.html';
      return;
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  },
  get: (path) => fetch(API_BASE + path, { headers: api._headers() }).then(api._handle),
  post: (path, body) => fetch(API_BASE + path, { method: 'POST', headers: api._headers(), body: JSON.stringify(body) }).then(api._handle),
  put: (path, body) => fetch(API_BASE + path, { method: 'PUT', headers: api._headers(), body: JSON.stringify(body) }).then(api._handle),
  del: (path) => fetch(API_BASE + path, { method: 'DELETE', headers: api._headers() }).then(api._handle),
  upload: (path, formData) => fetch(API_BASE + path, { method: 'POST', headers: { ...(api._token() ? { Authorization: `Bearer ${api._token()}` } : {}) }, body: formData }).then(api._handle),
};
window.api = api;
