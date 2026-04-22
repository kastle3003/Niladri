(function () {
  'use strict';

  const ROLE_HOMES = {
    admin: '/admin-panel.html',
    instructor: '/instructor-dashboard.html',
    student: '/student-dashboard.html',
  };

  function roleHome(role) {
    return ROLE_HOMES[role] || '/student-dashboard.html';
  }

  function getCachedUser() {
    try { return JSON.parse(localStorage.getItem('archive_user') || 'null'); }
    catch { return null; }
  }

  function logout() {
    localStorage.removeItem('archive_token');
    localStorage.removeItem('archive_user');
    window.location.replace('/index.html');
  }

  async function ensureAuth() {
    const token = localStorage.getItem('archive_token');
    if (!token) {
      console.warn('[auth-guard] no archive_token in localStorage → sign-in');
      window.location.replace('/index.html');
      return null;
    }
    try {
      const data = await api.get('/api/auth/me');
      if (!data || !data.user) {
        console.warn('[auth-guard] /api/auth/me returned no user payload', data);
        logout();
        return null;
      }
      window.currentUser = data.user;
      localStorage.setItem('archive_user', JSON.stringify(data.user));
      document.dispatchEvent(new CustomEvent('userLoaded', { detail: data.user }));
      return data.user;
    } catch (err) {
      console.warn('[auth-guard] /api/auth/me failed → sign-in', err);
      logout();
      return null;
    }
  }

  function requireRole(allowed) {
    const list = Array.isArray(allowed) ? allowed : [allowed];
    const cached = getCachedUser();
    if (cached && cached.role && !list.includes(cached.role)) {
      window.location.replace(roleHome(cached.role));
      return;
    }
    document.addEventListener('userLoaded', function (e) {
      if (!list.includes(e.detail.role)) {
        window.location.replace(roleHome(e.detail.role));
      }
    });
  }

  window.roleHome = roleHome;
  window.getCurrentUser = getCachedUser;
  window.logout = logout;
  window.requireRole = requireRole;

  ensureAuth();
})();
