(function () {
  'use strict';

  const MAP = {
    admin:      '/assets/js/admin-sidebar.js',
    instructor: '/assets/js/instructor-sidebar.js',
    student:    '/assets/js/student-sidebar.js',
  };

  function getCachedRole() {
    try {
      const u = JSON.parse(localStorage.getItem('archive_user') || 'null');
      return u && u.role;
    } catch { return null; }
  }

  function inject(src) {
    if (document.querySelector('script[data-sidebar-loaded="' + src + '"]')) return;
    const s = document.createElement('script');
    s.src = src;
    s.dataset.sidebarLoaded = src;
    document.head.appendChild(s);
  }

  function pick() {
    const role = getCachedRole();
    const src = MAP[role] || MAP.student;
    inject(src);
  }

  // Cached user present → load immediately
  if (getCachedRole()) {
    pick();
  } else {
    // Otherwise wait until auth-guard confirms the session
    document.addEventListener('userLoaded', pick, { once: true });
  }
})();
