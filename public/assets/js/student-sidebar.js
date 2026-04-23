(function () {
  'use strict';

  const I = {
    dashboard: '<rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/>',
    courses: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
    lessons: '<polygon points="5 3 19 12 5 21 5 3"/>',
    assignments: '<rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><polyline points="9 14 11 16 15 12"/>',
    certificates: '<circle cx="12" cy="8" r="6"/><polyline points="8.21 13.89 7 22 12 19 17 22 15.79 13.88"/>',
    catalog: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    practice: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    analytics: '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="3" y1="20" x2="21" y2="20"/>',
    calendar: '<rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>',
    sheet: '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
    resources: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
    archive: '<polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/>',
    messages: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    discussions: '<path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>',
    notifications: '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
    announcements: '<path d="M3 11l18-5v12L3 14v-3z"/><path d="M11.6 16.8a3 3 0 1 1-5.8-1.6"/>',
    studio: '<path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/>',
    profile: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  };

  const ITEMS = [
    { href: '/student-dashboard.html', label: 'Dashboard', icon: I.dashboard },
    { section: 'Learning' },
    { href: '/student-courses.html', label: 'My Courses', icon: I.courses },
    { href: '/student-lessons.html', label: 'My Lessons', icon: I.lessons },
    // { href: '/my-assignments.html',     label: 'Assignments',    icon: I.assignments },
    // { href: '/student-certificates.html', label: 'Certificates', icon: I.certificates },
    { href: '/student-course-catalog.html', label: 'Browse Catalog', icon: I.catalog },
    { section: 'Practice & Progress' },
    { href: '/student-practice-log.html', label: 'Practice Log', icon: I.practice },
    { href: '/studio.html',               label: 'Studio',       icon: I.studio },
    { href: '/analytics-student.html',    label: 'Analytics',    icon: I.analytics },
    { href: '/student-calendar.html',     label: 'Calendar',     icon: I.calendar },
    { section: 'Library' },
    { href: '/student-sheet-music.html', label: 'Sheet Music', icon: I.sheet },
    { href: '/student-resources.html', label: 'Resources', icon: I.resources },
    { href: '/student-archive.html', label: 'The Archive', icon: I.archive },
    { section: 'Community' },
    { href: '/student-announcements.html', label: 'Announcements', icon: I.announcements },
    { href: '/student-notifications.html', label: 'Notifications', icon: I.notifications },
    { section: 'Account' },
    { href: '/student-profile.html', label: 'Profile', icon: I.profile },
  ];

  const SVG_TPL = (inner) =>
    `<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;

  function ensureStyles() {
    if (document.getElementById('student-sidebar-styles')) return;
    const style = document.createElement('style');
    style.id = 'student-sidebar-styles';
    style.textContent = `
      .sidebar-nav .nav-section {
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1.4px;
        text-transform: uppercase;
        color: rgba(255,255,255,0.32);
        padding: 18px 24px 6px;
        pointer-events: none;
      }
      .sidebar-nav .nav-section:first-child { padding-top: 6px; }
    `;
    document.head.appendChild(style);
  }

  function getCachedUser() {
    try { return JSON.parse(localStorage.getItem('archive_user') || 'null') || {}; }
    catch { return {}; }
  }

  function initialsFor(user) {
    if (user.avatar_initials) return user.avatar_initials;
    const f = (user.first_name || '')[0] || '';
    const l = (user.last_name || '')[0] || '';
    return (f + l).toUpperCase() || '—';
  }

  function render() {
    const path = window.location.pathname;
    const user = getCachedUser();
    const name = [user.first_name, user.last_name].filter(Boolean).join(' ') || 'Student';
    const initials = initialsFor(user);

    const nav = ITEMS.map(it => {
      if (it.section) return `<div class="nav-section">${it.section}</div>`;
      const active = path === it.href ? ' active' : '';
      return `<a href="${it.href}" class="nav-item${active}">${SVG_TPL(it.icon)}${it.label}</a>`;
    }).join('');

    return `
      <div class="sidebar-brand">
        <div class="brand-monogram">TFR</div>
        <div class="brand-title">The Foundation Room</div>
        <div class="brand-sub">Student Portal</div>
      </div>
      <nav class="sidebar-nav">${nav}</nav>
      <div class="sidebar-footer">
        <div class="sidebar-user" onclick="(window.logout||function(){localStorage.clear();location.href='/index.html';})()">
          <div class="sidebar-avatar" id="sb-avatar">${initials}</div>
          <div class="sidebar-user-info">
            <div class="user-name" id="sb-name">${name}</div>
            <div class="user-role">Log Out</div>
          </div>
        </div>
      </div>
    `;
  }

  function mount() {
    const el = document.getElementById('sidebar') || document.querySelector('aside.sidebar');
    if (!el) return;
    ensureStyles();
    el.innerHTML = render();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mount);
  } else {
    mount();
  }
  document.addEventListener('userLoaded', mount);
})();
