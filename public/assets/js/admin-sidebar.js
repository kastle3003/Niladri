(function () {
  'use strict';

  const I = {
    dashboard:     '<rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/>',
    users:         '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    cms:           '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
    blog:          '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
    courses:       '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
    payments:      '<rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/>',
    analytics:     '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="3" y1="20" x2="21" y2="20"/>',
    announce:      '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    messages:      '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    email:         '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>',
    notifications: '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
    catalog:       '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    archive:       '<polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/>',
    profile:       '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    instructor:    '<circle cx="12" cy="8" r="4"/><path d="M12 14c-4 0-8 2-8 6v2h16v-2c0-4-4-6-8-6z"/>',
    student:       '<path d="M22 10L12 5 2 10l10 5 10-5z"/><path d="M6 12v5c0 1.7 2.7 3 6 3s6-1.3 6-3v-5"/>',
  };

  const CMS_SUBITEMS = [
    { hash: 'dashboard',   label: 'Dashboard',    icon: I.dashboard  },
    { hash: 'courses',     label: 'Courses',      icon: I.courses    },
    { hash: 'instructors', label: 'Instructors',  icon: I.instructor },
    { hash: 'blog',        label: 'Blog Posts',   icon: I.blog       },
    { hash: 'students',    label: 'Students',     icon: I.student    },
  ];

  const ITEMS = [
    { href: '/admin-panel.html',           label: 'Admin Panel',    icon: I.dashboard },
    { section: 'Content' },
    { href: '/admin-cms.html',             label: 'CMS',            icon: I.cms, subitems: CMS_SUBITEMS },
    { section: 'Commerce' },
    { href: '/admin-payments.html',        label: 'Payments',       icon: I.payments },
    { section: 'Engagement' },
    { href: '/admin-announcements.html',   label: 'Announcements',  icon: I.announce },
    { href: '/admin-messaging.html',       label: 'Messages',       icon: I.messages },
    { href: '/email-automation.html',      label: 'Email',          icon: I.email },
    { href: '/admin-notifications.html',   label: 'Notifications',  icon: I.notifications },
    { section: 'Insights' },
    { href: '/admin-panel.html#dashboard', label: 'Analytics',      icon: I.analytics },
    { section: 'Account' },
    { href: '/admin-profile.html',         label: 'Profile',        icon: I.profile },
  ];

  const SVG_TPL = (inner) =>
    `<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;

  function ensureStyles() {
    if (document.getElementById('role-sidebar-styles')) return;
    const style = document.createElement('style');
    style.id = 'role-sidebar-styles';
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
      .sidebar-nav .nav-subgroup {
        display: flex;
        flex-direction: column;
        margin: 2px 0 6px;
        padding-left: 22px;
        border-left: 1px solid rgba(200,168,75,0.12);
        margin-left: 22px;
      }
      .sidebar-nav .nav-subitem {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 10px;
        margin: 1px 0;
        font-size: 12.5px;
        color: var(--text-3, rgba(255,255,255,0.55));
        text-decoration: none;
        border-radius: 4px;
        transition: color .15s, background .15s;
      }
      .sidebar-nav .nav-subitem:hover {
        color: var(--text, #F0E6D3);
        background: rgba(200,168,75,0.06);
      }
      .sidebar-nav .nav-subitem.active {
        color: var(--gold, #C8A84B);
        background: rgba(200,168,75,0.1);
      }
      .sidebar-nav .nav-subicon { width: 14px; height: 14px; flex-shrink: 0; }
      .sidebar-user { cursor: default !important; }
      .sidebar-user:hover { background: transparent !important; }
      .sidebar-logout-btn {
        background: transparent;
        border: 1px solid rgba(200,168,75,0.15);
        border-radius: 6px;
        width: 32px; height: 32px;
        display: flex; align-items: center; justify-content: center;
        cursor: pointer;
        color: var(--text-3, rgba(255,255,255,0.55));
        transition: color .15s, border-color .15s, background .15s;
        flex-shrink: 0;
      }
      .sidebar-logout-btn:hover {
        color: var(--gold, #C8A84B);
        border-color: rgba(200,168,75,0.4);
        background: rgba(200,168,75,0.08);
      }
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
    const l = (user.last_name  || '')[0] || '';
    return (f + l).toUpperCase() || '—';
  }

  function render() {
    const path = window.location.pathname;
    const hash = (window.location.hash || '').replace(/^#/, '');
    const user = getCachedUser();
    const name = [user.first_name, user.last_name].filter(Boolean).join(' ') || 'Admin';
    const initials = initialsFor(user);

    const nav = ITEMS.map(it => {
      if (it.section) return `<div class="nav-section">${it.section}</div>`;
      const active = path === it.href ? ' active' : '';
      const main = `<a href="${it.href}" class="nav-item${active}">${SVG_TPL(it.icon)}${it.label}</a>`;
      if (!it.subitems || path !== it.href) return main;

      const defaultHash = it.subitems[0] && it.subitems[0].hash;
      const currentHash = hash || defaultHash;
      const subs = it.subitems.map(s => {
        const activeSub = s.hash === currentHash ? ' active' : '';
        const icon = s.icon
          ? `<svg class="nav-subicon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${s.icon}</svg>`
          : '';
        return `<a href="${it.href}#${s.hash}" class="nav-subitem${activeSub}" data-cms-hash="${s.hash}">${icon}${s.label}</a>`;
      }).join('');
      return `${main}<div class="nav-subgroup">${subs}</div>`;
    }).join('');

    return `
      <div class="sidebar-brand">
        <div class="brand-monogram">TFR</div>
        <div class="brand-title">The Foundation Room</div>
        <div class="brand-sub">Admin Console</div>
      </div>
      <nav class="sidebar-nav">${nav}</nav>
      <div class="sidebar-footer">
        <div class="sidebar-user">
          <div class="sidebar-avatar" id="sb-avatar">${initials}</div>
          <div class="sidebar-user-info">
            <div class="user-name" id="sb-name">${name}</div>
            <div class="user-role">Admin</div>
          </div>
          <button type="button" class="sidebar-logout-btn" title="Sign out"
            onclick="(window.logout||function(){localStorage.removeItem('archive_token');localStorage.removeItem('archive_user');location.href='/index.html';})()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
          </button>
        </div>
      </div>
    `;
  }

  function wireCmsSubitems() {
    if (window.location.pathname !== '/admin-cms.html') return;
    const subs = document.querySelectorAll('.nav-subitem[data-cms-hash]');
    subs.forEach(a => {
      a.addEventListener('click', (e) => {
        const hash = a.getAttribute('data-cms-hash');
        if (typeof window.switchSection === 'function') {
          e.preventDefault();
          history.replaceState(null, '', '#' + hash);
          window.switchSection(hash);
          subs.forEach(x => x.classList.toggle('active', x === a));
        }
      });
    });
    const initial = (window.location.hash || '').replace(/^#/, '');
    if (initial && typeof window.switchSection === 'function') {
      setTimeout(() => window.switchSection(initial), 0);
    }
  }

  function mount() {
    const el = document.getElementById('sidebar') || document.querySelector('aside.sidebar');
    if (!el) return;
    ensureStyles();
    el.innerHTML = render();
    wireCmsSubitems();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mount);
  } else {
    mount();
  }
  document.addEventListener('userLoaded', mount);
})();
