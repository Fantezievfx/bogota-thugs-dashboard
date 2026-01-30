require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');

const app = express();

/* =========================
   ROLES & PERMISSIONS
   ========================= */

const ROLES = {
  LIDER: 'Lider Bogota Thugs',
  CO_LIDER: 'Co Lider Bogota Thugs',
  DEV: 'Developer website',
  TESTER: 'Tester Bogota Thugs',
  MEMBRU: 'Membru Bogota Thugs'
};

const FULL_ACCESS_ROLES = [ROLES.LIDER, ROLES.CO_LIDER];
const CAN_ADD_MEMBERS_ROLES = [ROLES.LIDER, ROLES.CO_LIDER, ROLES.TESTER];

/* =========================
   IN-MEMORY DATA
   ========================= */

let taxaSaptamana = 'TAXA LIBERA PERMANENTA';
let sanctiuniActive = 'NICIUN FW';
let taxaItems = '2 ceas aur, 5 portofele, 5 brichete';

let taxaAfisataDate = '26 Jan 2026';
let taxaAfisataText = '2 ceas aur, 5 portofele, 5 brichete';

let userRoles = {
  // YOU
  '432966960800595990': [ROLES.DEV, ROLES.LIDER, ROLES.CO_LIDER]
};

let userJoinDates = {};

/* =========================
   EXPRESS CONFIG
   ========================= */

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'supersecret',
    resave: false,
    saveUninitialized: false
  })
);

/* =========================
   PASSPORT / DISCORD OAUTH
   ========================= */

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(
  new DiscordStrategy(
    {
      clientID: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      callbackURL: process.env.DISCORD_CALLBACK_URL,
      scope: ['identify']
    },
    (accessToken, refreshToken, profile, done) => {
      const roles = userRoles[profile.id] || [ROLES.MEMBRU];
      profile.appRoles = roles;

      profile.avatarUrl = profile.avatar
        ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
        : 'https://cdn.discordapp.com/embed/avatars/0.png';

      return done(null, profile);
    }
  )
);

app.use(passport.initialize());
app.use(passport.session());

/* =========================
   MIDDLEWARES
   ========================= */

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

function hasAnyRole(requiredRoles) {
  return (req, res, next) => {
    if (!req.isAuthenticated()) return res.redirect('/login');
    const roles = req.user.appRoles || [];
    const allowed = requiredRoles.some(r => roles.includes(r));
    if (!allowed) return res.status(403).render('unauthorized', { user: req.user });
    next();
  };
}

/* =========================
   AUTH ROUTES
   ========================= */

app.get('/', (req, res) => {
  if (!req.user) return res.redirect('/login');
  res.redirect('/dashboard');
});

app.get('/login', (req, res) => res.render('login'));

app.get('/auth/discord', passport.authenticate('discord'));

app.get(
  '/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/dashboard');
  }
);

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/login');
  });
});

/* =========================
   DASHBOARD
   ========================= */

app.get('/dashboard', isLoggedIn, (req, res) => {
  const roles = req.user.appRoles || [];
  const isFullAccess = roles.some(r => FULL_ACCESS_ROLES.includes(r));
  const canAddMembers = roles.some(r => CAN_ADD_MEMBERS_ROLES.includes(r));

  let timpInFamilie = 'Necunoscut';
  const joinDate = userJoinDates[req.user.id];
  if (joinDate) {
    const diffMs = Date.now() - new Date(joinDate).getTime();
    const months = Math.max(1, Math.floor(diffMs / (1000 * 60 * 60 * 24 * 30)));
    timpInFamilie = `${months} luni`;
  }

  res.render('dashboard', {
    user: req.user,
    ROLES,
    taxaSaptamana,
    sanctiuniActive,
    taxaItems,
    taxaAfisataDate,
    taxaAfisataText,
    timpInFamilie,
    isFullAccess,
    canAddMembers
  });
});

/* =========================
   ADMIN PANEL
   ========================= */

app.get('/admin', hasAnyRole(FULL_ACCESS_ROLES), (req, res) => {
  res.render('admin', {
    user: req.user,
    taxaSaptamana,
    taxaAfisataDate,
    taxaAfisataText
  });
});

app.post('/admin/update-taxa-saptamana', hasAnyRole(FULL_ACCESS_ROLES), (req, res) => {
  taxaSaptamana = req.body.taxaSaptamana || taxaSaptamana;
  res.redirect('/admin');
});

app.post('/admin/update-taxa-afisata', hasAnyRole(FULL_ACCESS_ROLES), (req, res) => {
  taxaAfisataDate = req.body.taxaAfisataDate || taxaAfisataDate;
  taxaAfisataText = req.body.taxaAfisataText || taxaAfisataText;
  res.redirect('/admin');
});

/* =========================
   MEMBERS
   ========================= */

app.get('/members', isLoggedIn, (req, res) => {
  const roles = req.user.appRoles || [];
  const canAddMembers = roles.some(r => CAN_ADD_MEMBERS_ROLES.includes(r));
  const canAssignAnyRole = roles.some(r => FULL_ACCESS_ROLES.includes(r));

  if (!canAddMembers) {
    return res.status(403).render('unauthorized', { user: req.user });
  }

  const members = Object.entries(userRoles).map(([id, r]) => ({
    id,
    role: r[0]
  }));

  res.render('members', {
    user: req.user,
    ROLES,
    canAssignAnyRole,
    canAddMembers,
    members
  });
});

app.post('/members/add', isLoggedIn, (req, res) => {
  const roles = req.user.appRoles || [];
  const canAddMembers = roles.some(r => CAN_ADD_MEMBERS_ROLES.includes(r));

  if (!canAddMembers) {
    return res.status(403).render('unauthorized', { user: req.user });
  }

  const discordId = req.body.discordId;
  let role = req.body.role;

  if (!discordId) return res.redirect('/members');

  if (role === ROLES.DEV || !Object.values(ROLES).includes(role)) {
    role = ROLES.MEMBRU;
  }

  userRoles[discordId] = [role];
  if (!userJoinDates[discordId]) {
    userJoinDates[discordId] = new Date();
  }

  res.redirect('/members');
});

app.post('/admin/roles/update', hasAnyRole(FULL_ACCESS_ROLES), (req, res) => {
  const { discordId, role } = req.body;

  if (!discordId || !Object.values(ROLES).includes(role)) {
    return res.redirect('/members');
  }

  const finalRole = role === ROLES.DEV ? ROLES.MEMBRU : role;
  userRoles[discordId] = [finalRole];

  res.redirect('/members');
});

app.post('/members/remove', hasAnyRole(FULL_ACCESS_ROLES), (req, res) => {
  const discordId = req.body.discordId;

  if (discordId && userRoles[discordId]) {
    delete userRoles[discordId];
    delete userJoinDates[discordId];
  }

  res.redirect('/members');
});

/* =========================
   START SERVER
   ========================= */

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});