const express = require('express');
const bcrypt = require('bcrypt');
const csrf = require('csurf');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const flash = require('connect-flash');
const passport = require('passport');
const connectEnsureLogin = require('connect-ensure-login');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const LocalStrategy = require('passport-local').Strategy;

const app = express();
const saltRounds = 10;

// SQLite database setup with sqlite3
(async () => {
  const db = await open({
    filename: './database.sqlite3',
    driver: sqlite3.Database,
  });

  // User table
  await db.run(`CREATE TABLE IF NOT EXISTS User (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstName TEXT NOT NULL,
    lastName TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
  )`);

  // Event table
  await db.run(`CREATE TABLE IF NOT EXISTS Event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    venue TEXT NOT NULL,
    team_limit INTEGER NOT NULL,
    description TEXT,
    adminId INTEGER NOT NULL,
    FOREIGN KEY(adminId) REFERENCES User(id)
  )`);

  // PlayerEvent table
  await db.run(`CREATE TABLE IF NOT EXISTS PlayerEvent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    playerId INTEGER NOT NULL,
    eventId INTEGER NOT NULL,
    FOREIGN KEY(playerId) REFERENCES User(id),
    FOREIGN KEY(eventId) REFERENCES Event(id)
  )`);

  console.log('Database setup with sqlite3 is complete!');

  // Middleware setup
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(csrf({ cookie: true }));
  app.use(flash());

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  app.use(
    session({
      secret: 'my-secret-key-12345678',
      resave: false,
      saveUninitialized: false,
      cookie: { maxAge: 24 * 60 * 60 * 1000 },
    })
  );

  app.use(passport.initialize());
  app.use(passport.session());

  // Passport configuration
  passport.use(
    new LocalStrategy(
      { usernameField: 'email', passwordField: 'password' },
      async (username, password, done) => {
        try {
          const user = await db.get('SELECT * FROM User WHERE email = ?', username);
          if (!user) {
            return done(null, false, { message: 'User not found' });
          }
          const isValidPassword = await bcrypt.compare(password, user.password);
          if (!isValidPassword) {
            return done(null, false, { message: 'Invalid password' });
          }
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await db.get('SELECT * FROM User WHERE id = ?', id);
      if (!user) {
        return done(null, false);
      }
      done(null, user);
    } catch (error) {
      done(error, false);
    }
  });

  app.use((req, res, next) => {
    res.locals.errorMessage = req.flash('error');
    next();
  });

  // Routes
  app.get('/signup', (req, res) => {
    res.render('signup', { csrfToken: req.csrfToken() });
  });

  app.get('/', (req, res) => {
    res.render('index', {
      csrfToken: req.csrfToken(),
    });
  });

  app.post('/create-player', async (req, res) => {
    try {
      const { firstName, lastName, email, password, role } = req.body;

      if (!firstName || !lastName || !email || !password || !role) {
        return res.status(400).json({ error: 'All fields are required.' });
      }

      const hashedPwd = await bcrypt.hash(password, saltRounds);

      await db.run(
        'INSERT INTO User (firstName, lastName, email, password, role) VALUES (?, ?, ?, ?, ?)',
        [firstName, lastName, email, hashedPwd, role]
      );

      res.render('login', { csrfToken: req.csrfToken() });
    } catch (error) {
      console.error('Error creating user:', error.message);
      res.status(500).json({ error: 'User may already exist or Internal server error' });
    }
  });

  app.get('/signin', (req, res) => {
    res.render('login', { csrfToken: req.csrfToken() });
  });

  app.post('/signinsubmit', passport.authenticate('local', {
    failureRedirect: '/signin',
    failureFlash: true,
  }), (req, res) => {
    if (req.user.role === 'admin') {
      res.redirect('/admindashboard');
    } else if (req.user.role === 'player') {
      res.redirect('/playerdashboard');
    } else {
      res.status(403).send('Unauthorized');
    }
  });

  // Route to render create event form
  app.get('/create-event', connectEnsureLogin.ensureLoggedIn(), (req, res) => {
    if (req.user.role !== 'admin') {
      return res.status(403).send('Unauthorized');
    }
    res.render('create-event', { csrfToken: req.csrfToken() });
  });

  // Route to handle event creation
  app.post('/create-event', connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
    if (req.user.role !== 'admin') {
      return res.status(403).send('Unauthorized');
    }

    try {
      const { title, date, time, venue, team_limit, description } = req.body;

      await db.run(
        'INSERT INTO Event (title, date, time, venue, team_limit, description, adminId) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [title, date, time, venue, team_limit, description, req.user.id]
      );

      res.redirect('/admindashboard');
    } catch (error) {
      console.error('Error creating event:', error.message);
      res.status(500).send('Internal server error');
    }
  });

  // Route to render admin dashboard with events
  app.get('/admindashboard', connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
    if (req.user.role !== 'admin') {
      return res.status(403).send('Unauthorized');
    }

    try {
      const events = await db.all('SELECT * FROM Event WHERE adminId = ?', req.user.id);
      res.render('admindashboard', { User: req.user, events, csrfToken: req.csrfToken() });
    } catch (error) {
      console.error('Error fetching events:', error.message);
      res.status(500).send('Internal server error');
    }
  });

  // Route to render player dashboard with all events and join/unjoin functionality
  app.get('/playerdashboard', connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
    if (req.user.role !== 'player') {
      return res.status(403).send('Unauthorized');
    }

    try {
      const events = await db.all('SELECT * FROM Event');
      const joinedEvents = await db.all('SELECT eventId FROM PlayerEvent WHERE playerId = ?', req.user.id);
      const joinedEventIds = joinedEvents.map((je) => je.eventId);

      res.render('playerdashboard', { User: req.user, events, joinedEventIds, csrfToken: req.csrfToken() });
    } catch (error) {
      console.error('Error fetching events:', error.message);
      res.status(500).send('Internal server error');
    }
  });

  // Route to handle joining an event
  app.post('/join-event/:id', connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
    if (req.user.role !== 'player') {
      return res.status(403).send('Unauthorized');
    }

    try {
      const { id } = req.params;
      const event = await db.get('SELECT * FROM Event WHERE id = ?', id);

      if (!event) {
        return res.status(404).send('Event not found');
      }

      await db.run('INSERT INTO PlayerEvent (playerId, eventId) VALUES (?, ?)', [req.user.id, id]);

      res.redirect('/playerdashboard');
    } catch (error) {
      console.error('Error joining event:', error.message);
      res.status(500).send('Internal server error');
    }
  });

  // Route to handle unjoining an event
  app.post('/unjoin-event/:id', connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
    if (req.user.role !== 'player') {
      return res.status(403).send('Unauthorized');
    }

    try {
      const { id } = req.params;
      const playerEvent = await db.get('SELECT * FROM PlayerEvent WHERE playerId = ? AND eventId = ?', [req.user.id, id]);

      if (!playerEvent) {
        return res.status(404).send('Player is not joined to this event');
      }

      await db.run('DELETE FROM PlayerEvent WHERE id = ?', playerEvent.id);

      res.redirect('/playerdashboard');
    } catch (error) {
      console.error('Error unjoining event:', error.message);
      res.status(500).send('Internal server error');
    }
  });

  // Route to logout
  app.get('/logout', (req, res) => {
    req.logout((err) => {
      if (err) {
        console.error('Error logging out:', err);
        return res.status(500).send('Internal server error');
      }
      res.redirect('/');
    });
  });

  app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
  });
})();
