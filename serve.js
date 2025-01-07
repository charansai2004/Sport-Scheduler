const express = require('express');
const bcrypt = require('bcrypt');
const csrf = require('csurf');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const flash = require('connect-flash');
const passport = require("passport");
const connectEnsureLogin = require("connect-ensure-login");
const session = require("express-session");
const { Sequelize, DataTypes } = require('sequelize');
const LocalStrategy = require("passport-local").Strategy;

const app = express();
const saltRounds = 10;

// SQLite database setup with Sequelize
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: './database.sqlite3', // SQLite database file
});

const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  firstName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  role: {
    type: DataTypes.STRING,
    allowNull: false,
  }
});

const Event = sequelize.define('Event', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  title: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  date: {
    type: DataTypes.DATE,
    allowNull: false,
  },
  time: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  venue: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  team_limit: {
    type: DataTypes.INTEGER,
    allowNull: false,
  },
  description: {
    type: DataTypes.STRING,
  },
  adminId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Users', // Reference to User model
      key: 'id',
    }
  }
});

const PlayerEvent = sequelize.define('PlayerEvent', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  playerId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Users', // Reference to User model
      key: 'id',
    }
  },
  eventId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Events', // Reference to Event model
      key: 'id',
    }
  }
});

sequelize.sync()
  .then(() => console.log('Database synced with SQLite!'))
  .catch((err) => console.error('Error syncing database: ', err));

// Middleware setup
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(csrf({ cookie: true }));
app.use(flash());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: 'my-secret-key-12345678',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());
app.use(passport.session());

// Passport configuration
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password',
}, async (username, password, done) => {
  try {
    const user = await User.findOne({ where: { email: username } });
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
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findByPk(id);
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

app.get("/", (req, res) => {
  res.render("index", {
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

    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPwd,
      role
    });

    res.render("login", { csrfToken: req.csrfToken() });
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

    const newEvent = await Event.create({
      title,
      date,
      time,
      venue,
      team_limit,
      description,
      adminId: req.user.id
    });

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
    const events = await Event.findAll({ where: { adminId: req.user.id } });
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
    const events = await Event.findAll();
    const joinedEvents = await PlayerEvent.findAll({ where: { playerId: req.user.id } });
    const joinedEventIds = joinedEvents.map(je => je.eventId);

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
    const event = await Event.findByPk(id);

    if (!event) {
      return res.status(404).send('Event not found');
    }

    await PlayerEvent.create({ playerId: req.user.id, eventId: id });

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
    const playerEvent = await PlayerEvent.findOne({ where: { playerId: req.user.id, eventId: id } });

    if (!playerEvent) {
      return res.status(404).send('Player is not joined to this event');
    }

    await playerEvent.destroy();

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
