import express from 'express';
import { configDotenv } from 'dotenv';
import bcrypt from 'bcrypt';
import passport from 'passport';
import { initialize as initializePassport } from './passport-config.js';
import flash from 'express-flash';
import session from 'express-session';
import methodOverride from 'method-override';

const users = []; // Just for demo purposes, we are storing our user information in memory

/*
Remember, initialize function in passport-config is written by us. So we can change the function parameteras need be
These are not required parameters and can be adjusted to your authentication needs
*/

initializePassport(passport, users);

const envFile =
  process.env.NODE_ENV === 'production'
    ? '.env.production'
    : '.env.development';
configDotenv({ path: envFile });

const app = express();
const port = process.env.PORT || 3001;
app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false })); // Take information from forms and pass it to request methods
app.use(flash());
app.use(
  session({
    secret: process.env.SESSION_SECRET, // This is a randomly generated long string that is used for encryption
    resave: false, // Should we re-save the session if everything is still the same and nothing changed
    saveUninitialized: false, // Do you want to save an empty vaue in the session?
  })
);
app.use(passport.initialize()); // A function inside passport library that setups up some basics
app.use(passport.session()); // To persist the session across pages
app.use(methodOverride('_method')); // Specify what key/param to use for the method name. Check example in dashboard page

app.get('/', checkUserAuthenticated, (req, res) => {
  res.redirect('/login');
});

app.get('/dashboard', secureProtectedPage, (req, res) => {
  res.render('dashboard.ejs', { name: req.user.name });
});

app.get('/login', checkUserAuthenticated, (req, res) => {
  res.render('login.ejs');
});

// For login, use the passport's authenticate feature, with local strategy and pass a list of options we want to modify
app.post(
  '/login',
  checkUserAuthenticated,
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true, // Passport uses flash internally, that's why we needed to import flash. The messages we setup in passport configuration will show up here. In order to show the messages on the page, you need to setup the ejs files to check for messages.error
  })
);

app.get('/register', checkUserAuthenticated, (req, res) => {
  res.render('register.ejs');
});

app.post('/register', checkUserAuthenticated, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    // 10 is a number that denotes how many times we want to has our password for security. 10 is a good standard to ensure safety and speed.

    // Save the user, in memory for this demo
    users.push({
      id: Date.now().toString(), // database would have an internal id
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    });
    res.redirect('/login');
  } catch {
    res.redirect('/register');
  }
  console.log(users);
});

// A delete method is now allowed from HTML, so we need to use the method-override library
app.delete('/logout', (req, res) => {
  req.logout(function (err) {
    // Passports sets the logOut function. It removes the user session and logs them out
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
});

// Create a middleware function to prevent users from accessing internal pages when not logged in
function secureProtectedPage(req, res, next) {
  /*
  Passport provides a method on request object isAuthenticated to see if user is authenticated, 
  without writing this logic. You can add this middleware function to protected routes
  */
  if (req.isAuthenticated()) {
    return next(); // Everything is good, nothing to do. return next()
  }
  res.redirect('/login'); // Redirect to login if user is not authenticated
}

// Create a middleware function to check if the user is Not Authenticated
function checkUserAuthenticated(req, res, next) {
  /*
  Passport provides a method on request object isAuthenticated to see if user is authenticated, 
  without writing this logic. You can add this middleware function to not have users visit 
  the login, register page if they are already authenticated
  */
  if (req.isAuthenticated()) {
    return res.redirect('/dashboard'); // Redirect to dashboard if user is already authenticated
  }
  return next();
}

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
