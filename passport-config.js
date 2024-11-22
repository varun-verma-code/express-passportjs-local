import { Strategy as LocalStrategy } from 'passport-local';
import bcrypt from 'bcrypt';

// Passport configuration
// You are taking the users from app.js, but if this was centralized in DB, you could fetch it here itself without app having to pass it during initialization
const initialize = (passport, users) => {
  passport.use(
    new LocalStrategy(
      { usernameField: 'email', passwordField: 'password' }, // By default, express is looking for a username or password field. If we used a different field name in HTML, we can specify the field names here.
      async (enteredEmail, enteredPassword, done) => {
        // The name of the variables were specifically chosen to denote that they aren't fixed to the field mappings provided above
        const user = users.find((user) => user.email === enteredEmail);

        // If entered user does not match any in the system, return false
        if (user === undefined || user == null) {
          return done(null, false, { message: 'No user with that email' });
          /*
          done(err, user, message)
          ========================
          The first parameter for done is an error, if any on the server. There is none in our case.
          Not finding a user is not an error, it's a valid use case.

          The second parameter is the user that we found. In our case, we didn't find any so we return false

          The third parameter is a message that we can send back
          */
        }

        // console.log(enteredEmail, user.email);
        // console.log(enteredPassword, user.password);
        // console.log(enteredEmail === user.email);
        // console.log(await bcrypt.compare(enteredPassword, users[0].password));

        const passwordMatch = await bcrypt.compare(
          enteredPassword,
          user.password
        );
        // console.log(passwordMatch);
        // We have already compared for username match. Return true if passwords also match along with the user. No message in case of success
        if (passwordMatch) {
          return done(null, user);
        } else {
          // Return false since no user was found along with message
          return done(null, false, { message: 'Incorrect password' });
        }
      }
    )
  );

  passport.serializeUser((user, done) => done(null, user.id)); // Seralizes the user and saves in the session
  passport.deserializeUser((id, done) => {
    // Deserialize user objects out of the session. Since we only saved the userId in the session, this will retrieve the user Id, get the user based on id and call done(null, user)
    const user = users.find((u) => u.id === id);
    done(null, user);
  });
};

export { initialize };
