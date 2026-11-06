const path = require("node:path");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
require("dotenv").config();
const pool = require("./db");
const { body, validationResult } = require("express-validator");
const { rmSync } = require("node:fs");
const { asyncWrapProviders } = require("node:async_hooks");

const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));

app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username=$1",
        [username],
      );
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }),
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id =$1", [id]);
    const user = rows[0];
    return done(null, user);
  } catch (err) {
    return done(err);
  }
});

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

app.get("/", async (req, res, next) => {
  try {
    const { rows: messages } =
      await pool.query(`SELECT messages.id, messages.title, messages.text, messages.timestamp, messages.user_id, users.username AS author
      FROM messages
      JOIN users ON messages.user_id=users.id
      ORDER BY messages.timestamp DESC `);
    res.render("index", { messages });
  } catch (err) {
    return next(err);
  }
});
app.get("/sign-up", (req, res) => res.render("sign-up"));
app.get("/join-club", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/log-in");
  }
  res.render("join-club");
});
app.get("/log-in", (req, res) => res.render("log-in"));
app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
app.get("/create-message", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/log-in");
  } else {
    res.render("create-message");
  }
});
app.get("/profile", async (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/log-in");
  }
  try {
    const { rows: myMessages } = await pool.query(
      "SELECT * FROM messages WHERE user_id = $1 ORDER BY timestamp DESC",
      [req.user.id],
    );
    res.render("profile", { messages: myMessages });
  } catch (err) {
    return next(err);
  }
});

app.post(
  "/sign-up",
  [
    body("firstName", "First name is required").trim().notEmpty().escape(),
    body("lastName", "Last name is requires").trim().notEmpty().escape(),
    body("username", "Username is required").trim().notEmpty().escape(),
    body("password", "Password must be at least 6 characters long").isLength({
      min: 6,
    }),
    body("confirmPassword").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Password confirmation does not match password");
      }
      return true;
    }),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render("sign-up", { errors: errors.array() });
    }
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const isAdmin = req.body.admin === "on" ? true : false;
      await pool.query(
        "INSERT INTO users (first_name, last_name, username, password, membership_status,admin) VALUES ($1, $2, $3, $4, $5, $6)",
        [
          req.body.firstName,
          req.body.lastName,
          req.body.username,
          hashedPassword,
          false,
          isAdmin,
        ],
      );
      res.redirect("/log-in");
    } catch (err) {
      return next(err);
    }
  },
);

app.post("/join-club", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/log-in");
  }
  const SECRET_CODE = "theodinproject";

  if (req.body.passcode === SECRET_CODE) {
    try {
      const query = "UPDATE users SET membership_status = true WHERE id=$1";
      await pool.query(query, [req.user.id]);

      req.user.membership_status = true;

      res.redirect("/profile");
    } catch (err) {
      res.render("join-club", { error: "Error updating your status" });
    }
  } else {
    res.render("join-club", { error: "Passcode incorrect!" });
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/profile",
    failureRedirect: "/",
  }),
);

app.post("/create-message", async (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/log-in");
  }
  try {
    const { title, message } = req.body;
    const userId = req.user.id;

    await pool.query(
      "INSERT INTO messages (title, text, user_id) VALUES ($1, $2, $3)",
      [title, message, userId],
    );
    res.redirect("/profile");
  } catch (err) {
    return next(err);
  }
});

app.post("/delete-message/:id", async (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/log-in");
  }
  try {
    const messageId = req.params.id;
    const messageQuery = await pool.query(
      "SELECT * FROM messages WHERE id=$1",
      [messageId],
    );
    const message = messageQuery.rows[0];
    if (!message) {
      return res.redirect("/profile");
    }
    if (req.user.admin || message.user_id === req.user.id) {
      await pool.query("DELETE FROM messages WHERE id=$1", [messageId]);
      return res.redirect("/profile");
    } else {
      return res
        .status(403)
        .send("Unauthorized: You can only delete your own messages.");
    }
  } catch (err) {
    return next(err);
  }
});

app.post("/become-admin", async (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/log-in");
  }
  try {
    await pool.query("UPDATE users SET admin=true WHERE id =$1", [req.user.id]);
    req.user.admin = true;
    res.redirect("/profile");
  } catch (err) {
    return next(err);
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on PORT ${PORT}`);
});
