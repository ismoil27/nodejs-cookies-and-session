const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const db = require("./config/db");
const PORT = process.env.PORT || 3000;
const cookieParser = require("cookie-parser");
const session = require("express-session");
const cors = require("cors");
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);

app.use(cookieParser());
app.use(
  session({
    key: "userId",
    secret: "secretword",
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: 60 * 60 * 24,
    },
  })
);

app.post("/register", (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.log(err);
    }

    db.query(
      "insert into users (name, email, password) values (?, ?, ?)",
      [name, email, hash],
      (err, result) => {
        console.log(err);
      }
    );
  });
  res.send({ message: req.body });
});

app.post("/login", (req, res) => {
  // const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;

  db.query(
    "select * from users where email = ?;",

    email,
    (err, result) => {
      if (err) {
        res.send({ err: err });
      }
      if (result.length > 0) {
        bcrypt.compare(password, result[0].password, (err, response) => {
          if (response) {
            req.session.user = result;
            console.log(req.session.user);
            res.send(result);
          } else {
            res.send({ message: `Wrong credentials` });
          }
        });
      } else {
        res.send({ message: `User does not exist` });
      }
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});
