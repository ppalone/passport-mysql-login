if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config()
}

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')
const mysql = require("mysql")

const DB_HOST = "localhost"
const DB_USER = "development"
const DB_PASSWORD = "Password@123"
const DB_DATABASE = "passport"
const DB_PORT = 3306

const db = mysql.createPool({
  connectionLimit: 100,
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_DATABASE,
  port: DB_PORT
})

const initializePassport = require('./passport-config')
initializePassport(
  passport,
  email => {
    return new Promise((resolve, reject) => {
      db.getConnection((err, connection) => {
        if (err) return reject(err)
        const q = "SELECT * FROM users WHERE email = ?"
        const query = mysql.format(q, [email])
        return connection.query(query, (err, results) => {
          connection.release()
          if (err) return reject(err)
          console.log(results[0])
          return resolve(results[0])
        })
      })
    })
  },
  id => {
    return new Promise((resolve, reject) => {
      db.getConnection((err, connection) => {
        if (err) return reject(err)
        const q = "SELECT * FROM users WHERE id = ?"
        const query = mysql.format(q, [id])
        return connection.query(query, (err, results) => {
          connection.release()
          if (err) return reject(err)
          console.log(results[0])
          return resolve(results[0])
        })
      })
    })
  }
)

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))

app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs', { name: req.user.name })
})

app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs')
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}))

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs')
})

app.post('/register', checkNotAuthenticated, async (req, res) => {
  try {
    const id = Date.now().toString()
    const email = req.body.email
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    const name = req.body.name

    db.getConnection((err, connection) => {
      if (err) throw (err)

      // Find if user with provided email already exists
      const e = "SELECT * FROM users WHERE email = ?"
      const search = mysql.format(e, [email])

      connection.query(search, (err, results) => {
        if (err) throw err
        if (results.length > 0) {
          connection.release()
          throw "User with email already exists"
        } else {
          // Insert into users table
          const i = "INSERT INTO users VALUES (?, ?, ?, ?)"
          const insert = mysql.format(i, [id, email, hashedPassword, name])
          connection.query(insert, (err, result) => {
            connection.release()
            if (err) throw err
            console.log("Create a new user: ", result.insertId)
            res.redirect("/login")
          })
        }
      })
    })

  } catch (err) {
    console.log(err)
    res.redirect('/register')
  }
})

app.delete('/logout', (req, res) => {
  req.logOut()
  res.redirect('/login')
})

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next()
  }

  res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/')
  }
  next()
}

app.listen(3000)