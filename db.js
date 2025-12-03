// db.js
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database("./hospital.db", (err) => {
  if (err) {
    return console.error("Error opening database", err.message);
  }
  console.log("Connected to the hospital database.");
});

const saltRounds = 10;

// Create tables and seed data
db.serialize(() => {
  // Users table (for login)
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT
    )
  `, (err) => {
    if (err) return console.error("Error creating users table", err.message);
  });

  // Appointments table
  db.run(`
    CREATE TABLE IF NOT EXISTS appointments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      patient TEXT,
      doctor TEXT,
      date TEXT,
      status TEXT DEFAULT 'pending'
    )
  `, (err) => {
    if (err) return console.error("Error creating appointments table", err.message);
  });

  // Billing table
  db.run(`
    CREATE TABLE IF NOT EXISTS billing (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      patient TEXT,
      amount REAL
    )
  `, (err) => {
    if (err) return console.error("Error creating billing table", err.message);
  });

  // Staff table
  db.run(`
    CREATE TABLE IF NOT EXISTS staff (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      role TEXT,
      shift TEXT
    )
  `, (err) => {
    if (err) return console.error("Error creating staff table", err.message);
  });

  // Medical history table
  db.run(`
    CREATE TABLE IF NOT EXISTS medical_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      patient TEXT,
      doctor TEXT,
      notes TEXT,
      date TEXT
    )
  `, (err) => {
    if (err) return console.error("Error creating medical history table", err.message);
  });


  // Insert default users with hashed passwords if they don't exist
  const usersToSeed = [
    { username: 'patient1', password: '123', role: 'patient' },
    { username: 'doctor1', password: '123', role: 'doctor' },
    { username: 'staff1', password: '123', role: 'staff' }
  ];

  usersToSeed.forEach(user => {
    db.get('SELECT * FROM users WHERE username = ?', [user.username], (err, row) => {
      if (err) return console.error("Error checking for user:", err.message);
      if (!row) {
        bcrypt.hash(user.password, saltRounds, (err, hash) => {
          if (err) return console.error("Error hashing password:", err.message);
          db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [user.username, hash, user.role], (err) => {
            if (err) return console.error("Error inserting user:", err.message);
            console.log(`User ${user.username} created.`);
          });
        });
      }
    });
  });
});

module.exports = db;
