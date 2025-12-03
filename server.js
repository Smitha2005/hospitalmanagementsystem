const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require("./db");

const app = express();
const PORT = 4000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

// Session Configuration
app.use(session({
  secret: 'a-very-strong-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// Middleware to protect routes
const requireLogin = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
};

const requireRole = (role) => {
  return (req, res, next) => {
    if (!req.session || !req.session.user || req.session.user.role !== role) {
      return res.status(403).send('Forbidden: You do not have access to this page.');
    }
    next();
  };
};

// Helper to promisify db.all
const dbAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

// Home
app.get("/", (req, res) => {
  res.render("index", { user: req.session.user });
});

// Dashboard route
app.get("/dashboard", requireLogin, (req, res) => {
  const role = req.session.user && req.session.user.role;
  if (!role) return res.redirect('/login');
  return res.redirect(`/${role}`);
});

// Login page
app.get("/login", (req, res) => {
  res.render("login", { error: null, user: req.session.user || null });
});

// Login submission
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error("DB error during login:", err);
      return res.status(500).render('login', { error: 'Internal server error.', user: req.session.user || null });
    }
    if (!user) return res.status(401).render('login', { error: 'Invalid username or password.', user: req.session.user || null });

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error("Bcrypt error:", err);
        return res.status(500).render('login', { error: 'Internal server error.', user: req.session.user || null });
      }
      if (!isMatch) return res.status(401).render('login', { error: 'Invalid username or password.', user: req.session.user || null });

      req.session.user = { id: user.id, username: user.username, role: user.role };
      return res.redirect('/dashboard');
    });
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/');
    }
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// Signup page
app.get("/signup", (req, res) => {
  res.render("signup", { error: null, user: req.session.user || null });
});

// Replace or add this POST /signup handler (server-side validation)
app.post("/signup", (req, res) => {
  const { username, password, confirm_password, role } = req.body || {};

  if (!username || !username.trim()) {
    return res.status(400).render("signup", { error: "Name is required,special characters are not allowed.", user: req.session.user || null });
  }
  if (!password) {
    return res.status(400).render("signup", { error: "Password is required.", user: req.session.user || null });
  }
  if (!confirm_password) {
    return res.status(400).render("signup", { error: "Please confirm your password.", user: req.session.user || null });
  }
  if (!role) {
    return res.status(400).render("signup", { error: "Role is required.", user: req.session.user || null });
  }

  const name = username.trim();

  // Name: only letters, length 3-15
  const nameRe = /^[A-Za-z]{3,15}$/;
  if (!nameRe.test(name)) {
    return res.status(400).render("signup", { error: "Name must be 3–15 alphabetic characters (no special chars allowed).", user: req.session.user || null });
  }

  // Password validation
  const pwdRe = /^(?=.{8,32}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&*()_\-+=[\]{};':"\\|,.<>\/?]).*$/;
  if (!pwdRe.test(password)) {
    return res.status(400).render("signup", { error: "Password must be 8–32 chars and include upper, lower, number and special character.", user: req.session.user || null });
  }

  if (password !== confirm_password) {
    return res.status(400).render("signup", { error: "Passwords do not match.", user: req.session.user || null });
  }

  db.get("SELECT id FROM users WHERE username = ?", [name], (err, row) => {
    if (err) {
      console.error("DB error (signup):", err);
      return res.status(500).render("signup", { error: "Server error.", user: req.session.user || null });
    }
    if (row) {
      return res.status(409).render("signup", { error: "Username taken.", user: req.session.user || null });
    }

    bcrypt.hash(password, 10, (hashErr, hash) => {
      if (hashErr) {
        console.error("Bcrypt error (signup):", hashErr);
        return res.status(500).render("signup", { error: "Server error.", user: req.session.user || null });
      }
      db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [name, hash, role], function(insertErr) {
        if (insertErr) {
          console.error("DB insert error (signup):", insertErr);
          return res.status(500).render("signup", { error: "Server error.", user: req.session.user || null });
        }
        return res.redirect("/login");
      });
    });
  });
});

// Show account page
app.get("/account", requireLogin, (req, res) => {
  res.render("account", { user: req.session.user, error: null });
});

// Delete account
app.post("/account/delete", requireLogin, (req, res) => {
  const pw = (req.body.password || '').trim();
  const user = req.session.user;

  if (!pw) return res.status(400).render("account", { user, error: "Password is required to confirm deletion." });

  db.get("SELECT * FROM users WHERE id = ?", [user.id], (err, row) => {
    if (err) {
      console.error("DB error (account delete):", err);
      return res.status(500).render("account", { user, error: "Server error." });
    }
    if (!row) return res.status(404).render("account", { user, error: "User not found." });

    bcrypt.compare(pw, row.password, (bcryptErr, match) => {
      if (bcryptErr) {
        console.error("Bcrypt error:", bcryptErr);
        return res.status(500).render("account", { user, error: "Server error." });
      }
      if (!match) return res.status(401).render("account", { user, error: "Incorrect password." });

      db.serialize(() => {
        db.run("DELETE FROM appointments WHERE patient = ? OR doctor = ?", [row.username, row.username]);
        db.run("DELETE FROM medical_history WHERE patient = ? OR doctor = ?", [row.username, row.username]);
        db.run("DELETE FROM users WHERE id = ?", [user.id], (deleteErr) => {
          if (deleteErr) {
            console.error("Error deleting user:", deleteErr);
            return res.status(500).render("account", { user, error: "Error deleting account." });
          }
          req.session.destroy();
          res.redirect("/login");
        });
      });
    });
  });
});

// -------- PATIENT PORTAL --------

app.get("/patient", requireLogin, requireRole('patient'), async (req, res) => {
  try {
    const appointments = await dbAll("SELECT * FROM appointments WHERE patient = ?", [req.session.user.username]);
    const medicalHistory = await dbAll("SELECT * FROM medical_history WHERE patient = ? ORDER BY date DESC", [req.session.user.username]);
    
    const doctors = await dbAll("SELECT id, username as name FROM users WHERE role = 'doctor'");
    
    const departments = [
      { id: 1, name: 'Cardiology' },
      { id: 2, name: 'Neurology' },
      { id: 3, name: 'Orthopedics' },
      { id: 4, name: 'Pediatrics' },
      { id: 5, name: 'General Practice' }
    ];

    const doctorsByDepartment = {};
    departments.forEach((dept, idx) => {
      const docsPerDept = Math.ceil(doctors.length / departments.length);
      const startIdx = idx * docsPerDept;
      const endIdx = Math.min(startIdx + docsPerDept, doctors.length);
      doctorsByDepartment[dept.id] = doctors.slice(startIdx, endIdx);
    });

    res.render("patient", { 
      appointments, 
      medicalHistory, 
      departments,
      doctorsByDepartment,
      user: req.session.user 
    });
  } catch (err) {
    console.error("DB error (patient):", err);
    res.status(500).send("Error loading patient data");
  }
});

// Patient appointment
app.post("/appointments", requireLogin, requireRole('patient'), (req, res) => {
  const { date, doctor } = req.body;
  const patient = req.session.user.username;

  db.run(
    "INSERT INTO appointments (patient, doctor, date, status) VALUES (?, ?, ?, 'pending')",
    [patient, doctor || null, date],
    function (err) {
      if (err) {
        console.error("Error creating appointment:", err);
        return res.status(500).send("Error creating appointment");
      }
      return res.redirect("/patient");
    }
  );
});

// -------- DOCTOR PORTAL --------

app.get("/doctor", requireLogin, requireRole('doctor'), async (req, res) => {
  try {
    const currentDoctor = (req.session.user.username || '').trim();

    const appointments = await dbAll(
      "SELECT * FROM appointments WHERE doctor = ? AND deleted_by_doctor = 0",
      [currentDoctor]
    );

    const staff = await dbAll("SELECT * FROM staff", []);

    const enriched = await Promise.all(appointments.map(async (a) => {
      const history = await dbAll(
        `SELECT * FROM medical_history 
         WHERE patient = ? 
           AND (LOWER(COALESCE(doctor,'')) = LOWER(COALESCE(?,'')) OR doctor IS NULL OR doctor = '') 
         ORDER BY date DESC`,
        [a.patient, currentDoctor]
      );
      return { ...a, history };
    }));

    res.render("doctor", { appointments: enriched, staff, user: req.session.user }, (renderErr, html) => {
      if (renderErr) {
        console.error("EJS render error (doctor):", renderErr);
        return res.status(500).send("Template render error - check server logs.");
      }
      res.type('html').send(html);
    });
  } catch (err) {
    console.error("DB error (doctor):", err);
    res.status(500).send("Error loading doctor data");
  }
});

// Doctor adds appointment
app.post("/doctor/appointments", requireLogin, requireRole('doctor'), (req, res) => {
  const { patient, date } = req.body;
  const doctor = req.session.user.username;
  const medical = (req.body.medical_history || '').trim();

  db.run(
    "INSERT INTO appointments (patient, doctor, date, status) VALUES (?, ?, ?, 'accepted')",
    [patient, doctor, date],
    function (err) {
      if (err) {
        console.error("Error adding appointment (doctor):", err);
        return res.status(500).send("Error adding appointment");
      }

      if (medical) {
        const entryDate = new Date().toISOString();
        db.run(
          "INSERT INTO medical_history (patient, doctor, notes, date) VALUES (?, ?, ?, ?)",
          [patient, doctor, medical, entryDate],
          (mhErr) => {
            if (mhErr) console.error("Error inserting medical history (doctor):", mhErr);
            return res.redirect("/doctor");
          }
        );
      } else {
        return res.redirect("/doctor");
      }
    }
  );
});

// Doctor accepts appointment
app.post("/appointments/:id/accept", requireLogin, requireRole('doctor'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  db.run("UPDATE appointments SET status = 'accepted' WHERE id = ?", [id], function(err) {
    if (err) {
      console.error("Error accepting appointment:", err);
      return res.status(500).send("Error updating appointment");
    }
    res.redirect('/doctor');
  });
});

// Doctor rejects appointment
app.post("/appointments/:id/reject", requireLogin, requireRole('doctor'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  db.run("UPDATE appointments SET status = 'rejected' WHERE id = ?", [id], function(err) {
    if (err) {
      console.error("Error rejecting appointment:", err);
      return res.status(500).send("Error updating appointment");
    }
    res.redirect('/doctor');
  });
});

// Doctor: create medical history entry
app.post("/medical/add", requireLogin, requireRole('doctor'), (req, res) => {
  const { patient, notes, date } = req.body;
  const doctor = req.session.user && req.session.user.username;
  if (!patient || !notes || !notes.trim()) {
    return res.status(400).send("Patient and notes are required");
  }
  const entryDate = (date && date.trim()) ? date : new Date().toISOString();
  db.run(
    "INSERT INTO medical_history (patient, doctor, notes, date) VALUES (?, ?, ?, ?)",
    [patient.trim(), doctor, notes.trim(), entryDate],
    function (err) {
      if (err) {
        console.error("Error inserting medical history (doctor):", err);
        return res.status(500).send("Error creating medical history");
      }
      return res.redirect("/doctor");
    }
  );
});

// Doctor: add staff (doctor-only)
app.post("/doctor/staff/add", requireLogin, requireRole('doctor'), (req, res) => {
  const { name, role, shift } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).send("Staff name is required");
  }
  const cleanName = name.trim();
  const cleanRole = (role || '').trim() || null;
  const cleanShift = (shift || '').trim() || null;

  db.run(
    "INSERT INTO staff (name, role, shift) VALUES (?, ?, ?)",
    [cleanName, cleanRole, cleanShift],
    function (err) {
      if (err) {
        console.error("Error adding staff (doctor):", err);
        return res.status(500).send("Error adding staff record");
      }
      return res.redirect("/doctor");
    }
  );
});

// -------- STAFF PORTAL --------

app.get("/staff", requireLogin, requireRole('staff'), async (req, res) => {
  const rawQuery = (req.query.q || '').trim();
  const like = rawQuery ? `%${rawQuery}%` : '%';

  try {
    const [staff, appointments, billing] = await Promise.all([
      dbAll("SELECT * FROM staff WHERE name LIKE ? OR role LIKE ? OR shift LIKE ?", [like, like, like]),
      dbAll("SELECT * FROM appointments WHERE deleted_by_doctor = 0", []), // Hide soft-deleted
      dbAll("SELECT * FROM billing", [])
    ]);

    res.render("staff", { staff, appointments, billing, user: req.session.user, query: rawQuery }, (renderErr, html) => {
      if (renderErr) {
        console.error("EJS render error (staff):", renderErr);
        return res.status(500).send("Template render error - check server logs.");
      }
      res.type('html').send(html);
    });
  } catch (err) {
    console.error("DB error (staff):", err);
    res.status(500).send("Error fetching staff data.");
  }
});

// Staff creates appointment
app.post("/staff/appointment", requireLogin, requireRole('staff'), (req, res) => {
  const { patient, date } = req.body;
  const rawDoctor = (req.body.doctor || '').trim();
  const doctor = rawDoctor === '' ? null : rawDoctor;

  db.run(
    "INSERT INTO appointments (patient, doctor, date, status) VALUES (?, ?, ?, 'pending')",
    [patient, doctor, date],
    function (err) {
      if (err) {
        console.error("Error creating appointment (staff):", err);
        return res.status(500).send("Error creating appointment");
      }
      return res.redirect("/staff");
    }
  );
});

// Staff creates billing
app.post("/staff/billing", requireLogin, requireRole('staff'), async (req, res) => {
  try {
    const { patient, amount, description, date } = req.body;

    if (!patient || !amount) {
      return res.status(400).send("Patient name and amount are required");
    }

    const sql = "INSERT INTO billing (patient, amount, description, date, created_at) VALUES (?, ?, ?, ?, datetime('now'))";
    
    db.run(sql, [patient, amount, description || null, date || null], function(err) {
      if (err) {
        console.error("DB error (billing):", err);
        return res.status(500).send("Error creating bill");
      }
      res.redirect("/staff");
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Error creating bill");
  }
});

// Delete billing record
app.post("/staff/billing/:id/delete", requireLogin, requireRole('staff'), (req, res) => {
  const id = req.params.id;
  db.run("DELETE FROM billing WHERE id = ?", [id], function (err) {
    if (err) {
      console.error("Error deleting billing:", err);
      return res.status(500).send("Error deleting billing");
    }
    res.redirect("/staff");
  });
});

// Delete staff record
app.post('/staff/:id/delete', requireLogin, requireRole('staff'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) return res.status(400).send('Invalid staff id');
  db.run('DELETE FROM staff WHERE id = ?', [id], function(err) {
    if (err) {
      console.error('Error deleting staff:', err);
      return res.status(500).send('Error deleting staff');
    }
    res.redirect('/staff');
  });
});

// Delete appointment (DOCTOR or OWNING PATIENT)
// Doctor delete: soft-delete (hidden from doctor/staff, visible to patient)
// Patient delete: hard-delete (removed completely)
app.post("/appointments/:id/delete", requireLogin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) return res.status(400).send("Invalid appointment id");

  const user = req.session.user;
  db.get("SELECT * FROM appointments WHERE id = ?", [id], (err, row) => {
    if (err) {
      console.error("DB error fetching appointment for delete:", err);
      return res.status(500).send("Internal error");
    }
    if (!row) return res.status(404).send("Appointment not found");

    const userRole = (user.role || '').toString().toLowerCase();
    const userName = (user.username || '').toString().trim().toLowerCase();
    const apptDoctor = (row.doctor || '').toString().trim().toLowerCase();

    const isAssignedDoctor = userRole === 'doctor' && apptDoctor === userName;
    const isOwnerPatient = userRole === 'patient' && row.patient === user.username;

    if (!isAssignedDoctor && !isOwnerPatient) {
      return res.status(403).send("Forbidden: only the assigned doctor or patient can delete this appointment");
    }

    // Doctor: soft-delete (mark as deleted_by_doctor)
    if (isAssignedDoctor) {
      db.run("UPDATE appointments SET deleted_by_doctor = 1 WHERE id = ?", [id], function(updateErr) {
        if (updateErr) {
          console.error("Error soft-deleting appointment:", updateErr);
          return res.status(500).send("Error deleting appointment");
        }
        return res.redirect('/doctor');
      });
    }
    // Patient: hard-delete (remove completely)
    else if (isOwnerPatient) {
      db.run("DELETE FROM appointments WHERE id = ?", [id], function(deleteErr) {
        if (deleteErr) {
          console.error("Error deleting appointment:", deleteErr);
          return res.status(500).send("Error deleting appointment");
        }
        return res.redirect('/patient');
      });
    }
  });
});

// Show notes for an appointment (DOCTOR ONLY)
app.get("/appointments/:id/notes", requireLogin, requireRole('doctor'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) return res.status(400).send("Invalid appointment id");

  db.get("SELECT * FROM appointments WHERE id = ?", [id], async (err, appt) => {
    if (err) {
      console.error("DB error fetching appointment:", err);
      return res.status(500).send("Server error");
    }
    if (!appt) return res.status(404).send("Appointment not found");

    try {
      // Fetch initial medical history from appointment request
      const medicalHistory = await dbAll(
        `SELECT * FROM medical_history WHERE patient = ? ORDER BY date DESC`,
        [appt.patient]
      );

      // Fetch notes added by doctor
      const doctorNotes = await dbAll(
        `SELECT * FROM notes WHERE appointment_id = ? ORDER BY date DESC`,
        [id]
      );

      res.render("appointment-notes", { 
        appointment: appt, 
        medicalHistory, 
        doctorNotes,
        user: req.session.user 
      }, (renderErr, html) => {
        if (renderErr) {
          console.error("EJS render error (appointment-notes):", renderErr);
          return res.status(500).send("Template render error");
        }
        res.type('html').send(html);
      });
    } catch (e) {
      console.error("DB error (notes):", e);
      res.status(500).send("Server error");
    }
  });
});

// Add notes to an appointment (DOCTOR ONLY)
app.post("/appointments/:id/notes", requireLogin, requireRole('doctor'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) return res.status(400).send("Invalid appointment id");

  const { notes } = req.body;
  if (!notes || !notes.trim()) {
    return res.status(400).send("Notes cannot be empty");
  }

  const user = req.session.user;

  db.get("SELECT * FROM appointments WHERE id = ?", [id], (err, appt) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).send("Server error");
    }
    if (!appt) return res.status(404).send("Appointment not found");

    const entryDate = new Date().toISOString();

    db.run(
      "INSERT INTO notes (appointment_id, doctor, notes, date) VALUES (?, ?, ?, ?)",
      [id, user.username, notes.trim(), entryDate],
      (insertErr) => {
        if (insertErr) {
          console.error("Error inserting notes:", insertErr);
          return res.status(500).send("Error saving notes");
        }
        return res.redirect(`/appointments/${id}/notes`);
      }
    );
  });
});

// Delete a medical history note (DOCTOR ONLY)
app.post("/medical/:id/delete", requireLogin, requireRole('doctor'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) return res.status(400).send("Invalid note id");

  db.get("SELECT * FROM medical_history WHERE id = ?", [id], (err, row) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).send("Server error");
    }
    if (!row) return res.status(404).send("Note not found");

    // verify doctor ownership
    if (row.doctor !== req.session.user.username) {
      return res.status(403).send("Forbidden: can only delete your own notes");
    }

    db.run("DELETE FROM medical_history WHERE id = ?", [id], function(delErr) {
      if (delErr) {
        console.error("Error deleting note:", delErr);
        return res.status(500).send("Error deleting note");
      }
      // redirect back to doctor portal (or use referer header if available)
      const referer = req.get('referer') || '/doctor';
      res.redirect(referer);
    });
  });
});

// Delete a doctor note (DOCTOR ONLY)
app.post("/notes/:id/delete", requireLogin, requireRole('doctor'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) return res.status(400).send("Invalid note id");

  db.get("SELECT * FROM notes WHERE id = ?", [id], (err, row) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).send("Server error");
    }
    if (!row) return res.status(404).send("Note not found");

    // verify doctor ownership
    if (row.doctor !== req.session.user.username) {
      return res.status(403).send("Forbidden: can only delete your own notes");
    }

    db.run("DELETE FROM notes WHERE id = ?", [id], function(delErr) {
      if (delErr) {
        console.error("Error deleting note:", delErr);
        return res.status(500).send("Error deleting note");
      }
      const appointmentId = row.appointment_id;
      res.redirect(`/appointments/${appointmentId}/notes`);
    });
  });
});

// -------- SERVER START --------

db.run(`
  CREATE TABLE IF NOT EXISTS billing (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient TEXT NOT NULL,
    amount REAL NOT NULL,
    description TEXT,
    date TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`, (err) => {
  if (err) {
    console.error("Error creating billing table:", err);
  } else {
    console.log("Billing table created or already exists");
  }
});

db.run(`
  ALTER TABLE appointments ADD COLUMN deleted_by_doctor INTEGER DEFAULT 0
`, (err) => {
  // ignore if column already exists
  if (err && !err.message.includes('duplicate column')) {
    console.error("Error adding deleted_by_doctor column:", err);
  }
});

db.run(`
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    appointment_id INTEGER NOT NULL,
    doctor TEXT NOT NULL,
    notes TEXT,
    date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (appointment_id) REFERENCES appointments(id)
  )
`, (err) => {
  if (err && !err.message.includes('already exists')) {
    console.error("Error creating notes table:", err);
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
