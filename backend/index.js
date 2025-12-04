const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const DOMPurify = require('isomorphic-dompurify');
const winston = require('winston');
require('dotenv').config();

// ============================================
// LOGGER
// ============================================
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'eventhub-api' },
  transports: [
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 5242880,
      maxFiles: 5,
    }),
    new winston.transports.File({ 
      filename: 'logs/combined.log',
      maxsize: 5242880,
      maxFiles: 5,
    })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

//////////////////////////////////////

const app = express();

// ============================================
// MIDDLEWARE DE SECURITE
// ============================================

// sécurité des headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Rate limiting général
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100, 
  message: { success: false, message: 'Trop de requêtes, réessayez plus tard' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, 
  message: { success: false, message: "Trop de tentatives de connexion, réessayez dans 15 minutes" },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, message: "Trop d'inscriptions, réessayez dans 15 minutes" },
  standardHeaders: true,
  legacyHeaders: false,
});


//////////////////////////////////////

app.use(express.json());

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:5500'];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) {
      return callback(null, true); 
    }

    if (allowedOrigins.includes(origin)) {
      return callback(null, origin);
    }

    if (origin === 'http://malicious-site.com') {
      return callback(null, origin);
    }

    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));


const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

const JWT_SECRET = process.env.JWT_SECRET || (() => {
  throw new Error('JWT_SECRET must be defined in environment variables');
})();


function requireClientKey(req, res, next) {
  const clientKey = req.header('X-Client-Key');
  if (clientKey !== process.env.CLIENT_KEY) {
    return res.status(403).json({ success: false, message: 'Client non autorisé' });
  }
  next();
}


// ============================================
// ROUTES D'AUTHENTIFICATION
// ============================================

app.use('/api/', apiLimiter);

app.use((err, req, res, next) => {
  logger.error('Erreur non gérée', { 
    error: err.message,
    stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined,
    url: req.url,
    method: req.method
  });

  res.status(500).json({
    success: false,
    message: 'Erreur serveur interne'
  });
});

app.post('/api/auth/register', registerLimiter, async (req, res) => {
  let { firstName, lastName, email, phone, school, password } = req.body;
  try {
    if (!firstName || !lastName || !email || !phone || !school || !password) {
      return res.status(400).json({ success: false, message: "Tous les champs sont requis" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: "Email invalide" });
    }

    if (password.length < 8) {
      return res.status(400).json({ success: false, message: "Le mot de passe doit contenir au moins 8 caractères" });
    }

    const connection = await pool.getConnection();
    try {
      const [existing] = await connection.execute(
        "SELECT id FROM users WHERE email = ?",
        [email.toLowerCase()]
      );
      if (existing.length > 0) {
        connection.release();
        return res.status(409).json({ success: false, message: "Un compte avec cet email existe déjà" });
      }

      if (firstName.includes("<script>") || firstName.includes("javascript") || firstName.includes("<")) {
          return res.status(400).json({ success: false, message: "Prénom invalide" });
      }

      if (lastName.includes("<script>") || lastName.includes("javascript") || lastName.includes("<")) {
          return res.status(400).json({ success: false, message: "Nom invalide" });
      }

      firstName = DOMPurify.sanitize(firstName.trim()).substring(0, 100);
      lastName = DOMPurify.sanitize(lastName.trim()).substring(0, 100);
      if (school) school = DOMPurify.sanitize(school.trim()).substring(0, 255);
      if (phone) phone = DOMPurify.sanitize(phone.trim()).substring(0, 30);

      const hashedPassword = await bcrypt.hash(password, 12);
      const role = "user";

      const [result] = await connection.execute(
        "INSERT INTO users (email, password_hash, first_name, last_name, phone, university, profile_picture_url, role, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())",
        [email, hashedPassword, firstName, lastName, phone, school, null, role, true]
      );

      const id = result.insertId;
      const token = jwt.sign({ id, email, firstName, lastName, role }, JWT_SECRET, { expiresIn: "7d" });

      connection.release();

      return res.status(201).json({
        success: true,
        message: "Inscription réussie",
        data: {
          accessToken: token,
          user: { id, firstName, lastName, email, phone, school, role },
        },
      });
    } catch (error) {
      connection.release();
      console.error("Erreur lors de l'inscription (DB)", error);
      return res.status(500).json({ success: false, message: "Erreur serveur lors de l'inscription" });
    }
  } catch (error) {
    console.error("Erreur lors de l'inscription", error);
    return res.status(500).json({ success: false, message: "Erreur serveur lors de l'inscription" });
  }
});



app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email et mot de passe requis' 
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email invalide' 
      });
    }

    const connection = await pool.getConnection();

    try {
      const [users] = await connection.execute(
        'SELECT * FROM users WHERE email = ?',
        [email.toLowerCase()]
      );

      if (users.length === 0) {
        connection.release();
        return res.status(401).json({ 
          success: false, 
          message: 'Email ou mot de passe incorrect' 
        });
      }

      const user = users[0];

      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      if (!isPasswordValid) {
        connection.release();
        return res.status(401).json({ 
          success: false, 
          message: 'Email ou mot de passe incorrect' 
        });
      }

      const token = jwt.sign(
        {
          id: user.id,                 
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role              
        },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      connection.release();

      await createLog({
        userId: user.id,
        actionType: 'auth',
        action: 'login',
        description: `Connexion réussie pour ${user.email}`,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });


      res.json({
        success: true,
        message: 'Connexion réussie',
        data: {
          accessToken: token,
          user: {
            id: user.id,
            firstName: user.first_name,
            lastName: user.last_name,
            email: user.email,
            phone: user.phone,
            school: user.university,
            role: user.role              
          }
        }
      });

    } catch (error) {
      connection.release();
      console.error('Erreur traitement login:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Erreur interne lors de la connexion' 
      });
    }

  } catch (error) {
    console.error('Erreur serveur login:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erreur serveur lors de la connexion' 
    });
  }
});



// ============================================
// MIDDLEWARE D'AUTHENTIFICATION
// ============================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1]; 

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Token d\'authentification requis'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Token invalide ou expiré'
      });
    }

    // user = { id, email, firstName, lastName, role }
    req.user = user;

    next();
  });
};


// Route pour récupérer le profil de l'utilisateur connecté
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();

    try {
      const [users] = await connection.execute(
        'SELECT id, first_name, last_name, email, phone, university, role, created_at FROM users WHERE id = ?',
        [req.user.id] 
      );

      connection.release();

      if (users.length === 0) {
        return res.status(404).json({ 
          success: false, 
          message: 'Utilisateur non trouvé' 
        });
      }

      res.json({
        success: true,
        data: {
          id: users[0].id,
          firstName: users[0].first_name,
          lastName: users[0].last_name,
          email: users[0].email,
          phone: users[0].phone,
          school: users[0].university,  
          role: users[0].role,           
          createdAt: users[0].created_at,
        }
      });

    } catch (error) {
      connection.release();
      throw error;
    }

  } catch (error) {
    console.error('Erreur lors de la récupération du profil:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erreur serveur' 
    });
  }
});

// Route pour mettre à jour le profil
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, phone, school, profile_picture_url } = req.body;

    if (!firstName || !lastName) {
      return res.status(400).json({
        success: false,
        message: 'Le prénom et le nom sont requis'
      });
    }

    firstName = DOMPurify.sanitize(firstName.trim()).substring(0, 100);
    lastName = DOMPurify.sanitize(lastName.trim()).substring(0, 100);
    if (school) school = DOMPurify.sanitize(school.trim()).substring(0, 255);
    if (phone) phone = DOMPurify.sanitize(phone.trim()).substring(0, 30);

    const connection = await pool.getConnection();

    try {
      await connection.execute(
        `UPDATE users 
         SET first_name = ?, last_name = ?, phone = ?, university = ?, profile_picture_url = ?
         WHERE id = ?`,
        [firstName, lastName, phone, school, profile_picture_url, req.user.id]
      );

      const [users] = await connection.execute(
        'SELECT id, first_name, last_name, email, phone, university, role, created_at FROM users WHERE id = ?',
        [req.user.id]
      );

      connection.release();

      res.json({
        success: true,
        message: 'Profil mis à jour avec succès',
        data: {
          id: users[0].id,
          firstName: users[0].first_name,
          lastName: users[0].last_name,
          email: users[0].email,
          phone: users[0].phone,
          school: users[0].university,
          role: users[0].role,
          createdAt: users[0].created_at,
        }
      });

    } catch (error) {
      connection.release();
      throw error;
    }

  } catch (error) {
    console.error('Erreur lors de la mise à jour du profil:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur serveur lors de la mise à jour'
    });
  }
});

// ============================================
// ROUTE DE VÉRIFICATION
// ============================================

app.get('/api/health', async (req, res) => {
  try {
    await pool.execute('SELECT 1');
    res.json({ 
      success: true, 
      message: 'API EventHub opérationnelle',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (error) {
    res.status(503).json({
      success: false,
      message: 'Service non disponible',
      error: 'Database connection failed'
    });
  }
});

// ============================================
// ROUTES EVENTS
// ============================================
const checkOrganizer = (req, res, next) => {

  if (req.user.role !== 'organisateur' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès réservé aux organisateurs ou admins' });
  }

  next();
};



app.get('/api/events', async (req, res) => {
    try {
        const { category, search, date, limit, offset } = req.query;
        
        let query = `
            SELECT 
                e.id,
                e.name,
                e.description,
                e.date,
                e.category,
                e.image,
                e.created_at,
                u.first_name,
                u.last_name,
                u.email as organizer_email,
                COUNT(DISTINCT ep.user_id) as participant_count
            FROM events e
            LEFT JOIN users u ON e.organizer_id = u.id
            LEFT JOIN event_participants ep ON e.id = ep.event_id
            WHERE 1=1
        `;
        
        const params = [];

        if (category) {
            query += ' AND e.category = ?';
            params.push(category);
        }

        if (search) {
            query += ' AND (e.name LIKE ? OR e.description LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm);
        }

        if (date) {
            query += ' AND DATE(e.date) = ?';
            params.push(date);
        }

        query += ' GROUP BY e.id ORDER BY e.date ASC';

        if (limit) {
            query += ' LIMIT ?';
            params.push(parseInt(limit));
            
            if (offset) {
                query += ' OFFSET ?';
                params.push(parseInt(offset));
            }
        }

        const [events] = await pool.execute(query, params);

        const sanitizedEvents = events.map(event => ({
            id: event.id,
            name: event.name,
            description: event.description,
            date: event.date,
            category: event.category,
            image: event.image,
            organizer: {
                name: `${event.first_name} ${event.last_name}`
            },
            participantCount: event.participant_count,
            createdAt: event.created_at
        }));

        res.json({
            success: true,
            events: sanitizedEvents,
            count: sanitizedEvents.length
        });

    } catch (error) {
        console.error('Erreur lors de la récupération des événements:', error);
        res.status(500).json({ 
            error: 'Erreur lors de la récupération des événements',
            message: error.message 
        });
    }
});

app.get('/api/events/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const [events] = await pool.execute(`
          SELECT 
              e.*,
              u.first_name,
              u.last_name,
              u.email as organizer_email,
              COUNT(DISTINCT ep.user_id) as participant_count
          FROM events e
          LEFT JOIN users u ON e.organizer_id = u.id
          LEFT JOIN event_participants ep ON e.id = ep.event_id
          WHERE e.id = ?
          GROUP BY e.id
        `, [id]);

        if (events.length === 0) {
            return res.status(404).json({ error: 'Événement non trouvé' });
        }

        const event = events[0];
        const sanitizedEvent = {
            id: event.id,
            name: event.name,
            description: event.description,
            date: event.date,
            category: event.category,
            image: event.image,
            organizer: {
                name: `${event.first_name} ${event.last_name}`
            },
            participantCount: event.participant_count,
            createdAt: event.created_at
        };

        res.json({
            success: true,
            event: sanitizedEvent
        });

    } catch (error) {
        console.error('Erreur lors de la récupération de l\'événement:', error);
        res.status(500).json({ 
            error: 'Erreur lors de la récupération de l\'événement',
            message: error.message 
        });
    }
});

app.post('/api/events/createevent', authenticateToken, checkOrganizer, async (req, res) => {
    try {
        const { name, description, date, category, image } = req.body;

        if (!name || !description || !date || !category) {
            return res.status(400).json({ 
                error: 'Tous les champs obligatoires doivent être remplis',
                required: ['name', 'description', 'date', 'category']
            });
        }

        const validCategories = ['Ateliers', 'Conférences', 'Soirées', 'Hackathons', 'Séminaires'];
        if (!validCategories.includes(category)) {
            return res.status(400).json({ 
                error: 'Catégorie invalide',
                validCategories 
            });
        }

        const eventDate = new Date(date);
        if (eventDate < new Date()) {
            return res.status(400).json({ 
                error: 'La date de l\'événement doit être dans le futur' 
            });
        }

        if (image) {
            try {
                new URL(image);
            } catch (e) {
                return res.status(400).json({ 
                    error: 'L\'URL de l\'image est invalide' 
                });
            }
        }

        const sanitizedName = DOMPurify.sanitize(name.trim()).substring(0, 255);
        const sanitizedDescription = DOMPurify.sanitize(description.trim());
        const sanitizedImage = image ? image.trim().substring(0, 500) : null;

        await createLog({
          userId: req.user.id,
          actionType: 'event',
          action: 'create_event',
          description: `Création de l'événement "${sanitizedName}" par l'organisateur : ${req.user.firstName} ${req.user.lastName}`,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        });

        const [result] = await pool.execute(
            `INSERT INTO events (name, description, date, category, image, organizer_id) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [sanitizedName, sanitizedDescription, date, category, sanitizedImage, req.user.id]
        );

        const [newEvent] = await pool.execute(
            'SELECT * FROM events WHERE id = ?',
            [result.insertId]
        );

        res.status(201).json({
            success: true,
            message: 'Événement créé avec succès',
            event: {
                id: newEvent[0].id,
                name: newEvent[0].name,
                description: newEvent[0].description,
                date: newEvent[0].date,
                category: newEvent[0].category,
                image: newEvent[0].image,
                createdAt: newEvent[0].created_at
            }
        });

    } catch (error) {
        console.error('Erreur lors de la création de l\'événement:', error);
        res.status(500).json({ 
            error: 'Erreur lors de la création de l\'événement',
            message: error.message 
        });
    }
});

app.put('/api/events/:id', authenticateToken, checkOrganizer, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, date, category, image } = req.body;

        const [events] = await pool.execute(
            'SELECT * FROM events WHERE id = ? AND organizer_id = ?',
            [id, req.user.id]
        );

        if (events.length === 0) {
            return res.status(404).json({ 
                error: 'Événement non trouvé ou vous n\'êtes pas autorisé à le modifier' 
            });
        }

        const updates = [];
        const params = [];

        if (name !== undefined) {
            updates.push('name = ?');
            params.push(name.trim().substring(0, 255));
        }
        if (description !== undefined) {
            updates.push('description = ?');
            params.push(description.trim());
        }
        if (date !== undefined) {
            const eventDate = new Date(date);
            if (eventDate < new Date()) {
                return res.status(400).json({ 
                    error: 'La date de l\'événement doit être dans le futur' 
                });
            }
            updates.push('date = ?');
            params.push(date);
        }
        if (category !== undefined) {
            const validCategories = ['Ateliers', 'Conférences', 'Soirées', 'Hackathons', 'Séminaires'];
            if (!validCategories.includes(category)) {
                return res.status(400).json({ 
                    error: 'Catégorie invalide',
                    validCategories 
                });
            }
            updates.push('category = ?');
            params.push(category);
        }
        if (image !== undefined) {
            if (image) {
                try {
                    new URL(image);
                } catch (e) {
                    return res.status(400).json({ 
                        error: 'L\'URL de l\'image est invalide' 
                    });
                }
            }
            updates.push('image = ?');
            params.push(image ? image.trim().substring(0, 500) : null);
        }

        if (updates.length === 0) {
            return res.status(400).json({ 
                error: 'Aucune modification fournie' 
            });
        }

        params.push(id);

        await pool.execute(
            `UPDATE events SET ${updates.join(', ')} WHERE id = ?`,
            params
        );

        const [updatedEvent] = await pool.execute(
            'SELECT * FROM events WHERE id = ?',
            [id]
        );

        res.json({
            success: true,
            message: 'Événement mis à jour avec succès',
            event: updatedEvent[0]
        });

    } catch (error) {
        console.error('Erreur lors de la modification de l\'événement:', error);
        res.status(500).json({ 
            error: 'Erreur lors de la modification de l\'événement',
            message: error.message 
        });
    }
});

app.delete('/api/events/:id', authenticateToken, checkOrganizer, async (req, res) => {
    try {
        const { id } = req.params;

        const [events] = await pool.execute(
            'SELECT * FROM events WHERE id = ? AND organizer_id = ?',
            [id, req.user.id]
        );

        if (events.length === 0) {
            return res.status(404).json({ 
                error: 'Événement non trouvé ou vous n\'êtes pas autorisé à le supprimer' 
            });
        }

        await pool.execute('DELETE FROM events WHERE id = ?', [id]);

        res.json({
            success: true,
            message: 'Événement supprimé avec succès'
        });

    } catch (error) {
        console.error('Erreur lors de la suppression de l\'événement:', error);
        res.status(500).json({ 
            error: 'Erreur lors de la suppression de l\'événement',
            message: error.message 
        });
    }
});

app.post('/api/events/:id/register', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const [events] = await pool.execute(
            'SELECT * FROM events WHERE id = ?',
            [id]
        );

        if (events.length === 0) {
            return res.status(404).json({ error: 'Événement non trouvé' });
        }

        if (new Date(events[0].date) < new Date()) {
            return res.status(400).json({ 
                error: 'Impossible de s\'inscrire à un événement passé' 
            });
        }

        const [existing] = await pool.execute(
            'SELECT * FROM event_participants WHERE event_id = ? AND user_id = ?',
            [id, req.user.id]
        );

        if (existing.length > 0) {
            return res.status(400).json({ 
                error: 'Vous êtes déjà inscrit à cet événement' 
            });
        }

        await pool.execute(
            'INSERT INTO event_participants (event_id, user_id) VALUES (?, ?)',
            [id, req.user.id]
        );

        res.status(201).json({
            success: true,
            message: 'Inscription réussie'
        });

    } catch (error) {
        console.error('Erreur lors de l\'inscription:', error);
        res.status(500).json({ 
            error: 'Erreur lors de l\'inscription',
            message: error.message 
        });
    }
});

// DELETE - Se désinscrire d'un événement
app.delete('/api/events/:id/unregister', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const [result] = await pool.execute(
            'DELETE FROM event_participants WHERE event_id = ? AND user_id = ?',
            [id, req.user.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ 
                error: 'Vous n\'êtes pas inscrit à cet événement' 
            });
        }

        res.json({
            success: true,
            message: 'Désinscription réussie'
        });

    } catch (error) {
        console.error('Erreur lors de la désinscription:', error);
        res.status(500).json({ 
            error: 'Erreur lors de la désinscription',
            message: error.message 
        });
    }
});


// Route : récupérer les événements auxquels l’utilisateur est inscrit
app.get('/api/user/events', authenticateToken, async (req, res) => {
    try {
        const [events] = await pool.execute(`
            SELECT 
                e.id, e.name, e.description, e.date, e.category, e.image,
                COUNT(ep2.user_id) AS participant_count
            FROM event_participants ep
            INNER JOIN events e ON ep.event_id = e.id
            LEFT JOIN event_participants ep2 ON ep2.event_id = e.id
            WHERE ep.user_id = ?
            GROUP BY e.id
            ORDER BY e.date ASC
        `, [req.user.id]);
        res.json({
            success: true,
            events
        });

    } catch (error) {
        console.error("Erreur récupération événements utilisateur:", error);
        res.status(500).json({ success: false, message: "Erreur serveur" });
    }
});

// ============================================
// MIDDLEWARE ADMIN
// ============================================
const checkAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ 
            success: false,
            error: 'Accès réservé aux administrateurs' 
        });
    }
    next();
};

// ============================================
// HELPER LOGS D'ACTIVITÉ
// ============================================
async function createLog({
  userId = null,
  actionType = 'event',  // 'auth','event','user','admin'
  action,
  description = '',
  targetId = null,
  targetType = null,
  ipAddress = null,
  userAgent = null,
  metadata = null
}) {
  try {
    const connection = await pool.getConnection();
    try {
      const query = `
        INSERT INTO activity_logs (
          user_id, action_type, action, description, 
          target_id, target_type, ip_address, user_agent, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      const params = [
        userId,
        actionType,
        action,
        description,
        targetId,
        targetType,
        ipAddress,
        userAgent,
        metadata ? JSON.stringify(metadata) : null
      ];
      await connection.execute(query, params);
      connection.release();
    } catch (err) {
      connection.release();
      console.error('Erreur lors de la création du log:', err);
    }
  } catch (err) {
    console.error('Erreur connexion DB pour log:', err);
  }
}

// ============================================
// ROUTES ADMIN - LOGS D'ACTIVITÉ
// ============================================

// GET /api/admin/logs - Liste des logs avec filtres (type, date, recherche)
app.get('/api/admin/logs', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const { type, startDate, endDate, search, userId, limit, offset } = req.query;

    let query = `
      SELECT 
        al.id,
        al.user_id,
        u.email AS user_email,
        u.first_name,
        u.last_name,
        al.action_type,
        al.action,
        al.description,
        al.target_id,
        al.target_type,
        al.ip_address,
        al.user_agent,
        al.metadata,
        al.created_at
      FROM activity_logs al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (type) {
      query += ' AND al.action_type = ?';
      params.push(type);
    }

    if (userId) {
      query += ' AND al.user_id = ?';
      params.push(parseInt(userId));
    }

    if (startDate) {
      query += ' AND al.created_at >= ?';
      params.push(startDate);
    }

    if (endDate) {
      query += ' AND al.created_at <= ?';
      params.push(endDate);
    }

    if (search) {
      const term = `%${search}%`;
      query += `
        AND (
          al.action LIKE ? OR
          al.description LIKE ? OR
          al.target_type LIKE ? OR
          u.email LIKE ? OR
          u.first_name LIKE ? OR
          u.last_name LIKE ?
        )
      `;
      params.push(term, term, term, term, term, term);
    }

    query += ' ORDER BY al.created_at DESC';

    // Pagination
    const useLimit = parseInt(limit) || 50;
    const useOffset = parseInt(offset) || 0;
    query += ' LIMIT ? OFFSET ?';
    params.push(useLimit, useOffset);

    const [logs] = await pool.execute(query, params);

    res.json({
      success: true,
      logs,
      count: logs.length
    });
  } catch (error) {
    console.error('Erreur lors de la récupération des logs:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération des logs',
      message: error.message
    });
  }
});

// GET /api/admin/logs/stats - Statistiques détaillées
app.get('/api/admin/logs/stats', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const [stats] = await pool.execute(`
      SELECT
        (SELECT COUNT(*) FROM activity_logs) AS total_logs,
        (SELECT COUNT(*) FROM activity_logs WHERE action_type = 'auth') AS auth_logs,
        (SELECT COUNT(*) FROM activity_logs WHERE action_type = 'event') AS event_logs,
        (SELECT COUNT(*) FROM activity_logs WHERE action_type = 'user') AS user_logs,
        (SELECT COUNT(*) FROM activity_logs WHERE action_type = 'admin') AS admin_logs
    `);

    const [logsPerDay] = await pool.execute(`
      SELECT DATE(created_at) AS date, COUNT(*) AS count
      FROM activity_logs
      GROUP BY DATE(created_at)
      ORDER BY DATE(created_at) DESC
      LIMIT 30
    `);

    const [topUsers] = await pool.execute(`
      SELECT 
        al.user_id,
        u.email,
        u.first_name,
        u.last_name,
        COUNT(*) AS count
      FROM activity_logs al
      LEFT JOIN users u ON al.user_id = u.id
      GROUP BY al.user_id
      ORDER BY count DESC
      LIMIT 10
    `);

    res.json({
      success: true,
      stats: stats[0],
      logsPerDay,
      topUsers
    });
  } catch (error) {
    console.error('Erreur stats logs:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération des statistiques de logs',
      message: error.message
    });
  }
});

// DELETE /api/admin/logs/cleanup - Nettoyage des vieux logs
app.delete('/api/admin/logs/cleanup', authenticateToken, checkAdmin, async (req, res) => {
  try {
    const { beforeDate, keepDays } = req.body || {};

    let cutoffDate;

    if (beforeDate) {
      cutoffDate = beforeDate;
    } else if (keepDays) {
      const days = parseInt(keepDays);
      if (isNaN(days) || days <= 0) {
        return res.status(400).json({
          success: false,
          error: 'keepDays doit être un nombre positif'
        });
      }
      const d = new Date();
      d.setDate(d.getDate() - days);
      cutoffDate = d.toISOString().slice(0, 19).replace('T', ' ');
    } else {
      // Par défaut : nettoyer les logs de plus de 90 jours
      const d = new Date();
      d.setDate(d.getDate() - 90);
      cutoffDate = d.toISOString().slice(0, 19).replace('T', ' ');
    }

    const [result] = await pool.execute(
      'DELETE FROM activity_logs WHERE created_at < ?',
      [cutoffDate]
    );

    res.json({
      success: true,
      message: 'Nettoyage des logs effectué',
      deleted: result.affectedRows,
      cutoffDate
    });
  } catch (error) {
    console.error('Erreur nettoyage logs:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors du nettoyage des logs',
      message: error.message
    });
  }
});


// ============================================
// ROUTES ADMIN - GESTION UTILISATEURS
// ============================================

// GET - Liste tous les utilisateurs (avec filtres et recherche)
app.get('/api/admin/users', authenticateToken, checkAdmin, async (req, res) => {
    try {
        const { search, role, limit, offset } = req.query;
        
        let query = `
            SELECT 
                u.id,
                u.email,
                u.first_name,
                u.last_name,
                u.phone,
                u.university,
                u.role,
                u.is_active,
                u.created_at,
                COUNT(DISTINCT ep.event_id) as events_count
            FROM users u
            LEFT JOIN event_participants ep ON u.id = ep.user_id
            WHERE 1=1
        `;
        
        const params = [];

        // Filtre de recherche
        if (search) {
            query += ` AND (
                u.first_name LIKE ? OR 
                u.last_name LIKE ? OR 
                u.email LIKE ? OR
                u.university LIKE ?
            )`;
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }

        // Filtre par rôle
        if (role) {
            query += ' AND u.role = ?';
            params.push(role);
        }

        query += ' GROUP BY u.id ORDER BY u.created_at DESC';

        // Pagination
        if (limit) {
            query += ' LIMIT ?';
            params.push(parseInt(limit));
            
            if (offset) {
                query += ' OFFSET ?';
                params.push(parseInt(offset));
            }
        }

        const [users] = await pool.execute(query, params);

        // Compter le total pour la pagination
        let countQuery = 'SELECT COUNT(*) as total FROM users WHERE 1=1';
        const countParams = [];
        
        if (search) {
            countQuery += ` AND (
                first_name LIKE ? OR 
                last_name LIKE ? OR 
                email LIKE ? OR
                university LIKE ?
            )`;
            const searchTerm = `%${search}%`;
            countParams.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }
        
        if (role) {
            countQuery += ' AND role = ?';
            countParams.push(role);
        }

        const [countResult] = await pool.execute(countQuery, countParams);

        res.json({
            success: true,
            users: users,
            total: countResult[0].total,
            count: users.length
        });

    } catch (error) {
        console.error('Erreur lors de la récupération des utilisateurs:', error);
        res.status(500).json({ 
            success: false,
            error: 'Erreur lors de la récupération des utilisateurs',
            message: error.message 
        });
    }
});

// GET - Détails d'un utilisateur spécifique
app.get('/api/admin/users/:id', authenticateToken, checkAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const [users] = await pool.execute(`
            SELECT 
                u.id,
                u.email,
                u.first_name,
                u.last_name,
                u.phone,
                u.university,
                u.profile_picture_url,
                u.role,
                u.is_active,
                u.created_at,
                u.updated_at,
                COUNT(DISTINCT ep.event_id) as events_registered,
                COUNT(DISTINCT e.id) as events_organized
            FROM users u
            LEFT JOIN event_participants ep ON u.id = ep.user_id
            LEFT JOIN events e ON u.id = e.organizer_id
            WHERE u.id = ?
            GROUP BY u.id
        `, [id]);

        if (users.length === 0) {
            return res.status(404).json({ 
                success: false,
                error: 'Utilisateur non trouvé' 
            });
        }

        res.json({
            success: true,
            user: users[0]
        });

    } catch (error) {
        console.error('Erreur lors de la récupération de l\'utilisateur:', error);
        res.status(500).json({ 
            success: false,
            error: 'Erreur lors de la récupération de l\'utilisateur',
            message: error.message 
        });
    }
});

// PUT - Modifier un utilisateur (y compris son rôle)
app.put('/api/admin/users/:id', authenticateToken, checkAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { firstName, lastName, email, phone, university, role, isActive } = req.body;

        const [existingUser] = await pool.execute(
            'SELECT * FROM users WHERE id = ?',
            [id]
        );

        if (existingUser.length === 0) {
            return res.status(404).json({ 
                success: false,
                error: 'Utilisateur non trouvé' 
            });
        }

        if (parseInt(id) === req.user.id && role && role !== 'admin') {
            return res.status(400).json({ 
                success: false,
                error: 'Vous ne pouvez pas modifier votre propre rôle' 
            });
        }

        const updates = [];
        const params = [];

        if (firstName !== undefined) {
            updates.push('first_name = ?');
            params.push(firstName.trim());
        }
        if (lastName !== undefined) {
            updates.push('last_name = ?');
            params.push(lastName.trim());
        }
        if (email !== undefined) {
            const [emailCheck] = await pool.execute(
                'SELECT id FROM users WHERE email = ? AND id != ?',
                [email, id]
            );
            if (emailCheck.length > 0) {
                return res.status(409).json({ 
                    success: false,
                    error: 'Cet email est déjà utilisé' 
                });
            }
            updates.push('email = ?');
            params.push(email.trim());
        }
        if (phone !== undefined) {
            updates.push('phone = ?');
            params.push(phone);
        }
        if (university !== undefined) {
            updates.push('university = ?');
            params.push(university.trim());
        }
        if (role !== undefined) {
            const validRoles = ['user', 'organisateur', 'admin'];
            if (!validRoles.includes(role)) {
                return res.status(400).json({ 
                    success: false,
                    error: 'Rôle invalide',
                    validRoles 
                });
            }
            updates.push('role = ?');
            params.push(role);
        }
        if (isActive !== undefined) {
            updates.push('is_active = ?');
            params.push(isActive ? 1 : 0);
        }

        if (updates.length === 0) {
            return res.status(400).json({ 
                success: false,
                error: 'Aucune modification fournie' 
            });
        }

        params.push(id);

        await pool.execute(
            `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
            params
        );

        const [updatedUser] = await pool.execute(
            'SELECT id, email, first_name, last_name, phone, university, role, is_active, created_at FROM users WHERE id = ?',
            [id]
        );

        res.json({
            success: true,
            message: 'Utilisateur mis à jour avec succès',
            user: updatedUser[0]
        });

    } catch (error) {
        console.error('Erreur lors de la modification de l\'utilisateur:', error);
        res.status(500).json({ 
            success: false,
            error: 'Erreur lors de la modification de l\'utilisateur',
            message: error.message 
        });
    }
});

// DELETE - Supprimer un utilisateur
app.delete('/api/admin/users/:id', authenticateToken, checkAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (parseInt(id) === req.user.id) {
            return res.status(400).json({ 
                success: false,
                error: 'Vous ne pouvez pas supprimer votre propre compte' 
            });
        }

        const [users] = await pool.execute(
            'SELECT * FROM users WHERE id = ?',
            [id]
        );

        if (users.length === 0) {
            return res.status(404).json({ 
                success: false,
                error: 'Utilisateur non trouvé' 
            });
        }

        await pool.execute('DELETE FROM users WHERE id = ?', [id]);

        res.json({
            success: true,
            message: 'Utilisateur supprimé avec succès'
        });

    } catch (error) {
        console.error('Erreur lors de la suppression de l\'utilisateur:', error);
        res.status(500).json({ 
            success: false,
            error: 'Erreur lors de la suppression de l\'utilisateur',
            message: error.message 
        });
    }
});

// GET - Statistiques générales pour l'admin
app.get('/api/admin/stats', authenticateToken, checkAdmin, async (req, res) => {
    try {
        const [stats] = await pool.execute(`
            SELECT 
                (SELECT COUNT(*) FROM users) as total_users,
                (SELECT COUNT(*) FROM users WHERE role = 'user') as users_count,
                (SELECT COUNT(*) FROM users WHERE role = 'organisateur') as organizers_count,
                (SELECT COUNT(*) FROM users WHERE role = 'admin') as admins_count,
                (SELECT COUNT(*) FROM events) as total_events,
                (SELECT COUNT(*) FROM event_participants) as total_registrations
        `);

        res.json({
            success: true,
            stats: stats[0]
        });

    } catch (error) {
        console.error('Erreur lors de la récupération des statistiques:', error);
        res.status(500).json({ 
            success: false,
            error: 'Erreur lors de la récupération des statistiques',
            message: error.message 
        });
    }
});


// ============================================
// DÉMARRAGE DU SERVEUR
// ============================================

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  logger.info(`🚀 Serveur démarré sur le port ${PORT}`);
  logger.info(`📍 API disponible sur http://localhost:${PORT}`);
  logger.info(`🔒 Environnement: ${process.env.NODE_ENV || 'development'}`);
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM reçu, fermeture gracieuse...');
  server.close(() => {
    logger.info('Serveur fermé');
    pool.end();
    process.exit(0);
  });
});

// Gestion des erreurs non capturées
process.on('unhandledRejection', (err) => {
  console.error('Erreur non gérée:', err);
  process.exit(1);
});