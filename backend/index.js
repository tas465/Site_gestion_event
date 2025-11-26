const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(express.json());
app.use(cors());

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'eventhub',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

// Secret pour JWT
const JWT_SECRET = process.env.JWT_SECRET || '4c03abc78244a1e8691a3f8121f04ca8';
console.log('JWT_SECRET:', process.env.JWT_SECRET);  // Log de la clé JWT pour vérifier


// ============================================
// ROUTES D'AUTHENTIFICATION
// ============================================

app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, email, phone, school, password } = req.body;

  try {
    // Vérification champs obligatoires
    if (!firstName || !lastName || !email || !phone || !school || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Tous les champs sont requis' 
      });
    }

    // Email valide
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email invalide' 
      });
    }

    // Mot de passe sécurisé
    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Le mot de passe doit contenir au moins 8 caractères'
      });
    }

    const connection = await pool.getConnection();

    try {
      // Vérifier si email existe déjà
      const [existing] = await connection.execute(
        'SELECT id FROM users WHERE email = ?',
        [email]
      );

      if (existing.length > 0) {
        connection.release();
        return res.status(409).json({
          success: false,
          message: 'Un compte avec cet email existe déjà'
        });
      }

      // Hash du mot de passe
      const hashedPassword = await bcrypt.hash(password, 10);

      // Rôle par défaut = user
      const role = "user";

      // Insérer l'utilisateur
      const [result] = await connection.execute(
        `INSERT INTO users (
          email, password_hash, first_name, last_name, phone, university, 
          profile_picture_url, role, is_active, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [email, hashedPassword, firstName, lastName, phone, school, null, role, true]
      );

      const id = result.insertId;

      // 🔥 CRÉER TOKEN AVEC LE RÔLE
      const token = jwt.sign(
        { 
          id,
          email,
          firstName,
          lastName,
          role        // 🔥🔥🔥 essentiel !
        },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      connection.release();

      // Réponse
      res.status(201).json({
        success: true,
        message: 'Inscription réussie',
        data: {
          token,
          user: {
            id,
            firstName,
            lastName,
            email,
            phone,
            school,
            role
          }
        }
      });

    } catch (error) {
      connection.release();
      throw error;
    }

  } catch (error) {
    console.error('Erreur lors de l\'inscription:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur serveur lors de l\'inscription'
    });
  }
});


app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Requête reçue:', req.body);

  try {
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email et mot de passe requis' 
      });
    }

    const connection = await pool.getConnection();

    try {
      const [users] = await connection.execute(
        'SELECT * FROM users WHERE email = ?',
        [email]
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

      // 🔥 Inclure le rôle dans le JWT
      const token = jwt.sign(
        {
          id: user.id,                  // id utilisateur
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role               // <-- rôle ajouté
        },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      connection.release();

      res.json({
        success: true,
        message: 'Connexion réussie',
        data: {
          token,
          user: {
            id: user.id,
            firstName: user.first_name,
            lastName: user.last_name,
            email: user.email,
            phone: user.phone,
            school: user.university,
            role: user.role              // <-- rôle aussi ici
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


// ============================================
// ROUTE PROTÉGÉE EXEMPLE
// ============================================

// Route pour récupérer le profil de l'utilisateur connecté
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();

    try {
      const [users] = await connection.execute(
        'SELECT id, first_name, last_name, email, phone, school, created_at FROM users WHERE id = ?',
        [req.user.userId]
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
          school: users[0].school,
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

// ============================================
// ROUTE DE VÉRIFICATION
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'API EventHub opérationnelle',
    timestamp: new Date().toISOString()
  });
});

// ============================================
// ROUTES EVENTS
// ============================================
const checkOrganizer = (req, res, next) => {
  console.log(req.user.role)
    if (req.user.role !== 'organisateur') {
        return res.status(403).json({ error: 'Accès réservé aux organisateurs' });
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

        const sanitizedName = name.trim().substring(0, 255);
        const sanitizedDescription = description.trim();
        const sanitizedImage = image ? image.trim().substring(0, 500) : null;

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

        // Vérifier si l'utilisateur est déjà inscrit
        const [existing] = await pool.execute(
            'SELECT * FROM event_participants WHERE event_id = ? AND user_id = ?',
            [id, req.user.id]
        );

        if (existing.length > 0) {
            return res.status(400).json({ 
                error: 'Vous êtes déjà inscrit à cet événement' 
            });
        }

        // Inscrire l'utilisateur
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

// ============================================
// DÉMARRAGE DU SERVEUR
// ============================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré sur le port ${PORT}`);
  console.log(`📍 API disponible sur http://localhost:${PORT}`);
});

// Gestion des erreurs non capturées
process.on('unhandledRejection', (err) => {
  console.error('Erreur non gérée:', err);
  process.exit(1);
});