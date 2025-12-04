# 🎓 EventHub - Backend API

> Plateforme de gestion d'événements étudiants avec système d'inscription complet, gestion des rôles et tableau de bord administrateur.

![Node.js](https://img.shields.io/badge/Node.js-20.x-green)
![Express](https://img.shields.io/badge/Express-4.x-blue)
![MySQL](https://img.shields.io/badge/MySQL-8.0-orange)
![Security Score](https://img.shields.io/badge/Security-94%25-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Architecture](#-architecture)
- [Sécurité](#-sécurité)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Utilisation](#-utilisation)
- [API Endpoints](#-api-endpoints)
- [Tests](#-tests)
- [CI/CD](#-cicd)
- [Base de données](#-base-de-données)

---

## 🎯 Fonctionnalités

### 🔐 Authentification & Autorisation
- **Inscription/Connexion** sécurisée avec JWT (expiration 7 jours)
- **Système de rôles** : `user`, `organisateur`, `admin`
- **Protection des routes** avec middleware d'authentification
- **Rate limiting** : 5 tentatives de connexion max / 15 minutes

### 📅 Gestion des événements
- **CRUD complet** pour les événements
- **Catégories** : Ateliers, Conférences, Soirées, Hackathons, Séminaires
- **Filtres avancés** : recherche, catégorie, date, pagination
- **Comptage en temps réel** des participants
- **Restrictions** : seul l'organisateur peut modifier/supprimer ses événements

### 👥 Système d'inscription
- **Inscription/désinscription** aux événements
- **Prévention des doublons** (contrainte UNIQUE en BDD)
- **Validation** : impossible de s'inscrire à un événement passé
- **Liste personnalisée** des événements de chaque utilisateur

### 📊 Tableau de bord administrateur
- **Gestion complète des utilisateurs** (modification de rôle, activation/désactivation)
- **Statistiques globales** : total utilisateurs, événements, inscriptions
- **Logs d'activité détaillés** avec filtres (type, date, utilisateur, recherche)
- **Nettoyage automatique** des vieux logs (90 jours par défaut)
- **Audit trail** : toutes les actions importantes sont enregistrées

### 🔍 Logs d'activité
- **Types d'actions** : `auth`, `event`, `user`, `admin`
- **Traçabilité** : IP, user-agent, timestamp, description
- **Métadonnées** JSON pour contexte additionnel
- **Dashboard** avec statistiques et graphiques

---

## 🏗️ Architecture

```
eventhub-backend/
│
├── index.js                 # Point d'entrée principal
├── test.js                  # Tests de sécurité automatisés
├── .env                     # Variables d'environnement
├── package.json             # Dépendances NPM
│
├── logs/                    # Logs Winston (error.log, combined.log)
│   ├── error.log
│   └── combined.log
│
├── .github/
│   └── workflows/
│       └── backend-ci.yml   # Pipeline CI/CD
│
└── eventhub.sql             # Structure de la base de données
```

### Stack technique

| Technologie | Version | Usage |
|------------|---------|-------|
| **Node.js** | 20.x | Runtime JavaScript |
| **Express.js** | 4.x | Framework web |
| **MySQL** | 8.0 | Base de données relationnelle |
| **JWT** | - | Authentification stateless |
| **bcrypt** | - | Hachage des mots de passe (12 rounds) |
| **Winston** | - | Logging avancé |
| **Helmet** | - | Sécurisation des headers HTTP |
| **DOMPurify** | - | Sanitisation des entrées (XSS) |

---

## 🔒 Sécurité

### Score global : **94%** ✅

#### Mesures implémentées

##### 1️⃣ **Protection des headers (Helmet)**
```javascript
✅ Content-Security-Policy
✅ X-Frame-Options: DENY
✅ X-Content-Type-Options: nosniff
✅ Strict-Transport-Security
```

##### 2️⃣ **Rate Limiting**
- **API générale** : 100 requêtes / minute
- **Login** : 5 tentatives / 15 minutes
- **Inscription** : 5 tentatives / 15 minutes

##### 3️⃣ **Validation des entrées**
```javascript
✅ Regex stricte pour les emails
✅ Mot de passe minimum 8 caractères
✅ Sanitisation DOMPurify (prévention XSS)
✅ Détection de scripts malveillants
```

##### 4️⃣ **Protection SQL Injection**
```javascript
// ✅ Requêtes préparées (JAMAIS de concaténation)
await pool.execute(
  'SELECT * FROM users WHERE email = ?',
  [email.toLowerCase()]
);
```

##### 5️⃣ **CORS configuré**
```javascript
// Liste blanche d'origines autorisées
const allowedOrigins = process.env.ALLOWED_ORIGINS.split(',');
```

##### 6️⃣ **Gestion des erreurs**
- Logger Winston (fichiers séparés)
- **Pas de stack traces** exposées en production
- Messages d'erreur génériques

##### 7️⃣ **Authentification robuste**
- JWT avec secret obligatoire
- Tokens expirés après 7 jours
- Middleware de vérification systématique

##### 8️⃣ **Système de rôles**
```javascript
✅ checkOrganizer() → Création d'événements
✅ checkAdmin() → Routes d'administration
✅ authenticateToken() → Toutes les routes protégées
```

---

## 🚀 Installation

### Prérequis
- Node.js 20.x ou supérieur
- MySQL 8.0 ou supérieur
- npm ou yarn

### Étapes

1. **Cloner le repository**
```bash
git clone https://github.com/votre-username/eventhub-backend.git
cd eventhub-backend
```

2. **Installer les dépendances**
```bash
npm install
```

3. **Créer la base de données**
```bash
mysql -u root -p < eventhub.sql
```

4. **Configurer les variables d'environnement**
```bash
cp .env.example .env
# Puis éditer .env avec vos valeurs
```

5. **Lancer le serveur**
```bash
# Développement
npm run dev

# Production
npm start
```

Le serveur démarre sur `http://localhost:3000` 🎉

---

## ⚙️ Configuration

Créez un fichier `.env` à la racine :

```env
# Serveur
PORT=3000
NODE_ENV=development

# Base de données
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=votre_mot_de_passe
DB_NAME=eventhub

# Sécurité
JWT_SECRET=votre_secret_jwt_ultra_securise_minimum_32_caracteres

# CORS
ALLOWED_ORIGINS=http://localhost:5500,http://localhost:3000

# Logging
LOG_LEVEL=info
```

⚠️ **Important** : Ne commitez JAMAIS votre fichier `.env` !

---

## 💻 Utilisation

### Démarrer l'API

```bash
# Mode développement (avec nodemon)
npm run dev

# Mode production
npm start

# Tests de sécurité
npm run test:security
```

### Vérifier le statut

```bash
curl http://localhost:3000/api/health
```

Réponse attendue :
```json
{
  "success": true,
  "message": "API EventHub opérationnelle",
  "timestamp": "2025-12-04T10:30:00.000Z",
  "environment": "development"
}
```

---

## 📡 API Endpoints

### 🔐 Authentification

| Méthode | Endpoint | Description | Auth |
|---------|----------|-------------|------|
| POST | `/api/auth/register` | Inscription | ❌ |
| POST | `/api/auth/login` | Connexion | ❌ |

#### Exemple : Inscription
```bash
POST /api/auth/register
Content-Type: application/json

{
  "firstName": "Jean",
  "lastName": "Dupont",
  "email": "jean.dupont@example.com",
  "phone": "+33612345678",
  "school": "Université Paris",
  "password": "MotDePasseSecurise123!"
}
```

Réponse :
```json
{
  "success": true,
  "message": "Inscription réussie",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": 1,
      "firstName": "Jean",
      "lastName": "Dupont",
      "email": "jean.dupont@example.com",
      "role": "user"
    }
  }
}
```

---

### 👤 Profil utilisateur

| Méthode | Endpoint | Description | Auth |
|---------|----------|-------------|------|
| GET | `/api/user/profile` | Récupérer profil | ✅ |
| PUT | `/api/user/profile` | Modifier profil | ✅ |
| GET | `/api/user/events` | Mes événements | ✅ |

#### Exemple : Récupérer son profil
```bash
GET /api/user/profile
Authorization: Bearer {votre_token}
```

---

### 📅 Événements

| Méthode | Endpoint | Description | Auth | Rôle |
|---------|----------|-------------|------|------|
| GET | `/api/events` | Liste événements | ❌ | - |
| GET | `/api/events/:id` | Détail événement | ❌ | - |
| POST | `/api/events/createevent` | Créer événement | ✅ | Organisateur |
| PUT | `/api/events/:id` | Modifier événement | ✅ | Organisateur |
| DELETE | `/api/events/:id` | Supprimer événement | ✅ | Organisateur |
| POST | `/api/events/:id/register` | S'inscrire | ✅ | User |
| DELETE | `/api/events/:id/unregister` | Se désinscrire | ✅ | User |

#### Exemple : Créer un événement
```bash
POST /api/events/createevent
Authorization: Bearer {token_organisateur}
Content-Type: application/json

{
  "name": "Hackathon IA 2025",
  "description": "24h de code intensif sur l'IA générative",
  "date": "2025-12-15T09:00:00",
  "category": "Hackathons",
  "image": "https://example.com/image.jpg"
}
```

#### Filtres disponibles (GET /api/events)
```bash
GET /api/events?category=Hackathons&search=IA&limit=10&offset=0
```

---

### 👑 Administration

| Méthode | Endpoint | Description | Auth | Rôle |
|---------|----------|-------------|------|------|
| GET | `/api/admin/users` | Liste utilisateurs | ✅ | Admin |
| GET | `/api/admin/users/:id` | Détail utilisateur | ✅ | Admin |
| PUT | `/api/admin/users/:id` | Modifier utilisateur | ✅ | Admin |
| DELETE | `/api/admin/users/:id` | Supprimer utilisateur | ✅ | Admin |
| GET | `/api/admin/stats` | Statistiques globales | ✅ | Admin |
| GET | `/api/admin/logs` | Logs d'activité | ✅ | Admin |
| GET | `/api/admin/logs/stats` | Stats des logs | ✅ | Admin |
| DELETE | `/api/admin/logs/cleanup` | Nettoyer logs | ✅ | Admin |

#### Exemple : Modifier le rôle d'un utilisateur
```bash
PUT /api/admin/users/5
Authorization: Bearer {token_admin}
Content-Type: application/json

{
  "role": "organisateur"
}
```

#### Exemple : Consulter les logs avec filtres
```bash
GET /api/admin/logs?type=auth&startDate=2025-12-01&search=login&limit=50
```

---

## 🧪 Tests

### Tests de sécurité automatisés

```bash
npm run test:security
```

#### Couverture des tests
- ✅ Health check
- ✅ Headers de sécurité (Helmet)
- ✅ Rate limiting (API + Auth)
- ✅ Validation des entrées
- ✅ Flux d'authentification complet
- ✅ Protection SQL Injection
- ✅ Protection XSS
- ✅ Configuration CORS
- ✅ Gestion des erreurs

#### Résultat attendu
```
╔═══════════════════════════════════════════════════════════╗
║     TESTS DE SÉCURITÉ - EventHub Backend API              ║
╚═══════════════════════════════════════════════════════════╝

✓ Tests réussis: 24
✗ Tests échoués: 1
⚠ Avertissements: 1

╔═══════════════════════════════════════════════════════════╗
║  SCORE DE SÉCURITÉ: 94%                                   ║
╚═══════════════════════════════════════════════════════════╝

✅ Excellent! Votre API est bien sécurisée.
```

---

## 🔄 CI/CD

Pipeline automatisé avec **GitHub Actions** (`.github/workflows/backend-ci.yml`)

### Déclencheurs
- Push sur `main` ou `master`
- Pull requests

### Étapes du pipeline

```yaml
1. ✅ Checkout du code
2. ✅ Setup Node.js 20 (avec cache npm)
3. ✅ Installation des dépendances (npm ci)
4. ✅ Setup MySQL 8 (service Docker)
5. ✅ Health checks de la BDD
6. ✅ Migrations de la base de données
7. ✅ Exécution des tests de sécurité
8. ✅ Smoke test (curl /api/health)
```

### Badge de statut
![CI Status](https://github.com/votre-username/eventhub-backend/workflows/Backend%20CI/badge.svg)

---

## 🗄️ Base de données

### Schéma relationnel

```
┌─────────────────┐
│     users       │
├─────────────────┤
│ id (PK)         │──┐
│ email (UNIQUE)  │  │
│ password_hash   │  │
│ first_name      │  │
│ last_name       │  │
│ phone           │  │
│ university      │  │
│ role (ENUM)     │  │
│ is_active       │  │
│ created_at      │  │
└─────────────────┘  │
                     │
        ┌────────────┴──────────┐
        │                       │
        ▼                       ▼
┌─────────────────┐    ┌──────────────────┐
│     events      │    │ activity_logs    │
├─────────────────┤    ├──────────────────┤
│ id (PK)         │◄─┐ │ id (PK)          │
│ name            │  │ │ user_id (FK)     │
│ description     │  │ │ action_type      │
│ date            │  │ │ action           │
│ category (ENUM) │  │ │ description      │
│ image           │  │ │ ip_address       │
│ organizer_id(FK)│──┘ │ user_agent       │
│ created_at      │    │ created_at       │
└─────────────────┘    └──────────────────┘
        │
        │
        ▼
┌────────────────────┐
│ event_participants │
├────────────────────┤
│ id (PK)            │
│ event_id (FK)      │──► Contrainte UNIQUE
│ user_id (FK)       │    (event_id, user_id)
│ registered_at      │
└────────────────────┘
```

### Tables principales

#### 1. **users** - Utilisateurs
- Authentification avec `password_hash` (bcrypt 12 rounds)
- Rôles : `user`, `organisateur`, `admin`
- Soft delete possible via `is_active`

#### 2. **events** - Événements
- 5 catégories : Ateliers, Conférences, Soirées, Hackathons, Séminaires
- Lié à un organisateur (`organizer_id`)
- Cascade delete si l'organisateur est supprimé

#### 3. **event_participants** - Inscriptions
- Relation Many-to-Many entre `users` et `events`
- Contrainte UNIQUE pour éviter les doublons
- Cascade delete automatique

#### 4. **activity_logs** - Logs d'audit
- 4 types : `auth`, `event`, `user`, `admin`
- Traçabilité complète avec IP et user-agent
- Métadonnées JSON pour contexte additionnel

### Index de performance

```sql
-- Événements
CREATE INDEX idx_date ON events(date);
CREATE INDEX idx_category ON events(category);
CREATE INDEX idx_organizer ON events(organizer_id);

-- Logs
CREATE INDEX idx_user_id ON activity_logs(user_id);
CREATE INDEX idx_action_type ON activity_logs(action_type);
CREATE INDEX idx_created_at ON activity_logs(created_at);
CREATE INDEX idx_user_action ON activity_logs(user_id, action_type, created_at);
```

---

## 📊 Statistiques du projet

| Métrique | Valeur |
|----------|--------|
| **Lignes de code** | ~1500 |
| **Endpoints API** | 25+ |
| **Tables BDD** | 4 |
| **Score sécurité** | 94% |
| **Tests automatisés** | 25+ |
| **Dépendances** | 15 |

---

## 🛠️ Scripts NPM

```json
{
  "scripts": {
    "start": "node index.js",
    "test:security": "node test.js"
  }
}
```

---

## 📝 Variables d'environnement requises

| Variable | Description | Exemple |
|----------|-------------|---------|
| `PORT` | Port du serveur | `3000` |
| `NODE_ENV` | Environnement | `test` / `production` |
| `DB_HOST` | Hôte MySQL | `localhost` |
| `DB_USER` | Utilisateur BDD | `root` |
| `DB_PASSWORD` | Mot de passe BDD | `password` |
| `DB_NAME` | Nom de la BDD | `eventhub` |
| `JWT_SECRET` | Secret JWT (32+ chars) | `super_secret_key_...` |
| `ALLOWED_ORIGINS` | Origines CORS (séparées par ,) | `http://localhost:5500` |
| `LOG_LEVEL` | Niveau de log | `info` / `debug` / `error` |

---

## 👨‍💻 Auteur

**LISSILLOUR Arthur**
**ALVES SERGIO Tony**
**BRAHIMI Merwan**
**LEGRAND Quentin**

---

## 🙏 Remerciements

- [Express.js](https://expressjs.com/)
- [MySQL](https://www.mysql.com/)
- [JWT](https://jwt.io/)
- [Helmet](https://helmetjs.github.io/)
- [Winston](https://github.com/winstonjs/winston)

---