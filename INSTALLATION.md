# MedicM Pro - Guide d'Installation Complet

## 📋 Prérequis

- **Node.js** 18+ et npm/pnpm
- **Python** 3.8+
- **Git**
- **Docker** (optionnel, pour le déploiement)

## 🚀 Installation Rapide

### 1. Frontend (React + TypeScript + Tailwind)

```bash
# Cloner et naviguer
cd medicm-pro-complete

# Installer les dépendances
pnpm install

# Lancer le serveur de développement
pnpm dev
```

L'application sera disponible sur `http://localhost:3000`

### 2. Backend (Python Flask)

```bash
# Extraire le backend
unzip medicm-backend-python.zip
cd medicm-backend-python

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Configurer l'environnement
cp .env.example .env
# Éditer .env avec vos paramètres

# Initialiser la base de données
python
>>> from app import create_app, db
>>> app = create_app()
>>> with app.app_context():
>>>     db.create_all()
>>> exit()

# Lancer le serveur
python app.py
```

Le backend sera disponible sur `http://localhost:5000`

## 📁 Structure du Projet

```
medicm-pro-complete/
├── client/                    # Frontend React
│   ├── src/
│   │   ├── pages/            # Pages de l'application
│   │   ├── components/       # Composants réutilisables
│   │   ├── lib/              # Utilitaires
│   │   └── App.tsx           # Composant principal
│   └── index.html
├── server/                    # Backend Node.js (tRPC)
│   ├── routers.ts            # Routes API
│   └── db.ts                 # Requêtes base de données
├── drizzle/                   # Migrations base de données
├── medicm-backend-python.zip  # Backend Python Flask
├── package.json              # Dépendances Node.js
├── vite.config.ts            # Configuration Vite
└── README.md

medicm-backend-python/
├── app.py                    # Application Flask
├── models.py                 # Modèles SQLAlchemy
├── routes.py                 # Routes API
├── config.py                 # Configuration
├── requirements.txt          # Dépendances Python
├── Dockerfile                # Image Docker
└── docker-compose.yml        # Orchestration Docker
```

## 🎯 Fonctionnalités Principales

### Frontend
- ✅ Landing page publique
- ✅ Mode démo sans authentification
- ✅ Tableau de bord admin professionnel
- ✅ KPIs animés avec graphiques Recharts
- ✅ Gestion des patients avec exports PDF/CSV
- ✅ Gestion multi-rôles (admin, doctor, health_agent)
- ✅ Analyses avancées avec filtres
- ✅ Paramètres professionnels
- ✅ Thème clair/sombre
- ✅ Interface responsive

### Backend Node.js (tRPC)
- ✅ Authentification OAuth Manus
- ✅ API tRPC type-safe
- ✅ Base de données MySQL/TiDB
- ✅ Gestion des rôles et permissions
- ✅ Audit log complet
- ✅ Notifications en temps réel

### Backend Python (Flask)
- ✅ API REST complète
- ✅ Authentification JWT
- ✅ Modèles SQLAlchemy
- ✅ Support MySQL/PostgreSQL/SQLite
- ✅ CORS configuré
- ✅ Prêt pour Docker

## 🔐 Authentification

### Frontend
- Authentification OAuth Manus intégrée
- Session persistante
- Mode démo sans authentification

### Backend Python
```bash
# Enregistrement
POST /api/auth/register
{
  "email": "user@example.com",
  "password": "password",
  "full_name": "Jean Dupont",
  "region": "Centre"
}

# Connexion
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "password"
}
```

## 📊 Base de Données

### Modèles Principaux
- **User**: Utilisateurs du système
- **HealthCenter**: Centres de santé
- **Patient**: Dossiers patients
- **Alert**: Alertes système
- **AuditLog**: Logs d'audit
- **Notification**: Notifications
- **Analysis**: Analyses épidémiologiques

### Migration
```bash
# Frontend (Node.js)
pnpm drizzle-kit generate
pnpm drizzle-kit migrate

# Backend (Python)
# Les tables sont créées automatiquement au démarrage
```

## 🐳 Déploiement avec Docker

### Backend Python
```bash
cd medicm-backend-python

# Build
docker build -t medicm-backend:latest .

# Run
docker run -p 5000:5000 \
  -e FLASK_ENV=production \
  -e SECRET_KEY=your-secret-key \
  medicm-backend:latest

# Avec docker-compose
docker-compose up -d
```

### Frontend
```bash
# Build
pnpm build

# Servir avec un serveur web
npm install -g serve
serve dist
```

## 🧪 Tests

```bash
# Tests frontend
pnpm test

# Tests backend Python
cd medicm-backend-python
python -m pytest
```

## 📝 Variables d'Environnement

### Frontend (.env)
```
VITE_API_URL=http://localhost:5000
VITE_APP_TITLE=MedicM Pro
```

### Backend Python (.env)
```
FLASK_ENV=development
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
DATABASE_URL=sqlite:///medicm.db
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
```

## 🚨 Dépannage

### Port déjà utilisé
```bash
# Frontend (port 3000)
pnpm dev -- --port 3001

# Backend (port 5000)
python app.py --port 5001
```

### Base de données
```bash
# Réinitialiser la base de données
rm medicm.db  # SQLite
# Ou vider la base MySQL/PostgreSQL
```

### Erreurs CORS
Vérifier que `CORS_ORIGINS` inclut l'URL du frontend

## 📚 Documentation

- **Frontend**: Voir `client/README.md`
- **Backend Python**: Voir `medicm-backend-python/README.md`
- **API Routes**: Voir `medicm-backend-python/README.md#api-endpoints`

## 🤝 Support

Pour toute question ou problème:
1. Vérifier la documentation
2. Consulter les logs (`pnpm dev` ou `python app.py`)
3. Créer une issue sur le repository

## 📄 Licence

MIT License

## 🎉 Prêt à démarrer!

```bash
# Terminal 1 - Frontend
cd medicm-pro-complete
pnpm install
pnpm dev

# Terminal 2 - Backend Python
cd medicm-backend-python
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Accédez à l'application sur `http://localhost:3000`
