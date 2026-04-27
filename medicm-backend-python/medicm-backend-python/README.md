# MedicM Pro - Backend Python

Backend Flask pour l'application MedicM Pro - Système de Gestion Médicale Avancé.

## Installation

### Prérequis
- Python 3.8+
- pip ou pipenv
- MySQL/PostgreSQL (optionnel, SQLite par défaut)

### Setup

1. **Cloner le repository**
```bash
git clone <repository-url>
cd medicm-backend-python
```

2. **Créer un environnement virtuel**
```bash
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate
```

3. **Installer les dépendances**
```bash
pip install -r requirements.txt
```

4. **Configurer les variables d'environnement**
```bash
cp .env.example .env
# Éditer .env avec vos paramètres
```

5. **Initialiser la base de données**
```bash
python
>>> from app import create_app, db
>>> app = create_app()
>>> with app.app_context():
>>>     db.create_all()
>>> exit()
```

6. **Lancer le serveur**
```bash
python app.py
```

Le serveur sera disponible sur `http://localhost:5000`

## Structure du Projet

```
medicm-backend-python/
├── app.py              # Application Flask principale
├── config.py           # Configuration
├── models.py           # Modèles SQLAlchemy
├── routes.py           # Routes API
├── requirements.txt    # Dépendances Python
├── .env.example        # Exemple de configuration
└── README.md           # Ce fichier
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Enregistrer un nouvel utilisateur
- `POST /api/auth/login` - Se connecter
- `GET /api/auth/me` - Obtenir l'utilisateur courant

### Users
- `GET /api/users` - Lister les utilisateurs
- `GET /api/users/<id>` - Obtenir un utilisateur
- `PUT /api/users/<id>` - Mettre à jour un utilisateur
- `PUT /api/users/<id>/role` - Mettre à jour le rôle (admin seulement)
- `DELETE /api/users/<id>` - Supprimer un utilisateur (admin seulement)

### Patients
- `GET /api/patients` - Lister les patients
- `POST /api/patients` - Créer un patient
- `GET /api/patients/<id>` - Obtenir un patient
- `PUT /api/patients/<id>` - Mettre à jour un patient
- `DELETE /api/patients/<id>` - Supprimer un patient

### Health Centers
- `GET /api/health-centers` - Lister les centres de santé
- `POST /api/health-centers` - Créer un centre (admin seulement)
- `GET /api/health-centers/<id>` - Obtenir un centre
- `PUT /api/health-centers/<id>` - Mettre à jour un centre (admin seulement)

### Alerts
- `GET /api/alerts` - Lister les alertes
- `PUT /api/alerts/<id>/read` - Marquer une alerte comme lue

### Analysis
- `POST /api/analysis` - Créer une analyse
- `GET /api/analysis` - Lister les analyses

### Admin
- `GET /api/admin/stats` - Obtenir les statistiques (admin seulement)
- `GET /api/admin/audit-logs` - Obtenir les logs d'audit (admin seulement)

## Authentification

L'API utilise JWT (JSON Web Tokens) pour l'authentification.

1. Se connecter: `POST /api/auth/login`
2. Inclure le token dans les headers: `Authorization: Bearer <token>`

## Rôles et Permissions

- **Admin**: Accès complet
- **Doctor**: Accès aux patients et analyses
- **Health Agent**: Accès limité aux patients
- **User**: Accès basique

## Base de Données

### Modèles
- **User**: Utilisateurs du système
- **HealthCenter**: Centres de santé
- **Patient**: Dossiers patients
- **Alert**: Alertes système
- **AuditLog**: Logs d'audit
- **Notification**: Notifications utilisateur
- **Analysis**: Analyses épidémiologiques

## Déploiement

### Production avec Gunicorn

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:create_app()
```

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:create_app()"]
```

## Développement

### Tests

```bash
python -m pytest
```

### Linting

```bash
flake8 .
```

### Format Code

```bash
black .
```

## Support

Pour toute question ou problème, veuillez créer une issue sur le repository.

## Licence

MIT License
