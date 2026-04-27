"""
Modèles SQLAlchemy pour MedicM Pro
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from enum import Enum
import bcrypt

db = SQLAlchemy()

class UserRole(Enum):
    """Rôles utilisateur"""
    ADMIN = "admin"
    DOCTOR = "doctor"
    HEALTH_AGENT = "health_agent"
    USER = "user"

class SeverityLevel(Enum):
    """Niveaux de sévérité"""
    LIGHT = "Légère"
    MODERATE = "Modérée"
    SEVERE = "Sévère"

class User(db.Model):
    """Modèle utilisateur"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    health_center_id = db.Column(db.Integer, db.ForeignKey('health_centers.id'))
    region = db.Column(db.String(100))
    role = db.Column(db.Enum(UserRole), default=UserRole.USER)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    health_center = db.relationship('HealthCenter', backref='users')
    
    def set_password(self, password):
        """Hash et stocke le mot de passe"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        """Vérifie le mot de passe"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'full_name': self.full_name,
            'health_center_id': self.health_center_id,
            'region': self.region,
            'role': self.role.value,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
        }

class HealthCenter(db.Model):
    """Modèle centre de santé"""
    __tablename__ = 'health_centers'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    region = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(500))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(255))
    director_name = db.Column(db.String(255))
    total_staff = db.Column(db.Integer, default=0)
    total_beds = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    patients = db.relationship('Patient', backref='health_center', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'region': self.region,
            'address': self.address,
            'phone': self.phone,
            'email': self.email,
            'director_name': self.director_name,
            'total_staff': self.total_staff,
            'total_beds': self.total_beds,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
        }

class Patient(db.Model):
    """Modèle patient"""
    __tablename__ = 'patients'
    
    id = db.Column(db.Integer, primary_key=True)
    health_center_id = db.Column(db.Integer, db.ForeignKey('health_centers.id'), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    age = db.Column(db.Integer)
    sex = db.Column(db.String(20))
    email = db.Column(db.String(255))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(500))
    region = db.Column(db.String(100))
    primary_pathology = db.Column(db.String(255))
    severity = db.Column(db.Enum(SeverityLevel), default=SeverityLevel.LIGHT)
    temperature = db.Column(db.Float)
    patient_satisfaction = db.Column(db.Float, default=0.0)
    medical_history = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_visit = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'health_center_id': self.health_center_id,
            'full_name': self.full_name,
            'age': self.age,
            'sex': self.sex,
            'email': self.email,
            'phone': self.phone,
            'address': self.address,
            'region': self.region,
            'primary_pathology': self.primary_pathology,
            'severity': self.severity.value,
            'temperature': self.temperature,
            'patient_satisfaction': self.patient_satisfaction,
            'medical_history': self.medical_history,
            'created_at': self.created_at.isoformat(),
            'last_visit': self.last_visit.isoformat() if self.last_visit else None,
        }

class Alert(db.Model):
    """Modèle alerte"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'))
    health_center_id = db.Column(db.Integer, db.ForeignKey('health_centers.id'))
    severity = db.Column(db.Enum(SeverityLevel), default=SeverityLevel.LIGHT)
    message = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    patient = db.relationship('Patient')
    
    def to_dict(self):
        return {
            'id': self.id,
            'patient_id': self.patient_id,
            'health_center_id': self.health_center_id,
            'severity': self.severity.value,
            'message': self.message,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat(),
        }

class AuditLog(db.Model):
    """Modèle audit log"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(255), nullable=False)
    entity_type = db.Column(db.String(100))
    entity_id = db.Column(db.Integer)
    old_values = db.Column(db.JSON)
    new_values = db.Column(db.JSON)
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'entity_type': self.entity_type,
            'entity_id': self.entity_id,
            'old_values': self.old_values,
            'new_values': self.new_values,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat(),
        }

class Notification(db.Model):
    """Modèle notification"""
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text)
    notification_type = db.Column(db.String(50))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'content': self.content,
            'notification_type': self.notification_type,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat(),
        }

class Analysis(db.Model):
    """Modèle analyse"""
    __tablename__ = 'analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    health_center_id = db.Column(db.Integer, db.ForeignKey('health_centers.id'))
    analysis_type = db.Column(db.String(100))
    filters = db.Column(db.JSON)
    results = db.Column(db.JSON)
    ai_insights = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    health_center = db.relationship('HealthCenter')
    
    def to_dict(self):
        return {
            'id': self.id,
            'health_center_id': self.health_center_id,
            'analysis_type': self.analysis_type,
            'filters': self.filters,
            'results': self.results,
            'ai_insights': self.ai_insights,
            'created_at': self.created_at.isoformat(),
        }
