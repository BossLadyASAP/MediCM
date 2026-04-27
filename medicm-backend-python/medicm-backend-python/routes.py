"""
Routes API pour MedicM Pro
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, HealthCenter, Patient, Alert, AuditLog, Notification, Analysis, UserRole, SeverityLevel
from datetime import datetime
from functools import wraps
import json

# Blueprints
auth_bp = Blueprint('auth', __name__)
users_bp = Blueprint('users', __name__)
patients_bp = Blueprint('patients', __name__)
health_centers_bp = Blueprint('health_centers', __name__)
alerts_bp = Blueprint('alerts', __name__)
analysis_bp = Blueprint('analysis', __name__)
admin_bp = Blueprint('admin', __name__)

# Helper functions
def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or user.role != UserRole.ADMIN:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def log_action(user_id, action, entity_type, entity_id, old_values=None, new_values=None):
    """Enregistre une action dans l'audit log"""
    log = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        old_values=old_values,
        new_values=new_values,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

# ============ AUTH ROUTES ============
@auth_bp.route('/register', methods=['POST'])
def register():
    """Enregistrer un nouvel utilisateur"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 409
    
    user = User(
        email=data['email'],
        full_name=data.get('full_name', ''),
        region=data.get('region'),
        role=UserRole.USER
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify(user.to_dict()), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    """Connexion utilisateur"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    access_token = create_access_token(identity=user.id)
    return jsonify({
        'access_token': access_token,
        'user': user.to_dict()
    }), 200

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Obtenir l'utilisateur courant"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user.to_dict()), 200

# ============ USERS ROUTES ============
@users_bp.route('', methods=['GET'])
@jwt_required()
def list_users():
    """Lister tous les utilisateurs"""
    users = User.query.all()
    return jsonify([u.to_dict() for u in users]), 200

@users_bp.route('/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Obtenir un utilisateur"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user.to_dict()), 200

@users_bp.route('/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """Mettre à jour un utilisateur"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    old_values = user.to_dict()
    
    if 'full_name' in data:
        user.full_name = data['full_name']
    if 'region' in data:
        user.region = data['region']
    if 'health_center_id' in data:
        user.health_center_id = data['health_center_id']
    
    db.session.commit()
    
    current_user_id = get_jwt_identity()
    log_action(current_user_id, 'UPDATE', 'User', user_id, old_values, user.to_dict())
    
    return jsonify(user.to_dict()), 200

@users_bp.route('/<int:user_id>/role', methods=['PUT'])
@admin_required
def update_user_role(user_id):
    """Mettre à jour le rôle d'un utilisateur"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    if 'role' not in data:
        return jsonify({'error': 'Role required'}), 400
    
    old_role = user.role.value
    user.role = UserRole[data['role'].upper()]
    db.session.commit()
    
    current_user_id = get_jwt_identity()
    log_action(current_user_id, 'UPDATE_ROLE', 'User', user_id, 
               {'role': old_role}, {'role': user.role.value})
    
    return jsonify(user.to_dict()), 200

@users_bp.route('/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """Supprimer un utilisateur"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    current_user_id = get_jwt_identity()
    log_action(current_user_id, 'DELETE', 'User', user_id)
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'User deleted'}), 200

# ============ PATIENTS ROUTES ============
@patients_bp.route('', methods=['GET'])
@jwt_required()
def list_patients():
    """Lister les patients"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = Patient.query
    
    # Filters
    if request.args.get('health_center_id'):
        query = query.filter_by(health_center_id=request.args.get('health_center_id', type=int))
    if request.args.get('severity'):
        query = query.filter_by(severity=SeverityLevel[request.args.get('severity').upper()])
    if request.args.get('region'):
        query = query.filter_by(region=request.args.get('region'))
    
    pagination = query.paginate(page=page, per_page=per_page)
    
    return jsonify({
        'patients': [p.to_dict() for p in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    }), 200

@patients_bp.route('', methods=['POST'])
@jwt_required()
def create_patient():
    """Créer un patient"""
    data = request.get_json()
    
    if not data.get('full_name') or not data.get('health_center_id'):
        return jsonify({'error': 'full_name and health_center_id required'}), 400
    
    patient = Patient(
        health_center_id=data['health_center_id'],
        full_name=data['full_name'],
        age=data.get('age'),
        sex=data.get('sex'),
        email=data.get('email'),
        phone=data.get('phone'),
        address=data.get('address'),
        region=data.get('region'),
        primary_pathology=data.get('primary_pathology'),
        severity=SeverityLevel[data.get('severity', 'LIGHT').upper()],
        temperature=data.get('temperature'),
        patient_satisfaction=data.get('patient_satisfaction', 0.0),
        medical_history=data.get('medical_history'),
        last_visit=datetime.utcnow()
    )
    
    db.session.add(patient)
    db.session.commit()
    
    current_user_id = get_jwt_identity()
    log_action(current_user_id, 'CREATE', 'Patient', patient.id, None, patient.to_dict())
    
    return jsonify(patient.to_dict()), 201

@patients_bp.route('/<int:patient_id>', methods=['GET'])
@jwt_required()
def get_patient(patient_id):
    """Obtenir un patient"""
    patient = Patient.query.get(patient_id)
    if not patient:
        return jsonify({'error': 'Patient not found'}), 404
    return jsonify(patient.to_dict()), 200

@patients_bp.route('/<int:patient_id>', methods=['PUT'])
@jwt_required()
def update_patient(patient_id):
    """Mettre à jour un patient"""
    patient = Patient.query.get(patient_id)
    if not patient:
        return jsonify({'error': 'Patient not found'}), 404
    
    data = request.get_json()
    old_values = patient.to_dict()
    
    if 'full_name' in data:
        patient.full_name = data['full_name']
    if 'age' in data:
        patient.age = data['age']
    if 'severity' in data:
        patient.severity = SeverityLevel[data['severity'].upper()]
    if 'temperature' in data:
        patient.temperature = data['temperature']
    if 'patient_satisfaction' in data:
        patient.patient_satisfaction = data['patient_satisfaction']
    if 'medical_history' in data:
        patient.medical_history = data['medical_history']
    
    patient.updated_at = datetime.utcnow()
    patient.last_visit = datetime.utcnow()
    db.session.commit()
    
    current_user_id = get_jwt_identity()
    log_action(current_user_id, 'UPDATE', 'Patient', patient_id, old_values, patient.to_dict())
    
    return jsonify(patient.to_dict()), 200

@patients_bp.route('/<int:patient_id>', methods=['DELETE'])
@jwt_required()
def delete_patient(patient_id):
    """Supprimer un patient"""
    patient = Patient.query.get(patient_id)
    if not patient:
        return jsonify({'error': 'Patient not found'}), 404
    
    current_user_id = get_jwt_identity()
    log_action(current_user_id, 'DELETE', 'Patient', patient_id)
    
    db.session.delete(patient)
    db.session.commit()
    
    return jsonify({'message': 'Patient deleted'}), 200

# ============ HEALTH CENTERS ROUTES ============
@health_centers_bp.route('', methods=['GET'])
@jwt_required()
def list_health_centers():
    """Lister les centres de santé"""
    centers = HealthCenter.query.all()
    return jsonify([c.to_dict() for c in centers]), 200

@health_centers_bp.route('', methods=['POST'])
@admin_required
def create_health_center():
    """Créer un centre de santé"""
    data = request.get_json()
    
    if not data.get('name') or not data.get('region'):
        return jsonify({'error': 'name and region required'}), 400
    
    center = HealthCenter(
        name=data['name'],
        region=data['region'],
        address=data.get('address'),
        phone=data.get('phone'),
        email=data.get('email'),
        director_name=data.get('director_name'),
        total_staff=data.get('total_staff', 0),
        total_beds=data.get('total_beds', 0)
    )
    
    db.session.add(center)
    db.session.commit()
    
    current_user_id = get_jwt_identity()
    log_action(current_user_id, 'CREATE', 'HealthCenter', center.id, None, center.to_dict())
    
    return jsonify(center.to_dict()), 201

@health_centers_bp.route('/<int:center_id>', methods=['GET'])
@jwt_required()
def get_health_center(center_id):
    """Obtenir un centre de santé"""
    center = HealthCenter.query.get(center_id)
    if not center:
        return jsonify({'error': 'Health center not found'}), 404
    return jsonify(center.to_dict()), 200

@health_centers_bp.route('/<int:center_id>', methods=['PUT'])
@admin_required
def update_health_center(center_id):
    """Mettre à jour un centre de santé"""
    center = HealthCenter.query.get(center_id)
    if not center:
        return jsonify({'error': 'Health center not found'}), 404
    
    data = request.get_json()
    old_values = center.to_dict()
    
    if 'name' in data:
        center.name = data['name']
    if 'region' in data:
        center.region = data['region']
    if 'address' in data:
        center.address = data['address']
    if 'phone' in data:
        center.phone = data['phone']
    if 'email' in data:
        center.email = data['email']
    if 'director_name' in data:
        center.director_name = data['director_name']
    if 'total_staff' in data:
        center.total_staff = data['total_staff']
    if 'total_beds' in data:
        center.total_beds = data['total_beds']
    
    db.session.commit()
    
    current_user_id = get_jwt_identity()
    log_action(current_user_id, 'UPDATE', 'HealthCenter', center_id, old_values, center.to_dict())
    
    return jsonify(center.to_dict()), 200

# ============ ALERTS ROUTES ============
@alerts_bp.route('', methods=['GET'])
@jwt_required()
def list_alerts():
    """Lister les alertes"""
    alerts = Alert.query.order_by(Alert.created_at.desc()).all()
    return jsonify([a.to_dict() for a in alerts]), 200

@alerts_bp.route('/<int:alert_id>/read', methods=['PUT'])
@jwt_required()
def mark_alert_read(alert_id):
    """Marquer une alerte comme lue"""
    alert = Alert.query.get(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    alert.is_read = True
    db.session.commit()
    
    return jsonify(alert.to_dict()), 200

# ============ ANALYSIS ROUTES ============
@analysis_bp.route('', methods=['POST'])
@jwt_required()
def create_analysis():
    """Créer une analyse"""
    data = request.get_json()
    
    analysis = Analysis(
        health_center_id=data.get('health_center_id'),
        analysis_type=data.get('analysis_type'),
        filters=data.get('filters'),
        results=data.get('results'),
        ai_insights=data.get('ai_insights')
    )
    
    db.session.add(analysis)
    db.session.commit()
    
    return jsonify(analysis.to_dict()), 201

@analysis_bp.route('', methods=['GET'])
@jwt_required()
def list_analyses():
    """Lister les analyses"""
    analyses = Analysis.query.order_by(Analysis.created_at.desc()).all()
    return jsonify([a.to_dict() for a in analyses]), 200

# ============ ADMIN ROUTES ============
@admin_bp.route('/stats', methods=['GET'])
@admin_required
def get_admin_stats():
    """Obtenir les statistiques admin"""
    total_patients = Patient.query.count()
    total_centers = HealthCenter.query.count()
    total_users = User.query.count()
    severe_cases = Patient.query.filter_by(severity=SeverityLevel.SEVERE).count()
    
    return jsonify({
        'total_patients': total_patients,
        'total_centers': total_centers,
        'total_users': total_users,
        'severe_cases': severe_cases,
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@admin_bp.route('/audit-logs', methods=['GET'])
@admin_required
def get_audit_logs():
    """Obtenir les logs d'audit"""
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return jsonify([l.to_dict() for l in logs]), 200
