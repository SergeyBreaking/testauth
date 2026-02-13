from functools import wraps
from flask import request, jsonify, g
from datetime import datetime, timedelta
import jwt
from models import db, User
from config import Config


def generate_jwt_token(user):
    now = datetime.utcnow()
    payload = {
        'user_id': user.id,
        'email': user.email,
        'roles': [user_role.role.name for user_role in user.roles],
        'iat': int(now.timestamp()),
        'exp': int((now + Config.JWT_EXPIRATION_DELTA).timestamp())
    }
    
    token = jwt.encode(payload, Config.SECRET_KEY, algorithm=Config.JWT_ALGORITHM)
    return token


def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        return None
    
    try:
        token = auth_header.split(' ')[1]
    except IndexError:
        return None
    
    payload = decode_jwt_token(token)
    
    if not payload:
        return None
    
    user_id = payload.get('user_id')
    if not user_id:
        return None
    
    user = User.query.get(user_id)
    
    if not user or not user.is_active:
        return None
    
    return user


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        
        g.current_user = user
        return f(*args, **kwargs)
    
    return decorated_function
