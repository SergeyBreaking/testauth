from functools import wraps
from flask import jsonify, g
from models import RolePermission, Permission, Resource


def check_permission(resource_name, permission_name):
    user = g.current_user
    
    if not user:
        return False
    
    for user_role in user.roles:
        role = user_role.role
        
        role_permission = RolePermission.query.filter_by(
            role_id=role.id
        ).join(Permission).filter(
            Permission.name == permission_name
        ).join(Resource).filter(
            Resource.name == resource_name
        ).first()
        
        if role_permission:
            return True
    
    return False


def require_permission(resource_name, permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not check_permission(resource_name, permission_name):
                return jsonify({
                    'error': 'Access denied',
                    'message': f'You do not have permission to {permission_name} on {resource_name}'
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def has_permission(user, resource_name, permission_name):
    for user_role in user.roles:
        role = user_role.role
        
        role_permission = RolePermission.query.filter_by(
            role_id=role.id
        ).join(Permission).filter(
            Permission.name == permission_name
        ).join(Resource).filter(
            Resource.name == resource_name
        ).first()
        
        if role_permission:
            return True
    
    return False
