from flask import Blueprint, request, jsonify, g
from models import db, User, Role, Permission, Resource, RolePermission, UserRole
from auth import login_required, generate_jwt_token
from permissions import require_permission, has_permission
from datetime import datetime, timedelta
import re

api = Blueprint('api', __name__)


def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


@api.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    required_fields = ['email', 'password', 'first_name', 'last_name']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Field {field} is required'}), 400

    email = data['email'].strip().lower()
    password = data['password']
    password_confirm = data.get('password_confirm', '')
    first_name = data['first_name'].strip()
    last_name = data['last_name'].strip()
    surname = data.get('surname', '').strip() or None

    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400

    if password != password_confirm:
        return jsonify({'error': 'Passwords do not match'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'User with this email already exists'}), 409

    user = User(
        email=email,
        first_name=first_name,
        last_name=last_name,
        surname=surname
    )
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify({
        'message': 'User registered successfully',
        'user': user.to_dict()
    }), 201


@api.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()

    if 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password are required'}), 400

    email = data['email'].strip().lower()
    password = data['password']

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid email or password'}), 401

    if not user.is_active:
        return jsonify({'error': 'Account is deactivated'}), 403

    token = generate_jwt_token(user)
    expires_at = datetime.utcnow() + timedelta(days=7)

    return jsonify({
        'message': 'Login successful',
        'token': token,
        'expires_at': expires_at.isoformat(),
        'user': user.to_dict()
    }), 200


@api.route('/auth/logout', methods=['POST'])
@login_required
def logout():
    return jsonify({
        'message': 'Logout successful',
        'note': 'Please delete the token on client side'
    }), 200


@api.route('/auth/profile', methods=['GET'])
@login_required
def get_profile():
    return jsonify({'user': g.current_user.to_dict()}), 200


@api.route('/auth/profile', methods=['PUT'])
@login_required
def update_profile():
    data = request.get_json()
    user = g.current_user

    if 'first_name' in data:
        user.first_name = data['first_name'].strip()

    if 'last_name' in data:
        user.last_name = data['last_name'].strip()

    if 'surname' in data:
        user.surname = data['surname'].strip() or None

    if 'email' in data:
        new_email = data['email'].strip().lower()
        if not validate_email(new_email):
            return jsonify({'error': 'Invalid email format'}), 400

        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({'error': 'Email already in use'}), 409

        user.email = new_email

    if 'password' in data:
        password = data['password']
        password_confirm = data.get('password_confirm', '')

        if password != password_confirm:
            return jsonify({'error': 'Passwords do not match'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        user.set_password(password)

    user.updated_at = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'message': 'Profile updated successfully',
        'user': user.to_dict()
    }), 200


@api.route('/auth/profile', methods=['DELETE'])
@login_required
def delete_profile():
    user = g.current_user
    user.is_active = False
    user.updated_at = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'message': 'Account deactivated successfully',
        'note': 'Your account has been deactivated'
    }), 200


@api.route('/resources/products', methods=['GET'])
@login_required
@require_permission('products', 'read')
def get_products():
    mock_products = [
        {'id': 1, 'name': 'Ноутбук Lenovo ThinkPad', 'price': 87500},
        {'id': 2, 'name': 'Монитор Samsung 27"', 'price': 23400},
        {'id': 3, 'name': 'Клавиатура механическая', 'price': 8900},
    ]
    return jsonify({'products': mock_products}), 200


@api.route('/resources/products/<int:product_id>', methods=['GET'])
@login_required
@require_permission('products', 'read')
def get_product(product_id):
    mock_product = {'id': product_id, 'name': f'Товар #{product_id}', 'price': product_id * 12000}
    return jsonify({'product': mock_product}), 200


@api.route('/resources/products', methods=['POST'])
@login_required
@require_permission('products', 'create')
def create_product():
    data = request.get_json()
    mock_product = {
        'id': 999,
        'name': data.get('name', 'Новый товар'),
        'price': data.get('price', 0)
    }
    return jsonify({'product': mock_product, 'message': 'Product created (mock)'}), 201


@api.route('/resources/orders', methods=['GET'])
@login_required
@require_permission('orders', 'read')
def get_orders():
    mock_orders = [
        {'id': 1, 'user_id': g.current_user.id, 'total': 125000, 'date': '2026-02-01'},
        {'id': 2, 'user_id': g.current_user.id, 'total': 45600, 'date': '2026-02-01'},
    ]
    return jsonify({'orders': mock_orders}), 200


@api.route('/resources/reports', methods=['GET'])
@login_required
@require_permission('reports', 'read')
def get_reports():
    mock_reports = [
        {'id': 1, 'name': 'Отчет по продажам за январь', 'date': '2026-02-01'},
        {'id': 2, 'name': 'Аналитика склада', 'date': '2026-02-01'},
    ]
    return jsonify({'reports': mock_reports}), 200


@api.route('/admin/role-permissions', methods=['GET'])
@login_required
@require_permission('admin', 'read')
def get_role_permissions():
    role_permissions = RolePermission.query.all()

    result = []
    for rp in role_permissions:
        result.append({
            'id': rp.id,
            'role': rp.role.name,
            'permission': rp.permission.name,
            'resource': rp.resource.name
        })

    return jsonify({'role_permissions': result}), 200


@api.route('/admin/role-permissions', methods=['POST'])
@login_required
@require_permission('admin', 'create')
def create_role_permission():
    data = request.get_json()

    required_fields = ['role_id', 'permission_id', 'resource_id']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Field {field} is required'}), 400

    role_id = data['role_id']
    permission_id = data['permission_id']
    resource_id = data['resource_id']

    if not Role.query.get(role_id):
        return jsonify({'error': 'Role not found'}), 404

    if not Permission.query.get(permission_id):
        return jsonify({'error': 'Permission not found'}), 404

    if not Resource.query.get(resource_id):
        return jsonify({'error': 'Resource not found'}), 404

    existing = RolePermission.query.filter_by(
        role_id=role_id,
        permission_id=permission_id,
        resource_id=resource_id
    ).first()

    if existing:
        return jsonify({'error': 'This already exists'}), 409

    role_permission = RolePermission(
        role_id=role_id,
        permission_id=permission_id,
        resource_id=resource_id
    )

    db.session.add(role_permission)
    db.session.commit()

    return jsonify({
        'message': 'Role permission created successfully',
        'role_permission': {
            'id': role_permission.id,
            'role': role_permission.role.name,
            'permission': role_permission.permission.name,
            'resource': role_permission.resource.name
        }
    }), 201


@api.route('/admin/role-permissions/<int:rp_id>', methods=['DELETE'])
@login_required
@require_permission('admin', 'delete')
def delete_role_permission(rp_id):
    role_permission = RolePermission.query.get(rp_id)

    if not role_permission:
        return jsonify({'error': 'Role permission not found'}), 404

    db.session.delete(role_permission)
    db.session.commit()

    return jsonify({'message': 'Role permission deleted successfully'}), 200
