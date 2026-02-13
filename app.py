import os
from datetime import datetime
from flask import Flask
from config import Config
from models import db, User, Role, Permission, Resource, RolePermission, UserRole
from routes import api

app = Flask(__name__, instance_relative_config=False)
app.config.from_object(Config)

db.init_app(app)
app.register_blueprint(api, url_prefix='/api')


def init_database():
    db.create_all()
    
    if Role.query.first() is None:
        admin_role = Role(name='admin', description='Full system access')
        manager_role = Role(name='manager', description='Management operations')
        user_role = Role(name='user', description='Standard access')
        
        db.session.add(admin_role)
        db.session.add(manager_role)
        db.session.add(user_role)
        db.session.commit()
        
        read_perm = Permission(name='read', description='View resources')
        create_perm = Permission(name='create', description='Add new items')
        update_perm = Permission(name='update', description='Modify existing')
        delete_perm = Permission(name='delete', description='Remove items')
        
        db.session.add(read_perm)
        db.session.add(create_perm)
        db.session.add(update_perm)
        db.session.add(delete_perm)
        db.session.commit()
        
        products_resource = Resource(name='products', description='Product catalog')
        orders_resource = Resource(name='orders', description='Order processing')
        reports_resource = Resource(name='reports', description='Analytics data')
        admin_resource = Resource(name='admin', description='System administration')
        
        db.session.add(products_resource)
        db.session.add(orders_resource)
        db.session.add(reports_resource)
        db.session.add(admin_resource)
        db.session.commit()
        
        def assign_permissions(role_id, resources, permissions):
            for resource in resources:
                for permission in permissions:
                    rp = RolePermission(role_id=role_id, permission_id=permission.id, resource_id=resource.id)
                    db.session.add(rp)
        
        assign_permissions(admin_role.id,
                          [products_resource, orders_resource, reports_resource, admin_resource],
                          [read_perm, create_perm, update_perm, delete_perm])
        
        assign_permissions(manager_role.id,
                          [products_resource, orders_resource],
                          [read_perm, create_perm, update_perm])
        
        assign_permissions(manager_role.id,
                          [reports_resource],
                          [read_perm])
        
        assign_permissions(user_role.id,
                          [products_resource, orders_resource],
                          [read_perm])
        
        db.session.commit()
        
        admin_user = User(
            email='test1@mail.ru',
            first_name='admin',
            last_name='amdin2',
            surname='admin3'
        )
        admin_user.set_password('SecurePass2026')
        
        manager_user = User(
            email='test2@mail.ru',
            first_name='manager',
            last_name='manager2',
            surname='manager3'
        )
        manager_user.set_password('Manager2026!')
        
        regular_user = User(
            email='test3@mail.ru',
            first_name='user',
            last_name='user2',
            surname=None
        )
        regular_user.set_password('UserPass2026')
        
        db.session.add(admin_user)
        db.session.add(manager_user)
        db.session.add(regular_user)
        db.session.commit()
        
        admin_user_role = UserRole(user_id=admin_user.id, role_id=admin_role.id)
        manager_user_role = UserRole(user_id=manager_user.id, role_id=manager_role.id)
        regular_user_role = UserRole(user_id=regular_user.id, role_id=user_role.id)
        
        db.session.add(admin_user_role)
        db.session.add(manager_user_role)
        db.session.add(regular_user_role)
        db.session.commit()


@app.route('/')
def index():
    return {
        'message': 'Тестовое задание',
        'endpoints': {
            'auth': '/api/auth/*',
            'resources': '/api/resources/*',
            'admin': '/api/admin/*'
        }
    }


if __name__ == '__main__':
    os.makedirs('database', exist_ok=True)
    with app.app_context():
        init_database()
    app.run(debug=True)
