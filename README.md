Система аутентификации и авторизации

Структура базы данных

Users - пользователи системы
- id (PK)
- email (уникальный)
- password_hash
- first_name
- last_name
- surname (опционально)
- is_active (для мягкого удаления)
- created_at, updated_at

Roles - роли пользователей
- id (PK)
- name (уникальный)
- description
- created_at

UserRoles - связь пользователей и ролей (многие-ко-многим)
- id (PK)
- user_id (FK → Users.id)
- role_id (FK → Roles.id)
- assigned_at
- уникальное ограничение на (user_id, role_id)

Resources - ресурсы системы (products, orders, reports, admin)
- id (PK)
- name (уникальный)
- description
- created_at

Permissions - действия (read, create, update, delete)
- id (PK)
- name (уникальный)
- description
- created_at

RolePermissions - связь ролей, разрешений и ресурсов (многие-ко-многим)
- id (PK)
- role_id (FK → Roles.id)
- permission_id (FK → Permissions.id)
- resource_id (FK → Resources.id)
- created_at
- уникальное ограничение на (role_id, permission_id, resource_id)

Как работает проверка доступа

1. Пользователь логинится, получает JWT токен с информацией о ролях
2. При запросе к ресурсу система проверяет токен
3. Если токена нет или он невалиден - возвращается 401
4. Если токен валиден, система проверяет есть ли у ролей пользователя нужное разрешение на ресурс
5. Если права есть - доступ разрешен, если нет - возвращается 403

Пользователь может иметь несколько ролей. Если хотя бы одна роль имеет нужное право - доступ разрешен.

Таблицы реализованы в models.py через SQLAlchemy ORM. Все внешние ключи с каскадным удалением.

API Endpoints

Аутентификация

**POST /api/auth/register** - регистрация
```
Body: {
  "email": "user@example.com",
  "password": "password123",
  "password_confirm": "password123",
  "first_name": "Иван",
  "last_name": "Иванов",
  "surname": "Иванович"
}
```

**POST /api/auth/login** - вход
```
Body: {
  "email": "user@example.com",
  "password": "password123"
}
Response: {
  "token": "...",
  "expires_at": "...",
  "user": {...}
}
```

**POST /api/auth/logout** - выход
```
Headers: Authorization: Bearer <token>
```

**GET /api/auth/profile** - получение профиля
```
Headers: Authorization: Bearer <token>
```

**PUT /api/auth/profile** - обновление профиля
```
Headers: Authorization: Bearer <token>
Body: {
  "first_name": "Новое имя",
  "last_name": "Новая фамилия",
  "surname": "Новое отчество",
  "email": "newemail@mail.ru",
  "password": "newpassword123",
  "password_confirm": "newpassword123"
}
```

**DELETE /api/auth/profile** - удаление аккаунта
```
Headers: Authorization: Bearer <token>
```

Бизнес-ресурсы

**GET /api/resources/products** - список продуктов (требует products.read)

**GET /api/resources/products/<product_id>** - продукт по ID (требует products.read)

**POST /api/resources/products** - создание продукта (требует products.create)
```
Body: {"name": "...", "price": 100}
```

**GET /api/resources/orders** - список заказов (требует orders.read)

**GET /api/resources/reports** - список отчетов (требует reports.read)

Административные endpoints

**GET /api/admin/role-permissions** - получить все правила доступа (требует admin.read)

**POST /api/admin/role-permissions** - создать правило доступа (требует admin.create)
```
Body: {
  "role_id": 1,
  "permission_id": 1,
  "resource_id": 1
}
```

**DELETE /api/admin/role-permissions/<rp_id>** - удалить правило доступа (требует admin.delete)

Установка и запуск

```
pip install -r requirements.txt
python app.py
```

База данных создается автоматически при первом запуске с тестовыми данными.

