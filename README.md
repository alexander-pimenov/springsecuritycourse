# Spring Security Course

Educational project for learning Spring Security fundamentals.

## Overview

Demo-приложение на Spring Boot для изучения механизмов аутентификации и авторизации.

## Tech Stack

- Spring Boot 2.7.18
- Spring Security
- Spring Data JPA
- PostgreSQL
- Thymeleaf
- Lombok

### Основы работы с Spring Security

https://www.youtube.com/watch?v=7uxROJ1nduk
https://github.com/proselytear/springsecuritycourse

В данном видео на практических примерах рассмотрены основы работы с Spring Security Framework
00:00:00 Введение
00:03:08 Cоздание шаблона проекта
00:11:46 Интеграция Spring Security
00:15:35 Объяснение Basis Auth
00:18:03 Конфигурация spring security и работа с UserDetailsService (InMemoryUserDetailsManager)
00:26:06 Авторизация с использованием ролей (roles)
00:35:16 Авторизация с использованием прав доступа (authorities)
00:44:00 Использование аннотации @PreAuthorize
00:46:22 Аутентификация с использованием формы ввода (form based authentication)
00:55:58 Аутентификация и авторизация при работе с БД (DaoAuthenticationProvider)
01:16:30 Аутентификация и авторизация с использованием JWT токена
01:52:37 Заключение

Ссылка на github репозиторий:
https://github.com/proselytear/spring...

Ветки/Директории:
STEP1 - шаблон проекта
STEP2 - интеграция Spring Security
STEP3 - работа с InMemoryUserDetailsManager
STEP4 - авторизация с использованием ролей пользователя
STEP5 - авторизация с использованием прав доступа
STEP6 - использование аннотации @PreAuthorize
STEP7 - аутентификация с помощью формы логина (сессии)
STEP8 - аутентификация и авторизация при работе с БД
STEP9 - аутентификация и авторизация с использованием JWT токена

Цикл видео по SpringSecurity от JavaBrains:
https://www.youtube.com/playlist?list=PLqq-6Pq4lTTYTEooakHchTGglSvkZAjnE

## Project Structure

```
src/main/java/net/proselyte/springsecuritydemo/
├── config/
│   └── SecurityConfig.java          # Security configuration
├── controller/
│   └── AuthController.java          # Login/logout controllers
├── model/
│   ├── User.java              # User entity
│   ├── Developer.java         # Developer entity
│   ├── Role.java              # USER, ADMIN roles
│   ├── Permission.java        # DEVELOPERS_READ, DEVELOPERS_WRITE
│   └── Status.java            # User status enum
├── repository/
│   └── UserRepository.java    # JPA repository
├── security/
│   ├── UserDetailsServiceImpl.java     # Custom UserDetailsService
│   └── SecurityUser.java               # UserDetails wrapper
└── rest/
    └── DeveloperRestControllerV1.java  # REST API
```

## Features

- Form-based authentication
- Database-backed user authentication
- Role-based authorization (USER, ADMIN)
- Permission-based access control
- BCrypt password encoding (strength 12)
- Custom login page
- REST API with method-level security

## Data Model

### User

- id, email, password
- firstName, lastName
- role (USER/ADMIN)
- status

### Roles & Permissions

| Role  | Permissions            |
|-------|------------------------|
| USER  | developers:read        |
| ADMIN | developers:read, write |

## REST API

```
GET  /api/v1/developers        # All developers (authenticated)
GET  /api/v1/developers/{id}   # By ID (developers:read)
POST /api/v1/developers        # Create (developers:write)
DELETE /api/v1/developers/{id} # Delete (developers:write)
```

## Configuration

Database settings in `application.properties`:

- PostgreSQL connection parameters
- JPA settings

---

#### Чтобы разлогиниться нужно ввести:

http://localhost:8080/logout

#### Сайт для кодирования/декодирования пароль/логин

https://www.base64decode.org/

#### Простой инструмент для генерации и проверки хешей bcrypt.

https://bcrypt-generator.com/

Пароль в БД в таблице `users` в колонке `password` хранится, как раз, в закодированном виде с помощью bcrypt.

---

## Страница login

http://localhost:8080/auth/login

### Пользователи:

| № | email (уникальный идентификатор) | password |
|---|----------------------------------|----------|
| 1 | admin@mail.com                   | admin    |
| 2 | user@mail.com                    | user     |
|   |                                  |          |

---

# Особенность переключения в директорию с проектом: 
Т.к. opencode cli  был установлен в оболочке WSL (линукс для windows), а проект лежит на диске 'C' то, чтобы перейти
в директорию с проектом нужно использовать полный путь с динамическим определением username, если ваши проекты находятся 
на диске 'C' и у вас система Windows, то самый универсальный подход: 
определить переменную окружения в системе Windows, а затем читать её из WSL:
```bash
# В WSL можно прочитать переменную Windows
cd "/mnt/c/Users/$(cmd.exe /c echo %USERNAME% 2>/dev/null | tr -d '\r')/Documents/Development/projects_java/springsecuritycourse"
```

--- 

Step 9: аутентификация и авторизация с использованием JWT токена

Если нам нужно предоставлять доступ к серверу нашим клиентам без поддержания сессии, без передачи идентификатора JSESSIONID
в хэдере cookie, так как держать сессию не совсем удобно, для этих целей мы можем использовать подход - JWT (Json Web Token).

Онлайн Encoder/Decodr JWT - https://www.jwt.io/
В JWT хранятся какие-то данные.

Например: 
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iat": 1780235278,
  "role": "admin",
  "email": "admin@mail.com",
  "exp": 1780238878
}

```

"iat": 1780235278 - когда создан,
"exp": 1780238878 - когда протухнет.

Кодируется в такой вид:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc4MDIzNTI3OCwicm9sZSI6ImFkbWluIiwiZW1haWwiOiJhZG1pbkBtYWlsLmNvbSIsImV4cCI6MTc4MDIzODg3OH0.4nfs_YQq_itYxL7VppnEZ1KpTowtV0eGJ3b98I2LY5o

```

Для кодирования/декодирования еще указывается алгоритм шифрования и секретный ключ. Это можно посмотреть на это же сайте.

Например, такой алгоритм шифрования:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

---

### Что в модулях STEP1-9
Пройдя по модулям можно увидеть постепенное прикручивание SpringSecurity и развитие нашего проекта.  

---