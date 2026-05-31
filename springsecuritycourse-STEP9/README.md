# JWT-аутентификация (springsecuritycourse-STEP9)

## Отличие от form-login (модуль core)

| Характеристика | form-login (core) | JWT (STEP9) |
|---|---|---|
| Где хранится сессия | На сервере (JSESSIONID в куке) | В самом токене (stateless) |
| Клиент отправляет | Куку JSESSIONID автоматически | Токен в заголовке `Authorization` вручную |
| Логаут | Сервер удаляет сессию | Клиент просто удаляет токен |
| CSRF защита | Включена (кроме конфига) | Отключена (токену не нужна) |
| Эндпоинт логина | POST `/login` (Spring Security сам) | POST `/api/v1/auth/login` (кастомный) |

## Как работает JWT-аутентификация (sequence)

```
Шаг 1 — Вход (получение токена)
─────────────────────────────────
  Клиент                     AuthenticationRestControllerV1          БД
    │                                │                               │
    │  POST /api/v1/auth/login       │                               │
    │  {email, password}             │                               │
    │───────────────────────────────>│                               │
    │                                │  AuthenticationManager        │
    │                                │  .authenticate()              │
    │                                │──────────────────────────────>│
    │                                │  проверяет email/password     │
    │                                │<──────────────────────────────│
    │                                │                               │
    │                                │  UserRepository.findByEmail() │
    │                                │──────────────────────────────>│
    │                                │<────── User + role ───────────│
    │                                │                               │
    │                                │  JwtTokenProvider             │
    │                                │  .createToken(email, role)    │
    │                                │  ─► подписывает HS256        │
    │                                │                               │
    │  {email, token}                │                               │
    │<───────────────────────────────│                               │


Шаг 2 — Запрос с JWT (каждый последующий запрос)
─────────────────────────────────────────────────
  Клиент                     JwtTokenFilter (doFilter)        JwtTokenProvider           Контроллер
    │                                │                             │                        │
    │  GET /api/v1/developers        │                             │                        │
    │  Authorization: Bearer <token> │                             │                        │
    │───────────────────────────────>│                             │                        │
    │                                │  resolveToken(request)      │                        │
    │                                │  ─► вытаскивает токен       │                        │
    │                                │  из заголовка               │                        │
    │                                │                             │                        │
    │                                │  validateToken(token)       │                        │
    │                                │────────────────────────────>│                        │
    │                                │  проверяет подпись          │                        │
    │                                │  и срок действия            │                        │
    │                                │<──── true/false ────────────│                        │
    │                                │                             │                        │
    │                                │  getAuthentication(token)   │                        │
    │                                │────────────────────────────>│                        │
    │                                │  извлекает username из      │                        │
    │                                │  subject, грузит UserDetails│                        │
    │                                │<─── Authentication ─────────│                        │
    │                                │                             │                        │
    │                                │  SecurityContextHolder      │                        │
    │                                │  .setAuthentication(...)    │                        │
    │                                │                             │                        │
    │                                │  filterChain.doFilter()     │                        │
    │                                │─────────────────────────────────────────────────────>│
    │                                │                             │                        │
    │  <response>                    │                             │                        │
    │<───────────────────────────────│                             │                        │


Шаг 3 — Ошибка (токен невалиден/просрочен)
────────────────────────────────────────────
  Клиент                     JwtTokenFilter                      JwtTokenProvider
    │                                │                             │
    │  любой запрос с плохим токеном  │                             │
    │───────────────────────────────>│                             │
    │                                │  validateToken(token)       │
    │                                │────────────────────────────>│
    │                                │  выбрасывает                │
    │                                │  JwtAuthenticationException │
    │                                │<────────────────────────────│
    │                                │                             │
    │                                │  SecurityContextHolder      │
    │                                │  .clearContext()            │
    │                                │  response.sendError(401)    │
    │  401 Unauthorized              │                             │
    │<───────────────────────────────│                             │
```

## Ключевые классы

| Класс | Роль |
|---|---|
| `JwtTokenProvider` | Генерирует, валидирует и парсит JWT-токены |
| `JwtTokenFilter` | Перехватывает запросы, проверяет токен, устанавливает контекст |
| `JwtConfigurer` | Подключает фильтр в цепочку Spring Security |
| `AuthenticationRestControllerV1` | REST-контроллер для входа (выдаёт токен) и выхода |
| `SecurityConfig` | Настройка Security: stateless, CSRF off, open endpoints |

## Как запустить

```bash
cd springsecuritycourse-STEP9
./mvnw spring-boot:run
```
