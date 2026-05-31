# Диагностика PostgreSQL в Docker

## Ошибка: "role postgres does not exist"

Симптомы:
- Контейнер postgres-db запущен и healthy
- При подключении (DBeaver, приложение) ошибка: `FATAL: role "postgres" does not exist`

### Причина
Старый volume с данными от предыдущего запуска. PostgreSQL видит уже инициализированную БД и пропускает создание дефолтной роли.

### Решение

1. Остановить контейнер и удалить volume:
```bash
docker-compose down -v
```

2. Запустить заново:
```bash
docker-compose up -d postgres-db
```

3. Проверить, что роль создалась:
```bash
docker exec postgres-db psql -U postgres -c '\du'
```

### Альтернатива: использовать bind mount

Чтобы избежать проблем с volume, использовать папку в проекте:

```yaml
# в docker-compose.yml раскомментировать:
#      - ./postgres-data:/var/lib/postgresql/data:Z
```

Тогда данные хранятся локально, удалить можно командой:
```bash
rm -rf postgres-data
```

## Полезные команды для работы с PostgreSQL в контейнере

### Подключение к БД

```bash
# Войти в контейнер и открыть psql
docker exec -it postgres-db psql -U postgres

# Подключиться к конкретной БД
docker exec -it postgres-db psql -U postgres -d springsecuritycourse
```

### Просмотр информации

```bash
# Список ролей/пользователей
docker exec postgres-db psql -U postgres -c '\du'

# Список баз данных
docker exec postgres-db psql -U postgres -c '\l'

# Список таблиц в текущей БД
docker exec postgres-db psql -U postgres -d springsecuritycourse -c '\dt'

# Список схем
docker exec postgres-db psql -U postgres -d springsecuritycourse -c '\dn'

# Список индексов
docker exec postgres-db psql -U postgres -d springsecuritycourse -c '\di'

# Информация о соединении
docker exec postgres-db psql -U postgres -c '\conninfo'
```

### Выполнение SQL-запросов

```bash
# Пример: выбрать всех пользователей
docker exec postgres-db psql -U postgres -d springsecuritycourse -c 'SELECT * FROM users;'

# Создать таблицу (если нужно вручную)
docker exec postgres-db psql -U postgres -d springsecuritycourse -c 'CREATE TABLE test (id SERIAL PRIMARY KEY);'
```

### Управление контейнером

```bash
# Посмотреть логи
docker logs postgres-db

# Логи в реальном времени
docker logs -f postgres-db

# Остановить
docker stop postgres-db

# Запустить
docker start postgres-db

# Перезапустить
docker restart postgres-db
```