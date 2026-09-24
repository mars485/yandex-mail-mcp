# Yandex Mail MCP

<img src="assets/icon.png" alt="Yandex Mail MCP" width="96" height="96">

Личный MCP-сервер для Яндекс Почты: поиск и чтение писем, просмотр папок, отметка прочитанного, перемещение и архивирование. IMAP по TLS, транспорт **Streamable HTTP**, OAuth через Authentik для подключения ChatGPT.

**Нет отправки и удаления писем.** MOVE меняет расположение письма и убирает его из исходной папки, поэтому считается записью. Сервис обслуживает **один настроенный ящик**: все допущенные пользователи работают с ним, а не со своей индивидуальной почтой.

Независимый проект, не официальный продукт Яндекса или OpenAI. Используется официальный Python SDK `mcp==2.2.0`, а не пакет `fastmcp`. Версия SDK не равна версии протокола MCP.

## Навигация

- [Установка](#установка-на-zimaos)
- [Authentik и ChatGPT](AUTHENTIK.md)
- [Результаты проверок](VALIDATION.md)
- [Статья для Хабра](docs/habr-post.md)

## Архитектура

```text
ChatGPT / MCP-клиент → HTTPS reverse proxy → ZimaOS:8822 → контейнер:8000
          │                                                    │
          └── OAuth / PKCE → Authentik             IMAP TLS:993 → Яндекс Почта
                               MCP проверяет JWT по публичным ключам JWKS
```

MCP не хранит базу писем, но возвращает содержимое выбранных писем клиенту и модели. Собственный сервер не означает, что письма остаются исключительно дома. Текст письма — недоверенные данные, а не команды для помощника. Первое подключение рекомендуется проверить без прав записи.

## Установка на ZimaOS

Нужны Docker Compose, включённый IMAP и пароль приложения Яндекса. Для внешнего клиента — домен, действующий HTTPS-сертификат и reverse proxy. Для OAuth — работающий Authentik по внешнему HTTPS-адресу. Все `example.com` ниже заменяются своими доменами.

```bash
cd /DATA/AppData
git clone https://github.com/mars485/yandex-mail-mcp.git
cd yandex-mail-mcp
cp .env.example .env
chmod 600 .env
openssl rand -hex 32
nano .env
```

Заполните `YANDEX_EMAIL`, `YANDEX_APP_PASSWORD`, `MCP_BEARER_TOKEN`. Последний — случайное сгенерированное значение, отдельное от пароля почты и OAuth Client Secret. Для первого запуска задайте `MCP_ENABLE_WRITE=false`. `.env` исключён из Git и Docker build context.

Команды учитывают особенность Docker CLI ZimaOS. На обычном Linux достаточно `docker compose`, при необходимости с `sudo`.

```bash
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose config --quiet
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose build --pull
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose up -d
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose ps
curl --fail http://127.0.0.1:8822/health
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose exec -T yandex-mail-mcp python smoke_test.py --imap
```

`/health` проверяет процесс, не IMAP. Smoke test проверяет отказ без токена, initialize, шесть инструментов и, с `--imap`, чтение реальных папок. Письма не изменяются, названия папок скрыты в отчёте.

Контейнер работает от UID/GID `10001:10001`, с read-only файловой системой, без capabilities, с ограничениями памяти/процессов/логов. Dockerfile явно задаёт права чтения исходникам: режим файлов после распаковки ZIP не мешает непривилегированному запуску.

## Настройки

| Переменная | Назначение |
|---|---|
| `YANDEX_EMAIL` | Единственный обслуживаемый ящик |
| `YANDEX_APP_PASSWORD` | Пароль приложения с доступом к почте |
| `YANDEX_IMAP_HOST` / `YANDEX_IMAP_PORT` | По умолчанию `imap.yandex.ru` / `993` |
| `YANDEX_ARCHIVE_FOLDER` | Существующая папка архива, `Archive` — только значение по умолчанию |
| `MCP_BEARER_TOKEN` | Обязательный случайный токен чтения и записи, 32–256 символов |
| `MCP_READ_ONLY_TOKEN` | Необязательный отдельный токен только для чтения |
| `MCP_ENABLE_WRITE` | `false` запрещает запись всем, включая OAuth |
| `MCP_OAUTH_ENABLED` | `true` включает JWT Authentik и OAuth discovery |
| `MCP_PUBLIC_URL` | При OAuth: точный URL `https://mail-mcp.example.com/mcp` |
| `OAUTH_ISSUER` | При OAuth: точный issuer `https://auth.example.com/application/o/yandex-mail-mcp/` |
| `OAUTH_CLIENT_ID` | При OAuth: Client ID выделенного провайдера |
| `OAUTH_JWKS_URL` | Необязательно: по умолчанию issuer + `jwks/` |
| `MCP_ALLOWED_HOSTS` | Явный список Host через запятую, включая необходимые порты |
| `MCP_ALLOWED_ORIGINS` | Разрешённые Origin через запятую, без `*` |
| `MCP_BIND_IP` | Адрес публикации порта 8822; по умолчанию `0.0.0.0` |

Статические токены должны различаться. Основной обязателен и при OAuth для локальной диагностики; он действует независимо от групп Authentik. Храните его как отдельный ключ доступа. Его ротация: заменить в `.env`, пересоздать контейнер и обновить доверенные клиенты.

Настройки читаются при старте. После изменения `.env` нужен `docker compose up -d --force-recreate`: обычный restart не обновляет окружение контейнера. OAuth URL должны быть HTTPS, без credentials/query/fragment. Поддерживаемый путь ресурса — `/mcp`; issuer указывается с завершающим `/`.

## Reverse proxy

В Nginx Proxy Manager создайте Proxy Host `mail-mcp.example.com` → HTTP → LAN-адрес ZimaOS → **8822**. Включите действующий TLS-сертификат и перенаправление на HTTPS. Сохраните Host и Authorization, не логируйте токены и тела запросов. Добавьте домен и `домен:443` в `MCP_ALLOWED_HOSTS`, HTTPS-origin — в `MCP_ALLOWED_ORIGINS`.

Наружу публикуйте HTTPS proxy, а 8822 ограничьте доверенной сетью. `127.0.0.1` внутри отдельного proxy-контейнера указывает на него самого. Bind на loopback хоста подходит только для схемы, в которой proxy действительно имеет к нему доступ.

```bash
curl --fail --connect-timeout 5 --max-time 15 https://mail-mcp.example.com/health
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose exec -T yandex-mail-mcp python smoke_test.py --url https://mail-mcp.example.com/mcp --imap
```

Обычный GET `/mcp` — не полноценный протокольный тест; без токена ожидается 401. Не передавайте токен в URL или по публичному HTTP.

## Авторизация и OAuth

Статический клиент передаёт `Authorization: Bearer <токен>`. Cookie/query не поддерживаются, дублирующиеся Authorization отклоняются. Сравнение использует SHA-256 и `compare_digest`.

Для ChatGPT выполните [настройку Authentik](AUTHENTIK.md). Проверяются RS256, issuer, audience MCP, `azp` Client ID, сроки, обязательные access-token claims, scopes и разрешения групп. `mail:read` + `mcp_read=true` разрешают чтение; дополнительно `mail:write` + `mcp_write=true` разрешают запись, если она включена глобально.

JWT проверяется локально без introspection. Удаление из группы и отзыв токена не прекращают действие уже выданного JWT мгновенно: он действует до exp с допуском 10 секунд. Рекомендуемый срок access token — 5 минут. JWKS кешируется 5 минут, обновляется не чаще раза в 30 секунд. При истечении кеша и сбое обновления OAuth закрывается, статические ключи остаются действующими.

## Инструменты

| Инструмент | Аргументы | Действие |
|---|---|---|
| `list_folders` | Нет | Имена, разделители, флаги; без количества писем |
| `search_messages` | `folder`, `query`, `sender`, `subject`, `unread_only`, `since`, `before`, `limit`, `offset` | Заголовки, UID и UIDVALIDITY |
| `read_message` | `uid`, `folder`, необязательный `uidvalidity` | Текст и метаданные вложений без отметки прочитанного |
| `mark_read` | `uid`, `uidvalidity`, `folder` | Добавить Seen |
| `move_message` | `uid`, `uidvalidity`, `destination`, `folder` | MOVE в существующую папку |
| `archive_message` | `uid`, `uidvalidity`, `folder` | MOVE в настроенный архив |

По умолчанию folder `INBOX`, limit 20, offset 0. Даты `YYYY-MM-DD`, since включительно, before исключительно. Limit 1–100, offset до 100000; сортировка по убыванию UID, не заголовку Date.

Сначала поиск, затем используйте `messages[].uid` и `uidvalidity` папки. UID — не порядковый номер и не Message-ID. Для записи UIDVALIDITY обязателен, для чтения рекомендуется. После MOVE заново ищите в целевой папке. Пагинация не фиксирует снимок ящика.

Примеры запросов: «Покажи папки», «Найди 10 непрочитанных писем во Входящих», «Прочитай выбранное письмо без отметки прочитанного». Для записи сначала выберите тестовое письмо и явно подтвердите действие.

Все шесть инструментов объявлены даже для read-only клиента. Аннотации информируют модель, но доступ проверяет сервер. Результат содержит `ok`; клиент должен учитывать `ok: false` внутри structuredContent независимо от HTTP 200 или MCP isError.

## Ограничения

- BODY.PEEK и read-only выбор папки для чтения.
- Отдельное IMAP TLS-соединение на операцию, socket timeout 20 секунд, до 4 параллельных операций.
- MIME до 8 МиБ, текст до 50000 символов, заголовки до 32 КиБ.
- Вложения — только метаданные; HTML возвращается как текст, не выполняется сервером.
- MOVE обязателен; fallback COPY/delete/EXPUNGE отсутствует. Распознанная Корзина запрещена как назначение.
- Нет создания папок, SMTP, bulk-операций, фонового индексирования.
- Лимит поисковой выдачи не ограничивает весь набор UID, найденный IMAP-сервером.

После обрыва связи при записи результат может быть неизвестен: команда могла выполниться. **Не повторяйте запись автоматически**; проверьте обе папки. Отсутствие delete-инструмента не исключает риска неверного перемещения.

## Диагностика

| Симптом | Проверка |
|---|---|
| Restart loop | `docker compose logs --tail=60 yandex-mail-mcp`, обязательные настройки, права |
| `/app/server.py: Permission denied` | Пересобрать текущий Dockerfile, не обходить запуском root |
| `invalid_configuration` | Обязательные env, токены, OAuth URL и Client ID |
| Health OK, IMAP FAIL | Пароль приложения, разрешение IMAP, исходящий TLS:993 |
| HTTPS timeout | DNS, 443, firewall, port forwarding, NAT loopback |
| OAuth не работает | Issuer, текущий callback, RSA, scopes, bindings |
| Запись запрещена | Глобальный флаг, обе группы, mail:write, новый токен |
| UIDVALIDITY / архив | Повторить поиск; проверить точное существующее имя архива |

Если домен недоступен только из LAN, сохраните имя для проверки TLS, но направьте запрос на LAN-IP proxy (IP ниже примерный):

```bash
curl --connect-timeout 5 --max-time 10 --resolve mail-mcp.example.com:443:192.168.1.10 https://mail-mcp.example.com/health
```

Если так работает, исследуйте split DNS / NAT loopback. Для контейнера можно создать локальный `docker-compose.override.yml`, исключённый из Git:

```yaml
services:
  yandex-mail-mcp:
    extra_hosts:
      - "mail-mcp.example.com:192.168.1.10"
      - "auth.example.com:192.168.1.10"
```

Это помогает контейнеру, но не создаёт внешний доступ ChatGPT. TLS-проверку не отключайте. Логи проекта содержат фиксированный тип события и имя инструмента, без исходных исключений, писем, токенов и паролей; логи proxy настраиваются отдельно.

## Обновление с персонального комплекта

Сохраните каталог и `.env` вне репозитория с правами 0700, а также текущий image для отката. Backup содержит секреты. Публичная версия больше не содержит домен, Client ID и LAN-IP в коде: добавьте `MCP_PUBLIC_URL`, `OAUTH_ISSUER`, `OAUTH_CLIENT_ID` и свои allowlists; перенесите extra_hosts в локальный override. Старого `.env` может быть недостаточно.

Для установки из Git с чистым рабочим деревом:

```bash
git pull --ff-only
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose build --pull
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose up -d --force-recreate
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose exec -T yandex-mail-mcp python smoke_test.py --imap
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose exec -T yandex-mail-mcp python oauth_check.py
```

Последняя проверка нужна при включённом OAuth. Откат: восстановите совместимые файлы и env из backup и пересоберите либо используйте сохранённый образ с соответствующей конфигурацией. Не возвращайте публичный сервер без защиты.

## Разработка

Python 3.12, отдельное окружение:

```bash
python -m venv .venv
# Linux: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m pip check
```

Тесты используют фиктивный IMAP и временные RSA-ключи. conftest изолирует OAuth-настройки от окружения оператора. Прямые зависимости закреплены; транзитивные версии и базовый Docker tag не составляют воспроизводимый lockfile. Подробности — [VALIDATION.md](VALIDATION.md).

`server.py` — IMAP, HTTP, инструменты и static auth; `oauth_auth.py` — JWT/JWKS; `oauth_check.py` — discovery; `smoke_test.py` — HTTP/MCP/IMAP; `test_*.py` — тесты; Dockerfile/Compose/env — установка; AUTHENTIK.md — OAuth; docs/habr-post.md — статья.

## Источники

- [MCP Python SDK: ASGI](https://py.sdk.modelcontextprotocol.io/run/asgi/)
- [OpenAI: аутентификация MCP](https://developers.openai.com/plugins/build/auth)
- [Authentik: OAuth2 provider](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)

В issue прикладывайте версию, этап сбоя и обезличенный результат. Не прикладывайте env, Authorization, Client Secret или письма.
