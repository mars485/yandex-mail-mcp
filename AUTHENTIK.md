# Подключение ChatGPT через Authentik

Этот пакет добавляет OAuth к уже работающему серверу. Статические Bearer-токены
остаются рабочими. Client Secret не нужен MCP: он проверяет RS256-подпись публичным
ключом Authentik. Секрет вводится только в форму ChatGPT и хранится в Authentik.

Ниже используются примерные домены. Замените их своими во всех полях и mapping.
Client ID берётся из вашего OAuth2-провайдера; callback копируется из текущей формы клиента.
Названия русских пунктов зависят от версии Authentik: рядом приведены английские.

## 0. Создать выделенное приложение и провайдер

В административном интерфейсе откройте «Приложения» (Applications) и создайте
приложение `Yandex Mail MCP` со slug `yandex-mail-mcp` и провайдером OAuth2/OpenID.
Выберите конфиденциальный тип клиента (Confidential), подходящий вашей установке
поток авторизации с подтверждением доступа и RSA signing key. Если используется
другой slug, измените issuer во всех настройках. Сохраните Client ID и Client Secret
в менеджере паролей. Последний передаётся непосредственно в форму клиента,
не в репозиторий и не в `.env` MCP. Выберите отдельный issuer для провайдера.

В «Каталог → Группы» (Directory → Groups) создайте группы из следующего раздела.
В карточке каждой группы добавьте свой аккаунт во вкладке пользователей/участников.
Не путайте членство в группе с её привязкой к приложению.

## 1. Ограничить доступ в Authentik

Создайте группу **yandex-mail-mcp-users**, добавьте в неё только свой аккаунт.
В «Приложения → Yandex Mail MCP → Привязки политик / групп / пользователей» (Applications → Policy / Group / User Bindings) привяжите эту
группу как разрешённую. Проверьте отсутствие других разрешающих привязок.
Это приложение открывает один настроенный ящик, а не индивидуальную почту каждого
пользователя Authentik.

Для разрешения изменения писем создайте отдельную группу **yandex-mail-mcp-writers**.
Добавьте туда свой аккаунт, если нужны mark_read/move/archive. Членство только
в writers без users не даёт доступа. На первом подключении можно ограничиться чтением.

## 2. Создать scope mappings

В «Настройка / Кастомизация → Сопоставления свойств» (Customization → Property Mappings) создайте два **Scope Mapping**
(название раздела может отличаться в вашей версии).

### Чтение

Name: `Yandex Mail MCP read`

Scope name: `mail:read`

Description: `Поиск и чтение писем Яндекс Почты`

Expression:

```python
return {
    "aud": [provider.client_id, "https://mail-mcp.example.com/mcp"],
    "scope": " ".join(token.scope),
    "mcp_read": ak_is_group_member(user, name="yandex-mail-mcp-users"),
}
```

### Запись

Name: `Yandex Mail MCP write`

Scope name: `mail:write`

Description: `Отметка прочитанного, перемещение и архивирование писем`

Expression:

```python
return {
    "mcp_write": ak_is_group_member(user, name="yandex-mail-mcp-writers"),
}
```

В OAuth2-провайдере приложения выберите **оба** созданных mapping и штатные mapping
`openid`, `profile`, `offline_access`. Сохраните существующие нужные mappings.
Если штатный offline_access недоступен, не подменяйте его произвольным scope:
сначала уточните версию Authentik; первичное подключение можно проверить без него,
но тогда повторный вход потребуется после истечения access token.

Оставьте **Include claims in id_token** включённым: Authentik использует набор
claims также для формирования access token. Выберите RSA signing key и режим
отдельного issuer для провайдера. Рекомендуемый срок access token: `minutes=5`.
Наш валидатор принимает только access token с `azp`, `uid`, `scope`, подписью RS256,
верным issuer, audience MCP, сроком действия и разрешающим `mcp_read`.

Настройка audience фиксированная и предназначена только для этого приложения;
это не универсальная реализация динамических RFC 8707 resource indicators.
Сохраняется audience Client ID для OIDC, а resource audience добавляется явно.

Установите Redirect URI **Strict** по текущему значению формы ChatGPT:

```text
COPY_CURRENT_CALLBACK_FROM_CHATGPT
```

Если форму создавали заново, адрес может отличаться — копируйте актуальный из неё.
Используйте authorization code с PKCE S256. Если версия Authentik позволяет
ограничить grant types, оставьте authorization_code и refresh_token.

## 3. Настройки MCP

В локальном `.env` задайте реальные значения:

```dotenv
MCP_OAUTH_ENABLED=true
MCP_PUBLIC_URL=https://mail-mcp.example.com/mcp
OAUTH_ISSUER=https://auth.example.com/application/o/yandex-mail-mcp/
OAUTH_CLIENT_ID=your-authentik-client-id
OAUTH_JWKS_URL=
```

Ресурс должен точно совпадать с audience в mapping, issuer — с discovery.
Включите домен в MCP_ALLOWED_HOSTS и MCP_ALLOWED_ORIGINS по README.
Client Secret серверу не передаётся. Основной статический MCP-токен сохраните.

```bash
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose build --pull
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose up -d --force-recreate
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose exec -T yandex-mail-mcp python smoke_test.py --imap
sudo env DOCKER_CONFIG=/DATA/AppData/docker-cli-config docker compose exec -T yandex-mail-mcp python oauth_check.py
```

Первая проверка использует статический токен и читает папки. Вторая проверяет
discovery, JWKS, S256, client_secret_basic и наличие mail:read/mail:write/offline_access.
Она не подтверждает, что mapping выдаёт правильные claims конкретному пользователю.
Полный вход и разрешения проверяются отдельно через клиент; токен в чат не копируйте.

## 4. Заполнить форму ChatGPT

| Поле | Значение |
|---|---|
| URL сервера | `https://mail-mcp.example.com/mcp` |
| Аутентификация | OAuth |
| Метод регистрации | Пользовательский клиент OAuth |
| Идентификатор клиента | `your-authentik-client-id` |
| Секрет клиента | Ваш Client Secret из Authentik; введите непосредственно в ChatGPT |
| Метод аутентификации конечной точки токена | `client_secret_basic` |
| Области по умолчанию | `mail:read` |
| Основные области | `openid`, `profile`, `offline_access`, `mail:read` — по одной на строку |
| URL аутентификации | `https://auth.example.com/application/o/authorize/` |
| URL токена | `https://auth.example.com/application/o/token/` |
| URL регистрации | Оставить пустым: используется заранее созданный клиент |
| База серверов авторизации | `https://auth.example.com/application/o/yandex-mail-mcp/` |
| Ресурс | `https://mail-mcp.example.com/mcp` |
| URL конфигурации OIDC | `https://auth.example.com/application/o/yandex-mail-mcp/.well-known/openid-configuration` |
| UserInfo endpoint OIDC | `https://auth.example.com/application/o/userinfo/` |
| Поддерживаемые OIDC scopes (если требуется) | `openid`, `profile` |

OIDC — вспомогательная информация для входа, не замена OAuth. Если интерфейс
сам обнаружил поля, сверяйте их с таблицей; не подставляйте сюда статический MCP-токен.
Для описанного конфиденциального клиента используйте client_secret_basic; поддержка должна совпадать с discovery вашего провайдера.

После успешной проверки сервера нажмите «Создать», войдите в Authentik и подтвердите
доступ. Выберите плагин в новом чате и попросите: «Покажи список папок Яндекс Почты».

На первом подключении отключите в настройках плагина инструменты `mark_read`,
`move_message`, `archive_message`. Для включения записи добавьте `mail:write`
в запрашиваемые области, включите инструменты и переподключите аккаунт;
пользователь должен состоять и в группе writers. Серверный `MCP_ENABLE_WRITE=false`
имеет приоритет и запретит запись даже при правильных OAuth-правах.

## Ограничения и отзыв доступа

Публичные ключи кешируются 5 минут; при неизвестном kid обновление ограничено
одним запросом в 30 секунд. При недоступности Authentik и истечении кеша OAuth
закрывается, статические токены продолжают работать. Подпись проверяется локально,
интроспекция на каждый запрос не выполняется. Отзыв токена или удаление пользователя
из группы отразится на доступе не мгновенно: уже выданный JWT действует до exp
(плюс допуск часов 10 секунд). Для срочного отключения всего OAuth задайте
`MCP_OAUTH_ENABLED=false` и пересоздайте контейнер.

Access token не используется повторно для IMAP и не пересылается в другой сервис.
Токены и claims не записываются в логи. Bearer-токены допускают повторное использование
до истечения; защиту от кражи обеспечивает HTTPS и безопасное хранение на клиенте.

## Отключение OAuth

Задайте `MCP_OAUTH_ENABLED=false` и пересоздайте контейнер. Статические токены
продолжат работать. Для их отзыва замените соответствующие секреты и снова
пересоздайте контейнер. Общий порядок обновления и отката приведён в README.

## Источники

- [OpenAI: аутентификация MCP](https://developers.openai.com/plugins/build/auth)
- [Authentik OAuth2: endpoints, issuer, scopes](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)
- [Authentik: scope mappings](https://docs.goauthentik.io/add-secure-apps/providers/property-mappings/)

Успешная работа персональной установки подтверждена её владельцем. Для новой установки необходима собственная проверка входа и прав.
