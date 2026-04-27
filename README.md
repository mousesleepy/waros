[English](#english) | [Русский](#русский)

---

<a id="english"></a>
# waros — Wazuh Active Response for MikroTik RouterOS 7

PHP script for Wazuh active response — blocks source IPs on MikroTik RouterOS 7 firewall via REST API.

Wazuh agent detects a threat → passes alert JSON via pipe to `waros.php` → script resolves source IP, calculates timeout based on rule severity, adds the IP to RouterOS address-list via REST API → exits.

## Features

- **Stateless** — single invocation per alert, no daemon, exits immediately.
- **Two timeout modes** — linear (proportional) and exponential (aggressive escalation for high-level threats).
- **Repeat offender tracking** — `firedtimes` counter from Wazuh rules increases effective level over time.
- **Deduplication cache** — flat file cache avoids redundant API calls when the same IP is blocked within its timeout window.
- **Flexible srcip resolution** — configurable dot-paths into alert JSON. Works with standard Wazuh alerts and ModSecurity audit logs.
- **Syslog logging** — writes to both STDERR (captured by Wazuh agent) and syslog.
- **Test/debug CLI modes** — `--test`, `--calc-level`, `--debug-syslog` for verification without Wazuh agent.
- **Phar packaging** — can be built as a single `.phar` executable for deployment as a unix utility.

## Requirements

- PHP 7.4+ with `curl` and `json` extensions
- Wazuh agent (any version supporting active response via custom scripts)
- MikroTik RouterOS 7 with REST API enabled

## Installation

### 1. Copy files to Wazuh agent

```bash
scp waros.php RosRestClient.php BlockManager.php CliOptio.php waros.conf.sample root@agent:/var/ossec/active-response/bin/
```

Or as a phar executable:

```bash
scp waros.phar root@agent:/var/ossec/active-response/bin/waros
chmod +x /var/ossec/active-response/bin/waros
```

### 2. Create configuration

```bash
cd /var/ossec/active-response/bin/
cp waros.conf.sample waros.conf
chmod 600 waros.conf
vi waros.conf
```

Edit `waros.conf` — set RouterOS IP, credentials, address-list name.

Configuration search order:
1. CLI flag `--config /path/to/waros.conf`
2. Environment variable `WAROS_CONF`
3. `/etc/waros.conf`
4. `/var/ossec/etc/waros.conf`
5. `<script_directory>/waros.conf`

### 3. Configure Wazuh active response

Add to Wazuh manager's `ossec.conf` (inside `<active-response>` section):

```xml
<active-response>
  <command>waros-block</command>
  <location>local</location>
  <rules_id>XXXXX</rules_id>
  <timeout_allowed>yes</timeout_allowed>
</active-response>
```

Register the command in `agent.conf` or `ossec.conf` on the agent:

```xml
<active-response>
  <command>waros-block</command>
  <location>defined-agent</location>
  <agent_id>001</agent_id>
</active-response>
```

Define the command in `ossec.conf`:

```xml
<command>
  <name>waros-block</name>
  <executable>waros.php</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

When using the phar build, set `<executable>waros</executable>` instead.

### 4. RouterOS setup

Create a dedicated API user with minimal permissions:

```routeros
/user add name=wazuh-ar password=YOUR_PASSWORD group=full
/ip/firewall/filter add chain=forward src-address-list=wazuh-blocked action=drop comment="wazuh blocked"
```

Enable REST API (HTTP or HTTPS):

```routeros
/ip/service enable www
# or for HTTPS:
/ip/service enable www-ssl
/certificate add name=api-cert common-name=router.example.com
/ip service set www-ssl certificate=api-cert
```

## CLI Modes

By default `waros.php` reads NDJSON from STDIN (normal Wazuh agent operation). The following modes bypass STDIN and are useful for testing and diagnostics:

### `--test`

Block a random safe IP (from `198.51.100.0/24`, RFC 5737 TEST-NET-2) on the router with a 5-minute timeout and comment "test run". Verifies router connectivity, REST API authentication and rule creation.

```bash
php waros.php --test
```

### `--calc-level <level>`

Calculate effective level and block timeout for a given Wazuh rule level. Shows the full computation with all config coefficients. Combined with `--firedtimes` to simulate repeat offenders.

```bash
php waros.php --calc-level 7
php waros.php --calc-level 7 --firedtimes 333
```

### `--debug-syslog`

Send a test message to syslog using the configured facility. Verifies that logging works and messages reach the log destination.

```bash
php waros.php --debug-syslog
```

### `--config <path>`

Override config file path (works with any mode):

```bash
php waros.php --config /etc/waros.conf --test
```

## Configuration Reference

### [routeros] section

| Parameter | Default | Description |
|-----------|---------|-------------|
| `ip` | — | RouterOS IP address or hostname (required) |
| `port` | 443 (HTTPS) / 80 (HTTP) | REST API port |
| `user` | — | API username (required) |
| `password` | — | API password (required) |
| `use_ssl` | true | Enable HTTPS |
| `verify_ssl` | false | Verify SSL certificate |
| `debug` | false | Verbose API request/response logging to STDERR |
| `cache_file` | `<system_temp>/waros_cache.txt` | Local `.id` cache file path |

### [block] section

| Parameter | Default | Description |
|-----------|---------|-------------|
| `list_name` | `wazuh-blocked` | RouterOS address-list name |
| `timeout` | `10m` | Base block timeout (`0` = permanent). Format: `1h`, `6h`, `1d`, `1w`, or combinations like `1w2d3h` |
| `timeout_mode` | `linear` | Timeout calculation mode: `linear` or `exponential` |
| `timeout_escalation` | `1.5` | Escalation coefficient (see timeout formulas below) |
| `timeout_max` | `30d` | Maximum timeout cap |
| `firedtimes_divisor` | `50` | Every N rule hits adds +1 to effective level |
| `srcip_sources` | `data.srcip, data.transaction.client_ip` | Comma-separated dot-paths to resolve source IP from alert JSON |
| `comment_template` | `{rule} \| {agent_name} \| {datetime} \| lvl={effective_level} ({level}+{level_bonus}) ttl={ttl} \| {description}` | Template for RouterOS address-list entry comments |

### Timeout calculation

**Effective level:**

```
level_bonus     = floor(rule.firedtimes / firedtimes_divisor)
effective_level = rule.level + level_bonus
```

**Linear mode** (default):

```
timeout = base_seconds * max(effective_level, 1) * escalation
timeout = min(timeout, max_seconds)
```

Example: base `10m` (600s), escalation `1.5`, rule level 7, firedtimes 333, divisor 50:
- effective_level = 7 + floor(333/50) = 7 + 6 = 13
- timeout = 600 * 13 * 1.5 = 11700s = 3h15m

**Exponential mode:**

```
timeout = base_seconds * escalation^(max(effective_level, 1) - 1)
timeout = min(timeout, max_seconds)
```

Example: base `10m` (600s), escalation `1.5`, rule level 7, firedtimes 333, divisor 50:
- effective_level = 7 + floor(333/50) = 7 + 6 = 13
- timeout = 600 * 1.5^12 = 600 * 129.75 = 77848s = 21h37m

Exponential mode makes high-level threats escalate much faster while keeping low-level blocks short. At escalation=1.5: level 1 = base, level 5 = 5x base, level 10 = 38x base, level 15 = 292x base.

### Comment template placeholders

| Placeholder | Description |
|-------------|-------------|
| `{srcip}` | Source IP address |
| `{rule}` | Wazuh rule ID |
| `{description}` | Wazuh rule description |
| `{agent_id}` | Wazuh agent ID |
| `{agent_name}` | Wazuh agent name |
| `{datetime}` | Timestamp of block (ISO 8601) |
| `{level}` | Wazuh rule level (base, without firedtimes bonus) |
| `{firedtimes}` | How many times the rule has fired (raw count) |
| `{level_bonus}` | `floor(firedtimes / divisor)` — escalation bonus |
| `{effective_level}` | `level + level_bonus` |
| `{ttl}` | Current timeout value |

RouterOS comment field is limited to 1024 characters — long comments are truncated automatically.

### [logging] section

| Parameter | Default | Description |
|-----------|---------|-------------|
| `level` | `INFO` | Log level: `ERROR` (0), `WARN` (1), `INFO` (2), `DEBUG` (3) |
| `facility` | `LOCAL0` | Syslog facility: `LOCAL0`–`LOCAL7` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (invalid config, API failure, missing srcip) |

## File Structure

```
waros.php            — entry point, CLI argument parsing, STDIN reader, mode handlers
RosRestClient.php    — HTTP client for RouterOS 7 REST API
BlockManager.php     — blocking logic, cache, timeout calculation, syslog logging
CliOptio.php         — CLI option parser library (required dependency)
waros.conf.sample    — example configuration
test_CliOptio.php    — CliOptio unit tests
```

## License

MIT

---

<a id="русский"></a>
# waros — Wazuh Active Response для MikroTik RouterOS 7

PHP-скрипт для активного ответа Wazuh — блокирует IP-адреса источников на файрволе MikroTik RouterOS 7 через REST API.

Агент Wazuh обнаруживает угрозу → передаёт JSON алерта через pipe в `waros.php` → скрипт резолвит IP источника, вычисляет таймаут на основе серьёзности правила, добавляет IP в address-list RouterOS через REST API → завершается.

## Возможности

- **Stateless** — один вызов на алерт, нет демона, немедленный выход.
- **Два режима таймаутов** — линейный (пропорциональный) и экспоненциальный (агрессивная эскалация для высокоуровневых угроз).
- **Учёт повторных нарушителей** — счётчик `firedtimes` из правил Wazuh увеличивает эффективный уровень со временем.
- **Кэш дедупликации** — плоский файловый кэш исключает лишние запросы к API при повторных алертах на один IP в пределах окна таймаута.
- **Гибкий резолвинг srcip** — настраиваемые dot-пути в JSON алерта. Работает как со стандартными алертами Wazuh, так и с ModSecurity audit logs.
- **Логирование в syslog** — пишет как в STDERR (перехватывается агентом Wazuh), так и в syslog.
- **CLI-режимы тестирования и отладки** — `--test`, `--calc-level`, `--debug-syslog` для проверки без агента Wazuh.
- **Упаковка в phar** — можно собрать как единый `.phar`-исполняемый файл для развертывания как unix-утилиты.

## Требования

- PHP 7.4+ с расширениями `curl` и `json`
- Агент Wazuh (любая версия, поддерживающая активный ответ через кастомные скрипты)
- MikroTik RouterOS 7 с включённым REST API

## Установка

### 1. Скопировать файлы на агент Wazuh

```bash
scp waros.php RosRestClient.php BlockManager.php CliOptio.php waros.conf.sample root@agent:/var/ossec/active-response/bin/
```

Либо как phar-исполняемый:

```bash
scp waros.phar root@agent:/var/ossec/active-response/bin/waros
chmod +x /var/ossec/active-response/bin/waros
```

### 2. Создать конфигурацию

```bash
cd /var/ossec/active-response/bin/
cp waros.conf.sample waros.conf
chmod 600 waros.conf
vi waros.conf
```

Отредактируйте `waros.conf` — укажите IP RouterOS, учётные данные, имя address-list.

Порядок поиска конфига:
1. CLI-флаг `--config /путь/к/waros.conf`
2. Переменная окружения `WAROS_CONF`
3. `/etc/waros.conf`
4. `/var/ossec/etc/waros.conf`
5. `<директория_скрипта>/waros.conf`

### 3. Настройка активного ответа Wazuh

Добавьте в `ossec.conf` на менеджере Wazuh (внутри секции `<active-response>`):

```xml
<active-response>
  <command>waros-block</command>
  <location>local</location>
  <rules_id>XXXXX</rules_id>
  <timeout_allowed>yes</timeout_allowed>
</active-response>
```

Зарегистрируйте команду в `agent.conf` или `ossec.conf` на агенте:

```xml
<active-response>
  <command>waros-block</command>
  <location>defined-agent</location>
  <agent_id>001</agent_id>
</active-response>
```

Определите команду в `ossec.conf`:

```xml
<command>
  <name>waros-block</name>
  <executable>waros.php</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

При использовании phar-сборки укажите `<executable>waros</executable>`.

### 4. Настройка RouterOS

Создайте выделенного пользователя API с минимальными правами:

```routeros
/user add name=wazuh-ar password=YOUR_PASSWORD group=full
/ip/firewall/filter add chain=forward src-address-list=wazuh-blocked action=drop comment="wazuh blocked"
```

Включите REST API (HTTP или HTTPS):

```routeros
/ip/service enable www
# или для HTTPS:
/ip/service enable www-ssl
/certificate add name=api-cert common-name=router.example.com
/ip service set www-ssl certificate=api-cert
```

## CLI-режимы

По умолчанию `waros.php` читает NDJSON из STDIN (нормальная работа через агента Wazuh). Следующие режимы обходят STDIN и полезны для тестирования и диагностики:

### `--test`

Заблокировать случайный безопасный IP (из `198.51.100.0/24`, RFC 5737 TEST-NET-2) на маршрутизаторе с таймаутом 5 минут и комментарием "test run". Проверяет подключение к маршрутизатору, аутентификацию REST API и создание правила.

```bash
php waros.php --test
```

### `--calc-level <уровень>`

Рассчитать эффективный уровень и таймаут блока для заданного уровня правила Wazuh. Показывает полное вычисление со всеми коэффициентами из конфига. Комбинируется с `--firedtimes` для симуляции повторных нарушителей.

```bash
php waros.php --calc-level 7
php waros.php --calc-level 7 --firedtimes 333
```

### `--debug-syslog`

Отправить тестовое сообщение в syslog с использованием настроенного facility. Проверяет, что логирование работает и сообщения достигают места назначения.

```bash
php waros.php --debug-syslog
```

### `--config <путь>`

Переопределить путь к конфигурационному файлу (работает с любым режимом):

```bash
php waros.php --config /etc/waros.conf --test
```

## Справка по конфигурации

### Секция [routeros]

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `ip` | — | IP-адрес или имя хоста RouterOS (обязательный) |
| `port` | 443 (HTTPS) / 80 (HTTP) | Порт REST API |
| `user` | — | Имя пользователя API (обязательный) |
| `password` | — | Пароль API (обязательный) |
| `use_ssl` | true | Использовать HTTPS |
| `verify_ssl` | false | Проверять SSL-сертификат |
| `debug` | false | Подробное логирование запросов/ответов API в STDERR |
| `cache_file` | `<системный_temp>/waros_cache.txt` | Путь к локальному файлу кэша `.id` |

### Секция [block]

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `list_name` | `wazuh-blocked` | Имя address-list в RouterOS |
| `timeout` | `10m` | Базовый таймаут блока (`0` = навсегда). Формат: `1h`, `6h`, `1d`, `1w`, или комбинации типа `1w2d3h` |
| `timeout_mode` | `linear` | Режим расчёта таймаута: `linear` или `exponential` |
| `timeout_escalation` | `1.5` | Коэффициент эскалации (см. формулы ниже) |
| `timeout_max` | `30d` | Максимальный предел таймаута |
| `firedtimes_divisor` | `50` | Каждые N срабатываний правила добавляют +1 к эффективному уровню |
| `srcip_sources` | `data.srcip, data.transaction.client_ip` | Запятые-разделённые dot-пути для резолвинга IP источника из JSON алерта |
| `comment_template` | `{rule} \| {agent_name} \| {datetime} \| lvl={effective_level} ({level}+{level_bonus}) ttl={ttl} \| {description}` | Шаблон комментария для записей в address-list RouterOS |

### Расчёт таймаута

**Эффективный уровень:**

```
level_bonus     = floor(rule.firedtimes / firedtimes_divisor)
effective_level = rule.level + level_bonus
```

**Линейный режим** (по умолчанию):

```
timeout = base_seconds * max(effective_level, 1) * escalation
timeout = min(timeout, max_seconds)
```

Пример: base `10m` (600s), escalation `1.5`, rule level 7, firedtimes 333, divisor 50:
- effective_level = 7 + floor(333/50) = 7 + 6 = 13
- timeout = 600 * 13 * 1.5 = 11700s = 3h15m

**Экспоненциальный режим:**

```
timeout = base_seconds * escalation^(max(effective_level, 1) - 1)
timeout = min(timeout, max_seconds)
```

Пример: base `10m` (600s), escalation `1.5`, rule level 7, firedtimes 333, divisor 50:
- effective_level = 7 + floor(333/50) = 7 + 6 = 13
- timeout = 600 * 1.5^12 = 600 * 129.75 = 77848s = 21h37m

Экспоненциальный режим делает эскалацию высокоуровневых угроз значительно быстрее, сохраняя короткие таймауты для низких уровней. При escalation=1.5: уровень 1 = base, уровень 5 = 5x base, уровень 10 = 38x base, уровень 15 = 292x base.

### Плейсхолдеры шаблона комментария

| Плейсхолдер | Описание |
|-------------|----------|
| `{srcip}` | IP-адрес источника |
| `{rule}` | ID правила Wazuh |
| `{description}` | Описание правила Wazuh |
| `{agent_id}` | ID агента Wazuh |
| `{agent_name}` | Имя агента Wazuh |
| `{datetime}` | Метка времени блокировки (ISO 8601) |
| `{level}` | Уровень правила Wazuh (базовый, без бонуса за firedtimes) |
| `{firedtimes}` | Сколько раз правило сработало (сырой счётчик) |
| `{level_bonus}` | `floor(firedtimes / divisor)` — бонус эскалации |
| `{effective_level}` | `level + level_bonus` |
| `{ttl}` | Текущее значение таймаута |

Поле комментария RouterOS ограничено 1024 символами — длинные комментарии обрезаются автоматически.

### Секция [logging]

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `level` | `INFO` | Уровень логирования: `ERROR` (0), `WARN` (1), `INFO` (2), `DEBUG` (3) |
| `facility` | `LOCAL0` | Фасилити syslog: `LOCAL0`–`LOCAL7` |

## Коды завершения

| Код | Значение |
|-----|----------|
| 0 | Успех |
| 1 | Ошибка (некорректный конфиг, ошибка API, не найден srcip) |

## Структура файлов

```
waros.php            — точка входа, разбор CLI-аргументов, чтение STDIN, обработчики режимов
RosRestClient.php    — HTTP-клиент для REST API RouterOS 7
BlockManager.php     — логика блокировки, кэш, вычисление таймаутов, логирование в syslog
CliOptio.php         — библиотека разбора CLI-опций (обязательная зависимость)
waros.conf.sample    — пример конфигурации
```

## Лицензия

MIT
