# safesetsh — Debian 12/13 baseline hardening

**`safeset.sh` — разовая базовая защита (hardening) для Debian 12 (bookworm) и Debian 13 (trixie).**
Сокращение поверхности атаки на внешних серверах: закрытие типовых SSH/brute-force/сканерных
путей, CIS-подобное hardening ядра и учётных записей, и защита от самоблокировки по ходу работы.

> **Прочитайте перед запуском.** Hardening живого сервера может отрезать доступ. Держите
> открытой вторую SSH-сессию, имейте доступ к консоли/VNC, сначала проверьте на staging.
> Скрипт не заменяет чтение того, что он меняет: каждое изменение печатается, логируется и
> резервируется в бэкап.

- [Что делает](#что-делает)
- [Быстрый старт](#быстрый-старт)
- [Опции](#опции)
- [Модули](#модули)
- [Модель безопасности](#модель-безопасности)
- [Откат](#откат)
- [Проверка (CI и локально)](#проверка-ci-и-локально)
- [Что проверено, а что нет](#что-проверено-а-что-нет)
- [Структура репозитория](#структура-репозитория)

## Что делает

| Область | Кратко |
| --- | --- |
| packages | Базовый набор инструментов (nftables, fail2ban, auditd, AIDE, rkhunter, Lynis, chrony, apparmor, unattended-upgrades, …) |
| sysctl | CIS-подобное hardening сети в ядре (syn cookies, off для redirect'ов, source routing, rp_filter, IPv6) |
| filesystem | `nodev,nosuid,noexec` на `/tmp` и `/var/tmp`, жёстче права на чувствительные файлы, login banner |
| accounts | Требования к паролям (`pwquality`), `login.defs`, `umask 027`, блокировка системных учёток, `su` только для sudo-группы, `cron.allow`, drop-in sudoers |
| audit | Правила auditd, постоянный journald с лимитами, база AIDE + еженедельная проверка целостности, еженедельные отчёты rkhunter/Lynis, chrony |
| firewall | nftables-таблица `inet safeset`, default-deny на вход, отбрасывание скан-паттернов, rate limit по источнику, rate limit для SSH, whitelist оператора |
| fail2ban | Jail для sshd (brute force) + опциональный web-jail, bootstrap лог-файлов, systemd-таймер |
| ssh | Drop-in `99-safeset.conf`: вход только по ключу, без root-логина, усиленные cipher/MAC/KEX, без forwarding, жёсткие `MaxAuthTries`/`LoginGraceTime`, опциональная смена порта |
| web | nginx/Apache hardening-сниппеты (заголовки, TLS, server tokens), если веб-сервер обнаружен |
| crowdsec | Опционально (`--crowdsec`): CrowdSec + nftables bouncer из внешнего репозитория, с проверкой GPG-ключа |
| honeypot | Опционально (`--honeypot`): endlessh-ловушка на порту 22 (смысл есть только после смены порта SSH) |

Скрипт — это **базовая линия**, а не серебряная пуля. Он уменьшает поверхность, которую
автоматические сканеры и брутфорсеры обычно ищут; он не защищает уже скомпрометированный
хост и не заменяет мониторинг, обновления и резервные копии.

## Быстрый старт

```bash
git clone https://github.com/0xSPRK/safesetsh.git
cd safesetsh

# 1. Посмотреть, что именно будет сделано (ничего не меняется)
sudo ./safeset.sh --dry-run

# 2. Hardening на staging-хосте
sudo ./safeset.sh --yes --admin-ip 203.0.113.10 --safe-timer 300

# 3. Со второй консоли убедиться, что вход работает, затем:
sudo ./safeset.sh --confirm
```

Рекомендуемый вариант для боевого хоста:

```bash
sudo ./safeset.sh --create-user ops --ssh-key ~/.ssh/id_ed25519.pub \
                  --admin-ip 203.0.113.10 \
                  --allow-ports 80,443 \
                  --safe-timer 300
```

Важна опция `--safe-timer`: правила firewall «взводятся» с watchdog'ом. Если связность не
подтверждена через `--confirm` (или интерактивный запрос) за отведённое время, **предыдущий
ruleset nftables автоматически восстанавливается**.

## Опции

```
MODES
  --dry-run                 show what would be done, change nothing
  --yes                     non-interactive (no prompts)
  --verbose                 verbose/debug output
  --only <list>             run only these modules (comma separated)
  --skip <list>             skip these modules
  --list-modules            list modules and exit
  --confirm                 confirm firewall connectivity (cancels safe-timer)
  --rollback [TIMESTAMP]    restore files from a backup (default: latest)
  --help                    this help
  --version                 print version

SSH / ACCESS
  --ssh-port <port>         change the SSH port
  --create-user <name>      create a sudo user for key-only login
  --ssh-key <file|key>      public key to install for --create-user
  --allow-users <list>      explicit AllowUsers list for sshd
  --keep-forwarding         keep X11/agent/TCP forwarding (default: disabled)

FIREWALL
  --allow-ports <list>      extra inbound ports, e.g. 80,443 or 8080/tcp
  --admin-ip <ip|cidr>      whitelist an operator IP (repeatable)
  --safe-timer <seconds>    auto-rollback firewall if not confirmed (0=off, default 300)
  --no-ipv6                 disable the IPv6 stack
  --crowdsec                install CrowdSec + nftables bouncer (external repo)
  --honeypot                endlessh tarpit on port 22 (only if SSH moved)

MISC
  --reboot-automatically    allow unattended-upgrades to reboot the host
  --web                     force the web module even without detected server
  --config <file>           load settings from a safeset.conf file
  --no-color                disable colored output
```

Пояснения:

- `--dry-run` работает и без root — просто предупреждает, если какой-то проверочный
  probe требует привилегий.
- Firewall сначала открывает **новый** порт SSH и только потом закрывает старый, поэтому
  смена порта не рвёт активную сессию.
- `--admin-ip` — это whitelist оператора в наборах `admin4`/`admin6` nftables. Если адрес не
  задан, ruleset всё равно применится, и для разблокировки потребуется консоль
  (`nft delete table inet safeset`).
- Вместо флагов можно использовать конфиг-файл: только пары `KEY=VALUE`, без исполнения
  shell-кода (см. `load_config_file` в `safeset.sh`). Ключи повторяют флаги
  (`SSH_PORT`, `ADMIN_IPS`, `ALLOW_PORTS`, `SAFE_TIMER`, `NO_IPV6`, `WEB`, `CROWDSEC`,
  `HONEYPOT`, `KEEP_FORWARDING`, `AUTO_REBOOT`).
- **Порядок поиска конфиг-файла**: `--config <file>` → `./safeset.conf` →
  `/etc/safeset/safeset.conf` (берётся первый доступный на чтение). Файл разбирается
  *до* командной строки, поэтому явно указанный флаг всегда перекрывает значение из файла.
  Логические ключи принимают `true/yes/on/1` и `false/no/off/0`; неизвестный ключ или
  нелогическое значение прерывают запуск.
- Некорректный ввод отвергается **до** проверки прав root: плохой `--admin-ip` (в том числе
  список через запятую) или `--ssh-key` без `--create-user` приводят к немедленной ошибке,
  поэтому неверно настроенный запуск ничего не применяет наполовину.
- Все пути переопределяются через окружение: `SAFESET_BACKUP_ROOT`, `SAFESET_LOG_DIR`,
  `SAFESET_ETC_DIR`, `SAFESET_RUN_DIR`.

## Модули

`safeset.sh --list-modules` печатает тот же список с пояснениями по модулям.

Порядок по умолчанию: `packages → sysctl → filesystem → accounts → audit → firewall →
fail2ban → ssh → web`. `crowdsec` и `honeypot` — только по явному флагу.

- `packages` — установка hardening-инструментов через apt, обработка `needrestart`, чистка
  кэша apt.
- `sysctl` — пишет `/etc/sysctl.d/99-safeset.conf` и применяет его сразу.
- `filesystem` — перемонтирует `/tmp` и `/var/tmp` с `nodev,nosuid,noexec`, ужесточает права
  на `/etc/passwd`, `/etc/shadow`, `/root`, каталоги cron, ставит `/etc/issue.net` и SSH banner.
- `accounts` — `/etc/security/pwquality.conf.d`, `login.defs` (PASS_MAX_DAYS, UMASK, SHA512),
  блокировка неиспользуемых системных учёток, `pam_wheel` для `su`, `umask 027`, `TMOUT=600`,
  запрет core dumps, `/etc/cron.allow`, drop-in sudoers.
- `audit` — `/etc/audit/rules.d/99-safeset.rules` + `augenrules --load`, drop-in journald,
  база AIDE, `safeset-scans.service/.timer` (еженедельные отчёты rkhunter + Lynis + AIDE в
  `/var/log/safeset`), chrony.
- `firewall` — таблица nftables `inet safeset`: default-deny на вход, accept для
  established/related, обработка ICMP, отбрасывание некорректных пакетов, throttle-наборы по
  источнику, rate limit для SSH, наборы whitelist оператора, policy drop для forward, accept
  для output.
- `fail2ban` — `jail.d/99-safeset.local` (sshd), опциональный `99-safeset-web.local`,
  bootstrap `/var/log/auth.log`, systemd-таймер.
- `ssh` — `/etc/ssh/sshd_config.d/99-safeset.conf`; перед установкой конфиг проверяется
  командой `sshd -t`, при ошибке предыдущий drop-in восстанавливается, `sshd` перечитывается
  (не перезапускается); опционально — создание пользователя с ключом.
- `web` — сниппеты для nginx/Apache; трогает конфиги только если веб-сервер обнаружен (или
  задан `--web`).
- `crowdsec` — только `--crowdsec`. Ставит CrowdSec из upstream-репозитория packagecloud
  после проверки GPG-отпечатка ключа репозитория
  (`6A89E3C2303A901A889971D3376ED5326E93CD0C`), затем nftables bouncer.
- `honeypot` — только `--honeypot`. Ловушка endlessh; предупреждает, если порт SSH не
  менялся.

## Модель безопасности

1. **Сначала dry-run.** `--dry-run` печатает каждое действие и ничего не меняет.
2. **Бэкапы.** Каждый изменяемый файл копируется в `/var/backups/safeset/<timestamp>/…` до
   изменения. Создаваемые скриптом файлы тоже фиксируются, поэтому откат удаляет их, а не
   оставляет.
3. **Защита от самоблокировки.** Перед отключением парольной аутентификации скрипт проверяет,
   что остаётся рабочий путь входа по ключу (`assert_no_self_lockout`).
4. **Валидация конфигов.** `sshd -t` и `nft --check` выполняются на *том самом* файле,
   который будет установлен. Неуспешная проверка прерывает модуль, а не оставляет сломанный
   конфиг.
5. **Firewall safe-timer.** `--safe-timer <seconds>` (по умолчанию 300) взводит отдельный
   watchdog. Без `--confirm` предыдущий ruleset nftables восстанавливается автоматически.
6. **Атомарная запись.** Конфиги пишутся во временный файл и переносятся на место, поэтому
   падение не оставит half-written конфиг.

## Откат

```bash
sudo ./safeset.sh --rollback                   # последний бэкап
sudo ./safeset.sh --rollback 20261019-184016   # конкретный запуск
```

Откат восстанавливает все изменённые файлы из набора бэкапа, удаляет созданные в этом
запуске файлы и перечитывает сервисы, где это возможно. Копия состояния «до отката»
остаётся в `/var/backups/safeset/pre-rollback-<timestamp>/`, поэтому откат можно откатить.

## Проверка (CI и локально)

GitHub Actions (`.github/workflows/ci.yml`) запускается на каждом push и pull request:

- `shellcheck -x -S style` по всем shell-файлам — должен быть чистым.
- `shfmt -d` (дефолтные флаги) по всем shell-файлам — должен быть чистым.
- `bats`-тесты в контейнерах `debian:12-slim` и `debian:13-slim`.
- Интеграционный job: реальный запуск скрипта в контейнерах `debian:12`/`debian:13` —
  dry-run, реальный прогон, идемпотентность (второй идентичный прогон), наличие
  `nft list table inet safeset`, валидность конфига fail2ban, модуль SSH с сгенерированным
  ключом и `sshd -t`, и наконец `--rollback`.

Локально (нужен Docker или Podman):

```bash
DOCKER_BIN=podman bash ci/container-smoke.sh docker.io/library/debian:12-slim
DOCKER_BIN=podman bash ci/container-smoke.sh docker.io/library/debian:13-slim
DOCKER_BIN=podman bash ci/lynis-compare.sh  docker.io/library/debian:12-slim
```

`ci/lynis-compare.sh` запускает аудит Lynis до и после реального hardening-прогона и печатает
`LYNIS_BEFORE=<n> LYNIS_AFTER=<n>`.

## Что проверено, а что нет

Честный статус утверждений из этого репозитория.

**Проверено автоматическими тестами в этом репозитории**

- `shellcheck -x -S style`: замечаний нет.
- `shfmt -d`: расхождений нет.
- `bats`-тесты (19): разбор аргументов, выбор модулей, работа с конфиг-файлом, вывод
  help/version и примитивы безопасности (учёт бэкапов, рендеринг шаблонов, откат изменённых и
  созданных файлов).
- Интеграционный smoke-тест (контейнеры Debian 12 и 13): полный dry-run, полный реальный
  прогон, идемпотентный второй прогон, наличие nftables-таблицы, валидный конфиг fail2ban,
  валидный SSH drop-in (`sshd -t`), откат возвращает систему в исходное состояние.
- nftables-ruleset: проверяется `nft --check` на ядре до применения (Debian 12, nft 1.0.6;
  Debian 13).

**Проверено вручную, не покрыто автотестами**

- Индекс hardening Lynis до/после. Последний измеренный прогон (2026-10-21,
  `debian:12-slim`): **58 → 73**. Для своего окружения перезапустите `ci/lynis-compare.sh`.
- Поведение модуля SSH с настоящим сервисом `sshd` (в контейнере проверяется конфиг через
  `sshd -t`, но не выполняется вход по сети).

**Не проверено / известные ограничения**

- Модули CrowdSec и honeypot ставят сторонние компоненты из сети; они опциональны и не
  прогоняются автотестами.
- Kernel-level hardening (blacklist модулей, hardening монтирований, правила auditd) в
  контейнерах пропускается или выполняется частично — скрипт это определяет и сообщает в
  отчёте.
- Инициализация базы AIDE требует `CAP_SETPCAP`/`CAP_SETFCAP` и потому падает в
  ограниченных контейнерах; на реальном хосте работает. Скрипт сообщает об этом как о
  ручном действии, а не падает молча.
- Никаких заявлений о соответствии сертификациям не делается. Конфигурация следует общим
  рекомендациям CIS Debian Level 1, но проект не проходил аудит.

## Структура репозитория

```
safeset.sh              точка входа: аргументы, preflight, цикл модулей, отчёт
lib/common.sh           логирование, файловые помощники, бэкапы, шаблоны, safe-timer
lib/detect.sh           определение ОС/виртуализации/контейнера/nft
lib/rollback.sh         логика отката
lib/modules/*.sh        по файлу на модуль (mod_<name> + mod_<name>_help)
configs/                все файлы, которые ставит скрипт (sysctl, nftables, ssh, audit, …)
tests/                  bats-тесты
ci/                     контейнерный smoke-тест и сравнение Lynis до/после
.github/workflows/      CI: shellcheck, shfmt, bats, интеграционный smoke
```

## Лицензия

MIT — см. [LICENSE](LICENSE).
