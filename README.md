# torwall

Transparent system-wide Tor firewall with a kill-switch. It forces all outbound
TCP traffic and DNS queries through Tor. If Tor isn't running, traffic is
dropped instead of leaking out, so you never accidentally connect outside Tor.
IPv6 is disabled by default because it's a common way to get deanonymized.

On load it also swaps your MAC address and hostname for random ones, and puts
them back automatically when you exit.

[Русская версия ниже](#torwall-русская-версия)

## What it does

- Routes everything through Tor at the iptables level.
- Kill-switch: if Tor goes down, nothing leaks.
- Blocks IPv6.
- Random MAC address and hostname, restored automatically on exit.
- A mode that leaves your identity untouched (for trusted networks / SSH).
- Optional IP rotation on a timer.

## Requirements

- Linux with systemd or SysV init.
- Python 3.8+ (standard library only, no pip packages).
- The `tor` package, installed and working.
- `iptables`, the `ip` tool (iproute2), and `hostnamectl`.
- Root access.

Install the dependencies on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install tor iptables iproute2
```

On Arch/BlackArch:

```bash
sudo pacman -S tor iptables iproute2
```

## Install

```bash
git clone https://github.com/<your-username>/torwall.git
cd torwall
chmod +x torwall.py
```

If you want to call it from anywhere, drop it in your PATH:

```bash
sudo cp torwall.py /usr/local/bin/torwall
```

Then you can run `sudo torwall` instead of `sudo python3 torwall.py`.

## Usage

It needs root. All examples assume you're in the project folder.

### On an untrusted network (cafe, hotel, public Wi-Fi)

Turns on the firewall and randomizes your MAC and hostname:

```bash
sudo python3 torwall.py --load
```

The script keeps running and holds the fake identity. Press `Ctrl+C` to put
your real MAC and hostname back - it happens automatically.

### On a trusted network (at home, over SSH)

Turns on the Tor firewall only, without touching your MAC or hostname. Use this
when you're connected over SSH: changing the MAC would kill your own connection.

```bash
sudo python3 torwall.py --load --keep-identity
```

You can also skip just one of them:

```bash
sudo python3 torwall.py --load --no-mac        # change hostname only
sudo python3 torwall.py --load --no-hostname   # change MAC only
```

### Turning it off

Clears the firewall rules and restores your original MAC and hostname:

```bash
sudo python3 torwall.py --flush
```

### Other commands

```bash
sudo python3 torwall.py --status     # tor + firewall state and current IP
sudo python3 torwall.py --ip         # show current public IP
sudo python3 torwall.py --refresh    # request a new circuit and new IP
sudo python3 torwall.py --auto 180   # change IP every 180 seconds
```

Add `--mac` and/or `--hostname` to `--auto` to also rotate those each cycle:

```bash
sudo python3 torwall.py --auto 300 --mac --hostname
```

## How the identity restore works

The first time something changes, the original MAC of each interface and the
hostname are saved to `/var/run/torwall_identity.json`. That file lives on tmpfs
and doesn't survive a reboot. Restore kicks in on a normal exit, on `Ctrl+C`
(and on TERM/HUP signals), and on `--flush`.

If the process gets killed hard (`SIGKILL`) and the restore doesn't run, just
fix it manually:

```bash
sudo python3 torwall.py --flush
```

## Project layout

```
torwall/
├── torwall.py    main script
└── README.md     this file
```

## Things to keep in mind

- Don't randomize the MAC of the interface you're connected through in a remote
  session. The interface bounces and your connection drops. For remote work use
  `--keep-identity`, or run it inside `tmux`/`screen`.
- Restore uses the interface names that existed when the values were saved.
- This touches your system firewall and network settings. Read through the
  rules and make sure they fit your setup before using it for real.

## License

MIT. See the `LICENSE` file.

---

# torwall (русская версия)

Прозрачный системный фаервол поверх Tor с kill-switch. Заворачивает весь
исходящий TCP-трафик и DNS-запросы в Tor. Если Tor не запущен, трафик
блокируется, а не идёт в обход - так что мимо Tor вы случайно не выйдете.
IPv6 по умолчанию отключается, потому что это частый способ деанонимизации.

При загрузке заодно меняет MAC-адрес и hostname на случайные и возвращает их
обратно сам, когда вы выходите.

## Что умеет

- Заворачивает весь трафик в Tor на уровне iptables.
- Kill-switch: упал Tor - ничего не утекает.
- Блокирует IPv6.
- Случайный MAC и hostname, откат при выходе автоматический.
- Режим, который не трогает вашу идентичность (для доверенных сетей / SSH).
- Ротация IP по таймеру, если нужно.

## Что нужно

- Linux с systemd или SysV init.
- Python 3.8+ (только стандартная библиотека, никаких pip-пакетов).
- Установленный и рабочий пакет `tor`.
- `iptables`, утилита `ip` (iproute2) и `hostnamectl`.
- Права root.

Поставить зависимости на Debian/Ubuntu:

```bash
sudo apt update
sudo apt install tor iptables iproute2
```

На Arch/BlackArch:

```bash
sudo pacman -S tor iptables iproute2
```

## Установка

```bash
git clone https://github.com/<your-username>/torwall.git
cd torwall
chmod +x torwall.py
```

Если хотите вызывать откуда угодно - закиньте в PATH:

```bash
sudo cp torwall.py /usr/local/bin/torwall
```

Тогда вместо `sudo python3 torwall.py` можно писать просто `sudo torwall`.

## Использование

Нужен root. Все примеры - из каталога проекта.

### В чужой сети (кафе, отель, публичный Wi-Fi)

Включает фаервол и меняет MAC и hostname на случайные:

```bash
sudo python3 torwall.py --load
```

Скрипт продолжает работать и держит подменённую идентичность. Нажмите `Ctrl+C`,
чтобы вернуть настоящие MAC и hostname - это происходит само.

### В доверенной сети (дома, по SSH)

Включает только Tor-фаервол, не трогая MAC и hostname. Это нужно, когда вы
сидите по SSH: смена MAC оборвала бы ваше же соединение.

```bash
sudo python3 torwall.py --load --keep-identity
```

Можно пропустить что-то одно:

```bash
sudo python3 torwall.py --load --no-mac        # сменить только hostname
sudo python3 torwall.py --load --no-hostname   # сменить только MAC
```

### Выключение

Сбрасывает правила фаервола и возвращает исходные MAC и hostname:

```bash
sudo python3 torwall.py --flush
```

### Остальные команды

```bash
sudo python3 torwall.py --status     # состояние tor + фаервола и текущий IP
sudo python3 torwall.py --ip         # показать текущий публичный IP
sudo python3 torwall.py --refresh    # новая цепочка и новый IP
sudo python3 torwall.py --auto 180   # менять IP каждые 180 секунд
```

К `--auto` можно добавить `--mac` и/или `--hostname`, чтобы на каждом цикле
менялись и они:

```bash
sudo python3 torwall.py --auto 300 --mac --hostname
```

## Как работает откат идентичности

При первой смене исходные MAC каждого интерфейса и hostname сохраняются в
`/var/run/torwall_identity.json`. Файл лежит на tmpfs и не переживает
перезагрузку. Откат срабатывает при обычном выходе, по `Ctrl+C` (а также по
сигналам TERM/HUP) и при `--flush`.

Если процесс убили жёстко (`SIGKILL`) и откат не отработал - почините руками:

```bash
sudo python3 torwall.py --flush
```

## Структура проекта

```
torwall/
├── torwall.py    основной скрипт
└── README.md     этот файл
```

## О чём помнить

- Не меняйте MAC интерфейса, через который вы подключены, в удалённой сессии.
  Интерфейс переподнимается, и связь рвётся. Для удалённой работы используйте
  `--keep-identity` или запускайте в `tmux`/`screen`.
- При откате берутся те имена интерфейсов, что были на момент сохранения.
- Скрипт правит системный фаервол и сетевые настройки. Прочитайте правила и
  убедитесь, что они подходят под вашу конфигурацию, прежде чем использовать
  всерьёз.

## Лицензия

MIT. См. файл `LICENSE`.
