# LDT — Local Data Transfer

> Одна команда. Без сервера. Тільки Python stdlib.

## Запуск

```
python ldt.py <ваше_ім'я> receive
python ldt.py <ваше_ім'я> send <адресат> <файл_або_папка>
python ldt.py <ваше_ім'я> peers
```

## Приклади

```bash
# Комп'ютер A — приймає файли (ім'я Alice)
python ldt.py Alice receive

# Комп'ютер B — дивимось хто в мережі
python ldt.py Bob peers

# Комп'ютер B — надсилаємо файл до Alice
python ldt.py Bob send Alice звіт.pdf

# Комп'ютер B — надсилаємо цілу папку
python ldt.py Bob send Alice ./проект
```

## Параметри

| Параметр | Опис |
|---|---|
| `--port N` | UDP/TCP порт (за замовч. 9900) |
| `--dir DIR` | Куди зберігати файли при receive (за замовч. `./received`) |
| `--quiet` | Без прогрес-бару |
| `--wait N` | Час очікування для peers (сек, за замовч. 3) |
| `-v` | Debug-логування |

## Технічні деталі

| | |
|---|---|
| **Виявлення** | UDP multicast `239.255.42.42:9900` |
| **Передача** | TCP стрімінг чанками по 512 KiB |
| **Стиснення** | zlib рівень 6 (stdlib) |
| **Цілісність** | SHA-256 на кожен чанк + весь файл |
| **Retry** | Автоматично до 3× при bad hash |
| **Залежності** | Тільки Python stdlib (3.10+) |
