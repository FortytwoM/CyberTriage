# Cyber Triage License4J Tool

[English](README.md) | **Русский**

Инструмент для **авторизованного security research** с Cyber Triage 4.0.0 и
License4J 4.7.3. Генерирует совместимый keypair RSA/EC, подписывает лицензии
Cyber Triage, патчит MSI (встраивает новый публичный ключ) и проверяет
результат.

> Используйте только на ПО, которым владеете или на тестирование которого у
> вас есть разрешение. Ответственность за соблюдение лицензии и закона лежит
> на вас.

## Возможности

* Keypair RSA-2048 (`SHA512withRSA`) + EC `secp112r1` (`SHA512withECDSA`) в
  composite-формате публичного ключа License4J.
* Создание, подпись и проверка `.l4j` из plaintext `EXTENDED_LICENSE_DATA`.
* Патч MSI: замена только встроенного public key в `License4JLicense.class`,
  пересборка JAR/CAB, обновление File table и удаление недействительной
  Authenticode-подписи.
* Одна команда: MSI кладётся в `input/`, всё остальное появляется в `output/`.
* Docker-образ (Linux containers) и нативные обёртки для Windows/Linux.

## Быстрый старт: Docker (рекомендуется)

### Требования

* Docker Engine или Docker Desktop с Linux-контейнерами (по умолчанию на
  Linux, macOS и Windows).
* Около 3 GB свободного места (образ, MSI и временные CAB).
* Интернет при первой сборке образа (пакеты Debian).

### Запуск

1. Положите ровно один `.msi` в `input/`:

   ```text
   input/CyberTriage-4.0.0.msi
   ```

2. Из корня репозитория выполните одну команду:

   ```powershell
   docker compose run --rm --build issue
   ```

3. Результаты появятся в `output/`:

   ```text
   output/keypair/                  ключи и publickey.txt
   output/CyberTriage-4.0.0-patched.msi
   output/licenses/CLIENT.l4j
   output/licenses/SERVER.l4j
   output/licenses/STANDALONE.l4j
   output/report.txt
   output/report.json
   ```

### Параметры

Переменные окружения задаются перед командой (PowerShell):

```powershell
$env:LICENSE_ID = "862145687"
$env:CUSTOMER = "Acme Corp"
$env:CUSTOMER_NAME = "Jane Doe"
$env:FORCE = "1"
docker compose run --rm issue
```

В Linux/macOS те же переменные можно передать inline:

```sh
LICENSE_ID=42 CUSTOMER="Acme Corp" docker compose run --rm issue
```

| Переменная | По умолчанию | Значение |
|---|---|---|
| `LICENSE_ID` | `862145687` | свойство `id` для всех трёх лицензий |
| `CUSTOMER` | `Example` (Java default) | `ucom` |
| `CUSTOMER_NAME` | `Example User` (Java default) | `ufn` |
| `FORCE` | `0` | перезаписать существующие результаты |
| `NEW_KEYPAIR` | `0` | сгенерировать новый keypair вместо `output/keypair` |
| `KEEP_SIGNATURE` | `0` | оставить недействительные signature streams MSI |
| `SKIP_MSI` | `0` | только лицензии, без патча MSI |

Дополнительные CLI-аргументы добавляются к entrypoint:

```powershell
docker compose run --rm issue --license-property lvp=365
```

## Быстрый старт: нативный Windows или Linux

### Windows

Требования:

* Python 3.10–3.12 (в Python 3.13 модуль `_msi` удалён);
* JDK 17+ (`java`, `javac`);
* 7-Zip (`7z.exe`);
* `makecab.exe` (входит в Windows).

Положите один MSI в `input/` и выполните:

```bat
issue.cmd
```

### Linux

Требования:

* Python 3.10+;
* JDK 17+ (`java`, `javac`);
* `msitools` (`msibuild`, `msiinfo`);
* `gcab`;
* `p7zip-full` (`7z`).

```sh
sudo apt install python3 default-jdk-headless msitools gcab p7zip-full
./issue.sh
```

или:

```sh
python3 tools/cybertriage-license/issue.py
```

Только лицензии, без MSI:

```sh
python3 tools/cybertriage-license/issue.py --skip-msi
```

## Результаты

| Путь | Содержимое |
|---|---|
| `output/keypair/publickey.txt` | composite public key, перенос по 60 символов |
| `output/keypair/publickey.singleline.txt` | composite public key одной строкой |
| `output/keypair/rsa-private.pem` | RSA private key (хранить offline) |
| `output/keypair/ec-private.pem` | EC `secp112r1` private key (хранить offline) |
| `output/<msi>-patched.msi` | MSI с новым публичным ключом |
| `output/licenses/*.l4j` | подписанные CLIENT/SERVER/STANDALONE |
| `output/report.txt` / `.json` | отчёт и статусы проверки |

Публичный ключ **уже встроен** в patched MSI. Устанавливать приложение нужно
из этого MSI; уже установленная копия продолжает использовать старый ключ.

## Как это устроено

### Keypair

License4J 4.7.3 ожидает:

* RSA-2048, `e=65537`, `SHA512withRSA` для текста лицензии;
* EC `secp112r1` (112 bit), `SHA512withECDSA` для license key;
* composite public key (743 ASCII-символа) с обоими X.509 ключами и
  метаданными алгоритмов.

Приватные ключи пишутся в PKCS#8 PEM и не попадают в MSI или приложение.

### Создание и подпись лицензии

Файлы `licenses/*.l4j` — это plaintext `EXTENDED_LICENSE_DATA` JSON, а не
зашифрованные контейнеры License4J. Для каждого файла инструмент:

1. собирает properties License4J (`lpn`, `lvpid`, `id`, `ucom`, `ufn`, `lft`,
   `dtqlads`, `lgdt`, custom feature, ...);
2. нормализует их так же, как `LicenseText.c()` в runtime License4J;
3. подписывает отсортированные **значения** свойств через `SHA512withRSA`;
4. шифрует properties через `PBEWithMD5AndDES` (пароль выводится из
   нормализованного composite public key);
5. пишет `# <product> License (id: ...)` + hex payload.

`license-id`, customer-поля и произвольные License4J properties можно
переопределять. `lft` и `dtqlads` важны: runtime License4J добавляет их при
валидации, поэтому они должны входить в подписанный текст.

### Патч MSI

`msi_patcher.py`:

1. копирует MSI в `output/`;
2. извлекает встроенный `disk1.cab` через 7-Zip;
3. находит `com/basistech/df/cybertriage/license/License4JLicense.class` в
   `cybertriage4.0.0.jar`;
4. заменяет только 755-байтную константу `publickey` (длина сохраняется,
   переносы LF);
5. пересобирает JAR и CAB (`makecab` в Windows, `gcab` в Linux);
6. заменяет stream `disk1.cab` и обновляет `FileSize` JAR в File table MSI;
7. удаляет `\x05DigitalSignature` и `\x05MsiDigitalSignatureEx`, потому что
   Authenticode-подпись исходного MSI после патча недействительна.

Исходный MSI не изменяется.

Используются два бэкенда:

* **Native Windows:** Python `_msi` + `makecab.exe`.
* **Linux/macOS/Docker:** `msitools` (`msiinfo`/`msibuild`) + `gcab` + `7z`.

Оба меняют одно и то же: только константу публичного ключа, размер JAR и
signature streams.

### Проверка

Наш verifier расшифровывает `.l4j`, собирает подписанный текст и проверяет
RSA-подпись:

```powershell
python tools/cybertriage-license/ct_keytool.py verify `
  --public-key output/keypair/publickey.txt `
  --licenses output/licenses
```

Лицензии также проверены настоящим `license4j-runtime-library-4.7.3.jar`:

```java
LicenseValidator.validate(
    licenseText, publicKey, "Cyber Triage", "", "",
    new Date(), new Date(System.currentTimeMillis() + 10L * 365 * 24 * 3600 * 1000));
// -> LICENSE_VALID
```

## Продвинутый CLI

`ct_keytool.py` — низкоуровневые операции:

```powershell
python tools/cybertriage-license/ct_keytool.py build
python tools/cybertriage-license/ct_keytool.py generate --out ./keypair
python tools/cybertriage-license/ct_keytool.py inspect --public-key ./keypair/publickey.txt
python tools/cybertriage-license/ct_keytool.py sign --license ./licenses/CLIENT.l4j `
  --public-key ./keypair/publickey.txt --private-key ./keypair/rsa-private.pem `
  --out ./CLIENT.l4j
python tools/cybertriage-license/ct_keytool.py verify `
  --public-key ./keypair/publickey.txt --licenses ./CLIENT.l4j
python tools/cybertriage-license/ct_keytool.py patch-msi `
  --msi ./input/CyberTriage-4.0.0.msi --out ./output/CyberTriage-4.0.0-patched.msi `
  --public-key ./keypair/publickey.txt
```

## Структура репозитория

```text
input/                         MSI пользователя (игнорируется git)
output/                        ключи, patched MSI, лицензии, отчёт
licenses/                      три типовых EXTENDED_LICENSE_DATA
tools/cybertriage-license/     Java-генератор, Python-обёртка, MSI patcher
Dockerfile                     образ Linux-контейнера
docker-compose.yml             сервис для одной команды
issue.cmd / issue.sh           нативные обёртки
README.md / README.ru.md       документация EN / RU
SECURITY.md                    безопасность и ответственное использование
LICENSE                        лицензия MIT
```

## Ограничения

* Патч MSI поддерживает только embedded cabinets (`Media.Cabinet = #...`).
  Внешние CAB и подписанные JAR не поддерживаются.
* Patched MSI не подписан; Windows может показать предупреждение об
  неизвестном издателе. Это ожидаемо.
* Patched MSI нужно устанавливать поверх/рядом с оригинальной установкой;
  уже установленное приложение не меняется на месте.
* В `licenses/*.l4j` API-ключи заменены на `<redacted>`; перед реальным
  использованием подставьте действующие значения и перевыпустите лицензии.
* `secp112r1` слабая по современным меркам; используется только потому, что
  License4J 4.7.3 жёстко задаёт её для license key.
* Docker-образ **Linux** (Linux containers); работает на Linux, macOS и
  Windows Docker Desktop. Нативный патч MSI использует `_msi` (Windows) или
  `msitools` (Linux); поддержаны оба бэкенда.

## Лицензия

MIT. См. [LICENSE](LICENSE).
