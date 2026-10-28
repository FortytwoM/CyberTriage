# Cyber Triage License4J Tool

**English** | [Русский](README.ru.md)

Toolkit for **authorized security research** with Cyber Triage 4.0.0 and
License4J 4.7.3. It generates a compatible RSA/EC keypair, signs Cyber Triage
licenses, patches the Cyber Triage MSI so the application trusts the new
public key, and verifies the result.

> Use only on software you own or are explicitly authorized to test. You are
> responsible for complying with the applicable license and law.

## Features

* RSA-2048 (`SHA512withRSA`) + EC `secp112r1` (`SHA512withECDSA`) keypair,
  encoded in the License4J composite public-key format.
* Create/sign/verify `.l4j` licenses from plaintext `EXTENDED_LICENSE_DATA`.
* Patch the Cyber Triage MSI: replace only the embedded public key in
  `License4JLicense.class`, rebuild the JAR/CAB, update the MSI File table and
  remove the invalid Authenticode signature.
* One-command workflow: put the MSI in `input/`, get everything in `output/`.
* Docker image (Linux containers) and native Windows/Linux wrappers.

## Quick start: Docker (recommended)

### Requirements

* Docker Engine or Docker Desktop with Linux containers (the default on
  Linux, macOS and Windows).
* About 3 GB free disk space for the image, MSI and temporary CAB files.
* Internet access during the first image build (Debian packages).

### Run

1. Put exactly one Cyber Triage `.msi` into `input/`:

   ```text
   input/CyberTriage-4.0.0.msi
   ```

2. Run one command from the repository root:

   ```powershell
   docker compose run --rm --build issue
   ```

3. Results are in `output/`:

   ```text
   output/keypair/                  RSA/EC keys + publickey.txt
   output/CyberTriage-4.0.0-patched.msi
   output/licenses/CLIENT.l4j
   output/licenses/SERVER.l4j
   output/licenses/STANDALONE.l4j
   output/report.txt
   output/report.json
   ```

### Parameters

Set environment variables before the command (PowerShell syntax):

```powershell
$env:LICENSE_ID = "862145687"
$env:CUSTOMER = "Acme Corp"
$env:CUSTOMER_NAME = "Jane Doe"
$env:FORCE = "1"
docker compose run --rm issue
```

On Linux/macOS the same variables can be passed inline:

```sh
LICENSE_ID=42 CUSTOMER="Acme Corp" docker compose run --rm issue
```

| Variable | Default | Meaning |
|---|---|---|
| `LICENSE_ID` | `862145687` | `id` property for all three licenses |
| `CUSTOMER` | Java default `Example` | `ucom` |
| `CUSTOMER_NAME` | Java default `Example User` | `ufn` |
| `FORCE` | `0` | overwrite existing output files |
| `NEW_KEYPAIR` | `0` | generate a new keypair instead of reusing `output/keypair` |
| `KEEP_SIGNATURE` | `0` | keep the now-invalid MSI signature streams |
| `SKIP_MSI` | `0` | license-only run (no MSI patch) |

Extra CLI arguments are appended to the entrypoint:

```powershell
docker compose run --rm issue --license-property lvp=365
```

## Quick start: native Windows or Linux

### Windows

Requirements:

* Python 3.10–3.12 (the `_msi` module is removed in Python 3.13);
* JDK 17+ (`java`, `javac`);
* 7-Zip (`7z.exe`);
* `makecab.exe` (included in Windows).

Put one MSI in `input/`, then run:

```bat
issue.cmd
```

### Linux

Requirements:

* Python 3.10+;
* JDK 17+ (`java`, `javac`);
* `msitools` (`msibuild`, `msiinfo`);
* `gcab`;
* `p7zip-full` (`7z`).

```sh
sudo apt install python3 default-jdk-headless msitools gcab p7zip-full
./issue.sh
```

or:

```sh
python3 tools/cybertriage-license/issue.py
```

License-only run without an MSI:

```sh
python3 tools/cybertriage-license/issue.py --skip-msi
```

## Output

| Path | Contents |
|---|---|
| `output/keypair/publickey.txt` | composite public key, wrapped at 60 chars |
| `output/keypair/publickey.singleline.txt` | composite public key, one line |
| `output/keypair/rsa-private.pem` | RSA private key (keep offline) |
| `output/keypair/ec-private.pem` | EC `secp112r1` private key (keep offline) |
| `output/<msi>-patched.msi` | MSI with the new public key |
| `output/licenses/*.l4j` | signed CLIENT/SERVER/STANDALONE licenses |
| `output/report.txt` / `.json` | summary and verification status |

The public key is **already embedded** in the patched MSI. Install the
application from that MSI; an already installed copy still contains the old
key.

## How it works

### Keypair

The License4J 4.7.3 runtime expects:

* RSA-2048, `e=65537`, `SHA512withRSA` for license text;
* EC `secp112r1` (112 bit), `SHA512withECDSA` for license keys;
* a composite public-key string (743 ASCII chars) that contains both X.509
  keys and the algorithm metadata.

The private keys are written as PKCS#8 PEM files. They never go into the MSI
or the application.

### License creation and signature

The input `licenses/*.l4j` files are plaintext `EXTENDED_LICENSE_DATA` JSON,
not encrypted License4J containers. For each file the tool:

1. builds License4J properties (`lpn`, `lvpid`, `id`, `ucom`, `ufn`, `lft`,
   `dtqlads`, `lgdt`, custom feature, ...);
2. normalizes them exactly like `LicenseText.c()` in the License4J runtime;
3. signs the sorted property **values** with `SHA512withRSA`;
4. encrypts the properties with `PBEWithMD5AndDES` (password derived from the
   normalized composite public key);
5. writes `# <product> License (id: ...)` + hex payload.

`license-id`, customer fields and arbitrary License4J properties can be
overridden. `lft` and `dtqlads` are important: the License4J runtime adds them
during validation, so they must be part of the signed text.

### MSI patch

`msi_patcher.py`:

1. copies the MSI to `output/`;
2. extracts the embedded `disk1.cab` with 7-Zip;
3. finds `com/basistech/df/cybertriage/license/License4JLicense.class` inside
   `cybertriage4.0.0.jar`;
4. replaces only the 755-byte `publickey` constant (same length, LF wrapping);
5. rewrites the JAR and rebuilds the CAB with `makecab` (Windows) or `gcab`
   (Linux);
6. replaces the `disk1.cab` stream and updates the JAR `FileSize` in the MSI
   File table;
7. removes `\x05DigitalSignature` and `\x05MsiDigitalSignatureEx`, because the
   original Authenticode signature becomes invalid after the patch.

The source MSI is never modified.

Two backends implement the MSI operations:

* **Windows native:** Python `_msi` + `makecab.exe`.
* **Linux/macOS/Docker:** `msitools` (`msiinfo`/`msibuild`) + `gcab` + `7z`.

Both patch the same bytes: only the public-key constant, the JAR size and the
signature streams are changed.

### Verification

Our verifier decrypts the `.l4j`, rebuilds the signed text and checks the RSA
signature:

```powershell
python tools/cybertriage-license/ct_keytool.py verify `
  --public-key output/keypair/publickey.txt `
  --licenses output/licenses
```

The generated licenses were also tested with the real
`license4j-runtime-library-4.7.3.jar`:

```java
LicenseValidator.validate(
    licenseText, publicKey, "Cyber Triage", "", "",
    new Date(), new Date(System.currentTimeMillis() + 10L * 365 * 24 * 3600 * 1000));
// -> LICENSE_VALID
```

## Advanced CLI

`ct_keytool.py` exposes the lower-level operations:

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

## Repository layout

```text
input/                         user-provided MSI (ignored by git)
output/                        generated keys, patched MSI, licenses, report
licenses/                      three typical EXTENDED_LICENSE_DATA files
tools/cybertriage-license/     Java generator, Python wrapper, MSI patcher
Dockerfile                     Linux container image
docker-compose.yml             one-command service
issue.cmd / issue.sh           native wrappers
README.md / README.ru.md       English / Russian documentation
SECURITY.md                    security and responsible-use notes
LICENSE                        MIT license
```

## Limitations

* MSI patching supports embedded cabinets (`Media.Cabinet = #...`). External
  CAB files and signed JARs are not supported.
* The patched MSI is unsigned; Windows may show an "unknown publisher"
  warning. This is expected.
* A patched MSI must be installed over/next to the original installation;
  the already installed application is not modified in place.
* `licenses/*.l4j` contain `<redacted>` API keys; replace them with real values
  before using the licenses.
* `secp112r1` is weak by modern standards; it is used only because License4J
  4.7.3 hard-codes it for license keys.
* The Docker image is a **Linux** image (Linux containers) and works on
  Linux, macOS and Windows Docker Desktop. Native MSI patching uses `_msi`
  (Windows) or `msitools` (Linux); both backends are supported.

## License

MIT. See [LICENSE](LICENSE).
