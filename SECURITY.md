# Security and responsible use

## Authorization

This tool changes the licensing behavior of Cyber Triage and removes the
Authenticode signature from the patched MSI. Use it only on software you own or
are explicitly authorized to test. Do not use it to bypass licensing for
third parties.

## Private keys

`output/keypair/rsa-private.pem` and `output/keypair/ec-private.pem` are the
signing keys. Anyone with these files can issue licenses that the patched
application accepts.

* Keep them offline and out of git.
* Do not attach them to issues or pull requests.
* The repository ignores `output/`, `**/keypair/`, `**/rsa-private.pem`
  and `**/ec-private.pem`.
* If a key leaks, generate a new keypair (`NEW_KEYPAIR=1` / `--new-keypair`),
  re-patch the MSI and reissue the licenses.

## Patched MSI

The patch replaces the embedded public key, rebuilds the cabinet and removes
the original Authenticode signature streams. The resulting MSI is unsigned and
will trigger the normal Windows "unknown publisher" warning.

Only the public key in `License4JLicense.class` is changed. No other
application logic is modified.

## Secrets in license data

The example files in `licenses/` contain a redacted ReversingLabs API key.
Generated licenses include whatever is in those files. Do not put real API
keys, credentials or customer data into a public repository.

## Reporting issues

When reporting a problem, include the command, exit code and sanitized log.
Never include private keys, real API keys or complete customer license data.
