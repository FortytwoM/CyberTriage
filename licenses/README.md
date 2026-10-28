Typical Cyber Triage runtime payloads
=====================================

These three `.l4j` files are plaintext `EXTENDED_LICENSE_DATA` JSON
(CLIENT, SERVER, STANDALONE). They are **not** signed License4J containers.

The tool embeds each file into a license as `csf-EXTENDED_LICENSE_DATA`,
adds the standard License4J properties, signs the result and encrypts it.

Do not put real API keys or other secrets here: the repository is public and
the values are copied into every generated license.
