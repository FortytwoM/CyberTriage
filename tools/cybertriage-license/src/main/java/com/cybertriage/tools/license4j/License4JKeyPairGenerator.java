package com.cybertriage.tools.license4j;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Generates a License4J 4.7.3-compatible keypair for Cyber Triage.
 *
 * <p>Fixed parameters (dictated by the License4J 4.7.3 runtime and by the
 * application's {@code LicenseValidator.validate(...)} call):
 *
 * <ul>
 *   <li>Product ID: {@code Cyber Triage}</li>
 *   <li>Product edition: empty</li>
 *   <li>Product version: empty</li>
 *   <li>License-text key: RSA 2048, SHA512withRSA</li>
 *   <li>License-key key: EC secp112r1 (112 bit), SHA512withECDSA</li>
 *   <li>Public key: License4J composite string (not PEM/DER)</li>
 * </ul>
 */
public final class License4JKeyPairGenerator {

    private static final Pattern CUSTOM_FEATURE_VERSION =
            Pattern.compile("\"version\"\\s*:\\s*\"?([0-9]+(?:\\.[0-9]+)*)\"?");

    private static final String DEFAULT_PRODUCT = "Cyber Triage";
    private static final String EXTENDED_LICENSE_DATA_KEY = "csf-EXTENDED_LICENSE_DATA";
    private static final String DEFAULT_EXTENDED_LICENSE_DATA =
            "{\"version\":2.4,\"license_details\":{\"type\":\"PAID\","
                    + "\"mode\":\"STAND_ALONE\"}}";

    private License4JKeyPairGenerator() {
    }

    public static void main(String[] args) {
        try {
            Options options = Options.parse(args);
            if (options.help) {
                printUsage();
                return;
            }
            int selected = (options.inspectPublicKey != null ? 1 : 0)
                    + (options.verifyLicense != null ? 1 : 0)
                    + (options.signLicense != null ? 1 : 0);
            if (selected > 1) {
                throw new IllegalArgumentException(
                        "--inspect-public-key, --verify-license and --sign-license are mutually exclusive");
            }
            if (options.licenseData != null && selected > 0 && options.signLicense == null) {
                throw new IllegalArgumentException(
                        "--license-data cannot be combined with --inspect-public-key or --verify-license");
            }
            if (options.inspectPublicKey != null) {
                inspectPublicKey(options.inspectPublicKey);
                return;
            }
            if (options.verifyLicense != null) {
                int status = verifyLicense(options);
                if (status != 0) {
                    System.exit(status);
                }
                return;
            }
            if (options.signLicense != null) {
                if (options.licenseData != null) {
                    throw new IllegalArgumentException(
                            "--license-data is used with --out (combined generate+sign); "
                                    + "use --sign-license for an existing keypair");
                }
                signLicense(options);
                return;
            }
            if (options.licenseData != null) {
                if (options.signedOutput == null) {
                    throw new IllegalArgumentException(
                            "--license-data requires --signed-output <file>");
                }
                if (!Files.isRegularFile(options.licenseData)) {
                    throw new IllegalArgumentException(
                            "License data file not found: " + options.licenseData);
                }
                if (Files.exists(options.signedOutput)) {
                    throw new IllegalArgumentException("Output already exists (will not overwrite): "
                            + options.signedOutput);
                }
            } else if (options.signedOutput != null) {
                throw new IllegalArgumentException(
                        "--signed-output requires --license-data or --sign-license");
            }
            if (options.licenseData == null && options.signLicense == null
                    && (options.licenseId != null || options.customer != null
                            || options.customerName != null
                            || !options.licenseProperties.isEmpty())) {
                throw new IllegalArgumentException(
                        "--license-id/--customer/--customer-name/--license-property "
                                + "require --license-data or --sign-license");
            }
            generate(options);
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            if (System.getenv("DEBUG") != null) {
                e.printStackTrace();
            }
            System.exit(2);
        }
    }

    // ------------------------------------------------------------------
    // Generation
    // ------------------------------------------------------------------

    private static void generate(Options options) throws Exception {
        System.out.println("Cyber Triage License4J keypair generator");
        System.out.println("  Product ID      : " + printable(options.productId));
        System.out.println("  Product edition : " + printable(options.productEdition));
        System.out.println("  Product version : " + printable(options.productVersion));
        System.out.println("  License text    : RSA 2048, SHA512withRSA");
        System.out.println("  License key     : EC secp112r1 (112 bit), SHA512withECDSA");
        System.out.println();

        SecureRandom random = new SecureRandom();

        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(
                new RSAKeyGenParameterSpec(License4JCompositeKey.RSA_KEY_SIZE,
                        RSAKeyGenParameterSpec.F4),
                random);
        KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();

        byte[] rsaPublicDer = rsaKeyPair.getPublic().getEncoded();
        if (rsaPublicDer.length != License4JCompositeKey.RSA_DER_LENGTH) {
            throw new IllegalStateException("Unexpected RSA public key length: "
                    + rsaPublicDer.length + " bytes (expected 294)");
        }

        EcMaterial ec = loadOrGenerateEc(options, random);
        String composite = License4JCompositeKey.encode(rsaPublicDer, ec.publicDer);

        License4JCompositeKey.Decoded decoded = License4JCompositeKey.decode(composite);
        if (!Arrays.equals(rsaPublicDer, decoded.rsaPublicKeyDer)) {
            throw new IllegalStateException("RSA public key round-trip failed");
        }
        if (!Arrays.equals(ec.publicDer, decoded.ecPublicKeyDer)) {
            throw new IllegalStateException("EC public key round-trip failed");
        }

        String sampleText = sampleSignedText();
        Signature rsaSigner = Signature.getInstance("SHA512withRSA");
        rsaSigner.initSign(rsaKeyPair.getPrivate());
        rsaSigner.update(sampleText.getBytes(StandardCharsets.UTF_8));
        byte[] rsaSignature = rsaSigner.sign();

        Signature rsaVerifier = Signature.getInstance("SHA512withRSA");
        rsaVerifier.initVerify(decoded.rsaPublicKey);
        rsaVerifier.update(sampleText.getBytes(StandardCharsets.UTF_8));
        if (!rsaVerifier.verify(rsaSignature)) {
            throw new IllegalStateException("RSA/SHA-512 self-test failed");
        }

        if (ec.privateScalar != null) {
            byte[] message = "License4J 4.7.3 ECDSA self-test".getBytes(StandardCharsets.UTF_8);
            Secp112r1.SignatureData signature = Secp112r1.sign(message, ec.privateScalar, random);
            if (!Secp112r1.verify(message, decoded.ecPublicKey.getW(), signature.r, signature.s)) {
                throw new IllegalStateException("ECDSA/secp112r1 self-test failed");
            }
        }

        System.out.println("[OK] composite public key round-trip");
        System.out.println("[OK] RSA/SHA-512 license-text signature");
        if (ec.privateScalar != null) {
            System.out.println("[OK] ECDSA/secp112r1 signature");
        } else {
            System.out.println("[WARN] no EC private key available; ECDSA self-test skipped");
        }
        System.out.println();

        prepareOutputDir(options);
        writeOutputs(options, rsaKeyPair, ec, composite);

        if (options.licenseData != null) {
            Path output = options.signedOutput.toAbsolutePath().normalize();
            Properties licenseProperties = buildLicenseProperties(options.licenseData, options, true);
            writeSignedLicense(licenseProperties, rsaKeyPair.getPrivate(), composite, output);
            System.out.println("Signed license  : " + output);
        }

        System.out.println("Output directory: " + options.out.toAbsolutePath());
        System.out.println("  publickey.txt             composite public key (wrapped at 60 chars)");
        System.out.println("  publickey.singleline.txt  composite public key (one line)");
        System.out.println("  rsa-private.pem           PKCS#8 RSA private key (KEEP OFFLINE)");
        System.out.println("  rsa-public.pem            X.509 RSA public key");
        if (ec.privateScalar != null) {
            System.out.println("  ec-private.pem            PKCS#8 secp112r1 private key (KEEP OFFLINE)");
        } else {
            System.out.println("  ec-private.pem            not written (no EC private key supplied)");
        }
        System.out.println("  ec-public.pem             X.509 secp112r1 public key");
        System.out.println("  keypair.properties        metadata");
        System.out.println("  keypair.json              metadata (JSON)");
        System.out.println();
        System.out.println("Composite public key SHA-256: "
                + License4JCompositeKey.sha256Hex(composite.getBytes(StandardCharsets.US_ASCII)));
        System.out.println("RSA public key SHA-256      : "
                + License4JCompositeKey.sha256Hex(rsaPublicDer));
        System.out.println("EC public key SHA-256       : "
                + License4JCompositeKey.sha256Hex(ec.publicDer));
        System.out.println();
        System.out.println("Embed publickey.singleline.txt (or publickey.txt) into the");
        System.out.println("License4J public-key constant. License4J strips newlines and");
        System.out.println("ignores '#' comment lines.");
    }

    private static final class EcMaterial {
        final BigInteger privateScalar; // nullable
        final ECPoint publicPoint;
        final byte[] publicDer;

        EcMaterial(BigInteger privateScalar, ECPoint publicPoint, byte[] publicDer) {
            this.privateScalar = privateScalar;
            this.publicPoint = publicPoint;
            this.publicDer = publicDer;
        }
    }

    private static EcMaterial loadOrGenerateEc(Options options, SecureRandom random)
            throws Exception {
        if (options.reuseEcPrivate != null) {
            BigInteger d = readEcPrivateScalar(options.reuseEcPrivate);
            ECPoint q = Secp112r1.multiply(d, Secp112r1.G);
            byte[] der;
            if (options.reuseEcPublic != null) {
                der = readEcPublicDer(options.reuseEcPublic);
                ECPoint supplied = Secp112r1.decodePublicKey(der);
                if (!q.equals(supplied)) {
                    throw new IllegalArgumentException(
                            "The supplied EC private key does not match the supplied EC public key");
                }
            } else {
                der = Secp112r1.encodePublicKey(q);
            }
            return new EcMaterial(d, q, der);
        }

        if (options.reuseEcPublic != null) {
            byte[] der = readEcPublicDer(options.reuseEcPublic);
            return new EcMaterial(null, Secp112r1.decodePublicKey(der), der);
        }

        Secp112r1.KeyData generated = Secp112r1.generate(random);
        return new EcMaterial(generated.d, generated.q,
                Secp112r1.encodePublicKey(generated.q));
    }

    private static byte[] readEcPublicDer(Path file) throws Exception {
        String text = readUtf8OrNull(file);
        if (text != null) {
            String normalized = License4JCompositeKey.normalize(text);
            if (!text.contains("-----BEGIN")
                    && normalized.length() >= 700
                    && normalized.indexOf(License4JCompositeKey.SEPARATOR) >= 0) {
                return License4JCompositeKey.decode(normalized).ecPublicKeyDer;
            }
        }

        byte[] der = text == null ? null : Pem.decode(text);
        if (der == null) {
            der = Files.readAllBytes(file);
        }
        ECPoint point = Secp112r1.decodePublicKey(der);
        return Secp112r1.encodePublicKey(point);
    }

    private static BigInteger readEcPrivateScalar(Path file) throws Exception {
        String text = readUtf8OrNull(file);
        byte[] der = text == null ? null : Pem.decode(text);
        if (der == null) {
            der = Files.readAllBytes(file);
        }

        BigInteger d;
        try {
            ECPrivateKey key = (ECPrivateKey) KeyFactory.getInstance("EC")
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
            d = key.getS();
        } catch (Exception e) {
            d = decodeEcPrivateKeyFallback(der);
            if (d == null) {
                throw new IllegalArgumentException(
                        "Cannot parse the EC private key as PKCS#8/SEC1 secp112r1: "
                                + e.getMessage(), e);
            }
        }

        if (!Secp112r1.isValidPrivateScalar(d)) {
            throw new IllegalArgumentException("EC private scalar is out of range");
        }
        return d;
    }

    /**
     * Parses the two common encodings without relying on provider support for
     * secp112r1: PKCS#8 PrivateKeyInfo (46 bytes) and SEC1 ECPrivateKey
     * (shorter, starts with version 1 and an OCTET STRING private key).
     */
    private static BigInteger decodeEcPrivateKeyFallback(byte[] der) {
        if (der == null) {
            return null;
        }
        // PKCS#8: 30 2c 02 01 00 30 10 ... 04 15 30 13 02 01 01 04 0e <d>
        if (der.length == 46
                && (der[0] & 0xff) == 0x30
                && (der[1] & 0xff) == 0x2c
                && (der[30] & 0xff) == 0x04
                && (der[31] & 0xff) == 0x0e) {
            return new BigInteger(1, Arrays.copyOfRange(der, 32, 46));
        }
        // SEC1: 30 1c 02 01 01 04 0e <d> [a0 07 06 05 2b 81 04 00 06]
        if (der.length >= 21
                && (der[0] & 0xff) == 0x30
                && (der[2] & 0xff) == 0x02
                && (der[5] & 0xff) == 0x04) {
            int length = der[6] & 0xff;
            if (length > 0 && 7 + length <= der.length) {
                return new BigInteger(1, Arrays.copyOfRange(der, 7, 7 + length));
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Output
    // ------------------------------------------------------------------

    private static void prepareOutputDir(Options options) throws IOException {
        if (Files.exists(options.out)) {
            if (!Files.isDirectory(options.out)) {
                throw new IllegalArgumentException("Output path is not a directory: " + options.out);
            }
            try (Stream<Path> entries = Files.list(options.out)) {
                if (entries.findAny().isPresent() && !options.force) {
                    throw new IllegalArgumentException("Output directory is not empty: "
                            + options.out + " (use --force to overwrite)");
                }
            }
        }
        Files.createDirectories(options.out);
    }

    private static void writeOutputs(Options options, KeyPair rsaKeyPair, EcMaterial ec,
            String composite) throws Exception {
        String id = UUID.randomUUID().toString();
        long createdMillis = System.currentTimeMillis();
        String created = Instant.ofEpochMilli(createdMillis).toString();

        String rsaPublicSha256 = License4JCompositeKey.sha256Hex(rsaKeyPair.getPublic().getEncoded());
        String ecPublicSha256 = License4JCompositeKey.sha256Hex(ec.publicDer);
        String compositeSha256 =
                License4JCompositeKey.sha256Hex(composite.getBytes(StandardCharsets.US_ASCII));

        write(options.out, "publickey.txt",
                License4JCompositeKey.wrap60(composite) + "\n");
        write(options.out, "publickey.singleline.txt", composite + "\n");

        write(options.out, "rsa-private.pem",
                Pem.encode("PRIVATE KEY", rsaKeyPair.getPrivate().getEncoded()));
        write(options.out, "rsa-public.pem",
                Pem.encode("PUBLIC KEY", rsaKeyPair.getPublic().getEncoded()));
        write(options.out, "ec-public.pem", Pem.encode("PUBLIC KEY", ec.publicDer));

        boolean ecPrivateAvailable = ec.privateScalar != null;
        if (ecPrivateAvailable) {
            write(options.out, "ec-private.pem",
                    Pem.encode("PRIVATE KEY", Secp112r1.encodePrivateKey(ec.privateScalar)));
        }

        write(options.out, "keypair.properties",
                properties(id, createdMillis, options, composite, rsaPublicSha256,
                        ecPublicSha256, compositeSha256, ecPrivateAvailable));

        write(options.out, "keypair.json",
                json(id, created, options, composite, rsaPublicSha256, ecPublicSha256,
                        compositeSha256, ecPrivateAvailable));

        write(options.out, "README.txt",
                outputReadme(id, created, options, ecPrivateAvailable));

        write(options.out, "sha256.txt", sha256File(compositeSha256, rsaPublicSha256,
                ecPublicSha256));
    }

    private static String properties(String id, long createdMillis, Options options,
            String composite, String rsaPublicSha256, String ecPublicSha256,
            String compositeSha256, boolean ecPrivateAvailable) {
        StringBuilder out = new StringBuilder();
        out.append("# Cyber Triage License4J 4.7.3 KeyPair\n");
        out.append("# Generated by license4j-keypair-generator\n");
        out.append("id=").append(id).append('\n');
        out.append("name=").append(property(options.name)).append('\n');
        out.append("description=").append(property(options.description)).append('\n');
        out.append("timecreated=").append(createdMillis).append('\n');
        out.append("productid=").append(property(options.productId)).append('\n');
        out.append("productedition=").append(property(options.productEdition)).append('\n');
        out.append("productversion=").append(property(options.productVersion)).append('\n');
        out.append('\n');
        out.append("rsa.algorithm=").append(License4JCompositeKey.RSA_ALGORITHM).append('\n');
        out.append("rsa.keysize=").append(License4JCompositeKey.RSA_KEY_SIZE).append('\n');
        out.append("rsa.signature=").append(License4JCompositeKey.RSA_SIGNATURE_ALGORITHM).append('\n');
        out.append("rsa.publickey.sha256=").append(rsaPublicSha256).append('\n');
        out.append("rsa.privatekey.file=rsa-private.pem\n");
        out.append('\n');
        out.append("ec.algorithm=").append(License4JCompositeKey.EC_ALGORITHM).append('\n');
        out.append("ec.curve=").append(Secp112r1.CURVE_NAME).append('\n');
        out.append("ec.oid=").append(Secp112r1.CURVE_OID).append('\n');
        out.append("ec.keysize=").append(License4JCompositeKey.EC_KEY_SIZE).append('\n');
        out.append("ec.signature=").append(License4JCompositeKey.EC_SIGNATURE_ALGORITHM).append('\n');
        out.append("ec.publickey.sha256=").append(ecPublicSha256).append('\n');
        out.append("ec.privatekey.available=").append(ecPrivateAvailable).append('\n');
        out.append("ec.privatekey.file=")
                .append(ecPrivateAvailable ? "ec-private.pem" : "").append('\n');
        out.append('\n');
        out.append("composite.length=").append(composite.length()).append('\n');
        out.append("composite.sha256=").append(compositeSha256).append('\n');
        out.append("publickey=").append(composite).append('\n');
        return out.toString();
    }

    private static String json(String id, String created, Options options,
            String composite, String rsaPublicSha256, String ecPublicSha256,
            String compositeSha256, boolean ecPrivateAvailable) {
        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append("  \"format\": \"license4j-keypair-generator/1\",\n");
        out.append("  \"created\": ").append(jsonString(created)).append(",\n");
        out.append("  \"id\": ").append(jsonString(id)).append(",\n");
        out.append("  \"name\": ").append(jsonString(options.name)).append(",\n");
        out.append("  \"description\": ").append(jsonString(options.description)).append(",\n");
        out.append("  \"product\": {\n");
        out.append("    \"id\": ").append(jsonString(options.productId)).append(",\n");
        out.append("    \"edition\": ").append(jsonString(options.productEdition)).append(",\n");
        out.append("    \"version\": ").append(jsonString(options.productVersion)).append("\n");
        out.append("  },\n");
        out.append("  \"licenseText\": {\n");
        out.append("    \"keyAlgorithm\": \"RSA\",\n");
        out.append("    \"keySize\": ").append(License4JCompositeKey.RSA_KEY_SIZE).append(",\n");
        out.append("    \"signatureAlgorithm\": \"")
                .append(License4JCompositeKey.RSA_SIGNATURE_ALGORITHM).append("\",\n");
        out.append("    \"publicKeySha256\": ").append(jsonString(rsaPublicSha256)).append("\n");
        out.append("  },\n");
        out.append("  \"licenseKey\": {\n");
        out.append("    \"keyAlgorithm\": \"EC\",\n");
        out.append("    \"curve\": \"").append(Secp112r1.CURVE_NAME).append("\",\n");
        out.append("    \"oid\": \"").append(Secp112r1.CURVE_OID).append("\",\n");
        out.append("    \"keySize\": ").append(License4JCompositeKey.EC_KEY_SIZE).append(",\n");
        out.append("    \"signatureAlgorithm\": \"")
                .append(License4JCompositeKey.EC_SIGNATURE_ALGORITHM).append("\",\n");
        out.append("    \"publicKeySha256\": ").append(jsonString(ecPublicSha256)).append(",\n");
        out.append("    \"privateKeyAvailable\": ").append(ecPrivateAvailable).append("\n");
        out.append("  },\n");
        out.append("  \"compositePublicKey\": ").append(jsonString(composite)).append(",\n");
        out.append("  \"compositePublicKeySha256\": ")
                .append(jsonString(compositeSha256)).append(",\n");
        out.append("  \"files\": {\n");
        out.append("    \"publicKeyWrapped\": \"publickey.txt\",\n");
        out.append("    \"publicKeySingleLine\": \"publickey.singleline.txt\",\n");
        out.append("    \"rsaPrivateKey\": \"rsa-private.pem\",\n");
        out.append("    \"rsaPublicKey\": \"rsa-public.pem\",\n");
        out.append("    \"ecPublicKey\": \"ec-public.pem\",\n");
        out.append("    \"ecPrivateKey\": ")
                .append(ecPrivateAvailable ? "\"ec-private.pem\"" : "null").append("\n");
        out.append("  }\n");
        out.append("}\n");
        return out.toString();
    }

    private static String outputReadme(String id, String created, Options options,
            boolean ecPrivateAvailable) {
        StringBuilder out = new StringBuilder();
        out.append("Cyber Triage License4J 4.7.3 KeyPair\n");
        out.append("=====================================\n\n");
        out.append("Generated: ").append(created).append('\n');
        out.append("Id       : ").append(id).append("\n\n");
        out.append("Parameters:\n");
        out.append("  Product ID      : ").append(printable(options.productId)).append('\n');
        out.append("  Product edition : ").append(printable(options.productEdition)).append('\n');
        out.append("  Product version : ").append(printable(options.productVersion)).append('\n');
        out.append("  License text    : RSA 2048, SHA512withRSA\n");
        out.append("  License key     : EC secp112r1 (112 bit), SHA512withECDSA\n");
        out.append("  Public key      : License4J composite string\n\n");
        out.append("Files:\n");
        out.append("  publickey.txt             composite public key, wrapped at 60 characters\n");
        out.append("  publickey.singleline.txt  composite public key, one line\n");
        out.append("  rsa-private.pem           PKCS#8 RSA private key\n");
        out.append("  rsa-public.pem            X.509 RSA public key\n");
        out.append("  ec-public.pem             X.509 secp112r1 public key\n");
        if (ecPrivateAvailable) {
            out.append("  ec-private.pem            PKCS#8 secp112r1 private key\n");
        } else {
            out.append("  ec-private.pem            absent (EC public key was reused)\n");
        }
        out.append("  keypair.properties        metadata\n");
        out.append("  keypair.json              metadata (JSON)\n\n");
        out.append("WARNING\n");
        out.append("  rsa-private.pem and ec-private.pem are private keys. Keep them\n");
        out.append("  offline. Do not ship them with the application or commit them.\n\n");
        out.append("Embedding\n");
        out.append("  Replace the License4J public-key constant in the application with the\n");
        out.append("  contents of publickey.singleline.txt. License4J removes line breaks\n");
        out.append("  and ignores '#' comment lines.\n");
        if (!ecPrivateAvailable) {
            out.append("\n");
            out.append("Note\n");
            out.append("  The EC public key was supplied without its private key. License\n");
            out.append("  files signed with RSA/SHA-512 still work, but SHA512withECDSA\n");
            out.append("  license-key signatures cannot be produced with this bundle.\n");
        }
        return out.toString();
    }

    private static String sha256File(String compositeSha256, String rsaPublicSha256,
            String ecPublicSha256) {
        return "composite public key  " + compositeSha256 + "\n"
                + "RSA public key        " + rsaPublicSha256 + "\n"
                + "EC public key         " + ecPublicSha256 + "\n";
    }

    // ------------------------------------------------------------------
    // Inspection and license verification
    // ------------------------------------------------------------------

    private static void inspectPublicKey(Path file) throws Exception {
        String text = Files.readString(file, StandardCharsets.UTF_8);

        if (text.contains("-----BEGIN")) {
            inspectPemOrDer(text, Files.readAllBytes(file));
            return;
        }

        String composite = License4JCompositeKey.normalize(text);
        if (composite.length() >= 700
                && composite.indexOf(License4JCompositeKey.SEPARATOR) >= 0) {
            License4JCompositeKey.Decoded decoded = License4JCompositeKey.decode(composite);
            ECPoint q = decoded.ecPublicKey.getW();
            System.out.println("License4J composite public key");
            System.out.println("  length            : " + composite.length());
            System.out.println("  RSA               : " + decoded.rsaKeySize + " bit, "
                    + decoded.rsaSignatureAlgorithm);
            System.out.println("  RSA SHA-256       : "
                    + License4JCompositeKey.sha256Hex(decoded.rsaPublicKeyDer));
            System.out.println("  EC                : " + decoded.ecKeySize + " bit "
                    + Secp112r1.CURVE_NAME + ", " + decoded.ecSignatureAlgorithm);
            System.out.println("  EC X              : "
                    + q.getAffineX().toString(16).toUpperCase(Locale.ROOT));
            System.out.println("  EC Y              : "
                    + q.getAffineY().toString(16).toUpperCase(Locale.ROOT));
            System.out.println("  EC SHA-256        : "
                    + License4JCompositeKey.sha256Hex(decoded.ecPublicKeyDer));
            System.out.println("  Composite SHA-256 : "
                    + License4JCompositeKey.sha256Hex(composite.getBytes(StandardCharsets.US_ASCII)));
            return;
        }

        inspectPemOrDer(text, Files.readAllBytes(file));
    }

    private static void inspectPemOrDer(String text, byte[] raw) throws Exception {
        byte[] der = Pem.decode(text);
        if (der == null) {
            der = raw;
        }
        try {
            ECPublicKey ec = (ECPublicKey) KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(der));
            ECPoint q = ec.getW();
            System.out.println("EC public key");
            System.out.println("  X: " + q.getAffineX().toString(16).toUpperCase(Locale.ROOT));
            System.out.println("  Y: " + q.getAffineY().toString(16).toUpperCase(Locale.ROOT));
            System.out.println("  on secp112r1: " + Secp112r1.isOnCurve(q));
            System.out.println("  SHA-256: " + License4JCompositeKey.sha256Hex(der));
            return;
        } catch (Exception ignored) {
            // Try RSA below.
        }

        PublicKey rsa = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(der));
        RSAPublicKey rsaKey = (RSAPublicKey) rsa;
        System.out.println("RSA public key");
        System.out.println("  modulus bits: " + rsaKey.getModulus().bitLength());
        System.out.println("  exponent    : " + rsaKey.getPublicExponent());
        System.out.println("  SHA-256     : " + License4JCompositeKey.sha256Hex(der));
    }

    private static int verifyLicense(Options options) throws Exception {
        if (options.publicKey == null) {
            throw new IllegalArgumentException("--verify-license requires --public-key <file>");
        }

        String composite = License4JCompositeKey.normalize(
                Files.readString(options.publicKey, StandardCharsets.UTF_8));
        if (composite.indexOf(License4JCompositeKey.SEPARATOR) < 0) {
            throw new IllegalArgumentException(
                    "--public-key must be the License4J composite public key, not PEM/DER");
        }
        License4JCompositeKey.Decoded decoded = License4JCompositeKey.decode(composite);

        String licenseText = Files.readString(options.verifyLicense, StandardCharsets.UTF_8);
        String plain;
        try {
            plain = decryptLicense(licenseText, composite);
        } catch (Exception e) {
            boolean container = looksLikeEncryptedLicense(licenseText);
            System.out.println("License file  : " + options.verifyLicense);
            System.out.println("Decryption    : FAILED");
            System.out.println("Status        : " + (container ? "UNREADABLE" : "UNSIGNED"));
            System.out.println("Reason        : " + e.getMessage());
            System.out.println();
            if (container) {
                System.out.println("The license is a License4J container but was not encrypted");
                System.out.println("with this public key, or the file is damaged.");
            } else {
                System.out.println("The file is not a License4J encrypted license container");
                System.out.println("(for example extended-license-data JSON or plaintext properties).");
            }
            return 1;
        }

        Properties properties = loadProperties(plain);
        String signatureHex = properties.getProperty("s");
        String status;
        boolean valid = false;
        if (signatureHex == null) {
            status = "UNSIGNED";
        } else {
            String signedText = signedText(properties);
            Signature verifier = Signature.getInstance("SHA512withRSA");
            verifier.initVerify(decoded.rsaPublicKey);
            verifier.update(signedText.getBytes(StandardCharsets.UTF_8));
            try {
                valid = verifier.verify(HexFormat.of().parseHex(signatureHex));
            } catch (IllegalArgumentException e) {
                valid = false;
            }
            status = valid ? "VALID" : "INVALID";
        }

        System.out.println("License file  : " + options.verifyLicense);
        System.out.println("Decryption    : OK");
        System.out.println("Status        : " + status);
        System.out.println("RSA signature : "
                + (signatureHex == null ? "MISSING" : (valid ? "VALID" : "INVALID")));
        System.out.println("License id    : " + value(properties, "id"));
        System.out.println("Product       : " + value(properties, "lpn"));
        System.out.println("Customer      : " + value(properties, "ucom")
                + (properties.getProperty("ufn") == null ? "" : " / " + properties.getProperty("ufn")));
        String customFeature = properties.getProperty(EXTENDED_LICENSE_DATA_KEY);
        if (customFeature != null) {
            Matcher matcher = CUSTOM_FEATURE_VERSION.matcher(customFeature);
            System.out.println("Custom feature: EXTENDED_LICENSE_DATA"
                    + (matcher.find() ? " version " + matcher.group(1) : ""));
        }

        if (options.showLicenseContent) {
            System.out.println();
            System.out.println("Decrypted content" + (options.showSecrets ? "" : " (secrets masked)")
                    + ":");
            System.out.println(options.showSecrets ? plain : maskSecrets(plain));
        }

        return valid ? 0 : 1;
    }

    /**
     * Creates or re-signs a license with the RSA license-text private key.
     *
     * <p>Three input formats are accepted: an encrypted License4J container
     * (decrypt and re-sign), an extended-license-data JSON payload, or a
     * properties file. The latter two create a new license.
     */
    private static void signLicense(Options options) throws Exception {
        if (options.publicKey == null || options.privateKey == null || options.signedOutput == null) {
            throw new IllegalArgumentException(
                    "--sign-license requires --public-key, --private-key and --signed-output");
        }
        Path input = options.signLicense.toAbsolutePath().normalize();
        Path output = options.signedOutput.toAbsolutePath().normalize();
        if (!Files.isRegularFile(input)) {
            throw new IllegalArgumentException("License file not found: " + input);
        }
        if (input.equals(output)) {
            throw new IllegalArgumentException("Output must not overwrite the source license");
        }

        String composite = License4JCompositeKey.normalize(
                Files.readString(options.publicKey, StandardCharsets.UTF_8));

        String privateText = readUtf8OrNull(options.privateKey);
        byte[] privateDer = privateText == null ? null : Pem.decode(privateText);
        if (privateDer == null) {
            privateDer = Files.readAllBytes(options.privateKey);
        }
        PrivateKey privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(privateDer));

        String original = Files.readString(input, StandardCharsets.UTF_8);
        Properties properties;
        if (looksLikeEncryptedLicense(original)) {
            properties = loadProperties(decryptLicense(original, composite));
            applyLicenseOverrides(properties, options);
        } else {
            properties = buildLicenseProperties(input, options, true);
        }

        writeSignedLicense(properties, privateKey, composite, output);
        System.out.println("SIGNED: " + input + " -> " + output);
    }

    /**
     * Builds a license property set. A JSON payload is embedded as
     * {@code csf-EXTENDED_LICENSE_DATA}; a properties file replaces the
     * defaults. The signature property is never taken from the input.
     */
    private static Properties buildLicenseProperties(Path spec, Options options, boolean generateId)
            throws IOException {
        String text = readUtf8OrNull(spec);
        if (text == null) {
            throw new IllegalArgumentException("License input is not valid UTF-8 text: " + spec);
        }
        String trimmed = stripBom(text).trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("License input is empty: " + spec);
        }

        Properties properties = new Properties();
        properties.setProperty("acc", "0");
        properties.setProperty("acr", "0");
        properties.setProperty(EXTENDED_LICENSE_DATA_KEY, DEFAULT_EXTENDED_LICENSE_DATA);
        properties.setProperty("dtqlads", "0");
        properties.setProperty("id", options.licenseId != null
                ? options.licenseId
                : (generateId ? randomLicenseId() : "0"));
        properties.setProperty("lft", "0");
        properties.setProperty("lgdt", Long.toString(System.currentTimeMillis()));
        properties.setProperty("lpn", DEFAULT_PRODUCT);
        properties.setProperty("lqu", "1");
        properties.setProperty("lvp", "36500");
        properties.setProperty("lvpid", DEFAULT_PRODUCT);
        properties.setProperty("ucom", "Example");
        properties.setProperty("ufn", "Example User");

        if (trimmed.startsWith("{")) {
            properties.setProperty(EXTENDED_LICENSE_DATA_KEY, trimmed);
        } else {
            Properties supplied = loadProperties(stripBom(text));
            for (String name : supplied.stringPropertyNames()) {
                if (!"s".equals(name)) {
                    properties.setProperty(name, supplied.getProperty(name));
                }
            }
        }

        applyLicenseOverrides(properties, options);
        return properties;
    }

    private static void applyLicenseOverrides(Properties properties, Options options) {
        if (options.licenseId != null) {
            properties.setProperty("id", options.licenseId);
        }
        if (options.customer != null) {
            properties.setProperty("ucom", options.customer);
        }
        if (options.customerName != null) {
            properties.setProperty("ufn", options.customerName);
        }
        for (String assignment : options.licenseProperties) {
            int equals = assignment.indexOf('=');
            if (equals <= 0) {
                throw new IllegalArgumentException(
                        "--license-property must be key=value: " + assignment);
            }
            properties.setProperty(assignment.substring(0, equals),
                    assignment.substring(equals + 1));
        }
        properties.remove("s");
    }

    private static void writeSignedLicense(Properties properties, PrivateKey privateKey,
            String composite, Path output) throws Exception {
        if (Files.exists(output)) {
            throw new IllegalArgumentException("Output already exists (will not overwrite): " + output);
        }

        License4JCompositeKey.Decoded decoded = License4JCompositeKey.decode(composite);

        // Verify that the private key corresponds to the public key embedded in
        // the composite key before writing anything.
        byte[] probe = "License4J signing key check".getBytes(StandardCharsets.UTF_8);
        Signature probeSigner = Signature.getInstance("SHA512withRSA");
        probeSigner.initSign(privateKey);
        probeSigner.update(probe);
        byte[] probeSignature = probeSigner.sign();
        Signature probeVerifier = Signature.getInstance("SHA512withRSA");
        probeVerifier.initVerify(decoded.rsaPublicKey);
        probeVerifier.update(probe);
        if (!probeVerifier.verify(probeSignature)) {
            throw new IllegalArgumentException(
                    "RSA private key does not match the RSA public key in --public-key");
        }

        Signature signer = Signature.getInstance("SHA512withRSA");
        signer.initSign(privateKey);
        signer.update(signedText(properties).getBytes(StandardCharsets.UTF_8));
        String signatureHex = HexFormat.of().withUpperCase().formatHex(signer.sign());

        String plain = serializeProperties(properties, signatureHex);
        byte[] encrypted = encryptLicense(plain, composite);
        String result = licenseHeader(properties)
                + HexFormat.of().withUpperCase().formatHex(encrypted)
                + System.lineSeparator();

        Path parent = output.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        // CREATE_NEW protects against races and accidental overwrites.
        Files.writeString(output, result, StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE_NEW,
                java.nio.file.StandardOpenOption.WRITE);
    }

    /** Writes a deterministic, Properties.load-compatible text representation. */
    private static String serializeProperties(Properties properties, String signatureHex) {
        TreeMap<String, String> sorted = new TreeMap<>();
        for (String name : properties.stringPropertyNames()) {
            sorted.put(name, properties.getProperty(name));
        }
        sorted.put("s", signatureHex);

        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> entry : sorted.entrySet()) {
            out.append(escapeProperty(entry.getKey()))
                    .append('=')
                    .append(escapeProperty(entry.getValue()))
                    .append('\n');
        }
        return out.toString();
    }

    private static String escapeProperty(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '=':
                case ':':
                case '#':
                case '!':
                    out.append('\\').append(c);
                    break;
                case ' ':
                    if (i == 0) {
                        out.append('\\');
                    }
                    out.append(' ');
                    break;
                default:
                    if (c < 0x20 || c > 0x7e) {
                        out.append(String.format(Locale.ROOT, "\\u%04X", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    private static String licenseHeader(Properties properties) {
        String product = oneLine(properties.getProperty("lpn", DEFAULT_PRODUCT));
        String id = oneLine(properties.getProperty("id", ""));
        return "# " + product + " License (id: " + id + ")" + System.lineSeparator();
    }

    private static String oneLine(String value) {
        String result = value == null ? "" : value.replaceAll("\\R", " ").trim();
        return result.isEmpty() ? "unknown" : result;
    }

    private static boolean looksLikeEncryptedLicense(String text) {
        String normalized = stripBom(text.replace("\r\n", "\n").replace('\r', '\n')).trim();
        if (!normalized.startsWith("#")) {
            return false;
        }
        normalized = normalized.replaceAll("(?s)/\\*.*?\\*/", "");
        int headerEnd = normalized.indexOf(')');
        if (headerEnd < 0) {
            return false;
        }
        String payload = normalized.substring(headerEnd + 1).replaceAll("\\s", "");
        return payload.matches("[0-9A-Fa-f]+") && payload.length() >= 32;
    }

    private static String stripBom(String text) {
        return !text.isEmpty() && text.charAt(0) == '\uFEFF' ? text.substring(1) : text;
    }

    private static String randomLicenseId() {
        return Long.toString(100_000_000L
                + ThreadLocalRandom.current().nextLong(900_000_000L));
    }

    private static byte[] encryptLicense(String plain, String composite) throws Exception {
        String password = composite
                + composite.substring(composite.length() - 4)
                + composite.substring(0, 5);
        byte[] salt = {-57, 115, 33, -116, 126, -56, -18, -103};
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES")
                .generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, 10));
        return cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
    }

    private static String decryptLicense(String licenseText, String composite) throws Exception {
        String data = licenseText.replace("\r\n", "").replace("\n", "");
        if (!data.isEmpty() && data.charAt(0) == '\uFEFF') {
            data = data.substring(1);
        }
        int headerEnd = data.indexOf(')');
        if (headerEnd < 0) {
            throw new IllegalArgumentException("license header not found");
        }
        data = data.substring(headerEnd + 1);
        while (data.contains("/**") && data.contains("*/")) {
            int start = data.indexOf("/**");
            int end = data.indexOf("*/", start);
            data = data.substring(0, start) + data.substring(end + 2);
        }
        data = data.replaceAll("\\s", "");

        String password = composite
                + composite.substring(composite.length() - 4)
                + composite.substring(0, 5);

        byte[] salt = {-57, 115, 33, -116, 126, -56, -18, -103};
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES")
                .generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, 10));
        byte[] plain = cipher.doFinal(HexFormat.of().parseHex(data));
        return new String(plain, StandardCharsets.UTF_8);
    }

    private static Properties loadProperties(String plain) throws IOException {
        Properties properties = new Properties();
        try (Reader reader = new InputStreamReader(
                new ByteArrayInputStream(plain.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }

    private static String signedText(Properties properties) {
        List<String> keys = new ArrayList<>(properties.stringPropertyNames());
        Collections.sort(keys);
        StringBuilder out = new StringBuilder();
        for (String key : keys) {
            if ("s".equals(key) || key.startsWith("cuf")) {
                continue;
            }
            out.append(properties.getProperty(key)).append('\n');
        }
        return out.toString();
    }

    private static String maskSecrets(String plain) {
        StringBuilder out = new StringBuilder();
        for (String line : plain.split("\\R", -1)) {
            int equals = line.indexOf('=');
            if (equals > 0) {
                String key = line.substring(0, equals).toLowerCase(Locale.ROOT);
                if (key.contains("api_key") || key.contains("apikey")
                        || key.contains("secret") || key.contains("password")
                        || key.contains("token")) {
                    out.append(line, 0, equals + 1).append("***").append('\n');
                    continue;
                }
            }
            out.append(line).append('\n');
        }
        String masked = out.toString();
        masked = masked.replaceAll("(?i)(\"api[_-]?key\"\\s*:\\s*\")[^\"]*(\")", "$1***$2");
        masked = masked.replaceAll(
                "(?i)(\"(?:secret|password|token)\"\\s*:\\s*\")[^\"]*(\")", "$1***$2");
        return masked;
    }

    // ------------------------------------------------------------------
    // Self-test data
    // ------------------------------------------------------------------

    /**
     * Builds a generic license-text blob using the exact input License4J signs:
     * property values sorted by property name, excluding {@code s} and
     * {@code cuf*} keys, each followed by a newline.
     */
    private static String sampleSignedText() {
        Map<String, String> values = new TreeMap<>();
        values.put("acc", "0");
        values.put("acr", "0");
        values.put("csf-EXTENDED_LICENSE_DATA",
                "{\"version\":2.4,\"license_details\":{\"type\":\"PAID\","
                        + "\"mode\":\"STAND_ALONE\"}}");
        values.put("id", "1");
        values.put("lgdt", "1");
        values.put("lpn", "Cyber Triage");
        values.put("lqu", "1");
        values.put("lvp", "36500");
        values.put("lvpid", "Cyber Triage");
        values.put("ucom", "Example");
        values.put("ufn", "Example User");

        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> entry : values.entrySet()) {
            out.append(entry.getValue()).append('\n');
        }
        return out.toString();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static String readUtf8OrNull(Path file) throws IOException {
        try {
            return Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            // Binary DER is not valid UTF-8; the caller will read the raw bytes.
            return null;
        }
    }

    private static String printable(String value) {
        return value == null || value.isEmpty() ? "(empty)" : value;
    }

    private static String value(Properties properties, String key) {
        String value = properties.getProperty(key);
        return value == null ? "" : value;
    }

    private static String property(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\r", " ").replace("\n", " ");
    }

    private static String jsonString(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder out = new StringBuilder(value.length() + 2);
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.append('"').toString();
    }

    private static void write(Path directory, String name, String content) throws IOException {
        Files.writeString(directory.resolve(name), content, StandardCharsets.UTF_8);
    }

    private static void printUsage() {
        System.out.println("Cyber Triage License4J tool (keypair + license)");
        System.out.println();
        System.out.println("Fixed parameters: RSA 2048 + SHA512withRSA, EC secp112r1 (112 bit)");
        System.out.println("+ SHA512withECDSA, public key in License4J composite format.");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  cybertriage-license [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --out <dir>                 Output directory (default: ./license4j-keypair)");
        System.out.println("  --name <name>               KeyPair name (default: Cyber Triage)");
        System.out.println("  --description <text>        Description");
        System.out.println("  --product-id <id>           Product ID metadata (default: Cyber Triage)");
        System.out.println("  --product-edition <text>    Product edition metadata (default: empty)");
        System.out.println("  --product-version <text>    Product version metadata (default: empty)");
        System.out.println("  --reuse-ec-public <file>    Reuse an existing EC public key");
        System.out.println("                              (composite, PEM or DER)");
        System.out.println("  --reuse-ec-private <file>   Reuse an existing EC private key");
        System.out.println("                              (PKCS#8 or SEC1, PEM or DER)");
        System.out.println("  --force                     Overwrite files in a non-empty output directory");
        System.out.println("  --inspect-public-key <file> Parse and print an existing public key");
        System.out.println("  --verify-license <file>     Decrypt and verify a .l4j license file");
        System.out.println("  --sign-license <file>       Re-sign an encrypted license or create one");
        System.out.println("                              from JSON extended data / properties");
        System.out.println("  --license-data <file>       Create + sign a license while generating a keypair");
        System.out.println("                              (JSON extended data or properties)");
        System.out.println("  --license-id <id>           License id override (default: random for new licenses)");
        System.out.println("  --customer <name>           Customer company (ucom) override");
        System.out.println("  --customer-name <name>      Customer name (ufn) override");
        System.out.println("  --license-property k=v      Any license property override (repeatable)");
        System.out.println("  --public-key <file>         Composite public key for verify/sign");
        System.out.println("  --private-key <file>        RSA PKCS#8 private key for --sign-license");
        System.out.println("  --signed-output <file>      Output path for create/sign (must not exist)");
        System.out.println("  --show-license-content      Print decrypted license properties");
        System.out.println("  --show-secrets              Do not mask api_key/password/token values");
        System.out.println("  --help                      Show this help");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  cybertriage-license --out ./my-keypair");
        System.out.println("  cybertriage-license --out ./rotated \\");
        System.out.println("      --reuse-ec-public ./existing-publickey.txt");
        System.out.println("  cybertriage-license --inspect-public-key ./publickey.txt");
        System.out.println("  cybertriage-license --verify-license ./license.l4j \\");
        System.out.println("      --public-key ./publickey.txt");
        System.out.println();
        System.out.println("Generate a keypair and immediately sign a license with it:");
        System.out.println("  cybertriage-license --out ./my-keypair \\");
        System.out.println("      --license-data ./licenses/CLIENT.l4j \\");
        System.out.println("      --signed-output ./CLIENT.l4j --license-id 862145687");
        System.out.println();
        System.out.println("Sign with an existing keypair (creates from JSON/properties");
        System.out.println("or re-signs an encrypted .l4j):");
        System.out.println("  cybertriage-license --sign-license ./licenses/CLIENT.l4j \\");
        System.out.println("      --public-key ./my-keypair/publickey.txt \\");
        System.out.println("      --private-key ./my-keypair/rsa-private.pem \\");
        System.out.println("      --signed-output ./CLIENT.l4j");
    }

    // ------------------------------------------------------------------
    // Options
    // ------------------------------------------------------------------

    private static final class Options {
        Path out = Path.of("license4j-keypair");
        String name = "Cyber Triage";
        String description = "";
        String productId = "Cyber Triage";
        String productEdition = "";
        String productVersion = "";
        Path reuseEcPublic;
        Path reuseEcPrivate;
        Path inspectPublicKey;
        Path verifyLicense;
        Path signLicense;
        Path signedOutput;
        Path licenseData;
        String licenseId;
        String customer;
        String customerName;
        final List<String> licenseProperties = new ArrayList<>();
        Path privateKey;
        Path publicKey;
        boolean showLicenseContent;
        boolean showSecrets;
        boolean force;
        boolean help;

        static Options parse(String[] args) {
            Options options = new Options();
            for (int i = 0; i < args.length; i++) {
                String argument = args[i];
                String key = argument;
                String inline = null;
                int equals = argument.startsWith("--") ? argument.indexOf('=') : -1;
                if (equals > 0) {
                    key = argument.substring(0, equals);
                    inline = argument.substring(equals + 1);
                }
                switch (key) {
                    case "--help":
                    case "-h":
                        options.help = true;
                        break;
                    case "--out":
                        options.out = Path.of(take(args, i, inline, key));
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--name":
                        options.name = take(args, i, inline, key);
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--description":
                        options.description = take(args, i, inline, key);
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--product-id":
                        options.productId = take(args, i, inline, key);
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--product-edition":
                        options.productEdition = take(args, i, inline, key);
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--product-version":
                        options.productVersion = take(args, i, inline, key);
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--reuse-ec-public":
                        options.reuseEcPublic = Path.of(take(args, i, inline, key));
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--reuse-ec-private":
                        options.reuseEcPrivate = Path.of(take(args, i, inline, key));
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--inspect-public-key":
                        options.inspectPublicKey = Path.of(take(args, i, inline, key));
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--verify-license":
                        options.verifyLicense = Path.of(take(args, i, inline, key));
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--sign-license":
                        options.signLicense = Path.of(take(args, i, inline, key));
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--signed-output":
                        options.signedOutput = Path.of(take(args, i, inline, key));
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--license-data":
                        options.licenseData = Path.of(take(args, i, inline, key));
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--license-id":
                        options.licenseId = take(args, i, inline, key);
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--customer":
                        options.customer = take(args, i, inline, key);
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--customer-name":
                        options.customerName = take(args, i, inline, key);
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--license-property":
                        options.licenseProperties.add(take(args, i, inline, key));
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--private-key":
                        options.privateKey = Path.of(take(args, i, inline, key));
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--public-key":
                        options.publicKey = Path.of(take(args, i, inline, key));
                        if (inline == null) {
                            i++;
                        }
                        break;
                    case "--show-license-content":
                        options.showLicenseContent = true;
                        break;
                    case "--show-secrets":
                        options.showSecrets = true;
                        break;
                    case "--force":
                        options.force = true;
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown option: " + key);
                }
            }
            return options;
        }

        private static String take(String[] args, int index, String inline, String option) {
            if (inline != null) {
                return inline;
            }
            if (index + 1 >= args.length) {
                throw new IllegalArgumentException("Missing value for " + option);
            }
            return args[index + 1];
        }
    }
}
