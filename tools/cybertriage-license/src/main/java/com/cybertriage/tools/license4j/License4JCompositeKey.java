package com.cybertriage.tools.license4j;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Encoder/decoder for the License4J 4.7.3 composite public-key string.
 *
 * <p>The string is assembled as follows (all key material is uppercase hex):
 *
 * <pre>
 *   rsaComposite = rsaDerHex[0..250)  + RSA_METADATA + rsaDerHex[250..)
 *   ecComposite  = ecDerHex[0..25)    + EC_METADATA  + ecDerHex[25..)
 *   composite    = rsaComposite[0..50) + ecComposite + "G" + rsaComposite[50..)
 *
 *   RSA_METADATA = "03" + "RSA" + "4" + "2048" + "13" + "SHA512withRSA"
 *   EC_METADATA  = "02" + "EC"  + "3" + "112"  + "15" + "SHA512withECDSA"
 * </pre>
 *
 * <p>The offsets and metadata layout mirror the parser in
 * {@code com.license4j.LicenseValidator} from
 * {@code license4j-runtime-library-4.7.3.jar}. License4J strips the
 * {@code G} separator and the metadata before passing the remaining hex to
 * {@link KeyFactory}.
 */
public final class License4JCompositeKey {

    public static final String RSA_ALGORITHM = "RSA";
    public static final String RSA_SIGNATURE_ALGORITHM = "SHA512withRSA";
    public static final int RSA_KEY_SIZE = 2048;
    public static final int RSA_DER_LENGTH = 294;
    public static final int RSA_METADATA_OFFSET = 250;

    public static final String EC_ALGORITHM = "EC";
    public static final String EC_SIGNATURE_ALGORITHM = "SHA512withECDSA";
    public static final int EC_KEY_SIZE = Secp112r1.KEY_SIZE_BITS;
    public static final int EC_DER_LENGTH = 52;
    public static final int EC_METADATA_OFFSET = 25;

    public static final int EC_INSERT_OFFSET = 50;
    public static final char SEPARATOR = 'G';
    public static final int COMPOSITE_LENGTH = 743;

    private static final HexFormat HEX = HexFormat.of().withUpperCase();

    private License4JCompositeKey() {
    }

    /**
     * Builds the composite public-key string.
     *
     * @param rsaPublicKeyDer X.509 SubjectPublicKeyInfo DER for an RSA-2048 key
     * @param ecPublicKeyDer  X.509 SubjectPublicKeyInfo DER for a secp112r1 key
     * @return the composite string without line breaks
     */
    public static String encode(byte[] rsaPublicKeyDer, byte[] ecPublicKeyDer) {
        requireLength(rsaPublicKeyDer, RSA_DER_LENGTH, "RSA public key DER (RSA-2048, e=65537)");
        requireLength(ecPublicKeyDer, EC_DER_LENGTH, "EC public key DER (secp112r1)");

        String rsaHex = HEX.formatHex(rsaPublicKeyDer);
        String ecHex = HEX.formatHex(ecPublicKeyDer);

        String rsaMetadata = metadata(RSA_ALGORITHM, Integer.toString(RSA_KEY_SIZE),
                RSA_SIGNATURE_ALGORITHM);
        String ecMetadata = metadata(EC_ALGORITHM, Integer.toString(EC_KEY_SIZE),
                EC_SIGNATURE_ALGORITHM);

        String rsaComposite = rsaHex.substring(0, RSA_METADATA_OFFSET)
                + rsaMetadata
                + rsaHex.substring(RSA_METADATA_OFFSET);
        String ecComposite = ecHex.substring(0, EC_METADATA_OFFSET)
                + ecMetadata
                + ecHex.substring(EC_METADATA_OFFSET);

        String composite = rsaComposite.substring(0, EC_INSERT_OFFSET)
                + ecComposite
                + SEPARATOR
                + rsaComposite.substring(EC_INSERT_OFFSET);

        if (composite.length() != COMPOSITE_LENGTH) {
            throw new IllegalStateException("Unexpected composite length: " + composite.length());
        }
        return composite;
    }

    /** Parses a composite public-key string, mirroring the License4J parser. */
    public static Decoded decode(String input) throws Exception {
        String composite = normalize(input);
        int separator = composite.indexOf(SEPARATOR);
        if (separator < EC_INSERT_OFFSET) {
            throw new IllegalArgumentException("Not a License4J composite public key (no G separator)");
        }

        String ecPart = composite.substring(EC_INSERT_OFFSET, separator);

        int p = EC_METADATA_OFFSET;
        int ecAlgorithmLength = parseInt(ecPart, p, 2);
        p += 2;
        String ecAlgorithm = ecPart.substring(p, p + ecAlgorithmLength);
        p += ecAlgorithmLength;

        int ecKeySizeLength = parseInt(ecPart, p, 1);
        p += 1;
        String ecKeySize = ecPart.substring(p, p + ecKeySizeLength);
        p += ecKeySizeLength;

        int ecSignatureLength = parseInt(ecPart, p, 2);
        p += 2;
        String ecSignatureAlgorithm = ecPart.substring(p, p + ecSignatureLength);
        p += ecSignatureLength;

        String ecDerHex = ecPart.substring(0, EC_METADATA_OFFSET) + ecPart.substring(p);

        String rsaComposite = composite.substring(0, EC_INSERT_OFFSET)
                + composite.substring(separator + 1);

        p = RSA_METADATA_OFFSET;
        int rsaAlgorithmLength = parseInt(rsaComposite, p, 2);
        p += 2;
        String rsaAlgorithm = rsaComposite.substring(p, p + rsaAlgorithmLength);
        p += rsaAlgorithmLength;

        int rsaKeySizeLength = parseInt(rsaComposite, p, 1);
        p += 1;
        String rsaKeySize = rsaComposite.substring(p, p + rsaKeySizeLength);
        p += rsaKeySizeLength;

        int rsaSignatureLength = parseInt(rsaComposite, p, 2);
        p += 2;
        String rsaSignatureAlgorithm = rsaComposite.substring(p, p + rsaSignatureLength);
        p += rsaSignatureLength;

        String rsaDerHex = rsaComposite.substring(0, RSA_METADATA_OFFSET)
                + rsaComposite.substring(p);

        requireMetadata("EC algorithm", ecAlgorithm, EC_ALGORITHM);
        requireMetadata("EC signature algorithm", ecSignatureAlgorithm, EC_SIGNATURE_ALGORITHM);
        requireMetadata("EC key size", ecKeySize, Integer.toString(EC_KEY_SIZE));
        requireMetadata("RSA algorithm", rsaAlgorithm, RSA_ALGORITHM);
        requireMetadata("RSA signature algorithm", rsaSignatureAlgorithm,
                RSA_SIGNATURE_ALGORITHM);
        requireMetadata("RSA key size", rsaKeySize, Integer.toString(RSA_KEY_SIZE));

        byte[] rsaDer = parseHex(rsaDerHex, RSA_DER_LENGTH, "RSA public key");
        byte[] ecDer = parseHex(ecDerHex, EC_DER_LENGTH, "EC public key");

        PublicKey rsaPublicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(rsaDer));
        ECPublicKey ecPublicKey = (ECPublicKey) KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(ecDer));

        if (!Secp112r1.isOnCurve(ecPublicKey.getW())) {
            throw new IllegalArgumentException("Composite EC key is not on secp112r1");
        }

        return new Decoded(
                rsaAlgorithm, Integer.parseInt(rsaKeySize), rsaSignatureAlgorithm,
                rsaDer, rsaPublicKey,
                ecAlgorithm, Integer.parseInt(ecKeySize), ecSignatureAlgorithm,
                ecDer, ecPublicKey);
    }

    /** Removes whitespace and comment lines, which are ignored by the application. */
    public static String normalize(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder result = new StringBuilder(input.length());
        for (String line : input.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            result.append(trimmed);
        }
        return result.toString();
    }

    /** Wraps the composite string at 60 characters, as License4J does. */
    public static String wrap60(String value) {
        StringBuilder result = new StringBuilder(value.length() + value.length() / 60);
        for (int i = 0; i < value.length(); i += 60) {
            if (i > 0) {
                result.append('\n');
            }
            result.append(value, i, Math.min(i + 60, value.length()));
        }
        return result.toString();
    }

    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static String metadata(String algorithm, String keySize, String signatureAlgorithm) {
        if (algorithm.length() > 99 || keySize.length() > 9 || signatureAlgorithm.length() > 99) {
            throw new IllegalArgumentException("Metadata value is too long");
        }
        return String.format(Locale.ROOT, "%02d", algorithm.length()) + algorithm
                + keySize.length() + keySize
                + String.format(Locale.ROOT, "%02d", signatureAlgorithm.length())
                + signatureAlgorithm;
    }

    private static int parseInt(String value, int offset, int length) {
        String part = value.substring(offset, offset + length);
        if (!part.chars().allMatch(Character::isDigit)) {
            throw new IllegalArgumentException("Expected a decimal length at offset " + offset);
        }
        return Integer.parseInt(part);
    }

    private static void requireMetadata(String name, String actual, String expected) {
        if (!expected.equals(actual)) {
            throw new IllegalArgumentException(
                    "Unsupported " + name + " in composite key: expected " + expected
                            + ", got " + actual);
        }
    }

    private static byte[] parseHex(String hex, int expectedLength, String name) {
        if (hex.length() != expectedLength * 2) {
            throw new IllegalArgumentException("Unexpected " + name + " length: "
                    + hex.length() / 2 + " bytes");
        }
        try {
            return HEX.parseHex(hex);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid hex in " + name, e);
        }
    }

    private static void requireLength(byte[] value, int expected, String name) {
        if (value == null || value.length != expected) {
            throw new IllegalArgumentException(
                    name + " must be " + expected + " bytes, got "
                            + (value == null ? "null" : value.length));
        }
    }

    /** Decoded composite key. */
    public static final class Decoded {
        public final String rsaAlgorithm;
        public final int rsaKeySize;
        public final String rsaSignatureAlgorithm;
        public final byte[] rsaPublicKeyDer;
        public final PublicKey rsaPublicKey;

        public final String ecAlgorithm;
        public final int ecKeySize;
        public final String ecSignatureAlgorithm;
        public final byte[] ecPublicKeyDer;
        public final ECPublicKey ecPublicKey;

        Decoded(String rsaAlgorithm, int rsaKeySize, String rsaSignatureAlgorithm,
                byte[] rsaPublicKeyDer, PublicKey rsaPublicKey,
                String ecAlgorithm, int ecKeySize, String ecSignatureAlgorithm,
                byte[] ecPublicKeyDer, ECPublicKey ecPublicKey) {
            this.rsaAlgorithm = rsaAlgorithm;
            this.rsaKeySize = rsaKeySize;
            this.rsaSignatureAlgorithm = rsaSignatureAlgorithm;
            this.rsaPublicKeyDer = rsaPublicKeyDer;
            this.rsaPublicKey = rsaPublicKey;
            this.ecAlgorithm = ecAlgorithm;
            this.ecKeySize = ecKeySize;
            this.ecSignatureAlgorithm = ecSignatureAlgorithm;
            this.ecPublicKeyDer = ecPublicKeyDer;
            this.ecPublicKey = ecPublicKey;
        }
    }
}
