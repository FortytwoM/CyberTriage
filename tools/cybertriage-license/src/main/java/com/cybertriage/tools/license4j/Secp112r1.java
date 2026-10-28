package com.cybertriage.tools.license4j;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * secp112r1 arithmetic and key material helpers.
 *
 * <p>License4J 4.7.3 hard-codes the license-key keypair as a 112-bit ECDSA key
 * (see {@code com.license4j.LicenseKeyPair#getLicenseKeyKeysize()}). The curve
 * encoded in the composite public-key bundle is secp112r1 (OID 1.3.132.0.6).
 *
 * <p>SunEC can parse and encode this curve but cannot sign or verify with it,
 * so the small ECDSA implementation below is used for the self-test only.
 */
public final class Secp112r1 {

    public static final String CURVE_NAME = "secp112r1";
    public static final String CURVE_OID = "1.3.132.0.6";
    public static final int KEY_SIZE_BITS = 112;
    public static final int FIELD_SIZE_BYTES = 14;

    public static final BigInteger P =
            new BigInteger("DB7C2ABF62E35E668076BEAD208B", 16);
    public static final BigInteger A =
            new BigInteger("DB7C2ABF62E35E668076BEAD2088", 16);
    public static final BigInteger B =
            new BigInteger("659EF8BA043916EEDE8911702B22", 16);
    public static final BigInteger GX =
            new BigInteger("09487239995A5EE76B55F9C2F098", 16);
    public static final BigInteger GY =
            new BigInteger("A89CE5AF8724C0A23E0E0FF77500", 16);
    public static final BigInteger N =
            new BigInteger("DB7C2ABF62E35E7628DFAC6561C5", 16);

    public static final ECPoint G = new ECPoint(GX, GY);

    private static final byte[] ID_EC_PUBLIC_KEY = {
            0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01
    };
    private static final byte[] SECP112R1_OID = {
            0x06, 0x05, 0x2b, (byte) 0x81, 0x04, 0x00, 0x06
    };

    private Secp112r1() {
    }

    public static ECParameterSpec params() {
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(P), A, B);
        return new ECParameterSpec(curve, G, N, 1);
    }

    /** A freshly generated (d, Q) pair. */
    public static final class KeyData {
        public final BigInteger d;
        public final ECPoint q;

        public KeyData(BigInteger d, ECPoint q) {
            this.d = d;
            this.q = q;
        }
    }

    public static KeyData generate(SecureRandom random) {
        BigInteger d = randomScalar(random);
        return new KeyData(d, multiply(d, G));
    }

    public static BigInteger randomScalar(SecureRandom random) {
        BigInteger d;
        do {
            d = new BigInteger(N.bitLength(), random);
        } while (d.signum() == 0 || d.compareTo(N) >= 0);
        return d;
    }

    public static boolean isValidPrivateScalar(BigInteger d) {
        return d != null && d.signum() > 0 && d.compareTo(N) < 0;
    }

    public static boolean isOnCurve(ECPoint point) {
        if (point == null || point.equals(ECPoint.POINT_INFINITY)) {
            return false;
        }
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        if (x == null || y == null || x.signum() < 0 || x.compareTo(P) >= 0
                || y.signum() < 0 || y.compareTo(P) >= 0) {
            return false;
        }
        BigInteger left = y.multiply(y).mod(P);
        BigInteger right = x.multiply(x).multiply(x).add(A.multiply(x)).add(B).mod(P);
        return left.equals(right);
    }

    public static ECPoint add(ECPoint p, ECPoint q) {
        if (p.equals(ECPoint.POINT_INFINITY)) {
            return q;
        }
        if (q.equals(ECPoint.POINT_INFINITY)) {
            return p;
        }
        BigInteger x1 = p.getAffineX();
        BigInteger y1 = p.getAffineY();
        BigInteger x2 = q.getAffineX();
        BigInteger y2 = q.getAffineY();

        BigInteger lambda;
        if (x1.equals(x2)) {
            if (mod(y1.add(y2)).signum() == 0) {
                return ECPoint.POINT_INFINITY;
            }
            BigInteger numerator = x1.multiply(x1).multiply(BigInteger.valueOf(3)).add(A);
            BigInteger denominator = y1.shiftLeft(1);
            lambda = mod(numerator.multiply(denominator.modInverse(P)));
        } else {
            lambda = mod(y2.subtract(y1).multiply(x2.subtract(x1).modInverse(P)));
        }

        BigInteger x3 = mod(lambda.multiply(lambda).subtract(x1).subtract(x2));
        BigInteger y3 = mod(lambda.multiply(x1.subtract(x3)).subtract(y1));
        return new ECPoint(x3, y3);
    }

    public static ECPoint multiply(BigInteger k, ECPoint point) {
        if (k == null || k.signum() == 0 || point.equals(ECPoint.POINT_INFINITY)) {
            return ECPoint.POINT_INFINITY;
        }
        ECPoint result = ECPoint.POINT_INFINITY;
        ECPoint addend = point;
        BigInteger n = k;
        while (n.signum() > 0) {
            if (n.testBit(0)) {
                result = add(result, addend);
            }
            addend = add(addend, addend);
            n = n.shiftRight(1);
        }
        return result;
    }

    /**
     * Encodes a secp112r1 public key as X.509 SubjectPublicKeyInfo DER.
     * The result is always 52 bytes, with the named curve and an uncompressed point.
     */
    public static byte[] encodePublicKey(ECPoint q) {
        if (!isOnCurve(q)) {
            throw new IllegalArgumentException("EC point is not on secp112r1");
        }
        byte[] x = toFixedLength(q.getAffineX(), FIELD_SIZE_BYTES);
        byte[] y = toFixedLength(q.getAffineY(), FIELD_SIZE_BYTES);

        byte[] out = new byte[52];
        int i = 0;
        out[i++] = 0x30;
        out[i++] = 0x32;
        out[i++] = 0x30;
        out[i++] = 0x10;
        System.arraycopy(ID_EC_PUBLIC_KEY, 0, out, i, ID_EC_PUBLIC_KEY.length);
        i += ID_EC_PUBLIC_KEY.length;
        System.arraycopy(SECP112R1_OID, 0, out, i, SECP112R1_OID.length);
        i += SECP112R1_OID.length;
        out[i++] = 0x03;
        out[i++] = 0x1e;
        out[i++] = 0x00;
        out[i++] = 0x04;
        System.arraycopy(x, 0, out, i, x.length);
        i += x.length;
        System.arraycopy(y, 0, out, i, y.length);
        return out;
    }

    /**
     * Encodes a secp112r1 private scalar as PKCS#8 PrivateKeyInfo DER.
     * The result is always 46 bytes.
     */
    public static byte[] encodePrivateKey(BigInteger d) {
        if (!isValidPrivateScalar(d)) {
            throw new IllegalArgumentException("EC private scalar is out of range");
        }
        byte[] raw = toFixedLength(d, FIELD_SIZE_BYTES);
        byte[] out = new byte[46];
        int i = 0;
        out[i++] = 0x30;
        out[i++] = 0x2c;
        out[i++] = 0x02;
        out[i++] = 0x01;
        out[i++] = 0x00;
        out[i++] = 0x30;
        out[i++] = 0x10;
        System.arraycopy(ID_EC_PUBLIC_KEY, 0, out, i, ID_EC_PUBLIC_KEY.length);
        i += ID_EC_PUBLIC_KEY.length;
        System.arraycopy(SECP112R1_OID, 0, out, i, SECP112R1_OID.length);
        i += SECP112R1_OID.length;
        out[i++] = 0x04;
        out[i++] = 0x15;
        out[i++] = 0x30;
        out[i++] = 0x13;
        out[i++] = 0x02;
        out[i++] = 0x01;
        out[i++] = 0x01;
        out[i++] = 0x04;
        out[i++] = 0x0e;
        System.arraycopy(raw, 0, out, i, raw.length);
        return out;
    }

    /**
     * Parses an X.509 EC public key. Uses the JDK provider when possible and
     * falls back to the known secp112r1 layout.
     */
    public static ECPoint decodePublicKey(byte[] der) throws GeneralSecurityException {
        try {
            ECPublicKey key = (ECPublicKey) KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(der));
            ECPoint point = key.getW();
            if (!isOnCurve(point)) {
                throw new GeneralSecurityException("EC public key is not on secp112r1");
            }
            return point;
        } catch (GeneralSecurityException e) {
            if (der.length == 52 && (der[0] & 0xff) == 0x30 && (der[1] & 0xff) == 0x32
                    && (der[23] & 0xff) == 0x04) {
                BigInteger x = new BigInteger(1, Arrays.copyOfRange(der, 24, 38));
                BigInteger y = new BigInteger(1, Arrays.copyOfRange(der, 38, 52));
                ECPoint point = new ECPoint(x, y);
                if (isOnCurve(point)) {
                    return point;
                }
            }
            throw e;
        }
    }

    /** ECDSA signature values. */
    public static final class SignatureData {
        public final BigInteger r;
        public final BigInteger s;

        public SignatureData(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }
    }

    /**
     * ECDSA with SHA-512 over secp112r1. The digest is truncated to the
     * leftmost 112 bits, as required by ECDSA for a 112-bit group order.
     */
    public static SignatureData sign(byte[] message, BigInteger d, SecureRandom random) {
        if (!isValidPrivateScalar(d)) {
            throw new IllegalArgumentException("EC private scalar is out of range");
        }
        BigInteger z = hashToInteger(message);
        while (true) {
            BigInteger k = randomScalar(random);
            ECPoint rPoint = multiply(k, G);
            if (rPoint.equals(ECPoint.POINT_INFINITY)) {
                continue;
            }
            BigInteger r = rPoint.getAffineX().mod(N);
            if (r.signum() == 0) {
                continue;
            }
            BigInteger s = k.modInverse(N)
                    .multiply(z.add(r.multiply(d)))
                    .mod(N);
            if (s.signum() == 0) {
                continue;
            }
            return new SignatureData(r, s);
        }
    }

    public static boolean verify(byte[] message, ECPoint q, BigInteger r, BigInteger s) {
        if (r == null || s == null
                || r.signum() <= 0 || r.compareTo(N) >= 0
                || s.signum() <= 0 || s.compareTo(N) >= 0
                || !isOnCurve(q)) {
            return false;
        }
        BigInteger z = hashToInteger(message);
        BigInteger w = s.modInverse(N);
        BigInteger u1 = z.multiply(w).mod(N);
        BigInteger u2 = r.multiply(w).mod(N);
        ECPoint point = add(multiply(u1, G), multiply(u2, q));
        if (point.equals(ECPoint.POINT_INFINITY)) {
            return false;
        }
        return point.getAffineX().mod(N).equals(r);
    }

    private static BigInteger hashToInteger(byte[] message) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-512").digest(message);
            int byteLength = (N.bitLength() + 7) / 8;
            BigInteger z = new BigInteger(1, Arrays.copyOf(digest, byteLength));
            int excessBits = byteLength * 8 - N.bitLength();
            if (excessBits > 0) {
                z = z.shiftRight(excessBits);
            }
            return z;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-512 is not available", e);
        }
    }

    private static BigInteger mod(BigInteger value) {
        BigInteger result = value.mod(P);
        return result.signum() < 0 ? result.add(P) : result;
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) {
            return raw;
        }
        if (raw.length == length + 1 && raw[0] == 0) {
            return Arrays.copyOfRange(raw, 1, raw.length);
        }
        if (raw.length > length) {
            throw new IllegalArgumentException("Value does not fit in " + length + " bytes");
        }
        byte[] out = new byte[length];
        System.arraycopy(raw, 0, out, length - raw.length, raw.length);
        return out;
    }
}
