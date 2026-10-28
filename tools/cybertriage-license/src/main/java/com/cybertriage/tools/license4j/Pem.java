package com.cybertriage.tools.license4j;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Minimal PEM encoder/decoder for PKCS#8 private keys and X.509 public keys. */
public final class Pem {

    private Pem() {
    }

    public static String encode(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN " + type + "-----\n"
                + base64
                + "\n-----END " + type + "-----\n";
    }

    /**
     * Returns the DER payload of the first PEM block, or {@code null} when the
     * input is not PEM.
     */
    public static byte[] decode(String text) {
        if (text == null) {
            return null;
        }
        String normalized = text.replace("\r\n", "\n").replace('\r', '\n');
        int begin = normalized.indexOf("-----BEGIN ");
        if (begin < 0) {
            return null;
        }
        int headerEnd = normalized.indexOf('\n', begin);
        if (headerEnd < 0) {
            return null;
        }
        int end = normalized.indexOf("-----END ", headerEnd);
        if (end < 0) {
            return null;
        }
        String base64 = normalized.substring(headerEnd + 1, end).replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64.getBytes(StandardCharsets.US_ASCII));
    }
}
