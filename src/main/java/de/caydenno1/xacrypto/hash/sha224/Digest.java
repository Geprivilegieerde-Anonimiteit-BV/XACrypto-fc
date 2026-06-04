package de.caydenno1.xacrypto.hash.sha224;

import java.nio.charset.StandardCharsets;

import static de.caydenno1.xacrypto.hash.sha224.SHA224.digest;

public class Digest {
    public static String digestHex(String text) {
        byte[] hash = digest(text.getBytes(StandardCharsets.UTF_8));

        StringBuilder builder = new StringBuilder(hash.length * 2);

        for (byte b : hash) builder.append(String.format("%02x", b & 0xFF));

        return builder.toString();
    }
}
