package de.caydenno1.xacrypto.hash.sha256;

import de.caydenno1.xacrypto.misc.XACryptoException;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Hex {
    public static byte[] hash(byte[] data) throws XACryptoException {
        return new Digest().upd(data).digest();
    }

    public static byte[] hash(String text) throws XACryptoException {
        return hash(text.getBytes(StandardCharsets.UTF_8));
    }

    public static String hashPlain(String text) throws XACryptoException {
        byte[] res = new Digest().upd(text).digest();
        StringBuilder builder = new StringBuilder();

        for (byte b :res) {
            builder.append(String.format("%02x", b & 0xFF));
        }

        return builder.toString();
    }

    public static String hashHex(String text) throws XACryptoException {
        return Byte2Hex(hash(text));
    }

    public static String hashHex(byte[] data) throws XACryptoException {
        return Byte2Hex(hash(data));
    }

    public static ByteBuffer Hash2Buffer(byte[] data) throws XACryptoException {
        return ByteBuffer.wrap(hash(data)).asReadOnlyBuffer();
    }

    public static byte[] doubleHash(byte[] data) throws XACryptoException {
        return hash(hash(data));
    }

    public static byte[] HashFile(String loc) throws java.io.IOException, XACryptoException {
        byte[] bytes = Files.readAllBytes(Paths.get(loc));
        return hash(bytes);
    }

    public static String Byte2Hex(byte[] b) {
        StringBuilder o = new StringBuilder(b.length * 2);
        for (byte bi : b) {
            o.append(String.format("%02x",bi&0xff));
        }
        return o.toString();
    }


}
