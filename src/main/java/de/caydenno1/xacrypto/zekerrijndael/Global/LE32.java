package de.caydenno1.xacrypto.zekerrijndael.Global;

public class LE32 {
    public static int read32LE(byte[] b, int off) { return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8) | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24); }
    public static void write32LE(int v, byte[] b, int off) { for (int i = 0 ; i < 4 ; i++) b[off + i] = (byte) (v >>> (i * 8)); }
}