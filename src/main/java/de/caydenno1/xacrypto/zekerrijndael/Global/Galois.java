package de.caydenno1.xacrypto.zekerrijndael.Global;

public class Galois {
    public static byte gm2(byte b) { return (byte)(((((b & 0xFF) << 1) & 0xFF) ^ (((b & 0xFF) & 0x80) != 0 ? 0x1b : 0))); }
    public static byte gm3(byte b) { return (byte)(gm2(b) ^ b); }
    public static byte gm9(byte b)  { byte g2 = gm2(b); byte g4 = gm2(g2); return (byte)(gm2(g4) ^ b); }
    public static byte gm11(byte b) { byte g2 = gm2(b); byte g4 = gm2(g2); return (byte)(gm2(g4) ^ g2 ^ b); }
    public static byte gm13(byte b) { byte g2 = gm2(b); byte g4 = gm2(g2); return (byte)(gm2((byte) (g4 ^ b)) ^ b); }
    public static byte gm14(byte b) { byte g2 = gm2(b); byte g4 = gm2(g2); return (byte)(gm2((byte) (g4 ^ b)) ^ g2); }
}
