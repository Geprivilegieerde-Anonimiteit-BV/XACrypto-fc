package de.caydenno1.xacrypto.hash.sha512;

import java.util.Arrays;

import static de.caydenno1.xacrypto.hash.ROT.ROTR64;
import static de.caydenno1.xacrypto.misc.Constants.SHA512_H0;
import static de.caydenno1.xacrypto.misc.Constants.SHA512_K;

public class SHA512 {
    public static byte[] digest(byte[] mesg) {
        long bitLen = (long) mesg.length * 8L;

        int mod = mesg.length % 128;
        int pLen;
        if (mod < 112) {
            pLen = 112 - mod;
        } else {
            pLen = 240 - mod;
        }

        byte[] pd = new byte[mesg.length + pLen + 16];
        System.arraycopy(mesg, 0, pd, 0, mesg.length);
        pd[mesg.length] = (byte) 0x80;

        int off = pd.length - 16;
        LONG2BYTE(0L, pd, off);
        LONG2BYTE(bitLen, pd, off + 8);

        long[] H = Arrays.copyOf(SHA512_H0, 8);
        long[] W = new long[80];

        for (int blk = 0; blk < pd.length / 128; blk++) {
            int base = blk * 128;
            long[] pH = Arrays.copyOf(H, 8);

            for (int t = 0; t < 16; t++) W[t] = BYTE2LONG(pd, base + t * 8);

            for (int t = 16; t < 80; t++) {
                long s0 = ROTR64(W[t - 15], 1) ^ ROTR64(W[t - 15], 8) ^ (W[t - 15] >>> 7);
                long s1 = ROTR64(W[t - 2], 19) ^ ROTR64(W[t - 2], 61) ^ (W[t - 2] >>> 6);
                W[t] = W[t - 16] + s0 + W[t - 7] + s1;
            }

            for (int t = 0; t < 80; t++) {
                long S1 = ROTR64(H[4], 14) ^ ROTR64(H[4], 18) ^ ROTR64(H[4], 41);
                long ch = (H[4] & H[5]) ^ (~H[4] & H[6]);
                long T1 = H[7] + S1 + ch + SHA512_K[t] + W[t];

                long S0 = ROTR64(H[0], 28) ^ ROTR64(H[0], 34) ^ ROTR64(H[0], 39);
                long maj = (H[0] & H[1]) ^ (H[0] & H[2]) ^ (H[1] & H[2]);
                long T2 = S0 + maj;

                H[7] = H[6];
                H[6] = H[5];
                H[5] = H[4];
                H[4] = H[3] + T1;
                H[3] = H[2];
                H[2] = H[1];
                H[1] = H[0];
                H[0] = T1 + T2;
            }

            for (int i = 0; i < 8; i++) H[i] += pH[i];
        }

        byte[] o = new byte[64];
        for (int i = 0; i < 8; i++) LONG2BYTE(H[i], o, i * 8);

        return o;
    }

    private static long BYTE2LONG(byte[] bytes, int off) {
        long res = 0;
        for (int i = 0; i < 8; i++) res = (res << 8) | (bytes[off + i] & 0xFFL);
        return res;
    }

    private static void LONG2BYTE(long val, byte[] bytes, int off) {
        for (int i = 7; i >= 0; i--) {
            bytes[off + i] = (byte) (val & 0xFF);
            val >>>= 8;
        }
    }

    public static String BYTE2STR(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);

        for (byte b : data) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }

        return sb.toString();
    }
}
