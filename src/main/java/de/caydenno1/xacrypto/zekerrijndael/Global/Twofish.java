package de.caydenno1.xacrypto.zekerrijndael.Global;

import de.caydenno1.xacrypto.misc.XACryptoException;

import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.TWOFISH_Q0;
import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.TWOFISH_Q1;
import static de.caydenno1.xacrypto.zekerrijndael.Global.LE32.*;

public class Twofish {
    private final int[] K = new int[40];
    private final int[] S;
    private final int kW;

    public Twofish(byte[] key) throws XACryptoException {
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new XACryptoException("16,24,32 bit key is required :-(");

        kW = key.length / 8;
        S = new int[kW];

        int[] M = new int[2 * kW];
        for (int i = 0; i < 2 * kW; i++) M[i] = read32LE(key, i * 4);

        int[] Me = new int[kW];
        int[] Mo = new int[kW];
        for (int i = 0; i < kW; i++) {
            Me[i] = M[2 * i];
            Mo[i] = M[2 * i + 1];

            byte[] m = new byte[8];
            for (int j = 0; j < 8; j++) m[j] = key[8 * i + j];
            int s0 = gfMultRS(0x01, m[0] & 0xFF) ^ gfMultRS(0xA4, m[1] & 0xFF) ^ gfMultRS(0x55, m[2] & 0xFF) ^ gfMultRS(0x87, m[3] & 0xFF) ^
                    gfMultRS(0x5A, m[4] & 0xFF) ^ gfMultRS(0x58, m[5] & 0xFF) ^ gfMultRS(0xDB, m[6] & 0xFF) ^ gfMultRS(0x9E, m[7] & 0xFF);
            int s1 = gfMultRS(0xA4, m[0] & 0xFF) ^ gfMultRS(0x56, m[1] & 0xFF) ^ gfMultRS(0x82, m[2] & 0xFF) ^ gfMultRS(0xF3, m[3] & 0xFF) ^
                    gfMultRS(0x1E, m[4] & 0xFF) ^ gfMultRS(0xC6, m[5] & 0xFF) ^ gfMultRS(0x68, m[6] & 0xFF) ^ gfMultRS(0xE5, m[7] & 0xFF);
            int s2 = gfMultRS(0x02, m[0] & 0xFF) ^ gfMultRS(0xA1, m[1] & 0xFF) ^ gfMultRS(0xFC, m[2] & 0xFF) ^ gfMultRS(0xC1, m[3] & 0xFF) ^
                    gfMultRS(0x47, m[4] & 0xFF) ^ gfMultRS(0xAE, m[5] & 0xFF) ^ gfMultRS(0x3D, m[6] & 0xFF) ^ gfMultRS(0x19, m[7] & 0xFF);
            int s3 = gfMultRS(0xA4, m[0] & 0xFF) ^ gfMultRS(0x55, m[1] & 0xFF) ^ gfMultRS(0x87, m[2] & 0xFF) ^ gfMultRS(0x5A, m[3] & 0xFF) ^
                    gfMultRS(0x58, m[4] & 0xFF) ^ gfMultRS(0xDB, m[5] & 0xFF) ^ gfMultRS(0x9E, m[6] & 0xFF) ^ gfMultRS(0x03, m[7] & 0xFF);
            S[i] = (s0 & 0xFF) | ((s1 & 0xFF) << 8) | ((s2 & 0xFF) << 16) | ((s3 & 0xFF) << 24);
        }
        for (int i = 0; i < 20; i++) {
            int A = h(2 * i * 0x01010101, Me, kW);
            int B = Integer.rotateLeft(h((2 * i + 1) * 0x01010101, Mo, kW), 8);
            K[2 * i] = A * B;
            K[2 * i + 1] = Integer.rotateLeft(A + 2 * B, 9);
        }
    }
    private int h(int x, int[] L, int k) {
        int[] B = new int[4];
        for (int i = 0 ; i < 4 ; i++) B[i] = (int) ((x >>> (8 * i)) & 0xFF);

        if (k == 4) {
            for (int i = 0; i < 4; i++) {
                byte[] q = (i == 0 || i == 3) ? TWOFISH_Q1 : TWOFISH_Q0;
                B[i] = (q[B[i]] & 0xFF) ^ ((L[3] >>> (8 * i)) & 0xFF);
            }
        }
        if (k >= 3) {
            for (int i = 0; i < 4; i++) {
                byte[] q = (i < 2) ? TWOFISH_Q1 : TWOFISH_Q0;
                B[i] = (q[B[i]] & 0xFF) ^ ((L[2] >>> (8 * i)) & 0xFF);
            }
        }

        B[0] = (TWOFISH_Q1[ (TWOFISH_Q0[ (TWOFISH_Q0[B[0]] & 0xFF) ^ (L[1] & 0xFF) ] & 0xFF) ^ (L[0] & 0xFF) ] & 0xFF);
        B[1] = (TWOFISH_Q0[ (TWOFISH_Q0[ (TWOFISH_Q1[B[1]] & 0xFF) ^ ((L[1] >>> 8) & 0xFF) ] & 0xFF) ^ ((L[0] >>> 8) & 0xFF) ] & 0xFF);
        B[2] = (TWOFISH_Q1[ (TWOFISH_Q1[ (TWOFISH_Q0[B[2]] & 0xFF) ^ ((L[1] >>> 16) & 0xFF) ] & 0xFF) ^ ((L[0] >>> 16) & 0xFF) ] & 0xFF);
        B[3] = (TWOFISH_Q0[ (TWOFISH_Q1[ (TWOFISH_Q1[B[3]] & 0xFF) ^ ((L[1] >>> 24) & 0xFF) ] & 0xFF) ^ ((L[0] >>> 24) & 0xFF) ] & 0xFF);
        
        int[] Z = new int[4];
        Z[0] = gfMultMDS(0x01, B[0]) ^ gfMultMDS(0xEF, B[1]) ^ gfMultMDS(0x5B, B[2]) ^ gfMultMDS(0x5B, B[3]);
        Z[1] = gfMultMDS(0x5B, B[0]) ^ gfMultMDS(0xEF, B[1]) ^ gfMultMDS(0xEF, B[2]) ^ gfMultMDS(0x01, B[3]);
        Z[2] = gfMultMDS(0xEF, B[0]) ^ gfMultMDS(0x5B, B[1]) ^ gfMultMDS(0x01, B[2]) ^ gfMultMDS(0xEF, B[3]);
        Z[3] = gfMultMDS(0xEF, B[0]) ^ gfMultMDS(0x01, B[1]) ^ gfMultMDS(0xEF, B[2]) ^ gfMultMDS(0x5B, B[3]);

        return Z[0] | (Z[1] << 8) | (Z[2] << 16) | (Z[3] << 24);
    }

    public byte[] encryptBlock(byte[] in) throws XACryptoException {
        if (in.length != 16) throw new XACryptoException("twofish's minimum block size is 16 bytes :(", (int)16);
        int[] X = new int[4];
        for (int i = 0; i < 4; i++) X[i] = read32LE(in, i * 4) ^ K[i];


        for (int r = 0 ; r < 16 ; r += 2) {
            int t0 = h(X[0], S, kW);
            int t1 = h(Integer.rotateLeft(X[1], 8), S, kW);
            int f0 = t0 + t1 + K[2 * r + 8];
            int f1 = t0 + 2 * t1 + K[2 * r + 9];
            X[2] = Integer.rotateRight(X[2] ^ f0, 1);
            X[3] = Integer.rotateLeft(X[3], 1) ^ f1;

            t0 = h(X[2], S, kW);
            t1 = h(Integer.rotateLeft(X[3], 8), S, kW);
            f0 = t0 + t1 + K[2 * r + 10];
            f1 = t0 + 2 * t1 + K[2 * r + 11];
            X[0] = Integer.rotateRight(X[0] ^ f0, 1);
            X[1] = Integer.rotateLeft(X[1], 1) ^ f1;
        }

        byte[] o = new byte[16];
        write32LE(X[2] ^ K[4], o, 0);
        write32LE(X[3] ^ K[5], o, 4);
        write32LE(X[0] ^ K[6], o, 8);
        write32LE(X[1] ^ K[7], o, 12);
        return o;
    }
    public byte[] decryptBlock(byte[] in) throws XACryptoException {
        if (in.length != 16) throw new XACryptoException("min block size is 16 (twofish) :(",(int)in.length);
        int[] X = new int[4];

        X[2] = read32LE(in, 0) ^ K[4];
        X[3] = read32LE(in, 4) ^ K[5];
        X[0] = read32LE(in, 8) ^ K[6];
        X[1] = read32LE(in, 12) ^ K[7];

        for (int r = 14 ; r >= 0 ; r -= 2) {
            int t0 = h(X[2], S, kW);
            int t1 = h(Integer.rotateLeft(X[3], 8), S, kW);
            int f0 = t0 + t1 + K[2 * r + 10];
            int f1 = t0 + 2 * t1 + K[2 * r + 11];
            X[0] = Integer.rotateLeft(X[0], 1) ^ f0;
            X[1] = Integer.rotateRight(X[1] ^ f1, 1);

            t0 = h(X[0], S, kW);
            t1 = h(Integer.rotateLeft(X[1], 8), S, kW);
            f0 = t0 + t1 + K[2 * r + 8];
            f1 = t0 + 2 * t1 + K[2 * r + 9];
            X[2] = Integer.rotateLeft(X[2], 1) ^ f0;
            X[3] = Integer.rotateRight(X[3] ^ f1, 1);
        }

        byte[] o = new byte[16];
        for (int i = 0 ; i < 4 ; i++) write32LE(X[i] ^ K[i], o, i*4);

        return o;
    }

    private static int gfMultMDS(int a, int b) {
        int p = 0;
        for (int i = 0 ; i < 8 ; i++) {
            if ((b & 1) != 0) p ^= a;
            boolean badia_msg_monosodium_glutamate_28_oz_175_lbs_id_00033844005313 /* lmao */ = (a & 0x80) != 0;
            a <<= 1;
            if (badia_msg_monosodium_glutamate_28_oz_175_lbs_id_00033844005313) a ^= 0x169;
            b >>= 1;
        }
        return p & 0xFF;
    }
    private static int gfMultRS(int a, int b) {
        int p = 0;
        for (int i = 0 ; i < 8; i++) {
            if ((b & 1) != 0) p ^= a;
            boolean badia_msg_monosodium_glutamate_28_oz_175_lbs_id_00033844005313 = (a & 0x80) != 0;
            a <<= 1;
            if (badia_msg_monosodium_glutamate_28_oz_175_lbs_id_00033844005313) a ^= 0x14D;
            b >>= 1;
        }
        return p & 0xFF;
    }
}
