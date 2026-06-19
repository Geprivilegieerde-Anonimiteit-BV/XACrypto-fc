package de.caydenno1.xacrypto.zekerrijndael.GCM;

import de.caydenno1.xacrypto.misc.XACryptoException;
import static de.caydenno1.xacrypto.zekerrijndael.Global.Galois.*;
import java.util.Arrays;

import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.*;
public final class AES implements BlockCipher {
    public final int bits;
    public int kc;
    private final byte[][] keys;

    public AES(byte[] key, int bits) throws XACryptoException {
        this.bits = bits;
        this.kc = switch (bits) {
            case 128 -> 44;
            case 192 -> 52;
            case 256 -> 60;
            default -> throw new XACryptoException(
                    "only 128, 192 and 256 bit ciphers are supported atm. sorry :%"
            );
        };
        keys = new byte[kc][4];

        keyExpansion(key);
    }

    public byte[] encryptBlock(byte[] input) throws XACryptoException {
        int m = switch (bits) {
            case 128 -> 10;
            case 192 -> 12;
            case 256 -> 14;
            default -> throw new XACryptoException("only 128, 192 and 256 bit ciphers are supported atm. sorry :%");
        };

            byte[][] s = new byte[4][4];

            for (int i = 0; i < 16; i++) {
                s[i & 3][i >> 2] = input[i];
            }

        addRoundKey(s, 0);

        for (int r = 1; r < m; r++) {
            sub(s);
            shift(s);
            mixColumns(s);
            addRoundKey(s, r);
        }

        sub(s);
        shift(s);
        addRoundKey(s, m);

        byte[] o = new byte[16];

        for (int i = 0; i < 16; i++) {
            o[i] = s[i & 3][i >> 2];
        }

        return o;
    }

    public byte[] decryptBlock(byte[] input) throws XACryptoException {
        int m = switch (bits) {
            case 128 -> 10;
            case 192 -> 12;
            case 256 -> 14;
            default -> throw new XACryptoException("only 128, 192 and 256 bit ciphers are supported atm. sorry :%");
        };

        byte[][] s = new byte[4][4];
        for (int i = 0; i < 16; i++) s[i & 3][i >> 2] = input[i];


        addRoundKey(s, m);

        for (int r = m - 1 ; r > 0 ; r--) {
            invShift(s);
            invSub(s);
            addRoundKey(s, r);
            invMC(s);
        }

        invShift(s);
        invSub(s);
        addRoundKey(s, 0);

        byte[] o = new byte[16];
        for (int i = 0 ; i < 16 ; i++) o[i] = s[i & 3][i >> 2];


        return o;
    }

    private static void invSub(byte[][] s) {
        for (int _0 = 0 ; _0 < 4 ; _0++) for (int _1 = 0 ; _1 < 4 ; _1++) s[_0][_1] = (byte) ARIA_XB1 /*for some reason ARIA's Inverse 1 Box is the same as AES's Inverse SBOX?*/ [s[_0][_1] & 0xFF];
    }

    private static void invShift(byte[][] s) {
        byte t;

        for (int _0 = 1 ; _0 < 4 ; _0++) {
            byte[] _1 = new byte[4];

            for (int _2 = 0 ; _2 < 4 ; _2++) _1[(_2 + _0) % 4] = s[_0][_2];
            for (int _2 = 0 ; _2 < 4 ; _2++) s[_0][_2] = _1[_2];
        }
    }

    private static void invMC(byte[][] s) {
        for (int _0 = 0; _0 < 4; _0++) {
            byte a0 = s[0][_0]; byte a1 = s[1][_0]; byte a2 = s[2][_0]; byte a3 = s[3][_0];

            s[0][_0] = (byte)(gm14(a0) ^ gm11(a1) ^ gm13(a2) ^ gm9(a3));
            s[1][_0] = (byte)(gm9(a0)  ^ gm14(a1) ^ gm11(a2) ^ gm13(a3));
            s[2][_0] = (byte)(gm13(a0) ^ gm9(a1)  ^ gm14(a2) ^ gm11(a3));
            s[3][_0] = (byte)(gm11(a0) ^ gm13(a1) ^ gm9(a2)  ^ gm14(a3));
        }
    }

//    private void sub(byte[][] s) {
//        for (int c = 0; c < 4; c++) {
//            for (int r = 0; r < 4; r++) {
//                s[r][c] = (byte)(s[r][c] ^ keys[r * 4 + c][r]);
//            }
//        }
//    }

    private static void sub(byte[][] s) {
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                s[r][c] = SBOX[s[r][c] & 0xFF];
            }
        }
    }

    private static void shift(byte[][] s) {
        byte t;

        t = s[1][0];
        s[1][0] = s[1][1];
        s[1][1] = s[1][2];
        s[1][2] = s[1][3];
        s[1][3] = t;

        t = s[2][0];
        byte t2 = s[2][1];
        s[2][0] = s[2][2];
        s[2][1] = s[2][3];
        s[2][2] = t;
        s[2][3] = t2;

        t = s[3][3];
        s[3][3] = s[3][2];
        s[3][2] = s[3][1];
        s[3][1] = s[3][0];
        s[3][0] = t;
    }
    private static void mixColumns(byte[][] s) {

        for (int c = 0; c < 4; c++) {

            byte a0 = s[0][c];
            byte a1 = s[1][c];
            byte a2 = s[2][c];
            byte a3 = s[3][c];

            s[0][c] = (byte)(gm2(a0) ^ gm3(a1) ^ a2 ^ a3);
            s[1][c] = (byte)(a0 ^ gm2(a1) ^ gm3(a2) ^ a3);
            s[2][c] = (byte)(a0 ^ a1 ^ gm2(a2) ^ gm3(a3));
            s[3][c] = (byte)(gm3(a0) ^ a1 ^ a2 ^ gm2(a3));
        }
    }



    private void addRoundKey(byte[][] s, int round) {
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                s[r][c] ^= keys[round * 4 + c][r];
            }
        }
    }

    private void keyExpansion(byte[] key) throws XACryptoException {
        int tem = switch(bits) {
            case 128 -> 4;
            case 192 -> 6;
            case 256 -> 8;
            default -> throw new XACryptoException(
                    "only 128, 192 and 256 bit ciphers are supported atm. sorry :%"
            );
        };

        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new XACryptoException("aes keys must be 16, 24, or 32 in length.");

        for (int i = 0; i < tem; i++) {
            System.arraycopy(key, i * 4, keys[i], 0, 4);
        }

        for (int i = tem; i < kc; i++) {

            byte[] temp = Arrays.copyOf(keys[i - 1], 4);

            if (i % tem == 0) {

                byte t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;

                for (int j = 0; j < 4; j++) {
                    temp[j] = SBOX[temp[j] & 0xFF];
                }

                temp[0] ^= (byte) RCON[i / tem];
            }

            if (bits == 256 && i % 8 == 4) for (int j = 0 ; j < 4 ; j++) temp[j] = SBOX[temp[j] & 0xFF];

            for (int j = 0; j < 4; j++) keys[i][j] = (byte)(keys[i - tem][j] ^ temp[j]);
        }
    }

    public byte[] encryptCBC(byte[] ln, byte[] iv) throws XACryptoException {

        int padLen = 16 - (ln.length % 16);
        if (padLen == 0) padLen = 16;

        byte[] pln = Arrays.copyOf(ln, ln.length + padLen);
        for (int i = ln.length; i < pln.length; i++) {
            pln[i] = (byte) padLen;
        }

        byte[] o = new byte[pln.length];
        byte[] prev = Arrays.copyOf(iv, 16);

        byte[] block = new byte[16];

        for (int i = 0; i < pln.length; i += 16) {

            for (int j = 0; j < 16; j++) {
                block[j] = (byte)(pln[i + j] ^ prev[j]);
            }

            byte[] enc = encryptBlock(block);

            System.arraycopy(enc, 0, o, i, 16);

            prev = enc;
        }

        return o;
    }

    public byte[] encryptCTR(byte[] ln, byte[] nonce) throws XACryptoException {

        byte[] o = new byte[ln.length];

        byte[] cnt = Arrays.copyOf(nonce, 16);
        byte[] ks;

        for (int i = 0; i < ln.length; i += 16) {

            int ctr = i >>> 4;

            cnt[12] = (byte)(ctr >>> 24);
            cnt[13] = (byte)(ctr >>> 16);
            cnt[14] = (byte)(ctr >>> 8);
            cnt[15] = (byte)(ctr);

            ks = encryptBlock(cnt);

            int limit = Math.min(16, ln.length - i);
            for (int j = 0; j < limit; j++) {
                o[i + j] = (byte) (ln[i + j] ^ ks[j]);
            }
        }

        return o;
    }
}