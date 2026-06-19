package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless;

import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.SM4_FK;
import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.SM4_CK;
import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.SM4_SBOX;
import static de.caydenno1.xacrypto.hash.ROT.ROTL;

public class SM4ECB implements ECBExceptionless {
    public final int[] encRK = new int[32];
    public final int[] decRK = new int[32];

    public SM4ECB(byte[] key) throws XACryptoException {
        if (key.length != 16) throw new XACryptoException("key length must be 16 bytes :{", (int) key.length);
        genRK(key);
    }

    private void genRK(byte[] key) {
        int[] K = new int[36];
        for (int i = 0; i < 4; i++) K[i] = BYTE2INT(key, i * 4) ^ SM4_FK[i];

        for (int i = 0 ; i < 32 ; i++) {
            int _0 = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ SM4_CK[i];

            int b = ((SM4_SBOX[(_0 >>> 24) & 0xFF]) << 24)
                    | ((SM4_SBOX[(_0 >>> 16) & 0xFF]) << 16)
                    | ((SM4_SBOX[(_0 >>> 8) & 0xFF]) << 8)
                    | (SM4_SBOX[_0 & 0xFF]);

            int l = b ^ ROTL(b, 13) ^ ROTL(b, 23);

            K[i + 4] = K[i] ^ l;
            this.encRK[i] = K[i + 4];
            this.decRK[31 - i] = K[i + 4];
        }
    }

    private void processBlock(byte[] in, int inOff, byte[] o, int outOff, int[] rk) {
        int[] X = new int[5];
        for (int i = 0; i < 4; i++) X[i] = BYTE2INT(in, inOff + (i * 4));


        for (int i = 0 ; i < 32 ; i++) {
            int tmp = X[1] ^ X[2] ^ X[3] ^ rk[i];

            int b = ((SM4_SBOX[(tmp >>> 24) & 0xFF]) << 24)
                    | ((SM4_SBOX[(tmp >>> 16) & 0xFF]) << 16)
                    | ((SM4_SBOX[(tmp >>> 8) & 0xFF]) << 8)
                    | (SM4_SBOX[tmp & 0xFF]);

            int l = b ^ ROTL(b, 2) ^ ROTL(b, 10) ^ ROTL(b, 18) ^ ROTL(b, 24);

            X[4] = X[0] ^ l;
            X[0] = X[1];
            X[1] = X[2];
            X[2] = X[3];
            X[3] = X[4];
        }

        for (int i = 0; i < 4; i++) INT2BYTE(X[3 - i], o, outOff + (i * 4));
    }

    public byte[] encrypt(byte[] pln) {
        int pLen = 16 - (pln.length % 16);
        byte[] pData = new byte[pln.length + pLen];

        System.arraycopy(pln, 0, pData, 0, pln.length);
        for (int i = pln.length; i < pData.length; i++) pData[i] = (byte) pLen;

        byte[] cip = new byte[pData.length];
        byte[] in = new byte[16];
        byte[] o = new byte[16];

        for (int i = 0; i < pData.length; i += 16) {
            System.arraycopy(pData, i, in, 0, 16);
            processBlock(in, 0, o, 0, encRK);
            System.arraycopy(o, 0, cip, i, 16);
        }

        return cip;
    }

    public byte[] decrypt(byte[] cip) throws XACryptoException {
        if (cip.length % 16 != 0) {
            throw new XACryptoException("length of ciphertext must be a multiple of 16 (16-byte size) :-{");
        }

        byte[] decomp = new byte[cip.length];
        byte[] _i = new byte[16];
        byte[] o = new byte[16];

        for (int i = 0; i < cip.length; i += 16) {
            System.arraycopy(cip, i, _i, 0, 16);
            processBlock(_i, 0, o, 0, decRK);
            System.arraycopy(o, 0, decomp, i, 16);
        }
        int pLen = decomp[decomp.length - 1] & 0xFF;
        if (pLen < 1 || pLen > 16) throw new XACryptoException("padding must be 1-16 exclusive in length", (int) pLen);


        byte[] pln = new byte[decomp.length - pLen];
        System.arraycopy(decomp, 0, pln, 0, pln.length);

        return pln;
    }
    private static int BYTE2INT(byte[] b, int off) {
        return ((b[off]     & 0xFF) << 24) |
                ((b[off + 1] & 0xFF) << 16) |
                ((b[off + 2] & 0xFF) <<  8) |
                (b[off + 3] & 0xFF);
    }

    private static void INT2BYTE(int v, byte[] b, int o) {
        for (int i = 0; i < 4; i++) b[o + i] = (byte) (v >>> (24 - 8 * i));
    }
}
