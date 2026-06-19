package de.caydenno1.xacrypto.zekerrijndael.Global;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.BlockCipher;

import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.SERPENT_SBOX;
import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.SERPENT_IBOX;
import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.SERPENT_PHI;

interface SerpentCipher extends BlockCipher {
    byte[] encryptBlock(byte[] in) throws XACryptoException;
    byte[] decryptBlock(byte[] in) throws XACryptoException;
}

public class Serpent implements SerpentCipher {
    private final int[][] K;

    public Serpent(byte[] key) throws XACryptoException {
        if (key.length != 16 && key.length != 24 && key.length != 32) throw new XACryptoException("serpent key must be either 16,24 or 32 bytes in length", key.length);
        this.K = new int[33][4];
        keyExpansion(key);
    }

    @Override
    public byte[] encryptBlock(byte[] in) throws XACryptoException {
        int[] X = new int[4];
        pack(in, X);

        for (int r = 0 ; r < 32 ; r++) {
            illumFOR(X, r);
            SBOXify(r % 8, X, SERPENT_SBOX);
            if (r==31) illumFOR(X, 32);
            else LT(X);
        }

        byte[] o = new byte[16];
        unpack(X, o);
        return o;
    }

    public byte[] decryptBlock(byte[] in) {
        int[] X = new int[4];
        pack(in, X);

        illumFOR(X, 32);

        for (int r = 31 ; r >= 0; r--) {
            if (r != 31) invLT(X);
            SBOXify(r % 8, X, SERPENT_IBOX);
            illumFOR(X, r);
        }
        byte[] o = new byte[16];
        unpack(X, o);
        return o;
    }
    private void illumFOR(int[] X, int N) {
        for (int i = 0 ; i < 4 ; i++) X[i] ^= K[N][i];
    }
    private void keyExpansion(byte[] key){
        byte[] pk = new byte[32];
        System.arraycopy(key, 0, pk, 0, key.length);
        if (key.length < 32) pk[key.length] = (byte) 0x01;

        int[] w = new int[104];
        for (int i = 0 ; i < 8 ; i++) {
            w[i] = (pk[i * 4] & 0xFF) | ((pk[i * 4 + 1] & 0xFF) << 8) |
                   ((pk[i * 4 + 2] & 0xFF) << 16) | ((pk[i * 4 + 3] & 0xFF) << 24);
        }

        for (int i = 8 ; i < 140 ; i++) {
            int _0 = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ SERPENT_PHI ^ (i - 8);
            w[i] = Integer.rotateLeft(_0, 11);
        }

        byte[] kb = new byte[16];
        for (int i = 0 ; i < 33 ; i++) {
            int[] group = { w[8 + 4 * i], w[8 + 4 * i + 1], w[8 + 4 * i + 2], w[8 + 4 * i + 3] };

            int index = (3 - i) % 8;

            SBOXify(index, group, SERPENT_SBOX);

            for (int j = 0 ; j < 4 ; j++) for (int k = 0; k < 4; k++) kb[j * 4 + k] = (byte) (group[j] >>> (k * 8));

            pack(kb, K[i]);
        }
    }
    private void SBOXify(int box, int[] X, byte[][] table) {
        int[] Y = new int[4];
        byte[] sbox = table[box];
        for (int i = 0 ; i < 32 ; i++) {
            int nibble = ((X[0] >>> i) & 1) | (((X[1] >>> i) & 1) << 1) |
                    (((X[2] >>> i) & 1) << 2) | (((X[3] >>> i) & 1) << 3);
            int out = sbox[nibble];
            Y[0] |= (out & 1) << i;
            Y[1] |= ((out >>> 1) & 1) << i;
            Y[2] |= ((out >>> 2) & 1) << i;
            Y[3] |= ((out >>> 3) & 1) << i;
        }
        for (int i = 0 ; i < 4 ; i++) X[i] = Y[i];
    }

    private void LT(int[] X) {
        X[0] = Integer.rotateLeft(X[0], 13);
        X[2] = Integer.rotateLeft(X[2], 3);
        X[1] ^= X[0] ^ X[2];
        X[3] ^= X[2] ^ (X[0] << 3);
        X[1] = Integer.rotateLeft(X[1], 1);
        X[3] = Integer.rotateLeft(X[3], 7);
        X[0] ^= X[1] ^ X[3];
        X[2] ^= X[3] ^ (X[1] << 7);
        X[0] = Integer.rotateLeft(X[0], 5);
        X[2] = Integer.rotateLeft(X[2], 22);

    }
    private void invLT(int[] X) {
        X[2] = Integer.rotateRight(X[2], 22);
        X[0] = Integer.rotateRight(X[0], 5);
        X[2] ^= X[3] ^ (X[1] << 7);
        X[0] ^= X[1] ^ X[3];
        X[3] = Integer.rotateRight(X[3], 7);
        X[1] = Integer.rotateRight(X[1], 1);
        X[3] ^= X[2] ^ (X[0] << 3);
        X[1] ^= X[0] ^ X[2];
        X[2] = Integer.rotateRight(X[2], 3);
        X[0] = Integer.rotateRight(X[0], 13);
    }
    private void pack(byte[] src, int[] dest) {
        dest[0] = dest[1] = dest[2] = dest[3] = 0;
        for (int i = 0 ; i < 128 ; i++) {
            int b = (src[i / 8] >>> (i % 8)) & 1;
            dest[i % 4] |= (b << (i / 4));
        }
    }
    private void unpack(int[] src, byte[] dest) {
        for (int i = 0 ; i < 128 ; i++) {
            int b = (src[i % 4] >>> (i / 4)) & 1;
            dest[i / 8] |= (b << (i % 8));
        }
    }
}
