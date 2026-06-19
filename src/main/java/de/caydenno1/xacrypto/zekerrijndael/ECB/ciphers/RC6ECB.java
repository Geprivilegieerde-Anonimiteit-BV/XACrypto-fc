package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB;
import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.*;
import static de.caydenno1.xacrypto.zekerrijndael.Global.LE32.*;

public class RC6ECB implements ECB {
    private final int[] S;
    // 20 rounds

    public RC6ECB(byte[] key) throws XACryptoException {
        if (key.length <= 0 || key.length > 255) throw new XACryptoException("keys must be 1-255 bytes inclusive :\\");

        int c = Math.max(1, (key.length + 3) / 4);
        int[] L = new int[c];
        for (int i = 0 ; i < key.length ; i++) L[i / 4] |= (key[i] & 0xFF) << (8 * (i % 4));

        S = new int[44 /* 2x 20 rounds = 40 rounds + 4 = 44. */];
        S[0] = RC6_P;
        for (int i = 1 ; i < S.length ; i++) S[i] = S[i - 1] + RC6_Q;

        int A = 0, B = 0, i = 0, j = 0;
        int v = 3 * Math.max(c, S.length);
        for (int s = 0 ; s < v ; s++) {
            A = S[i] = Integer.rotateLeft(S[i] + A + B, 3);
            B = L[j] = Integer.rotateLeft(L[j] + A + B, A + B);
            i = (i + 1)%S.length;
            j = (j + 1)%c;
        }
    }

    private void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int[] data = new int[4];
        for (int i = 0; i < 4; i++) data[i] = read32LE(in, inOff + (i * 4));

        data[1] += S[0];
        data[3] += S[1];

        for (int i = 1 ; i <= 20 ; i++) {
            int t = Integer.rotateLeft(data[1] * (2 * data[1] + 1), 5);
            int u = Integer.rotateLeft(data[3] * (2 * data[3] + 1), 5);

            data[0] = Integer.rotateLeft(data[0] ^ t, u) + S[2 * i];
            data[2] = Integer.rotateLeft(data[2] ^ u, t) + S[2 * i + 1];

            int _0 = data[0]; data[0] = data[1]; data[1] = data[2]; data[2] = data[3]; data[3] = _0;
        }

        data[0] += S[42];
        data[2] += S[43];

        for (int i = 0; i < 4; i++) write32LE(data[i], out, outOff + (i * 4));
    };

    private void decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int[] data = new int[4];
        for (int i = 0; i < 4; i++) data[i] = read32LE(in, inOff + (i * 4));

        data[2] -= S[43];
        data[0] -= S[42];

        for (int i = 20 ; i >= 1 ; i--) {
            int _0 = data[3]; data[2] = data[1]; data[1] = data[0]; data[0] = _0;

            int u = Integer.rotateLeft(data[3] * (2 * data[3] + 1), 5);
            int t = Integer.rotateLeft(data[1] * (2 * data[1] + 1), 5);

            data[2] = Integer.rotateRight(data[2] - S[2 * i + 1], t) ^ u;
            data[0] = Integer.rotateRight(data[0] - S[2 * i], u) ^ t;
        }

        data[3] -= S[1];
        data[1] -= S[0];
        for (int i = 0; i < 4; i++) write32LE(data[i], out, outOff + (i * 4));
    }

    public byte[] encrypt(byte[] pln) throws XACryptoException {
        int pLen = 16 - (pln.length % 16);
        byte[] pData = new byte[pln.length + pLen];
        System.arraycopy(pln, 0, pData, 0, pln.length);
        for (int i = pln.length ; i < pData.length ; i++) pData[i] = (byte) pLen;

        byte[] cip = new byte[pData.length];
        for (int i = 0 ; i < pData.length ; i += 16) encryptBlock(pData, i, cip, i);
        return cip;
    }

    public byte[] decrypt(byte[] cip) throws XACryptoException {
        if (cip.length % 16 != 0) throw new XACryptoException("ciptext length is not a multiple of 16");

        byte[] de = new byte[cip.length];
        for (int i = 0 ; i < cip.length ; i += 16) decryptBlock(cip, i, de, i);

        int pLen = de[de.length - 1] & 0xFF;

        byte[] pln = new byte[de.length - pLen];
        System.arraycopy(de, 0, pln, 0, pln.length);
        return pln;
    }
}
