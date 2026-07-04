package de.caydenno1.xacrypto.zekerrijndael.Global;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.BlockCipher;
import de.caydenno1.xacrypto.zekerrijndael.UnchangingData;
import de.caydenno1.xacrypto.hash.ROT;

interface CamelliaCipher {
    byte[] encryptBlock(byte[] in, int inputOffset, byte[] out, int outOffset) throws XACryptoException;
    byte[] decryptBlock(byte[] in);
}

public class Camellia implements CamelliaCipher, BlockCipher {
    private final long[] subkeys;

    public Camellia(byte[] key) throws XACryptoException {
        if (key.length != 16 && key.length != 24 && key.length != 32) throw new XACryptoException("16,24,32 byte key is required");
        this.subkeys = new long[key.length == 16 ? 26 : 34];
	    genKeySchedule(key);
    }

    public byte[] encryptBlock(byte[] in) throws XACryptoException {
        return encryptBlock(in, 0, new byte[16], 0);
    }

    @Override
    public byte[] encryptBlock(byte[] in, int inputOffset, byte[] out, int outOffset) {
        long d1 = bytes2Long(in, inputOffset);
        long d2 = bytes2Long(in, inputOffset + 8);

        d1 ^= subkeys[0];
        d2 ^= subkeys[1];

        d2 ^= F(d1, subkeys[2]);
        d1 ^= F(d2, subkeys[3]);
        d2 ^= F(d1, subkeys[4]);
        d1 ^= F(d2, subkeys[5]);
        d2 ^= F(d1, subkeys[6]);
        d1 ^= F(d2, subkeys[7]);

        d1 = FL(d1, subkeys[8]);
        d2 = FLINV(d2, subkeys[9]);

        d2 ^= F(d1, subkeys[10]);
        d1 ^= F(d2, subkeys[11]);
        d2 ^= F(d1, subkeys[12]);
        d1 ^= F(d2, subkeys[13]);
        d2 ^= F(d1, subkeys[14]);
        d1 ^= F(d2, subkeys[15]);

        d1 = FL(d1, subkeys[16]);
        d2 = FLINV(d2, subkeys[17]);

        d2 ^= F(d1, subkeys[18]);
        d1 ^= F(d2, subkeys[19]);
        d2 ^= F(d1, subkeys[20]);
        d1 ^= F(d2, subkeys[21]);
        d2 ^= F(d1, subkeys[22]);
        d1 ^= F(d2, subkeys[23]);

        if (subkeys.length == 34) {
            d1 = FL(d1, subkeys[24]);
            d2 = FLINV(d2, subkeys[25]);

            d2 ^= F(d1, subkeys[26]);
            d1 ^= F(d2, subkeys[27]);
            d2 ^= F(d1, subkeys[28]);
            d1 ^= F(d2, subkeys[29]);
            d2 ^= F(d1, subkeys[30]);
            d1 ^= F(d2, subkeys[31]);

            d2 ^= subkeys[32];
            d1 ^= subkeys[33];
        } else {
            d2 ^= subkeys[24];
            d1 ^= subkeys[25];
        }

        byte[] o = new byte[16];
        long2Bytes(d2, o, outOffset);
        long2Bytes(d1, o, outOffset + 8);
        return o;
    }

    public byte[] decryptBlock(byte[] in) {
        return decryptBlock(in, 0, new byte[16], 0);
    }

    public byte[] decryptBlock(byte[] in, int inputOffset, byte[] out, int outOffset) {
        long d1 = bytes2Long(in, inputOffset);
        long d2 = bytes2Long(in, inputOffset + 8);

        if (subkeys.length == 34) {
            d1 ^= subkeys[32];
            d2 ^= subkeys[33];

            d2 ^= F(d1, subkeys[31]);
            d1 ^= F(d2, subkeys[30]);
            d2 ^= F(d1, subkeys[29]);
            d1 ^= F(d2, subkeys[28]);
            d2 ^= F(d1, subkeys[27]);
            d1 ^= F(d2, subkeys[26]);

            d1 = FL(d1, subkeys[25]);
            d2 = FLINV(d2, subkeys[24]);
        } else {
            d1 ^= subkeys[24];
            d2 ^= subkeys[25];
        }

        d2 ^= F(d1, subkeys[23]);
        d1 ^= F(d2, subkeys[22]);
        d2 ^= F(d1, subkeys[21]);
        d1 ^= F(d2, subkeys[20]);
        d2 ^= F(d1, subkeys[19]);
        d1 ^= F(d2, subkeys[18]);

        d1 = FL(d1, subkeys[17]);
        d2 = FLINV(d2, subkeys[16]);

        d2 ^= F(d1, subkeys[15]);
        d1 ^= F(d2, subkeys[14]);
        d2 ^= F(d1, subkeys[13]);
        d1 ^= F(d2, subkeys[12]);
        d2 ^= F(d1, subkeys[11]);
        d1 ^= F(d2, subkeys[10]);

        d1 = FL(d1, subkeys[9]);
        d2 = FLINV(d2, subkeys[8]);

        d2 ^= F(d1, subkeys[7]);
        d1 ^= F(d2, subkeys[6]);
        d2 ^= F(d1, subkeys[5]);
        d1 ^= F(d2, subkeys[4]);
        d2 ^= F(d1, subkeys[3]);
        d1 ^= F(d2, subkeys[2]);

        d2 ^= subkeys[0];
        d1 ^= subkeys[1];

        long2Bytes(d2, out, outOffset);
        long2Bytes(d1, out, outOffset + 8);
        return out;
    }

    private void genKeySchedule(byte[] key) {
        long KL1 = bytes2Long(key, 0);
        long KL2 = bytes2Long(key, 8);
        long KR1=0,KR2 = 0;

        if (key.length == 24) {
            KR1 = bytes2Long(key, 16);
            KR2 = ~KR1;
        } else if (key.length == 32) {
            KR1 = bytes2Long(key, 16);
            KR2 = bytes2Long(key, 24);
        }

        long d1 = KL1 ^ KR1;
        long d2 = KL2 ^ KR2;
        d2 ^= F(d1, UnchangingData.CAMELLIA_SIGMA[1]);
        d1 ^= F(d2, UnchangingData.CAMELLIA_SIGMA[2]);
        d1 ^= KL1;
        d2 ^= KL2;
        d2 ^= F(d1, UnchangingData.CAMELLIA_SIGMA[3]);
        d1 ^= F(d2, UnchangingData.CAMELLIA_SIGMA[4]);
        long KA1 = d1;
        long KA2 = d2;

        long KB1 = 0, KB2 = 0;

        if (key.length > 16) {
            d1 = KA1 ^ KR1;
            d2 = KA2 ^ KR2;
            d2 ^= F(d1, UnchangingData.CAMELLIA_SIGMA[5]);
            d1 ^= F(d2, UnchangingData.CAMELLIA_SIGMA[6]);
            KB1 = d1;
            KB2 = d2;
        }

        if (key.length == 16) {
            subkeys[0] = KL1;
            subkeys[1] = KL2;
            subkeys[2] = KA1;
            subkeys[3] = KA2;

            long[] KLrot15 = ROT.ROTL64(KL1, KL2, 15);
            subkeys[4] = KLrot15[0];
            subkeys[5] = KLrot15[1];

            long[] KArot15 = ROT.ROTL64(KA1, KA2, 15);
            subkeys[6] = KArot15[0];
            subkeys[7] = KArot15[1];

            long[] KArot30 = ROT.ROTL64(KA1, KA2, 30);
            subkeys[8] = (KArot30[0] >>> 32) | (KArot30[0] << 32);
            subkeys[9] = (KArot30[1] >>> 32) | (KArot30[1] << 32);

            long[] KLrot45 = ROT.ROTL64(KL1, KL2, 45);
            subkeys[10] = KLrot45[0];
            subkeys[11] = KLrot45[1];

            long[] KArot45 = ROT.ROTL64(KA1, KA2, 45);
            subkeys[12] = KArot45[0];
            subkeys[13] = KArot45[1];

            long[] KLrot60 = ROT.ROTL64(KL1, KL2, 60);
            subkeys[14] = KLrot60[0];
            subkeys[15] = KLrot60[1];

            long[] KLrot77 = ROT.ROTL64(KL1, KL2, 77);
            subkeys[16] = (KLrot77[0] >>> 32) | (KLrot77[0] << 32);
            subkeys[17] = (KLrot77[1] >>> 32) | (KLrot77[1] << 32);

            long[] KLrot94 = ROT.ROTL64(KL1, KL2, 94);
            subkeys[18] = KLrot94[0];
            subkeys[19] = KLrot94[1];

            long[] KArot94 = ROT.ROTL64(KA1, KA2, 94);
            subkeys[20] = KArot94[0];
            subkeys[21] = KArot94[1];

            long[] KLrot111 = ROT.ROTL64(KL1, KL2, 111);
            subkeys[22] = KLrot111[0];
            subkeys[23] = KLrot111[1];

            long[] KArot111 = ROT.ROTL64(KA1, KA2, 111);
            subkeys[24] = KArot111[0];
            subkeys[25] = KArot111[1];
        } else {
            subkeys[0] = KL1;
            subkeys[1] = KL2;

            subkeys[2] = KB1;
            subkeys[3] = KB2;

            long[] KRrot15 = ROT.ROTL64(KR1, KR2, 15);
            subkeys[4] = KRrot15[0];
            subkeys[5] = KRrot15[1];

            long[] KArot15 = ROT.ROTL64(KA1, KA2, 15);
            subkeys[6] = KArot15[0];
            subkeys[7] = KArot15[1];

            long[] KRrot30 = ROT.ROTL64(KR1, KR2, 30);
            subkeys[8] = (KRrot30[0] >>> 32) | (KRrot30[0] << 32);
            subkeys[9] = (KRrot30[1] >>> 32) | (KRrot30[1] << 32);

            long[] KBrot30 = ROT.ROTL64(KB1, KB2, 30);
            subkeys[10] = KBrot30[0];
            subkeys[11] = KBrot30[1];

            long[] KLrot45 = ROT.ROTL64(KL1, KL2, 45);
            subkeys[12] = KLrot45[0];
            subkeys[13] = KLrot45[1];

            long[] KArot45 = ROT.ROTL64(KA1, KA2, 45);
            subkeys[14] = KArot45[0];
            subkeys[15] = KArot45[1];

            long[] KLrot60 = ROT.ROTL64(KL1, KL2, 60);
            subkeys[16] = (KLrot60[0] >>> 32) | (KLrot60[0] << 32);
            subkeys[17] = (KLrot60[1] >>> 32) | (KLrot60[1] << 32);

            long[] KRrot60 = ROT.ROTL64(KR1, KR2, 60);
            subkeys[18] = KRrot60[0];
            subkeys[19] = KRrot60[1];

            long[] KBrot60 = ROT.ROTL64(KB1, KB2, 60);
            subkeys[20] = KBrot60[0];
            subkeys[21] = KBrot60[1];

            long[] KLrot77 = ROT.ROTL64(KL1, KL2, 77);
            subkeys[22] = KLrot77[0];
            subkeys[23] = KLrot77[1];

            long[] KArot77 = ROT.ROTL64(KA1, KA2, 77);
            subkeys[24] = (KArot77[0] >>> 32) | (KArot77[0] << 32);
            subkeys[25] = (KArot77[1] >>> 32) | (KArot77[1] << 32);

            long[] KRrot94 = ROT.ROTL64(KR1, KR2, 94);
            subkeys[26] = KRrot94[0];
            subkeys[27] = KRrot94[1];

            long[] KArot94 = ROT.ROTL64(KA1, KA2, 94);
            subkeys[28] = KArot94[0];
            subkeys[29] = KArot94[1];

            long[] KLrot111 = ROT.ROTL64(KL1, KL2, 111);
            subkeys[30] = KLrot111[0];
            subkeys[31] = KLrot111[1];

            long[] KBrot111 = ROT.ROTL64(KB1, KB2, 111);
            subkeys[32] = KBrot111[0];
            subkeys[33] = KBrot111[1];
        }
    }

    private long F(long F_IN, long KE) {
        long x = F_IN ^ KE;

        int[] t = new int[9];
        for (int i = 1; i <= 8; i++) t[i] = (int) ((x >>> (64 - (i * 8))) & 0xFFL);

        t[1] = UnchangingData.CAMELLIA_SBOX1[t[1]];
        t[2] = UnchangingData.CAMELLIA_SBOX2[t[2]];
        t[3] = UnchangingData.CAMELLIA_SBOX3[t[3]];
        t[4] = UnchangingData.CAMELLIA_SBOX4[t[4]];
        t[5] = UnchangingData.CAMELLIA_SBOX2[t[5]];
        t[6] = UnchangingData.CAMELLIA_SBOX3[t[6]];
        t[7] = UnchangingData.CAMELLIA_SBOX4[t[7]];
        t[8] = UnchangingData.CAMELLIA_SBOX1[t[8]];

        int y1 = t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7] ^ t[8];
        int y2 = t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7] ^ t[8];
        int y3 = t[1] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[8];
        int y4 = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6] ^ t[7];
        int y5 = t[1] ^ t[2] ^ t[6] ^ t[7] ^ t[8];
        int y6 = t[2] ^ t[3] ^ t[5] ^ t[7] ^ t[8];
        int y7 = t[3] ^ t[4] ^ t[5] ^ t[6] ^ t[8];
        int y8 = t[1] ^ t[4] ^ t[5] ^ t[6] ^ t[7];

        return ((long) y1 << 56) | ((long) y2 << 48) | ((long) y3 << 40) | ((long) y4 << 32) |
                ((long) y5 << 24) | ((long) y6 << 16) | ((long) y7 << 8)  | (long) y8;
    }

    private long FL(long FL_IN, long KE) {
        long x1 = FL_IN >>> 32;
        long x2 = FL_IN & 0xFFFFFFFFL;
        long k1 = KE >>> 32;
        long k2 = KE & 0xFFFFFFFFL;

        long y2 = x2 ^ ROT.ROTL32((x1 & k1), 1);
        long y1 = x1 ^ (y2 | k2);

        return (y1 << 32) | (y2 & 0xFFFFFFFFL);
    }

    // <- im expert dev/programmer!
    private long FLINV(long FLINV_IN, long KE) {
        long y1 = FLINV_IN >>> 32;
        long y2 = FLINV_IN & 0xFFFFFFFFL;
        long k1 = KE >>> 32;
        long k2 = KE & 0xFFFFFFFFL;

        long x1 = y1 ^ (y2 | k2);
        long x2 = y2 ^ ROT.ROTL32((x1 & k1), 1);

        return (x1 << 32) | (x2 & 0xFFFFFFFFL);
    }

    private long bytes2Long(byte[] b, int off) {
        long res = 0;
        for (int i = 0; i < 8; i++) {
            int shift = 56 - (i * 8);
            res |= ((long) (b[off + i] & 0xFF) << shift);
        }
        return res;
    }

    private void long2Bytes(long v, byte[] b, int off) {
        for (int i = 0; i < 8; i++) {
            b[off + i] = (byte) (v >>> (56 - (i * 8)));
        }
    }
}
