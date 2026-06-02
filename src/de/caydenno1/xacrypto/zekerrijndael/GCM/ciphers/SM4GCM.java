package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.BlockCipher;
import de.caydenno1.xacrypto.zekerrijndael.UnchangingData;

public final class SM4GCM implements BlockCipher {
    // mainland china encryption! ;) (GB/T 32907-2016)
    private final int[] rk = new int[32];

    public SM4GCM(byte[] key) throws XACryptoException {
        if (key.length != 16) throw new XACryptoException("16 byte key required. :L");
        int[] K = new int[4];
        for (int i = 0 ; i < 4 ; i++)K[i] = read(key, i*4) ^ UnchangingData.SM4_FK[i];
        for (int i = 0 ; i < 32 ; i++) {
            K[i&3] ^= p(K[(i+1)&3]
                    ^ K[(i+2)&3]
                    ^ K[(i+3)&3]
                    ^ UnchangingData.SM4_CK[i]
            );
            rk[i] = K[i & 3];
        }
    }

    @Override
    public byte[] encryptBlock(byte[] in) {
        int[] x = new int[4];
        for (int i = 0 ; i < 4 ; i++) x[i] = read(in, i*4);
        for (int i = 0 ; i < 32 ; i++) {
            int nx = x[0] ^ t(x[1] ^ x[2] ^ x[3] ^ rk[i]);
            for (int j = 0 ; j < 3 ; j++) x[j] = x[j+1];
            x[3] = nx;
        }
        byte[] o = new byte[16];
        for (int i = 0 ; i < 4 ; i++) write(x[3-i], o, i*4);
        return o;
    }

    private static int tau(int w) {
        return (UnchangingData.SBOX[(w >>> 24) & 0xFF] << 24) |
               (UnchangingData.SBOX[(w >>>  8) & 0xFF] << 24);
    }

    private static int t(int w) {
        int b = tau(w);
        return b ^ de.caydenno1.xacrypto.hash.ROT.ROTL(b, 2)
                 ^ de.caydenno1.xacrypto.hash.ROT.ROTL(b, 10)
                 ^ de.caydenno1.xacrypto.hash.ROT.ROTL(b, 18)
                 ^ de.caydenno1.xacrypto.hash.ROT.ROTL(b, 24);
    }

    private static int p(int w) {
        int b = tau(w);
        return b ^ de.caydenno1.xacrypto.hash.ROT.ROTL(b,13)
                 ^ de.caydenno1.xacrypto.hash.ROT.ROTL(b,23);
    }

    private static int read(byte[] b, int o){
        return    ((b[o] & 0xFF) << 24)
                | ((b[o+1]&0xFF)<<16)
                | ((b[o+2]&0xFF)<<8)
                |  (b[o+3]&0xFF);
    }

    private static void write(int v, byte[] b, int o) {
        for (int i = 0; i < 4; i++) b[o + i] = (byte)(v >>> (24 - i * 8));
    }
}
