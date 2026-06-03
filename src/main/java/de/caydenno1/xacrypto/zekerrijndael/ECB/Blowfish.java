package de.caydenno1.xacrypto.zekerrijndael.ECB;

import de.caydenno1.xacrypto.misc.XACryptoException;

import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.BLOWFISH_IP;
import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.BLOWFISH_IS;

public class Blowfish {
    private final int[] P = new int[18];
    private final int[][] S = new int[4][256];
    public Blowfish(byte[] key) throws XACryptoException {
        if (key.length < 4 || key.length > 56) {
            throw new XACryptoException("blowfish keys must be between 4-56 bytes :&", (int) key.length);
        }
        initSubkey(key);
    }

    private void initSubkey(byte[] key) {
        System.arraycopy(BLOWFISH_IP, 0, this.P, 0, 18);
        for (int i = 0 ; i < 4 ; i++) for (int j = 0 ; j < Math.min(BLOWFISH_IS[i].length, 256) ; j++) this.S[i][j] = BLOWFISH_IS[i][j];

        int len = key.length;
        int idx = 0;
        for (int i = 0 ; i < 18 ; i++) {
            int _0 = 0;

            for (int j = 0 ; j < 4 ; j++) {
                _0 = (_0 << 8) | (key[idx] & 0xFF);
                idx = (idx + 1) % len;
            }
            P[i] ^= _0;
        }

        byte[] blk = new byte[8];
        for (int s = 0 ; s < 4 ; s++) {
            for (int i = 0 ; i < 18 ; i += 2){
                encryptBlock(blk, 0, blk, 0);
                S[s][i] = BYTE2INT(blk, 0);
                S[s][i + 1] = BYTE2INT(blk, 4);
            }
        }
    }
    public void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int xl = BYTE2INT(in, inOff);
        int xr = BYTE2INT(in, inOff + 4);

        for (int i = 0 ; i < 16 ; i++) {
            xl ^= P[i];
            xr ^= F(xl);

            int _0 = xl;
            xl = xr;
            xr = _0;
        }

        int _0 = xl;
        xl = xr;
        xr = _0;

        xl ^= P[16];
        xr ^= P[17];

        INT2BYTE(xl, out, outOff);
        INT2BYTE(xr, out, outOff + 4);
    }
    private int F(int x) {
        int a = (x >>> 24) & 0xFF;
        int b = (x >>> 16) & 0xFF;
        int c = (x >>> 8)  & 0xFF;
        int d =  x         & 0xFF;

        int val = (S[0][a] + S[1][b]) ^ S[2][c];
        return val + S[3][d];
    }
    public void decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int xl = BYTE2INT(in, inOff);
        int xr = BYTE2INT(in, inOff + 4);

        for (int i = 17 ; i > 1 ; i--) {
            xl ^= P[i];
            xr ^= F(xl);

            int _0 = xl;
            xl = xr;
            xr = _0;
        }

        int _0 = xl;
        xl = xr;
        xr = _0;

        xl ^= P[1];
        xr ^= P[0];

        INT2BYTE(xl, out, outOff);
        INT2BYTE(xr, out, outOff + 4);
    }
    private int BYTE2INT(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24) |
               ((b[off + 1] & 0xFF) << 16) |
               ((b[off + 2] & 0xFF) << 8) |
                (b[off + 3] & 0xFF);
    }
    private void INT2BYTE(int val, byte[] b, int off) {
        b[off] = (byte) (val >>> 24);
        b[off + 1] = (byte) (val >>> 16);
        b[off + 2] = (byte) (val >>> 8);
        b[off + 3] = (byte) val;
    }
}
