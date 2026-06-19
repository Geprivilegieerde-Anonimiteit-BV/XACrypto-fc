package de.caydenno1.xacrypto.hash.sha384;

import java.util.Arrays;

import static de.caydenno1.xacrypto.misc.Constants.SHA384_H0;
import static de.caydenno1.xacrypto.misc.Constants.SHA384_K;
import static de.caydenno1.xacrypto.hash.ROT.ROTR64;
import static de.caydenno1.xacrypto.hash.sha256.Hex.Byte2Hex;

public class SHA384 {
    // digest
    // pad
    public static byte[] digest(byte[] mesg) {
      long[] h = Arrays.copyOf(SHA384_H0, SHA384_H0.length);
      byte[] pd = pad(mesg);

      int c = pd.length / 128;

      long[] w = new long[80];

      for (int blk = 0 ; blk < c ; blk++) {
          int base = blk * 128;

          for (int t = 0 ; t < 16 ; t++) w[t] = BYTE2LONG(pd, base + t * 8);

          for (int t = 16 ; t < 80 ; t ++) {
              long s0 = ROTR64(w[t - 15], 1)
                       ^ ROTR64(w[t - 15], 8)
                       ^ (w[t - 15] >>> 7);
              long s1 = ROTR64(w[t - 2], 19)
                       ^ ROTR64(w[t - 2], 61)
                       ^ w[t - 2] >>> 6;
               w[t] = w[t - 16] + s0 + w[t - 7] + s1;
          }

          // a = h[0]
          // b = h[1]
          // c = h[2]
          // d = h[3]
          // e = h[4]
          // f = h[5]
          // g = h[6]
          // h = h[7]

          long[] h0 = Arrays.copyOf(h, h.length);

          for (int t = 0 ; t < 80 ; t++) {
              long S1 = ROTR64(h[4], 14)
                       ^ ROTR64(h[4], 18)
                       ^ ROTR64(h[4], 41);
              long ch = (h[4] & h[5]) ^ (~h[4] & h[6]);
              long _0 = h[7] + S1 + ch + SHA384_K[t] + w[t];

              long S0 = ROTR64(h[0], 28)
                       ^ ROTR64(h[0], 34)
                       ^ ROTR64(h[0], 39);

              long maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);

              long _1 = S0 + maj;

              h[7] = h[6];
              h[6] = h[5];
              h[5] = h[4];
              h[4] = h[3] + _0;
              h[3] = h[2];
              h[2] = h[1];
              h[1] = h[0];
              h[0] = _0 + _1;
          }

          for (int i = 0 ; i < 8 ; i++) h[i] += h0[i];
      }

      byte[] res = new byte[48];
      for (int i = 0 ; i < 6 ; i++) LONG2BYTE(h[i], res, i*8);

      return res;
    };

    public static byte[] pad(byte[] mesg) {
        long MLB = (long) mesg.length * 8L;

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
        LONG2BYTE(MLB, pd, off + 8);

        return pd;
    }

    private static long BYTE2LONG(byte[] bytes, int off) {
        long res = 0;
        for (int i = 0 ; i < 8 ; i++) res = (res << 8) | (bytes[off + i] & 0xFFL);
        return res;
    }

    private static void LONG2BYTE(long val, byte[] bytes, int off) {
        for (int i = 7 ; i >= 0 ; i--) {
            bytes[off + i] = (byte) (val & 0xFF);
            val >>>= 8;
        }
    }
}
