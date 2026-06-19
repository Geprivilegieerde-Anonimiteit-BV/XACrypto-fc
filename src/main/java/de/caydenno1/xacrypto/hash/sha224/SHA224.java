package de.caydenno1.xacrypto.hash.sha224;

import static de.caydenno1.xacrypto.hash.sha224.Helpers.ch;
import static de.caydenno1.xacrypto.hash.sha224.Helpers.maj;
import static de.caydenno1.xacrypto.hash.sha224.Helpers.bigSigma0;
import static de.caydenno1.xacrypto.hash.sha224.Helpers.bigSigma1;
import static de.caydenno1.xacrypto.hash.sha224.Helpers.smallSigma0;
import static de.caydenno1.xacrypto.hash.sha224.Helpers.smallSigma1;
import static de.caydenno1.xacrypto.misc.Constants.SHA224_H0;
import static de.caydenno1.xacrypto.misc.Constants.SHA224_K;

public class SHA224 {
    public static byte[] digest(byte[] message) {
        long bl = ((long) message.length) * 8L;

        int paddingLength = 64 - (int) ((message.length + 9) % 64);
        if (paddingLength == 64) paddingLength = 0;

        byte[] pd = new byte[message.length + 1 + paddingLength + 8];

        System.arraycopy(message, 0, pd, 0, message.length);

        pd[message.length] = (byte) 0x80;

        for (int i = 0 ; i < 8 ; i++) pd[pd.length - 1 - i] = (byte) (bl >>> (8 * i));

        int[] h = SHA224_H0.clone();
        int[] w = new int[64];

        for (int off = 0 ; off < pd.length ; off += 64) {
            for (int i = 0 ; i < 16 ; i++) {
                int pos = off + i * 4;

                w[i] = ((pd[pos] & 0xff) << 24) |
                       ((pd[pos + 1] & 0xff) << 16) |
                       ((pd[pos + 2] & 0xff) << 8) |
                       (pd[pos + 3] & 0xff);
            }

            for (int i = 16 ; i < 64 ; i++) {
                w[i] = smallSigma1(w[i - 2]) +
                                   w[i - 7]  +
                       smallSigma0(w[i - 15]) +
                                   w[i - 16];
            }

            int ha = h[0];
            int hb = h[1];
            int hc = h[2];
            int hd = h[3];
            int he = h[4];
            int hf = h[5];
            int hg = h[6];
            int hh = h[7];

            for (int i = 0 ; i < 64 ; i++) {
                int t1 = hh + bigSigma1(he) + ch(he, hf, hg) + SHA224_K[i] + w[i];
                int t2 = bigSigma0(ha) + maj(ha, hb, hc);

                hh = hg;
                hg = hf;
                hf = he;
                he = hd + t1;
                hd = hc;
                hc = hb;
                hb = ha;
                ha = t1 + t2;
            }


            h[0] += ha;
            h[1] += hb;
            h[2] += hc;
            h[3] += hd;
            h[4] += he;
            h[5] += hf;
            h[6] += hg;
            h[7] += hh;
        }

        byte[] res = new byte[28];
        for (int i = 0 ; i < 7 ; i++) for (int j = 0; j < 4; j++) res[i * 4 + j] = (byte) (h[i] >>> (24 - j * 8));

        return res;
    }
}
