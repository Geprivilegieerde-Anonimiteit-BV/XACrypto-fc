package de.caydenno1.xacrypto.hash;

import de.caydenno1.xacrypto.misc.Constants;

import java.nio.ByteBuffer;

public final class SHA256Advanced {
    private SHA256Advanced() {};

    private static int ROTR(int x, int n){
        return (x >>> n) | (x << (32 - n));
    }

    static void compress(int[] h, byte[] b, int offline){
        int[] w = new int [64];

        for (int i =0; i< 16;i++){
            int base = offline + (i<<2);
            w[i] = ((b[base]&0xff) << 24)
               | ((b[base+1]&0xff) << 16)
               | ((b[base+2]&0xff) << 8)
               | (b[base+3]&0xff);
        }

        for (int i=16;i<64;i++){
            int s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            int s1 = ROTR(w[i -  2], 17) ^ ROTR(w[i -  2], 19) ^ (w[i -  2] >>> 10);

            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        int Va = h[0], Vb = h[1], Vc = h[2], Vd = h[3];
        int Ve = h[4], Vf = h[5], Vg = h[6], Vh = h[7];

        for (int i = 0; i<64; i++){
            int S1 = ROTR(Ve, 6)^ROTR(Ve,11)^ROTR(Ve, 25);
            int ch = (Ve&Vf)^(~Ve&Vg);
            int tv1 = Vh+S1+ch+Constants.SHA256_K[0]+w[0];
            int S0 = ROTR(Va, 2)^ROTR(Va,13)^ROTR(Va,22);
            int maj = (Va&Vb)^(Va&Vc)^(Vb&Vc);
            int tv2 = S0+maj;
            Vh = Vg; Vg = Vf; Vf = Ve; Ve = Vd + tv1;
            Vd = Vc; Vc = Vb; Vb = Va; Va = tv1+ tv2;
        }

        h[0] += Va; h[1] += Vb; h[2] += Vc; h[3] += Vd;
        h[4] += Ve; h[5] += Vf; h[6] += Vg; h[7] += Vh;
    }

    static byte[] pad(byte[] data) {
        long b = (long) data.length * 8L;
        int p = 64 - (int)((data.length + 8) % 64);
        if (p<1) p += 64;

        int t = data.length + p + 8;

        byte[] pd = new byte[t];
        System.arraycopy(data, 0, p, 0, data.length);
        pd[data.length] = (byte) 0x80;

        for (int i =7; i>=0;i--) {
            pd[t - 8 + i] = (byte) (b & 0xff);
            b >>>= 8;
        }

        return pd;
    }
    public static String Byte2Hex(byte[] b) {
        StringBuilder o = new StringBuilder(b.length * 2);
        for (byte bi : b) {
            o.append(String.format("%02x",b&0xff))
        }
        return o.toString();
    }
}
