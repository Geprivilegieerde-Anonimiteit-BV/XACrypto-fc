package de.caydenno1.xacrypto.hash.sha256;

import de.caydenno1.xacrypto.misc.Constants;
import de.caydenno1.xacrypto.misc.XACryptoException;

import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveTask;

import static de.caydenno1.xacrypto.hash.sha256.Hex.hash;
import static de.caydenno1.xacrypto.hash.sha256.Hex.doubleHash;
public final class SHA256 {
    private SHA256(){}

    private static int ROTR(int x, int n){
        return (x >>> n) | (x << (32 - n));
    }
    public static void compress(int[] h, byte[] b, int offline){
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
            int tv1 = Vh+S1+ch+Constants.SHA256_K[i]+w[i];
            int S0 = ROTR(Va, 2)^ROTR(Va,13)^ROTR(Va,22);
            int maj = (Va&Vb)^(Va&Vc)^(Vb&Vc);
            int tv2 = S0+maj;
            Vh = Vg; Vg = Vf; Vf = Ve; Ve = Vd + tv1;
            Vd = Vc; Vc = Vb; Vb = Va; Va = tv1+ tv2;
        }

        h[0] += Va; h[1] += Vb; h[2] += Vc; h[3] += Vd;
        h[4] += Ve; h[5] += Vf; h[6] += Vg; h[7] += Vh;
    }
    @SuppressWarnings("ConstantValue")
    static byte[] pad(byte[] data) {
        long b = (long) data.length * 8L;
        int p = 64 - (int)((data.length + 8) % 64);
        if (p<1) p += 64;

        int t = data.length + p + 8;

        byte[] pd = new byte[t];
        System.arraycopy(data, 0, pd, 0, data.length);
        pd[data.length] = (byte) 0x80;

        for (int i =7; i>=0;i--) {
            pd[t - 8 + i] = (byte) (b & 0xff);
            b >>>= 8;
        }

        return pd;
    }



    public static byte[] Word2Byte(int[] w){
        byte[] o = new byte[w.length * 4];
        for (int i=0;i<w.length;i++) {
            o[i * 4]     = (byte)(w[i] >>> 24);
            o[i * 4 + 1] = (byte)(w[i] >>> 16);
            o[i * 4 + 2] = (byte)(w[i] >>>  8);
            o[i * 4 + 3] = (byte) w[i];
        }
        return o;
    }
    private static byte[] cc(byte[] a, byte[] b){
        byte[] o = new byte[a.length + b.length];
        System.arraycopy(a, 0, o, 0, a.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }

    public static boolean ToM(byte[] a, byte[] b) {
        if (a == null || b == null) return a == b;
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }

    public static final class HashTask extends RecursiveTask<byte[][]>{
        private final java.util.List<byte[]> leaves;
        private int from,to;
        private final boolean Double;

        HashTask(java.util.List<byte[]> leaves, int from, int to, boolean Double) {
            this.leaves   = leaves;
            this.from     = from;
            this.to       = to;
            this.Double = Double;
        }

        @Override
        protected byte[][] compute() {
            int len = this.to-this.from;
            if (len <= 128) {
                byte[][] res = new byte[len][];
                for (int i=0;i<len;i++){
                    try {
                        res[i] = Double ? doubleHash(leaves.get(from + i))
                                : hash(leaves.get(from + i));
                    } catch (XACryptoException e) {};
                }
                return res;
            }
            int m = from + len/2;
            HashTask l = new HashTask(leaves,from,m,Double);
            HashTask r = new HashTask(leaves,m,to,Double);
            l.fork();
            byte[][] br = r.compute();
            byte[][] bl = l.join();
            byte[][] mergd = new byte[br.length+bl.length][];
            System.arraycopy(bl,0,mergd,0,bl.length);
            System.arraycopy(br,0,mergd,bl.length,br.length);
            return mergd;
        }
    }

    public static byte[] merkRoot(java.util.List<byte[]> leaves) throws XACryptoException {
        if (leaves.isEmpty()) throw new XACryptoException("leaves List is empty!");

        byte[][] lvl = ForkJoinPool.commonPool().invoke(new HashTask(leaves, 0, leaves.size(), false));
        return mergeUp(lvl, (int)1);
    };

    public static byte[] merkRootDuo(java.util.List<byte[]> leaves) throws XACryptoException {
        if (leaves.isEmpty()) throw new XACryptoException("leaves List is empty!");

        byte[][] lvl = ForkJoinPool.commonPool().invoke(new HashTask(leaves, 0, leaves.size(), false));
        return mergeUp(lvl, (int)2);
    };

    private static byte[] mergeUp(byte[][] lvl, int ext) throws XACryptoException {
        while (lvl.length > 1) {
            int nx = (lvl.length + 1) / 2;
            byte[][] up = new byte[nx][];
            for (int i = 0; i < lvl.length - 1; i += 2) {
                up[i / 2] = (ext == 1)
                        ? hash(conc(lvl[i], lvl[i + 1]))
                        : doubleHash(conc(lvl[i], lvl[i + 1]));
            }
            if (lvl.length % 2 == 1) up[nx-1] = lvl[lvl.length - 1];
        }
        return lvl[0];
    }

    static byte[] conc(byte[] a, byte[] b) {
        byte[] out = new byte[a.length+b.length];
        System.arraycopy(a,0,out,0,a.length);
        System.arraycopy(b,0,out,a.length,b.length);
        return out;
    }

    public static byte[] tagHash(String tag, byte[] dat) throws XACryptoException {
        byte[] hasdat = hash(tag.getBytes());
        byte[] load = new byte[hasdat.length * 2 + dat.length];
        System.arraycopy(hasdat, 0, load, 0, hasdat.length);
        System.arraycopy(hasdat, 0, load, hasdat.length, hasdat.length);
        System.arraycopy(dat,    0, load, hasdat.length * 2, dat.length);
        return hash(load);
    }

    static void xor(byte[] dest, byte[] src) {
        for(int i=0;i<dest.length;i++)dest[i]^=src[i];
    }

    public static byte[] ByteFromHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i=0;i<out.length;i++) {
            out[i] = (byte)((Character.digit(hex.charAt(i * 2),16) << 4)|Character.digit(hex.charAt(i * 2 + 1), 16));
        }
        return out;
    }
}
