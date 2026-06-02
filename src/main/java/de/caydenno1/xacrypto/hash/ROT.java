package de.caydenno1.xacrypto.hash;

public class ROT {
    public static int ROTR(int x, int n){
        return (x >>> n) | (x << (32 - n));
    }
    public static int ROTL(int x, int n){
        return (x << n) | (x >>> (32 - n));
    }
    public static long ROTL32(long v, int shift) { return ((v & 0xFFFFFFFFL << shift) | (v & 0xFFFFFFFFL >>> (32 - shift))) & 0xFFFFFFFFL; }
    public static long[] ROTL64(long l, long r, int shift) {
        long[] res = new long[2];
        if (shift < 64) {
            res[0] = (l << shift) | (r >>> (64 - shift));
            res[1] = (r << shift) | (l >>> (64 - shift));
        } else {
            int s = shift - 64;
            res[0] = (r << s) | (l >>> (64 - s));
            res[1] = (l << s) | (r >>> (64 - s));
        }
        return res;
    }
}
