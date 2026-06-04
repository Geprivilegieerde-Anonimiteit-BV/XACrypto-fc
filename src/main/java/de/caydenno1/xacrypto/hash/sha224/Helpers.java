package de.caydenno1.xacrypto.hash.sha224;

import static de.caydenno1.xacrypto.hash.ROT.ROTR;

public class Helpers {
    public static int ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    public static int maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    public static int bigSigma0(int x) {
        return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    }

    public static int bigSigma1(int x) {
        return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    }

    public static int smallSigma0(int x) {
        return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >>> 3);
    }

    public static int smallSigma1(int x) {
        return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >>> 10);
    }
}
