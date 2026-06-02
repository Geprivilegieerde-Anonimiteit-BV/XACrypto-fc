package de.caydenno1.xacrypto.hash;

public class ROT {
    public static int ROTR(int x, int n){
        return (x >>> n) | (x << (32 - n));
    }
    public static int ROTL(int x, int n){
        return (x << n) | (x >>> (32 - n));
    }
}
