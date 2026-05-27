package de.caydenno1.xacrypto.hash.sha256;

import de.caydenno1.xacrypto.misc.XACryptoException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static de.caydenno1.xacrypto.hash.sha256.HMAC.*;
import static de.caydenno1.xacrypto.hash.sha256.SHA256.*;

public class HKDF {
    private HKDF(){}

    public static byte[] extract(byte[] salt, byte[] ikm) throws XACryptoException {
        byte[] effectivity = (salt == null || salt.length == 0) ? new byte[32] : salt;
        return hmac(effectivity, ikm);
    }

    public static byte[] expand(byte[] prk, byte[] inf, int len) throws XACryptoException {
        if (len <= 0 || len > 255 * 64) throw new XACryptoException(new String[]{"prk=" + java.util.Arrays.toString(prk), "inf=" + java.util.Arrays.toString(inf), "len=" + String.valueOf(len)}, (byte) 0);
        int n = (len + 32 - 1) / 32;
        byte[] okm = new byte[n*32];
        byte[] t = new byte[0];

        for (int i=1;i<=n;i++){
            byte[] in = new byte[t.length + inf.length + 1];
            System.arraycopy(t, 0, in, 0, t.length);
            System.arraycopy(inf, 0, in, t.length, inf.length);
            in[t.length+inf.length] = (byte) i;
            t = hmac(prk,in);
            System.arraycopy(t,0,okm,(i-1) * 32, 32);
        }

        return Arrays.copyOf(okm,len);
    }

    public static byte[] hkdf(byte[] ikm, byte[] sal, byte[] inf, int len) throws XACryptoException {
        byte[] prk = extract(sal, ikm);
        return expand(prk, inf, len);
    }

    public static byte[] pbkdf2(byte[] pass, byte[] sal, int it, int dk) throws XACryptoException {
        if (it<1) throw new XACryptoException("interations too low. given:".concat(" ").concat(String.valueOf(it)));
        int blk = (dk + 32 - 1) / 32;
        byte[] d = new byte[blk * 32];

        for (int i = 1; i<=blk; i++) {
            byte[] II = { (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte) i };
            byte[] SI = conc(sal, II);

            byte[] u = hmac(pass, SI);
            byte[] f = u.clone();

            for (int j = 1; j<it; j++) {
                u=hmac(pass,u);
                xor(f,u);
            }
            System.arraycopy(f,0,d, (i-1) * 32, 32);
        }
        return Arrays.copyOf(d,dk);
    }

    public static byte[] pbkdf2(String pass, byte[] sal, int it, int dk) throws XACryptoException {
        return pbkdf2(pass.getBytes(StandardCharsets.UTF_8), sal, it, dk);
    }
}
