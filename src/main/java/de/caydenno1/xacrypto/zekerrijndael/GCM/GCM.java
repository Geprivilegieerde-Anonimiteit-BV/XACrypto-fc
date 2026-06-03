package de.caydenno1.xacrypto.zekerrijndael.GCM;
import de.caydenno1.xacrypto.misc.ToM;
import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.misc.isNull;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Objects;

public class GCM {
    private final Object cip;
    private final GHASH gh;
    private final Method encryptor;

    public GCM(Object cip) throws XACryptoException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        this.cip = cip;
        this.encryptor = cip.getClass().getMethod("encryptBlock", byte[].class);

        byte[] H = (byte[]) this.encryptor.invoke(cip, (Object) new byte[16]);

        this.gh = new GHASH(H);
    }

    public Result encrypt(byte[] pln, byte[] aad, byte[] iv) throws XACryptoException, InvocationTargetException, IllegalAccessException {
      if (iv.length <= 0) throw new XACryptoException("iv does not have data or is corrupted :[");
      if (pln == null) pln = new byte[0];
      if (aad == null) aad = new byte[0];

      byte[] J0 = j0(iv);
      byte[] ct  = gctr(inc32(J0), pln);
      byte[] tag = tag(aad, ct, J0);

      byte[] packaged = new byte[iv.length+ct.length];
      System.arraycopy(iv,0,packaged,0,12);
      System.arraycopy(ct, 0, packaged, 12, ct.length);

      return new Result(packaged,tag);
    }
    
    public byte[] decrypt(Result res, byte[] aad) throws XACryptoException, InvocationTargetException, IllegalAccessException {
        return dec(res, aad, 12, false);
    }

    public byte[] decrypt(Result res, byte[] aad, String optflag) throws XACryptoException, InvocationTargetException, IllegalAccessException {
        return dec(res, aad, 12, Objects.equals(optflag, "-override"));
    }

    public byte[] decrypt(Result res, byte[] aad, int ivLen) throws XACryptoException, InvocationTargetException, IllegalAccessException {
        return dec(res, aad, ivLen, false);
    }

    public byte[] decrypt(Result res, byte[] aad, int ivLen, String optflag) throws XACryptoException, InvocationTargetException, IllegalAccessException {
        return dec(res, aad, ivLen, Objects.equals(optflag, "-override"));
    }

    private byte[] dec(Result res, byte[] aad, int ivLen, boolean override) throws XACryptoException, InvocationTargetException, IllegalAccessException {
        if (res.cip().length < 12) throw new XACryptoException("ciptext min len is 12 char");
        if (isNull.isNull(aad)) aad = new byte[0];

        byte[] iv = Arrays.copyOfRange(res.cip(), 0, 12);
        byte[] ct = Arrays.copyOfRange(res.cip(), 12, res.cip().length);

        byte[] J0 = j0(iv);
        byte[] expectedTag = tag(aad, ct, J0);

        boolean corr = ToM.ToM(res.tag(), expectedTag);

        if (!corr && !override) {
            throw new XACryptoException("GCM tag does not match. Use Flag -override to ignore this.",(byte)-1);
        } else if (!corr) {
            System.out.println("GCM tag does not match. Overriding...");
        }

        return gctr(inc32(J0), ct);
    }

    private byte[] j0(byte[] iv) {
        if (iv.length == 12) {
            byte[] J0 = new byte[16];
            System.arraycopy(iv, 0, J0, 0, 12);
            J0[15] = 0x01;
            return J0;
        } else {
            return gh.compute(new byte[0], iv);
        }
    }

    private byte[] tag(byte[] aad, byte[] ct, byte[] J0) throws InvocationTargetException, IllegalAccessException {
        byte[] S   = gh.compute(aad, ct);
        byte[] EJ0 = (byte[]) this.encryptor.invoke(J0);
        for (int i = 0; i < 16; i++) S[i] ^= EJ0[i];
        return S;
    }
    private byte[] gctr(byte[] icb, byte[] in) throws InvocationTargetException, IllegalAccessException {
        byte[] o = new byte[in.length];
        byte[] cnt = Arrays.copyOf(icb, 16);
        for (int i = 0 ; i < in.length ; i += 16){
            byte[] ks = (byte[]) this.encryptor.invoke(cnt);
            int len = Math.min(16, in.length -i);
            for (int j = 0; j < len; j++) o[i + j] = (byte)(in[i + j] ^ ks[j]);
            if (i+16<in.length) cnt = inc32(cnt);
        }
        return o;
    }
    private static byte[] inc32(byte[] b) {
        byte[] o = Arrays.copyOf(b,16);
        for (int i = 15; i >= 12; i--) if (++o[i] != 0) break;
        return o;
    }
}
