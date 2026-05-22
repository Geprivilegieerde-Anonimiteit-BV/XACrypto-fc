package main.java.de.caydenno1.xacrypto.encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AES_GCM {
    private static final String AES = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";

    private AES_GCM() {}

    public static SecretKey genKey(int bits) throws Exception {
        KeyGenerator g = KeyGenerator.getInstance(AES);
        g.init(bits);

        return g.generateKey();
    }

    public static String encrypt(String pln, SecretKey k, int TAG, int IV) throws Exception {
        byte[] iv = new byte[IV];
        new SecureRandom().nextBytes(iv);

        Cipher c  = Cipher.getInstance(AES_GCM);
        c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(TAG, iv));

        byte[] citext = c.doFinal(pln.getBytes());

        byte[] comb = new byte[iv.length + citext.length];
        System.arraycopy(iv, 0, comb, 0, iv.length);
        System.arraycopy(citext, 0, comb, iv.length, citext.length);

        return Base64.getEncoder().encodeToString(comb);
    }

    public static String decrypt(String enc, SecretKey k, int TAG, int IV) throws Exception {
        byte[] dat = Base64.getDecoder().decode(enc);

        byte[] iv = new byte[IV];
        byte[] cit = new byte[dat.length - IV];

        System.arraycopy(dat, 0, iv, 0, IV);
        System.arraycopy(dat, IV, cit, 0, cit.length);

        Cipher ci = Cipher.getInstance(AES_GCM);
        ci.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(TAG, iv));
        return new String(ci.doFinal(cit));
    }
}
