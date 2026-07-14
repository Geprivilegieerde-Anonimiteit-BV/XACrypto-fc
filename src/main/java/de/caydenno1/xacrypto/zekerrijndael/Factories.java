package de.caydenno1.xacrypto.zekerrijndael;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.*;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless;
import de.caydenno1.xacrypto.zekerrijndael.GCM.AES;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers.*;
import de.caydenno1.xacrypto.zekerrijndael.Global.Aria;
import de.caydenno1.xacrypto.zekerrijndael.Global.Camellia;

public class Factories {
    public static class GCM {
        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM AES128(byte[] key) throws XACryptoException { return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new AES(key, 128)); }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM SM4GCM(byte[] key) throws XACryptoException { return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new SM4GCM(key)); }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM Camellia(byte[] key) throws XACryptoException { return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new Camellia(key)); }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM ARIAGCM(byte[] key) throws XACryptoException { return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new Aria(true, key)); }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM SerpentGCM(byte[] key) throws XACryptoException { return new SerpentGCM(key); }
    }

    private static volatile boolean ecbOptIn = false;

    /**
     * Enables the use of ECB mode.
     *
     * <p><strong>Warning:</strong> ECB mode is insecure for
     * almost all applications because identical plaintext blocks
     * produce identical ciphertext blocks, leaking data patterns.
     *
     * <p>This method exists solely for backwards compatibility.
     * Prefer {@link Factories.GCM} or another secure encryption mode.
     * The contributor that has written this wishes to remain anonymous.
     */
    public static void allowInsecureECB() {
        ecbOptIn = true;
    }

    private static void checkECBenabled() throws XACryptoException {
        if (!ecbOptIn) {
        throw new XACryptoException(
            "ECB mode is not secure because it can leak data patterns. Call Factories.allowInsecureECB() before using ECB."
        );
        }
    }

/**
 * Provides ECB mode cipher factories.
 *
 * <p><strong>Warning:</strong> ECB mode is insecure because identical
 * plaintext blocks produce identical ciphertext blocks, leaking data patterns.
 *
 * <p>This class requires opt-in using
 * {@link Factories#allowInsecureECB()} and exists only for backwards compatibility.
 *
 * @deprecated Use GCM or another secure encryption mode instead.
 */
    @Deprecated
    public static class ECB {
        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless Blowfish(byte[] key) throws XACryptoException { checkECBenabled(); return new BlowfishECB(key); }

        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB Aria(byte[] key) throws XACryptoException { checkECBenabled(); return new AriaECB(key); }

        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless SM4(byte[] key) throws XACryptoException { checkECBenabled(); return new SM4ECB(key); }

        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB AES(byte[] key) throws XACryptoException { checkECBenabled(); return new AESECB(key); }

        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB Twofish(byte[] key) throws XACryptoException { checkECBenabled(); return new TwofishECB(key); }

        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB RC6ECB(byte[] key) throws XACryptoException { checkECBenabled(); return new RC6ECB(key); }

        //public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless CamelliaECB(byte[] key) throws XACryptoException { return new CamelliaECB(key); }
    }
}
