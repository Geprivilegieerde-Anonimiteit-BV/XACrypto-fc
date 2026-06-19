package de.caydenno1.xacrypto.zekerrijndael;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.*;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless;
import de.caydenno1.xacrypto.zekerrijndael.GCM.AES;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers.*;
import de.caydenno1.xacrypto.zekerrijndael.Global.Camellia;
import java.lang.reflect.InvocationTargetException;

public class Factories {
    public static class GCM {
        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM AES128(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new AES(key, 128)); }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM SM4GCM(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new SM4GCM(key)); }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM Camellia(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new Camellia(key)); }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM AESGCM() throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new AESGCM()); }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM ARIAGCM(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new ARIAGCM(key)); }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM SerpentGCM(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new SerpentGCM(key)); }
    }

    public static class ECB {
        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless Blowfish(byte[] key) throws XACryptoException { return new BlowfishECB(key); }

        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB Aria(byte[] key) throws XACryptoException { return new AriaECB(key); }

        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless SM4(byte[] key) throws XACryptoException { return new SM4ECB(key); }

        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB AES(byte[] key) throws XACryptoException { return new AESECB(key); }

        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB Twofish(byte[] key) throws XACryptoException { return new TwofishECB(key); }

        public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB RC6ECB(byte[] key) throws XACryptoException { return new RC6ECB(key); }

        //public static de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless CamelliaECB(byte[] key) throws XACryptoException { return new CamelliaECB(key); }
    }
}