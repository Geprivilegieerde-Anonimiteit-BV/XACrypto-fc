package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.Global.Aria;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.GCM.Result;

import java.lang.reflect.InvocationTargetException;

interface AriaCipher {
    Result encrypt(byte[] pln, byte[] aad, byte[] iv) throws XACryptoException, InvocationTargetException, IllegalAccessException;
    byte[] decrypt(Result res, byte[] aad) throws XACryptoException, InvocationTargetException, IllegalAccessException;
    byte[] decrypt(Result res, byte[] aad, String optflag) throws XACryptoException, InvocationTargetException, IllegalAccessException;
}

public class ARIAGCM implements AriaCipher {
    // comes from south korea (likely Seoul?)
    // i basically wrote the entire thing in Aria.java already lol. just inheriting it here
    private final GCM engine;

    public ARIAGCM(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException {
        Aria aria = new Aria(true, key);
        this.engine = new GCM(aria);
    }

    public Result encrypt(byte[] pln, byte[] aad, byte[] iv) throws XACryptoException, InvocationTargetException, IllegalAccessException {
        return engine.encrypt(pln, aad,iv);
    }

    public byte[] decrypt(Result res, byte[] aad) throws XACryptoException, InvocationTargetException, IllegalAccessException {
        return engine.decrypt(res, aad);
    }
    public byte[] decrypt(Result res, byte[] aad, String optflag) throws XACryptoException, InvocationTargetException, IllegalAccessException {
        return engine.decrypt(res, aad, optflag);
    }
}