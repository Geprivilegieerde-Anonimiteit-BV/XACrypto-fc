package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.Global.Aria;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.GCM.Result;

interface AriaCipher {
    Result encrypt(byte[] pln, byte[] aad, byte[] iv) throws XACryptoException;
    byte[] decrypt(Result res, byte[] aad) throws XACryptoException;
    byte[] decrypt(Result res, byte[] aad, String optflag) throws XACryptoException;
}

public class ARIAGCM implements AriaCipher {
    // comes from south korea (likely Seoul?)
    // i basically wrote the entire thing in Aria.java already lol. just inheriting it here
    private final GCM engine;

    public ARIAGCM(byte[] key) throws XACryptoException {
        Aria aria = new Aria(true, key);
        this.engine = new GCM(aria);
    }

    public Result encrypt(byte[] pln, byte[] aad, byte[] iv) throws XACryptoException {
        return engine.encrypt(pln, aad,iv);
    }

    public byte[] decrypt(Result res, byte[] aad) throws XACryptoException {
        return engine.decrypt(res, aad);
    }
    public byte[] decrypt(Result res, byte[] aad, String optflag) throws XACryptoException {
        return engine.decrypt(res, aad, optflag);
    }
}
