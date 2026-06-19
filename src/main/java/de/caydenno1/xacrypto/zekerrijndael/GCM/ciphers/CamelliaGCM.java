package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.Global.Camellia;

import java.lang.reflect.InvocationTargetException;

public class CamelliaGCM extends GCM {
    public CamelliaGCM(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException {
        super(new Camellia(key));
    }
}
