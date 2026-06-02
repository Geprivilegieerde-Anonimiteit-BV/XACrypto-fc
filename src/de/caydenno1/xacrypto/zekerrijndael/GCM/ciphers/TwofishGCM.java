package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.GCM.Twofish;

import java.lang.reflect.InvocationTargetException;

public class TwofishGCM extends GCM {
    public TwofishGCM(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException {
        super(new Twofish(key));
    }
}
