package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.Global.Twofish;

public class TwofishGCM extends GCM {
    public TwofishGCM(byte[] key) throws XACryptoException {
        super(new Twofish(key));
    }
}
