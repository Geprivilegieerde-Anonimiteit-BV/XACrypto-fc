package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.Global.Serpent;

public class SerpentGCM extends GCM {
    public SerpentGCM(byte[] key) throws XACryptoException { super(new Serpent(key)); }
}
