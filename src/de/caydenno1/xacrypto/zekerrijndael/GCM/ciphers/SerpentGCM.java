package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.BlockCipher;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.GCM.Serpent;

import java.lang.reflect.InvocationTargetException;

import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.SERPENT_SBOX;

public class SerpentGCM extends GCM {
    public SerpentGCM(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { super(new Serpent(key)); }
}
