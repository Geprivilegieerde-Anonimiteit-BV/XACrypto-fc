package de.caydenno1.xacrypto.zekerrijndael.GCM;

import de.caydenno1.xacrypto.misc.XACryptoException;

public interface BlockCipher {
    byte[] encryptBlock(byte[] pln) throws XACryptoException;
}