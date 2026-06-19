package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces;

import de.caydenno1.xacrypto.misc.XACryptoException;

public interface ECB {
    public byte[] encrypt(byte[] pln) throws XACryptoException;
    public byte[] decrypt(byte[] cip) throws XACryptoException;
}

