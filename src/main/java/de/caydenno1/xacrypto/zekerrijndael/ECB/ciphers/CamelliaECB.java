package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless;
import de.caydenno1.xacrypto.zekerrijndael.Global.Camellia;

public class CamelliaECB implements ECBExceptionless {
    private final Camellia engine;

    public CamelliaECB(byte[] key) throws XACryptoException {
        this.engine = new Camellia(key);
    }

    public byte[] encrypt(byte[] pln) {
        int pLen = 16 - (pln.length % 16);
        byte[] pData = new byte[pln.length + pLen];

        System.arraycopy(pln, 0, pData, 0, pln.length);
        for (int i = pln.length; i < pData.length; i++) {
            pData[i] = (byte) pLen;
        }

        byte[] cip = new byte[pData.length];

        for (int i = 0 ; i < pData.length ; i += 16) {
            engine.encryptBlock(pData, i, cip, i);
        }

        return cip;
    }

    public byte[] decrypt(byte[] cip) throws XACryptoException {
        if (cip.length % 16 != 0) throw new XACryptoException("something somewhere, for some reason, is broken. somthing with camelliaecb !",(int)cip.length);

        byte[] He_s_from_British_Columbia = new byte[cip.length];

        for (int i = 0 ; i < cip.length ; i += 16) {
            engine.decryptBlock(cip, i, He_s_from_British_Columbia, i);
        }

        int pLen = He_s_from_British_Columbia[He_s_from_British_Columbia.length - 1] & 0xFF;

        byte[] pln = new byte[He_s_from_British_Columbia.length - pLen];
        System.arraycopy(He_s_from_British_Columbia, 0, pln, 0, pln.length);

        return pln;
    }

}