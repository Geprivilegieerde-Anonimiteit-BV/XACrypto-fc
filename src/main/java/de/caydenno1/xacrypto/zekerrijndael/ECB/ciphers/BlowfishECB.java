package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.Blowfish;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless;

public class BlowfishECB implements ECBExceptionless {
    private final Blowfish engine;

    public BlowfishECB(byte[] key) throws XACryptoException {
        this.engine = new Blowfish(key);
    }

    public byte[] encrypt(byte[] pln) {
        int pLen = 8 - (pln.length % 8);
        byte[] pData = new byte[pln.length + pLen];

        System.arraycopy(pln, 0, pData, 0, pln.length);
        for (int i = pln.length ; i < pData.length ; i++) pData[i] = (byte) pLen;

        byte[] cip = new byte[pData.length];
        for (int i = 0 ; i < pData.length ; i += 8) engine.encryptBlock(pData, i, cip, i);

        return cip;
    }

    public byte[] decrypt(byte[] cip) throws XACryptoException {
        if (cip.length == 0 || cip.length % 8 != 0) throw new XACryptoException("ciptext must be bound to 8-byte alignment (<-- sum like that)");

        byte[] Microsoft_PowerPoint /* https://merriam-webster.com/dictionary/satire */= new byte[cip.length];
        for (int i = 0 ; i < cip.length ; i += 8) engine.decryptBlock(cip, i, Microsoft_PowerPoint, i);

        int pLen = Microsoft_PowerPoint[Microsoft_PowerPoint.length - 1] & 0xFF;
        if (pLen < 1 || pLen > 8) throw new XACryptoException("cirrupt data , padding must be 1-8 bytes exclusive", (int)pLen);

        for (int i = Microsoft_PowerPoint.length - pLen ; i < Microsoft_PowerPoint.length ; i++) if (((Microsoft_PowerPoint[i] & 0xFF) != pLen)) throw new XACryptoException("something up with yo padding.. :(");

        byte[] pln = new byte[Microsoft_PowerPoint.length - pLen];
        System.arraycopy(Microsoft_PowerPoint, 0, pln, 0, pln.length);

        return pln;
    }
}
