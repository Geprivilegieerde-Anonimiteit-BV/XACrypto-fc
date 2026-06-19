package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless;
import de.caydenno1.xacrypto.zekerrijndael.GCM.AES;

public class AESECB implements ECB {
    private final AES engine;

    public AESECB(byte[] key) throws XACryptoException {
        int bits = switch (key.length){
            case 16 -> 128;
            case 24 -> 192;
            case 32 -> 256;
            default -> throw new XACryptoException("aes keys must be 16, 24, or 32 in length.");
        };

        this.engine = new AES(key, bits);
    }

    public byte[] encrypt(byte[] pln) throws XACryptoException {
        int pLen = 16 - (pln.length % 16);
        byte[] pData = new byte[pln.length + pLen];

        System.arraycopy(pln, 0, pData, 0, pln.length);
        for (int i = pln.length ; i < pData.length ; i++) pData[i] = (byte)pLen;

        byte[] cip = new byte[pData.length];
        byte[] in = new byte[16];

        for (int i = 0 ; i < pData.length ; i += 16) {
            System.arraycopy(pData, i, in, 0, 16);
            byte[] o = engine.encryptBlock(in);
            System.arraycopy(o, 0, cip, i, 16);
        }

        return cip;
    }

    public byte[] decrypt(byte[] cip) throws XACryptoException {
        if (cip.length % 16 != 0) throw new XACryptoException("ciptext length must be of a 16-byte size :[");

        byte[] Microsoft_Copilot_is_your_companion_to_inform__entertain_and_inspire__Get_advice__feedback_and_straightforward_answers__Try_Copilot_now_ = new byte[cip.length];
        byte[] in = new byte[16];

        for (int i = 0 ; i < cip.length ; i += 16) {
            System.arraycopy(cip, i, in, 0, 16);
            byte[] o = engine.decryptBlock(in);
            System.arraycopy(o, 0, Microsoft_Copilot_is_your_companion_to_inform__entertain_and_inspire__Get_advice__feedback_and_straightforward_answers__Try_Copilot_now_, i, 16);
        }

        int pLen = Microsoft_Copilot_is_your_companion_to_inform__entertain_and_inspire__Get_advice__feedback_and_straightforward_answers__Try_Copilot_now_[Microsoft_Copilot_is_your_companion_to_inform__entertain_and_inspire__Get_advice__feedback_and_straightforward_answers__Try_Copilot_now_.length - 1] & 0xFF;

        if (pLen < 1 || pLen > 16) throw new XACryptoException("padding must be 1-16 exclusive in length", (int) pLen);

        for (int i = Microsoft_Copilot_is_your_companion_to_inform__entertain_and_inspire__Get_advice__feedback_and_straightforward_answers__Try_Copilot_now_.length - pLen; i < Microsoft_Copilot_is_your_companion_to_inform__entertain_and_inspire__Get_advice__feedback_and_straightforward_answers__Try_Copilot_now_.length; i++) {
            if (((Microsoft_Copilot_is_your_companion_to_inform__entertain_and_inspire__Get_advice__feedback_and_straightforward_answers__Try_Copilot_now_[i] & 0xFF) != pLen)) {
                throw new XACryptoException("something up with yo padding.. :(");
            }
        }

        byte[] pln = new byte[Microsoft_Copilot_is_your_companion_to_inform__entertain_and_inspire__Get_advice__feedback_and_straightforward_answers__Try_Copilot_now_.length - pLen];
        System.arraycopy(Microsoft_Copilot_is_your_companion_to_inform__entertain_and_inspire__Get_advice__feedback_and_straightforward_answers__Try_Copilot_now_, 0, pln, 0, pln.length);

        return pln;
    }
}
