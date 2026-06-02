package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GHASH;
import de.caydenno1.xacrypto.zekerrijndael.GCM.AES;
import de.caydenno1.xacrypto.zekerrijndael.GCM.Result;

import java.util.Objects;

import static de.caydenno1.xacrypto.misc.ToM.ToM;

interface AESCipher {
    Result encryptBlock(byte[] pln, byte[] key, byte[] nonce, byte[] aad) throws XACryptoException;

    byte[] decryptBlock(byte[] cip, byte[] key, byte[] nonce, byte[] aad, byte[] tag) throws XACryptoException;
}

public class AESGCM implements AESCipher {
    public Result encryptBlock(byte[] pln, byte[] key, byte[] nonce, byte[] aad) throws XACryptoException {
        System.out.println("WARNING! AESGCM may not be fully functional and partially broken. I am unsure if it fully works or not.");
        @SuppressWarnings("DuplicatedCode")
        byte[] zbyte = new byte[16];
        byte[] J0 = new byte[16];

        AES aes = new AES(key, getKeySize(key));
        @SuppressWarnings("DuplicatedCode")
        byte[] H = aes.encryptBlock(zbyte);
        GHASH gh = new GHASH(H);

        if (nonce.length == 12) {
            System.arraycopy(nonce, 0, J0, 0, 12);
            J0[15] = 1;
        } else {
           J0 = gh.compNonce(H, nonce);
        }

        byte[] cip = aes.encryptCTR(pln, J0);

        byte[] S = gh.compute(aad, cip);

        byte[] TB = aes.encryptBlock(J0);

        byte[] Tag = gh.xor(TB, S);

        return new Result(cip, Tag);
    }
    public byte[] decryptBlock(byte[] cip, byte[] key, byte[] nonce, byte[] aad, byte[] tag, String flag) throws XACryptoException {
        return decBack(cip, key, nonce, aad, tag, Objects.equals(flag, "-override"));
    }

    public byte[] decryptBlock(byte[] cip, byte[] key, byte[] nonce, byte[] aad, byte[] tag) throws XACryptoException {
        return decBack(cip, key, nonce, aad, tag, false);
    }

    private static int getKeySize(byte[] key) throws XACryptoException {
        return switch (key.length) {
            case 16 -> 128;
            case 24 -> 192;
            case 32 -> 256;
            default -> throw new XACryptoException(
                    "Invalid AES key length. Expected 16, 24, or 32 bytes."
            );
        };
    }
    private byte[] decBack(byte[] cip, byte[] key, byte[] nonce, byte[] aad, byte[] tag, boolean flag) throws XACryptoException {
        byte[] zbyte = new byte[16];
        byte[] J0 = new byte[16];
        @SuppressWarnings("DuplicatedCode")
        AES aes = new AES(key, getKeySize(key));
        byte[] H = aes.encryptBlock(zbyte);
        GHASH gh = new GHASH(H);

        if (nonce.length == 12) {
            System.arraycopy(nonce, 0, J0, 0, 12);
            J0[15] = 1;
        } else {
            J0 = gh.compNonce(H, nonce);
        }

        byte[] S = gh.compute(aad, cip);

        byte[] TB = aes.encryptBlock(J0);

        byte[] expectedTag = gh.xor(TB, S);

        if (!ToM(tag, expectedTag) && !flag) {
            throw new XACryptoException("Tag does not match. USE flag \"-override\" to ignore this.");
        } else if (!ToM(tag,expectedTag) && flag) {
            System.out.println("Continuing in insecure mode.");
        }

        return aes.encryptCTR(cip, J0);
    }
}