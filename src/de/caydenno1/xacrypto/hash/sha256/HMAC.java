package de.caydenno1.xacrypto.hash.sha256;

import de.caydenno1.xacrypto.misc.XACryptoException;

import java.nio.charset.StandardCharsets;

import static de.caydenno1.xacrypto.hash.sha256.Hex.hash;

public class HMAC {
    private HMAC(){}

    public static byte[] hmac(byte[] key, byte[] mesg) throws XACryptoException {
        byte[] k = (key.length > 64) ? hash(key) : key;

        byte[] i = new byte[64];
        byte[] o = new byte[64];
        for (int l=0;l<64;l++) {
            byte k_ = (l < k.length) ? k[l] : 0;
            i[l] = (byte)(k_^0x36);
            o[l] = (byte)(k_^0x5c);
        }

        byte[] in = new Digest().upd(i).upd(mesg).digest();

        return new Digest().upd(o).upd(in).digest();
    }

    public static byte[] hmac(String key, String mesg) throws XACryptoException {
        return hmac(key.getBytes(StandardCharsets.UTF_8),
                mesg.getBytes(StandardCharsets.UTF_8));
    }
}
