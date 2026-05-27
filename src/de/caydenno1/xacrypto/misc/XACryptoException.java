package de.caydenno1.xacrypto.misc;

import java.util.Arrays;

public class XACryptoException extends Exception {
    private int id = (int) 0x00;

    public XACryptoException(String res) {
        super(res);
    }
    public XACryptoException(byte id){
        super(String.format("0x%02X", id & 0xFF));
    }
    public XACryptoException(String res, byte id) {
        super(res);
        this.id = id & 0xFF;
    }
    public XACryptoException(String[] pnts, byte id){
        super(String.join("|", pnts));
        this.id = id & 0xFF;
    }
    public XACryptoException(String[] pnts, String other, byte id){
        String[] data = Arrays.copyOf(pnts, pnts.length+1);
        data[data.length - 1] = "REASON=".concat(other);
        super(String.join("|", data));
        this.id = id & 0xFF;
    }
}
