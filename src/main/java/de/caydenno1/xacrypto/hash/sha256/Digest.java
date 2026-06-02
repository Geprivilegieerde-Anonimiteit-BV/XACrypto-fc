package de.caydenno1.xacrypto.hash.sha256;

import de.caydenno1.xacrypto.misc.Constants;
import de.caydenno1.xacrypto.misc.XACryptoException;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static de.caydenno1.xacrypto.hash.sha256.SHA256.Word2Byte;
import static de.caydenno1.xacrypto.hash.sha256.SHA256.compress;

public final class Digest {
    private final int[] s = Constants.SHA256_H.clone();
    private final byte[] buf = new byte[64];
    private int bufLen = 0;
    private long total = 0L;

    public Digest(){};

    public Digest upd(byte[] d) throws XACryptoException {
        return upd(d, 0, d.length);
    }

    /**
     * i have never used javadoc before ;-; just using google for javadoc format lol
     * @param d data
     * @param o Offset
     * @param l count
     * @return {@code this} end data after modification
     */
    public Digest upd(byte[] d, int o, int l) throws XACryptoException {
        if(o<0||l<0||o+l>d.length) throw new XACryptoException("take a look at your code :)");
        total += l;
        if (bufLen > 0) {
            int fil = Math.min(64 - bufLen, l);
            System.arraycopy(d,o,buf,bufLen,fil);
            bufLen += fil;o+=fil;l-=fil;
            if (bufLen == 64) { compress(s, buf, 0); bufLen=0; }
        }

        while(l >= 64){
            compress(s,d,o);
            o += 64;
            l -= 64;
        };
        // save whats remaining i suppose..
        if (l>0) {
            System.arraycopy(d, o, buf, 0, l);
            bufLen = l;
        };
        return this; // we returned "this" !1
    }
    public Digest upd(String text) throws XACryptoException { return upd(text.getBytes(StandardCharsets.UTF_8) );};

    public Digest upd(ByteBuffer buf) throws XACryptoException {
        if (buf.hasArray()) { return upd(buf.array(), buf.arrayOffset() + buf.position(), buf.remaining()); }
        byte[] temp = new byte[buf.remaining()];
        buf.get(temp);
        return upd(temp);
    };

    @SuppressWarnings("ConstantValue")
    public byte[] digest() {
        byte[] t = new byte[bufLen];
        System.arraycopy(buf,0,t,0,bufLen);
        long bit = total * 8L;
        int pad = 64 - (int)((bufLen+1+8) % 64)%64;
        if (pad<0) pad += 64;
        int total = bufLen + 1 + pad + 8;

        byte[] last = new byte[total];
        System.arraycopy(t, 0, last, 0, bufLen);
        last[bufLen] = (byte) 0x80;
        for (int i = 7; i >= 0; i--) {
            last[total - 8 + i] = (byte) (bit & 0xff);
            bit >>>= 8;
        }

        int[] sa = s.clone();
        for (int off = 0; off < last.length; off += 64) { compress(sa, last, off); }
        byte[] o = Word2Byte(sa);
        reset();
        return o;
    }

    public void reset() {
        System.arraycopy(Constants.SHA256_H, 0, s, 0, 8);
        Arrays.fill(buf, (byte) 0);
        bufLen = 0;
        total = 0L;
    }

    public long get() {
        return total;
    }
}