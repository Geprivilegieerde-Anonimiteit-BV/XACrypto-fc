package de.caydenno1.xacrypto.zekerrijndael.GCM;

import de.caydenno1.xacrypto.zekerrijndael.UnchangingData;

import java.nio.ByteBuffer;
import java.util.Arrays;


public class GHASH {
    private final byte[] H;

    public GHASH(byte[] H) {
        this.H = Arrays.copyOf(H, 16);
    }

    public byte[] compute(byte[] aad, byte[] cip){
        byte[] Y = proc(new byte[16], aad);
        Y = proc(Y, cip);
        byte[] lenBlock = buildLenBlock(
                aad.length * 8L,
                cip.length * 8L
        );
        xor(Y, lenBlock);

        Y = multi(Y,H);
        return Y;
    }
    private byte[] proc(byte[] Y, byte[] in) {
        byte[] bloc = new byte[16];
        for (int off = 0; off < in.length; off+=16){
            int len = Math.min(16, in.length - off);
            System.arraycopy(in, off, bloc, 0, len);
            xor(Y, bloc);
            Y = multi(Y, H);
        }
        return Y;
    }
    private byte[] multi(byte[] X, byte[] Y) {
        byte[] Z = new byte[16];
        byte[] V = Arrays.copyOf(Y, 16);
        for (int bit = 0 ; bit < 128 ; bit++) {
            int byindex = bit / 8;
            int biindex = 7 - (bit%8);

            if (((X[byindex] >> biindex) & 1) == 1) xor(Z,V);

            boolean isLSB1 = (V[15] & 1) != 0;

            RS(V);

            if (isLSB1) xor(V,UnchangingData.R);
        }
        return Z;
    }
    private void RS(byte[] bloc) {
        int c = 0 ;
        for (int i = 0 ; i < 16 ; i++){
            int val = bloc[i] & 0xFF;
            int next = val & 1;
            bloc[i] = (byte) ((val >>> 1) | (c << 7));

            c = next;
        }
    }
    public byte[] compNonce(byte[] H, byte[] nonce){
        byte[] blk = new byte[16];

        int len = nonce.length;
        int off = 0;

        while (len > 0) {
            Arrays.fill(blk, (byte)0);

            int cl = Math.min(16, len);//count
            System.arraycopy(nonce, off, blk, 0, cl);

            multi(blk, H);

            off += cl;
            len -= cl;
        }

        Arrays.fill(blk, (byte)0);

        long bL = (long)nonce.length *8;

        for (int i = 8 ; i < 16 ; i++){
            blk[i] = (byte) ((bL >>> (8 * (15-i))) & 0xFF);
        }

        return multi(blk, H);
    }
    private byte[] buildLenBlock(long aad, long cipb) {
        ByteBuffer buf = ByteBuffer.allocate(16);

        buf.putLong(aad);
        buf.putLong(cipb);

        return buf.array();
    }
    public byte[] xor(byte[] a, byte[] b){
        for (int i = 0 ; i < 16 ; i++) a[i] ^= b[i];
        return a;
    }
}
