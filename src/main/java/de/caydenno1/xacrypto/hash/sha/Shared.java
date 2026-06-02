package de.caydenno1.xacrypto.hash.sha;

public class Shared {
    public static byte[] INT2BYTE(int a,int b,int c,int d,int e) {
        byte[] out = new byte[20];
        write(a, out, 0);
        write(b, out, 4);
        write(c, out, 8);
        write(d, out, 12);
        write(e, out, 16);
        return out;
    }

    public static void write(int v, byte[] o, int i) {
        o[i  ] = (byte)(v >>> 24);
        o[i+1] = (byte)(v >>> 16);
        o[i+2] = (byte)(v >>>  8);
        o[i+3] = (byte)(v       );
    }

    public static byte[] pad(byte[] mesg) {
        int len = mesg.length;
        long bit = (long) len * 8;

        int padL = (64 - ((len + 9) % 64)) % 64;
        byte[] o = new byte[len+padL+9];

        System.arraycopy(mesg,0,o,0,len);
        o[len] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            o[o.length - (i+1)] = (byte) (bit >>> (8*i));
        }

        return o;
    }

    public static String hex(byte[] data) {
        StringBuilder builder = new StringBuilder();
        for (byte b : data) builder.append(String.format("%02x", b));
        return builder.toString();
    }
}
