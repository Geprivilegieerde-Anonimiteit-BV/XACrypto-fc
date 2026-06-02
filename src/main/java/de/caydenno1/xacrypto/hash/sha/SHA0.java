package de.caydenno1.xacrypto.hash.sha;

import de.caydenno1.xacrypto.misc.Constants;

import java.nio.charset.StandardCharsets;

import static de.caydenno1.xacrypto.hash.sha.Shared.INT2BYTE;
import static de.caydenno1.xacrypto.hash.sha.Shared.hex;

public class SHA0 {
    // we really only need one file. very simple code
    public static byte[] hash(byte[] data){
        System.out.println("Beware, SHA0 is deprecated and cryptographically broken. Use at your own risk.");
        byte[] padded = Shared.pad(data);

        int a0 = Constants.SHA_H[0], a1 = Constants.SHA_H[1], a2 = Constants.SHA_H[2], a3 = Constants.SHA_H[3], a4 = Constants.SHA_H[4];

        int[] w = new int[80];

        for (int i = 0 ; i < padded.length ; i += 64) {

            for (int j = 0 ; j < 16 ; j++) {
                int o = i + j * 4;
                w[j] = ((padded[o] & 0xff) << 24)
                        | ((padded[o + 1] & 0xff) << 16)
                        | ((padded[o + 2] & 0xff) << 8)
                        | (padded[o + 3] & 0xff);
            }

            for (int t = 16; t < 80; t++) {
                w[t] = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16];
            }

            int a = a0, b = a1, c = a2, d = a3, e = a4;

            for (int t = 0 ; t < 80 ; t++) {
                int f, k;

                if (t < 20) {
                    f = (b & c);
                    k = Constants.SHA0_K[0];
                } else if (t < 40) {
                    f = b ^ c ^ d;
                    k = Constants.SHA0_K[1];
                } else if (t < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = Constants.SHA0_K[2];
                } else {
                    f = b ^ c ^ d;
                    k = Constants.SHA0_K[3];
                }

                int temp = de.caydenno1.xacrypto.hash.ROT.ROTL(a, 5);
                temp += f;
                temp += e;
                temp += k;
                temp += w[t];

                e = d;
                d = c;
                c = de.caydenno1.xacrypto.hash.ROT.ROTL(b, 30);
                b = a;
                a = temp;
            }

            a0 += a;
            a1 += b;
            a2 += c;
            a3 += d;
            a4 += e;
        }

        return INT2BYTE(a0, a1, a2, a3, a4);
    }
    public static String hash(String data) {
        byte[] result = hash(data.getBytes(StandardCharsets.UTF_8));
        return hex(result);
    }
}