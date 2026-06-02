package de.caydenno1.xacrypto.zekerrijndael.Global;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.UnchangingData;

public class Aria {
    // this is NOT a cipher, more or less and encryption type/method
    private final int round;
    private final byte[][] encRK;
    private final byte[][] decRK;

    public Aria(boolean enc, byte[] key) throws XACryptoException {
        int kb = key.length * 8;
        round = switch(kb) {
            case 128 -> 12;
            case 192 -> 14;
            case 256 -> 16;
            default -> throw new XACryptoException(
                    "only 128, 192 and 256 bit ciphers are supported atm. sorry :%"
            );
        };

        encRK = new byte[round + 1][16];
        decRK = new byte[round + 1][16];

        encRK(key);
        SDK();
    }

    public byte[] encryptBlock(byte[] in) throws XACryptoException{
        if (in.length != 16) throw new XACryptoException("input length is required to be 16 bytes", (byte)0x16);

        byte[] currentState = new byte[16];
        System.arraycopy(in, 0, currentState, 0, 16);

        procRound(currentState, this.encRK);

        return currentState;
    }

    public byte[] decryptBlock(byte[] in) throws XACryptoException {
        if (in.length != 16) throw new XACryptoException("input length is required to be 16 bytes", (byte)0x16);

        byte[] state = new byte[16];
        System.arraycopy(in,0,state,0,16);

        procRound(state, this.decRK);

        return state;
    }

    private void SDK() {
       System.arraycopy(encRK[0], 0, decRK[round], 0, 16);
       System.arraycopy(encRK[round], 0, decRK[0], 0, 16);

       byte[] _0 = new byte[16];
       for (int i = 1 ; i < round ; i++){
           A(encRK[i], _0);
           System.arraycopy(_0, 0, decRK[round-i], 0, 16);
       }
    }
    private void procRound(byte[] state, byte[][] rK){
        byte[] _0 = new byte[16];

        for (int r = 0 ; r < round - 1 ; r++){
            AriaXOR(state,rK[r]);
            if (r % 2 == 0) {
                SL1(state, _0);
            } else {
                SL2(state, _0);
            }
            A(_0, state);
        }

        AriaXOR(state, rK[round-1]);
        if((round-1) % 2 == 0) {
            SL1(state, _0);
        } else {
            SL2(state, _0);
        }

        AriaXOR(_0, rK[round], state);
    }

    private void AriaXOR(byte[] blk, byte[] key){
        for (int i = 0 ; i < 16 ; i++){
            blk[i] ^= key[i];
        }
    }

    private void AriaXOR(byte[] a, byte[] b, byte[] o) {
        for (int i = 0 ; i < 16 ; i++) {
            o[i] = (byte)(a[i] ^ b[i]);
        }
    }

    public void SROTR128(byte[] i, int bits, byte[] o) {
        int byS = bits / 8;
        int biS = bits % 8;

        for (int _0 = 0 ; _0 < 16 ; _0++){
            int idx1 = (_0 - byS + 32) % 16;
            int idx2 = (_0 - byS - 1 + 32) % 16;

            int b1 = i[idx1] & 0xFF;
            int b2 = i[idx2] & 0xFF;

            o[_0] = (byte) ((b1 >>> biS) | (b2 << (8 - biS)));
        }
    }
    // feistel odd
    private void FO(byte[] i, byte[] ck, byte[] o) {
        byte[] _0 = new byte[16];
        AriaXOR(i, ck, _0);
        SL1(_0, _0);
        A(_0, o);
    }
    //feistel even
    private void FE(byte[] i, byte[] ck, byte[] o) {
        byte[] _0 = new byte[16];
        AriaXOR(i, ck, _0);
        SL2(_0, _0);
        A(_0, o);
    }

    private void SL1(byte[] i,byte[] o){
        byte[][] tables = {
                UnchangingData.ARIA_SB1,
                UnchangingData.ARIA_SB2,
                UnchangingData.ARIA_XB1,
                UnchangingData.ARIA_XB2
        };

        for (int k = 0; k < 16; k++) {
            o[k] = tables[k & 3][i[k] & 0xff];
        }

    }

    private void encRK(byte[] key) throws XACryptoException {
        int size = key.length;

        byte[] KL = new byte[16];
        byte[] KR = new byte[16];
        byte[][] CK = new byte[4][16];

        if (size == 16 || size == 24 || size == 32) System.arraycopy(key,0,KL,0,16);
        switch(size) {
            case 16: CK[1]=UnchangingData.ARIA_C1;CK[2]=UnchangingData.ARIA_C2;CK[3]=UnchangingData.ARIA_C3; break;

            case 24: {
                System.arraycopy(key, 16, KR, 0, 8);
                CK[1] = UnchangingData.ARIA_C2; CK[2] = UnchangingData.ARIA_C3; CK[3] = UnchangingData.ARIA_C1;
                break;
            }

            case 32: {
                System.arraycopy(key,16,KR,0,16);
                CK[1] = UnchangingData.ARIA_C3; CK[2] = UnchangingData.ARIA_C1 ; CK[3] = UnchangingData.ARIA_C2;
                break;
            }

            default: throw new XACryptoException("only keysizes of 16,24,32 are supported atm :|");
        }

        byte[][] W = new byte[4][16];

        System.arraycopy(KL, 0, W[0], 0, 16);

        FO(W[0], CK[1], W[1]);
        AriaXOR(W[1], KR, W[1]);               // W1 = FO(W0, CK1) ^ KR

        FE(W[1], CK[2], W[2]);
        AriaXOR(W[2], W[0], W[2]);               // W2 = FE(W1, CK2) ^ W0

        FO(W[2], CK[3], W[3]);
        AriaXOR(W[3], W[1], W[3]);

        byte[] _0 = new byte[16];

        SROTR128(W[1], 19, _0);
        AriaXOR(W[0], _0, encRK[0]);

        SROTR128(W[2], 19, _0);
        AriaXOR(W[1], _0, encRK[1]);

        SROTR128(W[3], 19, _0);
        AriaXOR(W[2], _0, encRK[2]);

        SROTR128(W[0], 19, _0);
        AriaXOR(_0, W[3], encRK[3]);

        SROTR128(W[1], 31, _0);
        AriaXOR(W[0], _0, encRK[4]);

        SROTR128(W[2], 31, _0);
        AriaXOR(W[1], _0, encRK[5]);

        SROTR128(W[3], 31, _0);
        AriaXOR(W[2], _0, encRK[6]);

        SROTR128(W[0], 31, _0);
        AriaXOR(_0, W[3], encRK[7]);

        SROTR128(W[1], 128 - 61, _0);
        AriaXOR(W[0], _0, encRK[8]);

        SROTR128(W[2], 128 - 61, _0);
        AriaXOR(W[1], _0, encRK[9]);

        SROTR128(W[3], 128 - 61, _0);
        AriaXOR(W[2], _0, encRK[10]);

        SROTR128(W[0], 128 - 61, _0);
        AriaXOR(_0, W[3], encRK[11]);

        SROTR128(W[1], 128 - 31, _0);
        AriaXOR(W[0], _0, encRK[12]);

        if (round >= 14) {
            SROTR128(W[2], 128 - 31, _0);
            AriaXOR(W[1], _0, encRK[13]);

            // ek15 = W2 ^ (W3 <<< 31)
            SROTR128(W[3], 128 - 31, _0);
            AriaXOR(W[2], _0, encRK[14]);
        }

        if (round == 16) {
            SROTR128(W[0], 128 - 31, _0);
            AriaXOR(_0, W[3], encRK[15]);

            SROTR128(W[1], 128 - 19, _0);
            AriaXOR(W[0], _0, encRK[16]);
        }
    }

    private void SL2(byte[] i,byte[] o){
        byte[][] tables = {
                UnchangingData.ARIA_XB1,
                UnchangingData.ARIA_XB2,
                UnchangingData.ARIA_SB1,
                UnchangingData.ARIA_SB2
        };

        for (int k = 0; k < 16; k++) {
            o[k] = tables[k & 3][i[k] & 0xff];
        }

    }
    private void A(byte[] i, byte[] o) {
        // "diffusion layer" Matrix A
        o[0]  = (byte)(i[3] ^ i[4] ^ i[9] ^ i[14]);
        o[1]  = (byte)(i[2] ^ i[5] ^ i[8] ^ i[15]);
        o[2]  = (byte)(i[1] ^ i[6] ^ i[11] ^ i[12]);
        o[3]  = (byte)(i[0] ^ i[7] ^ i[10] ^ i[13]);
        o[4]  = (byte)(i[0] ^ i[5] ^ i[11] ^ i[14]);
        o[5]  = (byte)(i[1] ^ i[4] ^ i[10] ^ i[15]);
        o[6]  = (byte)(i[2] ^ i[7] ^ i[9] ^ i[12]);
        o[7]  = (byte)(i[3] ^ i[6] ^ i[8] ^ i[13]);
        o[8]  = (byte)(i[1] ^ i[7] ^ i[11] ^ i[13]);
        o[9]  = (byte)(i[0] ^ i[6] ^ i[10] ^ i[12]);
        o[10] = (byte)(i[3] ^ i[5] ^ i[9] ^ i[15]);
        o[11] = (byte)(i[2] ^ i[4] ^ i[8] ^ i[14]);
        o[12] = (byte)(i[2] ^ i[6] ^ i[9] ^ i[14]);
        o[13] = (byte)(i[3] ^ i[7] ^ i[8] ^ i[15]);
        o[14] = (byte)(i[0] ^ i[4] ^ i[11] ^ i[12]);
        o[15] = (byte)(i[1] ^ i[5] ^ i[10] ^ i[13]);
    }
}
