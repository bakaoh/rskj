package org.ethereum.crypto.cryptohash;

/**
 * Created by bakaking on 25/10/2019.
 */
public class Blake2b {

    /**
     * IV is an initialization vector for BLAKE2b
     */
    private static final long[] IV = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L,
    };

    /**
     * the PRECOMPUTED values for BLAKE2b
     * there are 10 16-byte arrays - one for each round
     * the entries are calculated from the sigma constants.
     */
    private static final byte[][] PRECOMPUTED = {
            {0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15},
            {14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3},
            {11, 12, 5, 15, 8, 0, 2, 13, 10, 3, 7, 9, 14, 6, 1, 4},
            {7, 3, 13, 11, 9, 1, 12, 14, 2, 5, 4, 15, 6, 10, 0, 8},
            {9, 5, 2, 10, 0, 7, 4, 15, 14, 11, 6, 3, 1, 12, 8, 13},
            {2, 6, 0, 8, 12, 10, 11, 3, 4, 7, 15, 1, 13, 5, 14, 9},
            {12, 1, 14, 4, 5, 15, 13, 10, 0, 6, 9, 8, 7, 3, 2, 11},
            {13, 7, 12, 3, 11, 14, 1, 9, 5, 15, 8, 2, 0, 4, 6, 10},
            {6, 14, 11, 0, 15, 9, 3, 8, 12, 13, 1, 10, 2, 7, 4, 5},
            {10, 8, 7, 1, 2, 4, 6, 5, 15, 9, 3, 13, 11, 14, 12, 0},
    };

    /**
     * F is a compression function for BLAKE2b. The state vector
     * provided as the first parameter is modified by the function.
     *
     * @param h      the state vector
     * @param m      the message block vector
     * @param c      offset counter
     * @param f      final block indicator flag
     * @param rounds number of rounds
     */
    public static void F(long[] h, long[] m, long[] c, boolean f, long rounds) {
        long c0 = c[0];
        long c1 = c[1];

        long v0 = h[0];
        long v1 = h[1];
        long v2 = h[2];
        long v3 = h[3];
        long v4 = h[4];
        long v5 = h[5];
        long v6 = h[6];
        long v7 = h[7];

        long v8 = IV[0];
        long v9 = IV[1];
        long v10 = IV[2];
        long v11 = IV[3];
        long v12 = IV[4];
        long v13 = IV[5];
        long v14 = IV[6];
        long v15 = IV[7];

        v12 ^= c0;
        v13 ^= c1;

        if (f) {
            v14 ^= 0xffffffffffffffffL;
        }

        for (long j = 0; j < rounds; j++) {
            byte[] s = PRECOMPUTED[(int) (j % 10)];

            v0 += m[s[0]];
            v0 += v4;
            v12 ^= v0;
            v12 = rotateLeft64(v12, -32);
            v8 += v12;
            v4 ^= v8;
            v4 = rotateLeft64(v4, -24);
            v1 += m[s[1]];
            v1 += v5;
            v13 ^= v1;
            v13 = rotateLeft64(v13, -32);
            v9 += v13;
            v5 ^= v9;
            v5 = rotateLeft64(v5, -24);
            v2 += m[s[2]];
            v2 += v6;
            v14 ^= v2;
            v14 = rotateLeft64(v14, -32);
            v10 += v14;
            v6 ^= v10;
            v6 = rotateLeft64(v6, -24);
            v3 += m[s[3]];
            v3 += v7;
            v15 ^= v3;
            v15 = rotateLeft64(v15, -32);
            v11 += v15;
            v7 ^= v11;
            v7 = rotateLeft64(v7, -24);

            v0 += m[s[4]];
            v0 += v4;
            v12 ^= v0;
            v12 = rotateLeft64(v12, -16);
            v8 += v12;
            v4 ^= v8;
            v4 = rotateLeft64(v4, -63);
            v1 += m[s[5]];
            v1 += v5;
            v13 ^= v1;
            v13 = rotateLeft64(v13, -16);
            v9 += v13;
            v5 ^= v9;
            v5 = rotateLeft64(v5, -63);
            v2 += m[s[6]];
            v2 += v6;
            v14 ^= v2;
            v14 = rotateLeft64(v14, -16);
            v10 += v14;
            v6 ^= v10;
            v6 = rotateLeft64(v6, -63);
            v3 += m[s[7]];
            v3 += v7;
            v15 ^= v3;
            v15 = rotateLeft64(v15, -16);
            v11 += v15;
            v7 ^= v11;
            v7 = rotateLeft64(v7, -63);

            v0 += m[s[8]];
            v0 += v5;
            v15 ^= v0;
            v15 = rotateLeft64(v15, -32);
            v10 += v15;
            v5 ^= v10;
            v5 = rotateLeft64(v5, -24);
            v1 += m[s[9]];
            v1 += v6;
            v12 ^= v1;
            v12 = rotateLeft64(v12, -32);
            v11 += v12;
            v6 ^= v11;
            v6 = rotateLeft64(v6, -24);
            v2 += m[s[10]];
            v2 += v7;
            v13 ^= v2;
            v13 = rotateLeft64(v13, -32);
            v8 += v13;
            v7 ^= v8;
            v7 = rotateLeft64(v7, -24);
            v3 += m[s[11]];
            v3 += v4;
            v14 ^= v3;
            v14 = rotateLeft64(v14, -32);
            v9 += v14;
            v4 ^= v9;
            v4 = rotateLeft64(v4, -24);

            v0 += m[s[12]];
            v0 += v5;
            v15 ^= v0;
            v15 = rotateLeft64(v15, -16);
            v10 += v15;
            v5 ^= v10;
            v5 = rotateLeft64(v5, -63);
            v1 += m[s[13]];
            v1 += v6;
            v12 ^= v1;
            v12 = rotateLeft64(v12, -16);
            v11 += v12;
            v6 ^= v11;
            v6 = rotateLeft64(v6, -63);
            v2 += m[s[14]];
            v2 += v7;
            v13 ^= v2;
            v13 = rotateLeft64(v13, -16);
            v8 += v13;
            v7 ^= v8;
            v7 = rotateLeft64(v7, -63);
            v3 += m[s[15]];
            v3 += v4;
            v14 ^= v3;
            v14 = rotateLeft64(v14, -16);
            v9 += v14;
            v4 ^= v9;
            v4 = rotateLeft64(v4, -63);
        }

        h[0] ^= v0 ^ v8;
        h[1] ^= v1 ^ v9;
        h[2] ^= v2 ^ v10;
        h[3] ^= v3 ^ v11;
        h[4] ^= v4 ^ v12;
        h[5] ^= v5 ^ v13;
        h[6] ^= v6 ^ v14;
        h[7] ^= v7 ^ v15;
    }

    private static long rotateLeft64(long n, int numBits) {
        assert numBits < 64;
        return Long.rotateLeft(n, numBits);
    }
}
