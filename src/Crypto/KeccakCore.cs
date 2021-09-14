using System;

namespace Crypto {

/*
 * Core implementation of Keccak; used by all SHA3 and SHAKE implementations.
 *
 * At any time, the core is in "absorb" or "squeeze" state. In absorb
 * state, data bytes can be injected into it, using the Update()
 * functions. In sueeze state, the Next() functions extract bytes from
 * the core. The initial state of the core is "absorb". The Flip()
 * function switches the state from absorb to squeeze.
 */

class KeccakCore {

	static ulong[] RC = {
		0x0000000000000001, 0x0000000000008082,
		0x800000000000808A, 0x8000000080008000,
		0x000000000000808B, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009,
		0x000000000000008A, 0x0000000000000088,
		0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B,
		0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080,
		0x000000000000800A, 0x800000008000000A,
		0x8000000080008081, 0x8000000000008080,
		0x0000000080000001, 0x8000000080008008
	};

	int c, r;
	bool prod;
	byte[] dbuf;
	int dptr;
	ulong[] A;

	/*
	 * Create the core with the specified capacity (in bits).
	 * Capacity must be a multiple of 64, strictly greater than 0
	 * and strictly lower than 1600.
	 */
	internal KeccakCore(int capacity)
	{
		A = new ulong[25];
		dbuf = new byte[200];
		Reset(capacity);
	}

	/*
	 * Reset the core to its initial state. Currently set capacity
	 * is conserved.
	 */
	internal void Reset()
	{
		Reset(c << 3);
	}

	/*
	 * Set the core capacity, and reset the state.
	 */
	internal void Reset(int capacity)
	{
		if (capacity >= 1600 || capacity <= 0 || (capacity & 63) != 0) {
			throw new ArgumentException(
				"bad capacity: " + capacity);
		}
		c = capacity >> 3;
		r = 200 - c;
		prod = false;
		dptr = 0;
		for (int i = 0; i < 25; i ++) {
			A[i] = 0;
		}
		A[ 1] = 0xFFFFFFFFFFFFFFFF;
		A[ 2] = 0xFFFFFFFFFFFFFFFF;
		A[ 8] = 0xFFFFFFFFFFFFFFFF;
		A[12] = 0xFFFFFFFFFFFFFFFF;
		A[17] = 0xFFFFFFFFFFFFFFFF;
		A[20] = 0xFFFFFFFFFFFFFFFF;
	}

	/*
	 * Inject one byte of input data.
	 * An ArgumentException is thrown if the current state is not "absorb".
	 */
	internal void Update(byte x)
	{
		if (prod) {
			throw new ArgumentException("bad state");
		}
		dbuf[dptr ++] = x;
		if (dptr == r) {
			ProcessBlock(dbuf, r);
			dptr = 0;
		}
	}

	/*
	 * Inject some bytes of input data.
	 * An ArgumentException is thrown if the current state is not "absorb".
	 */
	internal void Update(byte[] buf)
	{
		Update(buf, 0, buf.Length);
	}

	/*
	 * Inject some bytes of input data.
	 * An ArgumentException is thrown if the current state is not "absorb".
	 */
	internal void Update(byte[] buf, int off, int len)
	{
		if (prod) {
			throw new ArgumentException("bad state");
		}
		while (len > 0) {
			int clen = Math.Min(len, r - dptr);
			Array.Copy(buf, off, dbuf, dptr, clen);
			off += clen;
			len -= clen;
			dptr += clen;
			if (dptr == r) {
				ProcessBlock(dbuf, r);
				dptr = 0;
			}
		}
	}

	/*
	 * Flip the state from absorb to squeeze. The 'shake' flag, when
	 * true, selects the padding rule used in SHAKE; otherwise, the
	 * SHA3 padding rule is used.
	 * An ArgumentException is thrown if the current state is not "absorb".
	 */
	internal void Flip(bool shake)
	{
		if (prod) {
			throw new ArgumentException("bad state");
		}
		prod = true;
		if ((dptr + 1) == r) {
			dbuf[dptr ++] = shake ? (byte)0x9F : (byte)0x86;
		} else {
			dbuf[dptr ++] = shake ? (byte)0x1F : (byte)0x06;
			while ((dptr + 1) < r) {
				dbuf[dptr ++] = (byte)0x00;
			}
			dbuf[dptr ++] = 0x80;
		}
	}

	/*
	 * Extract the next byte of data.
	 * An ArgumentException is thrown if the current state is not "squeeze".
	 */
	internal byte Next()
	{
		if (!prod) {
			throw new ArgumentException("bad state");
		}
		if (dptr == r) {
			ProcessBlock(dbuf, r);
			EncodeState();
			dptr = 0;
		}
		return dbuf[dptr ++];
	}

	/*
	 * Extract the next bytes of data.
	 * An ArgumentException is thrown if the current state is not "squeeze".
	 */
	internal void Next(byte[] buf)
	{
		Next(buf, 0, buf.Length);
	}

	/*
	 * Extract the next bytes of data.
	 * An ArgumentException is thrown if the current state is not "squeeze".
	 */
	internal void Next(byte[] buf, int off, int len)
	{
		if (!prod) {
			throw new ArgumentException("bad state");
		}
		while (len > 0) {
			if (dptr == r) {
				ProcessBlock(dbuf, r);
				EncodeState();
				dptr = 0;
			}
			int clen = Math.Min(len, r - dptr);
			Array.Copy(dbuf, dptr, buf, off, clen);
			off += clen;
			len -= clen;
			dptr += clen;
		}
	}

	/*
	 * Internal block processing: XOR the input block into the current
	 * state, then run the Keccak-f permutation.
	 */
	void ProcessBlock(byte[] data, int len)
	{
		/* Input block */
		for (int i = 0; i < len; i += 8) {
			A[i >> 3] ^= Dec64LE(data, i);
		}

		ulong t0, t1, t2, t3, t4;
		ulong tt0, tt1, tt2, tt3;
		ulong t, kt;
		ulong c0, c1, c2, c3, c4, bnn;

		for (int j = 0; j < 24; j += 2) {

			tt0 = A[ 1] ^ A[ 6];
			tt1 = A[11] ^ A[16];
			tt0 ^= A[21] ^ tt1;
			tt0 = (tt0 << 1) | (tt0 >> 63);
			tt2 = A[ 4] ^ A[ 9];
			tt3 = A[14] ^ A[19];
			tt0 ^= A[24];
			tt2 ^= tt3;
			t0 = tt0 ^ tt2;

			tt0 = A[ 2] ^ A[ 7];
			tt1 = A[12] ^ A[17];
			tt0 ^= A[22] ^ tt1;
			tt0 = (tt0 << 1) | (tt0 >> 63);
			tt2 = A[ 0] ^ A[ 5];
			tt3 = A[10] ^ A[15];
			tt0 ^= A[20];
			tt2 ^= tt3;
			t1 = tt0 ^ tt2;

			tt0 = A[ 3] ^ A[ 8];
			tt1 = A[13] ^ A[18];
			tt0 ^= A[23] ^ tt1;
			tt0 = (tt0 << 1) | (tt0 >> 63);
			tt2 = A[ 1] ^ A[ 6];
			tt3 = A[11] ^ A[16];
			tt0 ^= A[21];
			tt2 ^= tt3;
			t2 = tt0 ^ tt2;

			tt0 = A[ 4] ^ A[ 9];
			tt1 = A[14] ^ A[19];
			tt0 ^= A[24] ^ tt1;
			tt0 = (tt0 << 1) | (tt0 >> 63);
			tt2 = A[ 2] ^ A[ 7];
			tt3 = A[12] ^ A[17];
			tt0 ^= A[22];
			tt2 ^= tt3;
			t3 = tt0 ^ tt2;

			tt0 = A[ 0] ^ A[ 5];
			tt1 = A[10] ^ A[15];
			tt0 ^= A[20] ^ tt1;
			tt0 = (tt0 << 1) | (tt0 >> 63);
			tt2 = A[ 3] ^ A[ 8];
			tt3 = A[13] ^ A[18];
			tt0 ^= A[23];
			tt2 ^= tt3;
			t4 = tt0 ^ tt2;

			A[ 0] = A[ 0] ^ t0;
			A[ 5] = A[ 5] ^ t0;
			A[10] = A[10] ^ t0;
			A[15] = A[15] ^ t0;
			A[20] = A[20] ^ t0;
			A[ 1] = A[ 1] ^ t1;
			A[ 6] = A[ 6] ^ t1;
			A[11] = A[11] ^ t1;
			A[16] = A[16] ^ t1;
			A[21] = A[21] ^ t1;
			A[ 2] = A[ 2] ^ t2;
			A[ 7] = A[ 7] ^ t2;
			A[12] = A[12] ^ t2;
			A[17] = A[17] ^ t2;
			A[22] = A[22] ^ t2;
			A[ 3] = A[ 3] ^ t3;
			A[ 8] = A[ 8] ^ t3;
			A[13] = A[13] ^ t3;
			A[18] = A[18] ^ t3;
			A[23] = A[23] ^ t3;
			A[ 4] = A[ 4] ^ t4;
			A[ 9] = A[ 9] ^ t4;
			A[14] = A[14] ^ t4;
			A[19] = A[19] ^ t4;
			A[24] = A[24] ^ t4;
			A[ 5] = (A[ 5] << 36) | (A[ 5] >> (64 - 36));
			A[10] = (A[10] << 3) | (A[10] >> (64 - 3));
			A[15] = (A[15] << 41) | (A[15] >> (64 - 41));
			A[20] = (A[20] << 18) | (A[20] >> (64 - 18));
			A[ 1] = (A[ 1] << 1) | (A[ 1] >> (64 - 1));
			A[ 6] = (A[ 6] << 44) | (A[ 6] >> (64 - 44));
			A[11] = (A[11] << 10) | (A[11] >> (64 - 10));
			A[16] = (A[16] << 45) | (A[16] >> (64 - 45));
			A[21] = (A[21] << 2) | (A[21] >> (64 - 2));
			A[ 2] = (A[ 2] << 62) | (A[ 2] >> (64 - 62));
			A[ 7] = (A[ 7] << 6) | (A[ 7] >> (64 - 6));
			A[12] = (A[12] << 43) | (A[12] >> (64 - 43));
			A[17] = (A[17] << 15) | (A[17] >> (64 - 15));
			A[22] = (A[22] << 61) | (A[22] >> (64 - 61));
			A[ 3] = (A[ 3] << 28) | (A[ 3] >> (64 - 28));
			A[ 8] = (A[ 8] << 55) | (A[ 8] >> (64 - 55));
			A[13] = (A[13] << 25) | (A[13] >> (64 - 25));
			A[18] = (A[18] << 21) | (A[18] >> (64 - 21));
			A[23] = (A[23] << 56) | (A[23] >> (64 - 56));
			A[ 4] = (A[ 4] << 27) | (A[ 4] >> (64 - 27));
			A[ 9] = (A[ 9] << 20) | (A[ 9] >> (64 - 20));
			A[14] = (A[14] << 39) | (A[14] >> (64 - 39));
			A[19] = (A[19] << 8) | (A[19] >> (64 - 8));
			A[24] = (A[24] << 14) | (A[24] >> (64 - 14));
			bnn = ~A[12];
			kt = A[ 6] | A[12];
			c0 = A[ 0] ^ kt;
			kt = bnn | A[18];
			c1 = A[ 6] ^ kt;
			kt = A[18] & A[24];
			c2 = A[12] ^ kt;
			kt = A[24] | A[ 0];
			c3 = A[18] ^ kt;
			kt = A[ 0] & A[ 6];
			c4 = A[24] ^ kt;
			A[ 0] = c0;
			A[ 6] = c1;
			A[12] = c2;
			A[18] = c3;
			A[24] = c4;
			bnn = ~A[22];
			kt = A[ 9] | A[10];
			c0 = A[ 3] ^ kt;
			kt = A[10] & A[16];
			c1 = A[ 9] ^ kt;
			kt = A[16] | bnn;
			c2 = A[10] ^ kt;
			kt = A[22] | A[ 3];
			c3 = A[16] ^ kt;
			kt = A[ 3] & A[ 9];
			c4 = A[22] ^ kt;
			A[ 3] = c0;
			A[ 9] = c1;
			A[10] = c2;
			A[16] = c3;
			A[22] = c4;
			bnn = ~A[19];
			kt = A[ 7] | A[13];
			c0 = A[ 1] ^ kt;
			kt = A[13] & A[19];
			c1 = A[ 7] ^ kt;
			kt = bnn & A[20];
			c2 = A[13] ^ kt;
			kt = A[20] | A[ 1];
			c3 = bnn ^ kt;
			kt = A[ 1] & A[ 7];
			c4 = A[20] ^ kt;
			A[ 1] = c0;
			A[ 7] = c1;
			A[13] = c2;
			A[19] = c3;
			A[20] = c4;
			bnn = ~A[17];
			kt = A[ 5] & A[11];
			c0 = A[ 4] ^ kt;
			kt = A[11] | A[17];
			c1 = A[ 5] ^ kt;
			kt = bnn | A[23];
			c2 = A[11] ^ kt;
			kt = A[23] & A[ 4];
			c3 = bnn ^ kt;
			kt = A[ 4] | A[ 5];
			c4 = A[23] ^ kt;
			A[ 4] = c0;
			A[ 5] = c1;
			A[11] = c2;
			A[17] = c3;
			A[23] = c4;
			bnn = ~A[ 8];
			kt = bnn & A[14];
			c0 = A[ 2] ^ kt;
			kt = A[14] | A[15];
			c1 = bnn ^ kt;
			kt = A[15] & A[21];
			c2 = A[14] ^ kt;
			kt = A[21] | A[ 2];
			c3 = A[15] ^ kt;
			kt = A[ 2] & A[ 8];
			c4 = A[21] ^ kt;
			A[ 2] = c0;
			A[ 8] = c1;
			A[14] = c2;
			A[15] = c3;
			A[21] = c4;
			A[ 0] = A[ 0] ^ RC[j + 0];

			tt0 = A[ 6] ^ A[ 9];
			tt1 = A[ 7] ^ A[ 5];
			tt0 ^= A[ 8] ^ tt1;
			tt0 = (tt0 << 1) | (tt0 >> 63);
			tt2 = A[24] ^ A[22];
			tt3 = A[20] ^ A[23];
			tt0 ^= A[21];
			tt2 ^= tt3;
			t0 = tt0 ^ tt2;

			tt0 = A[12] ^ A[10];
			tt1 = A[13] ^ A[11];
			tt0 ^= A[14] ^ tt1;
			tt0 = (tt0 << 1) | (tt0 >> 63);
			tt2 = A[ 0] ^ A[ 3];
			tt3 = A[ 1] ^ A[ 4];
			tt0 ^= A[ 2];
			tt2 ^= tt3;
			t1 = tt0 ^ tt2;

			tt0 = A[18] ^ A[16];
			tt1 = A[19] ^ A[17];
			tt0 ^= A[15] ^ tt1;
			tt0 = (tt0 << 1) | (tt0 >> 63);
			tt2 = A[ 6] ^ A[ 9];
			tt3 = A[ 7] ^ A[ 5];
			tt0 ^= A[ 8];
			tt2 ^= tt3;
			t2 = tt0 ^ tt2;

			tt0 = A[24] ^ A[22];
			tt1 = A[20] ^ A[23];
			tt0 ^= A[21] ^ tt1;
			tt0 = (tt0 << 1) | (tt0 >> 63);
			tt2 = A[12] ^ A[10];
			tt3 = A[13] ^ A[11];
			tt0 ^= A[14];
			tt2 ^= tt3;
			t3 = tt0 ^ tt2;

			tt0 = A[ 0] ^ A[ 3];
			tt1 = A[ 1] ^ A[ 4];
			tt0 ^= A[ 2] ^ tt1;
			tt0 = (tt0 << 1) | (tt0 >> 63);
			tt2 = A[18] ^ A[16];
			tt3 = A[19] ^ A[17];
			tt0 ^= A[15];
			tt2 ^= tt3;
			t4 = tt0 ^ tt2;

			A[ 0] = A[ 0] ^ t0;
			A[ 3] = A[ 3] ^ t0;
			A[ 1] = A[ 1] ^ t0;
			A[ 4] = A[ 4] ^ t0;
			A[ 2] = A[ 2] ^ t0;
			A[ 6] = A[ 6] ^ t1;
			A[ 9] = A[ 9] ^ t1;
			A[ 7] = A[ 7] ^ t1;
			A[ 5] = A[ 5] ^ t1;
			A[ 8] = A[ 8] ^ t1;
			A[12] = A[12] ^ t2;
			A[10] = A[10] ^ t2;
			A[13] = A[13] ^ t2;
			A[11] = A[11] ^ t2;
			A[14] = A[14] ^ t2;
			A[18] = A[18] ^ t3;
			A[16] = A[16] ^ t3;
			A[19] = A[19] ^ t3;
			A[17] = A[17] ^ t3;
			A[15] = A[15] ^ t3;
			A[24] = A[24] ^ t4;
			A[22] = A[22] ^ t4;
			A[20] = A[20] ^ t4;
			A[23] = A[23] ^ t4;
			A[21] = A[21] ^ t4;
			A[ 3] = (A[ 3] << 36) | (A[ 3] >> (64 - 36));
			A[ 1] = (A[ 1] << 3) | (A[ 1] >> (64 - 3));
			A[ 4] = (A[ 4] << 41) | (A[ 4] >> (64 - 41));
			A[ 2] = (A[ 2] << 18) | (A[ 2] >> (64 - 18));
			A[ 6] = (A[ 6] << 1) | (A[ 6] >> (64 - 1));
			A[ 9] = (A[ 9] << 44) | (A[ 9] >> (64 - 44));
			A[ 7] = (A[ 7] << 10) | (A[ 7] >> (64 - 10));
			A[ 5] = (A[ 5] << 45) | (A[ 5] >> (64 - 45));
			A[ 8] = (A[ 8] << 2) | (A[ 8] >> (64 - 2));
			A[12] = (A[12] << 62) | (A[12] >> (64 - 62));
			A[10] = (A[10] << 6) | (A[10] >> (64 - 6));
			A[13] = (A[13] << 43) | (A[13] >> (64 - 43));
			A[11] = (A[11] << 15) | (A[11] >> (64 - 15));
			A[14] = (A[14] << 61) | (A[14] >> (64 - 61));
			A[18] = (A[18] << 28) | (A[18] >> (64 - 28));
			A[16] = (A[16] << 55) | (A[16] >> (64 - 55));
			A[19] = (A[19] << 25) | (A[19] >> (64 - 25));
			A[17] = (A[17] << 21) | (A[17] >> (64 - 21));
			A[15] = (A[15] << 56) | (A[15] >> (64 - 56));
			A[24] = (A[24] << 27) | (A[24] >> (64 - 27));
			A[22] = (A[22] << 20) | (A[22] >> (64 - 20));
			A[20] = (A[20] << 39) | (A[20] >> (64 - 39));
			A[23] = (A[23] << 8) | (A[23] >> (64 - 8));
			A[21] = (A[21] << 14) | (A[21] >> (64 - 14));
			bnn = ~A[13];
			kt = A[ 9] | A[13];
			c0 = A[ 0] ^ kt;
			kt = bnn | A[17];
			c1 = A[ 9] ^ kt;
			kt = A[17] & A[21];
			c2 = A[13] ^ kt;
			kt = A[21] | A[ 0];
			c3 = A[17] ^ kt;
			kt = A[ 0] & A[ 9];
			c4 = A[21] ^ kt;
			A[ 0] = c0;
			A[ 9] = c1;
			A[13] = c2;
			A[17] = c3;
			A[21] = c4;
			bnn = ~A[14];
			kt = A[22] | A[ 1];
			c0 = A[18] ^ kt;
			kt = A[ 1] & A[ 5];
			c1 = A[22] ^ kt;
			kt = A[ 5] | bnn;
			c2 = A[ 1] ^ kt;
			kt = A[14] | A[18];
			c3 = A[ 5] ^ kt;
			kt = A[18] & A[22];
			c4 = A[14] ^ kt;
			A[18] = c0;
			A[22] = c1;
			A[ 1] = c2;
			A[ 5] = c3;
			A[14] = c4;
			bnn = ~A[23];
			kt = A[10] | A[19];
			c0 = A[ 6] ^ kt;
			kt = A[19] & A[23];
			c1 = A[10] ^ kt;
			kt = bnn & A[ 2];
			c2 = A[19] ^ kt;
			kt = A[ 2] | A[ 6];
			c3 = bnn ^ kt;
			kt = A[ 6] & A[10];
			c4 = A[ 2] ^ kt;
			A[ 6] = c0;
			A[10] = c1;
			A[19] = c2;
			A[23] = c3;
			A[ 2] = c4;
			bnn = ~A[11];
			kt = A[ 3] & A[ 7];
			c0 = A[24] ^ kt;
			kt = A[ 7] | A[11];
			c1 = A[ 3] ^ kt;
			kt = bnn | A[15];
			c2 = A[ 7] ^ kt;
			kt = A[15] & A[24];
			c3 = bnn ^ kt;
			kt = A[24] | A[ 3];
			c4 = A[15] ^ kt;
			A[24] = c0;
			A[ 3] = c1;
			A[ 7] = c2;
			A[11] = c3;
			A[15] = c4;
			bnn = ~A[16];
			kt = bnn & A[20];
			c0 = A[12] ^ kt;
			kt = A[20] | A[ 4];
			c1 = bnn ^ kt;
			kt = A[ 4] & A[ 8];
			c2 = A[20] ^ kt;
			kt = A[ 8] | A[12];
			c3 = A[ 4] ^ kt;
			kt = A[12] & A[16];
			c4 = A[ 8] ^ kt;
			A[12] = c0;
			A[16] = c1;
			A[20] = c2;
			A[ 4] = c3;
			A[ 8] = c4;
			A[ 0] = A[ 0] ^ RC[j + 1];
			t = A[ 5];
			A[ 5] = A[18];
			A[18] = A[11];
			A[11] = A[10];
			A[10] = A[ 6];
			A[ 6] = A[22];
			A[22] = A[20];
			A[20] = A[12];
			A[12] = A[19];
			A[19] = A[15];
			A[15] = A[24];
			A[24] = A[ 8];
			A[ 8] = t;
			t = A[ 1];
			A[ 1] = A[ 9];
			A[ 9] = A[14];
			A[14] = A[ 2];
			A[ 2] = A[13];
			A[13] = A[23];
			A[23] = A[ 4];
			A[ 4] = A[21];
			A[21] = A[16];
			A[16] = A[ 3];
			A[ 3] = A[17];
			A[17] = A[ 7];
			A[ 7] = t;
		}
	}

	/*
	 * Encode the current state (1600 bits) into the dbuf[] array.
	 */
	void EncodeState()
	{
		Enc64LE( A[ 0], dbuf,   0);
		Enc64LE(~A[ 1], dbuf,   8);
		Enc64LE(~A[ 2], dbuf,  16);
		Enc64LE( A[ 3], dbuf,  24);
		Enc64LE( A[ 4], dbuf,  32);
		Enc64LE( A[ 5], dbuf,  40);
		Enc64LE( A[ 6], dbuf,  48);
		Enc64LE( A[ 7], dbuf,  56);
		Enc64LE(~A[ 8], dbuf,  64);
		Enc64LE( A[ 9], dbuf,  72);
		Enc64LE( A[10], dbuf,  80);
		Enc64LE( A[11], dbuf,  88);
		Enc64LE(~A[12], dbuf,  96);
		Enc64LE( A[13], dbuf, 104);
		Enc64LE( A[14], dbuf, 112);
		Enc64LE( A[15], dbuf, 120);
		Enc64LE( A[16], dbuf, 128);
		Enc64LE(~A[17], dbuf, 136);
		Enc64LE( A[18], dbuf, 144);
		Enc64LE( A[19], dbuf, 152);
		Enc64LE(~A[20], dbuf, 160);
		Enc64LE( A[21], dbuf, 168);
		Enc64LE( A[22], dbuf, 176);
		Enc64LE( A[23], dbuf, 184);
		Enc64LE( A[24], dbuf, 192);
	}

	static void Enc64LE(ulong x, byte[] buf, int off)
	{
		for (int i = 0; i < 8; i ++) {
			buf[off ++] = (byte)x;
			x >>= 8;
		}
	}

	static ulong Dec64LE(byte[] buf, int off)
	{
		ulong x = 0;
		off += 8;
		for (int i = 0; i < 8; i ++) {
			x = (x << 8) | (ulong)buf[-- off];
		}
		return x;
	}
}

}
