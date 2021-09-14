using System;
using System.IO;
using System.IO.Compression;
using System.Text;

using BigInt;
using Crypto;

/*
 * Format:
 *
 * N is a big composite integer (basically an RSA public modulus). It is
 * the product of two big prime factors, which are not known. When N needs
 * to be encoded into bytes (for hashing purposes), unsigned big-endian
 * convention is used (with no extra leading byte). Default modulus was
 * generated as an RSA key with a general-purpose cryptographic library,
 * and a size of 2048 bits (256 bytes). I did not keep the private factors.
 *
 * Nlen = length of N in bytes
 *
 * G is the group of unordered pairs {u,-u} where u is an invertible integer
 * modulo N. Group law is: {u,-u} * {v,-v} = {u*v,-u*v}. This is equivalent
 * to saying that we use invertible integers modulo N, and multiply them
 * together, but, when encoding, decoding or comparing values, we normalize
 * them into 1..(N-1)/2 (replacing value x with N-x if necessary). An element
 * of G is encoded into a byte sequence of the same length as N (i.e. Nlen
 * bytes, exactly), with unsigned big-endian convention.
 *
 * T is a counter value in the 0..2^128-1 range. It is encoded over exactly
 * 16 bytes, with unsigned big-endian convention.
 *
 * H is a hash function that outputs a value in G. For an input e:
 *   1. Compute buf = SHAKE128(0x01 || e || N) with an output size equal
 *      to the size of N (i.e. 256 bytes for a 2048-bit modulus N).
 *   2. Interpret buf as a big integer x using unsigned big-endian convention
 *   3. Return x mod N.
 *
 * h is a hash function that outputs a small prime between 3 and 2^256 + 297
 * (inclusive), from inputs g, T and f (and N), where g and f are elements
 * of the group G:
 *   1. Compute buf = SHAKE128(0x02 || g || N || T || f) with a 32-byte output.
 *   2. Interpret buf as a big integer y using unsigned big-endian convention
 *   3. Return the smallest odd prime integer l >= y.
 *
 * VDF-Eval(T, e):
 *   1. Compute g = H(e)
 *   2. Compute f = g^(2^T)   (computation in the group G)
 *   3. Compute l = h(g, T, f)
 *   4. Compute pi = g^q (in the group G) where q = floor(2^T / l)
 *   5. Return (f, pi)
 *
 * VDF-Verify(T, e, f, pi):
 *   1. Compute g = H(e)
 *   2. Compute l = h(g, T, f)
 *   3. Compute r = 2^T mod l  (in the 0..l-1 range)
 *   4. Compute f' = pi^l*g^r  (in the group G)
 *   5. Return true if and only if f == f'  (comparison in the group G)
 *
 * Compression of an input file data[]:
 *   1. Compute d = DEFLATE-compress(data)
 *   2. If len(d) >= len(data) - 32 - 2*Nlen:
 *          Return data
 *   3. Split data = d || T || f || pi with T a counter (16 bytes), and
 *      f and pi two sequences of Nlen bytes.
 *   4. If f and pi can be decoded as elements of G (in the 1..(N-1)/2 range)
 *      and VDF-Verify(T, d, f, pi) == true:
 *          Return d || T+1 || VDF-Eval(T+1, d)
 *   5. Return data
 *
 * Decompression of an input file data[]:
 *   1. If len(data) <= 32 + 2*Nlen:
 *          Return data
 *   2. Split data = d || T || f || pi with T a counter (16 bytes), and
 *      f and pi two sequences of Nlen bytes.
 *   3. If f and pi can be decoded as elements of G (in the 1..(N-1)/2 range)
 *      and VDF-Verify(T, d, f, pi) == true:
 *          If T == 0:
 *              return DEFLATE-decompress(d)
 *          Else:
 *              return d || T-1 || VDF-Eval(T-1, d)
 *   4. Return data
 */

public class ParadoxCompress {

	/*
	 * Default modulus: a 2048-bit RSA public modulus, generated
	 * with BearSSL. It is a composite integer, product of two
	 * 1024-bit primes. I did not keep these prime factors.
	 */
	static ZInt DEFAULT_MODULUS = ZInt.Parse("0xC98F9A7148778F4D5C1F741DE4DA3033ACE4B962513D2A5FC04320B0B2BAC39B205551812091E5C82DA46F83D77C32B329F874EF0D71945E179DFF0D25A3251B48D005451BB370263B9A2254CD7BE02785305B8247A0153B5FCF012A66F394916E97D9195DCF5FD753980BB64AA079ED08931DB4C24DE008E0A93E6482F5BCA0E8438FB9BAD409F5882FD8AD28D149F2468B62758303C71D07754EAC37C570D785AE659A79A26769EB524D839FDACBCDB39DD3BD7DEA24F51E0CE2F1DA441EC7CBB5724C728CBE76898109C6179EE44AE959B67039EE2D738E8E525B2EDD7F76115C440472CAF8467DC63C31659C7FB8DD4A46122E6D0870E7C9B8ADEAE3F62D");

	ZInt N;        // modulus
	ZInt hN;       // (N-1)/2
	byte[] Nbuf;   // encoded modulus
	int Nlen;      // length of the encoded modulus, in bytes
	int clen;      // length of an encoded counter value, in bytes
	int ellLen;    // length of the source bytes for prime \ell, in bytes

	/*
	 * Create an instance with the default modulus.
	 */
	public ParadoxCompress()
		: this(DEFAULT_MODULUS)
	{
	}

	/*
	 * Create an instance with the specified modulus.
	 */
	public ParadoxCompress(ZInt N)
	{
		this.N = N;
		hN = N >> 1;
		Nbuf = N.ToBytesUnsignedBE();
		Nlen = Nbuf.Length;
		if (N.Sign <= 0 || (8 * Nlen) < 1024 || !N.TestBit(0)) {
			// We reject a few obviously false moduli:
			// nonpositive values, even values, and values
			// shorter than 1017 bits (128 bytes).
			throw new ArgumentException("invalid modulus");
		}
		clen = 16;    // 16 bytes = 128-bit counters
		ellLen = 32;  // 32 bytes = 256-bit challenge primes
	}

	/*
	 * Parse an encoded counter value.
	 */
	ZInt CounterParse(byte[] buf, int off)
	{
		return ZInt.DecodeUnsignedBE(buf, off, clen);
	}

	/*
	 * Encode a counter value into bytes (output length is clen).
	 */
	byte[] CounterEncode(ZInt c)
	{
		byte[] buf = new byte[clen];
		CounterEncode(c, buf, 0);
		return buf;
	}

	/*
	 * Encode a counter value into bytes (output length is clen).
	 */
	void CounterEncode(ZInt c, byte[] buf, int off)
	{
		// We do not check that c < 2^128 because that may happen
		// only if the VDF was broken or the attacker could use
		// an impossibly powerful computer that could make
		// 2^128 successive modular squarings.
		//
		// If the situation arises through the use of a modulus with
		// a known factorization (e.g. as part of tests), then
		// the counter value is silently truncated to 128 bits.
		c.ToBytesBE(buf, off, clen);
	}

	/*
	 * Try to parse a group element from bytes. Nlen bytes are
	 * interpreted as an integer with unsigned big-endian convention;
	 * if the value is not in the allowed 1..(N-1)/2 range, then
	 * decoding fails (x is set to 0 and the function returns false).
	 */
	bool GroupTryParse(byte[] buf, int off, out ZInt x)
	{
		x = ZInt.DecodeUnsignedBE(buf, off, Nlen);
		if (x.Sign <= 0 || x > hN) {
			x = 0;
			return false;
		}
		return true;
	}

	/*
	 * Encode a group element into Nlen bytes.
	 */
	byte[] GroupEncode(ZInt x)
	{
		byte[] buf = new byte[Nlen];
		GroupEncode(x, buf, 0);
		return buf;
	}

	/*
	 * Encode a group element into Nlen bytes.
	 */
	void GroupEncode(ZInt x, byte[] buf, int off)
	{
		if (x > hN) {
			x = N - x;
		}
		x.ToBytesBE(buf, off, Nlen);
	}

	/*
	 * H: hash an input message into an element of the group G.
	 */
	ZInt HashToGroup(byte[] buf, int off, int len)
	{
		IXOF xof = new SHAKE128();
		xof.Update((byte)0x01); // domain separation byte
		xof.Update(buf, off, len);
		xof.Update(Nbuf);
		xof.Flip();
		byte[] tmp = new byte[Nlen];
		xof.Next(tmp);
		return ZInt.DecodeUnsignedBE(tmp).Mod(N);
	}

	/*
	 * h: hash some data (group element g and f, work factor T)
	 * into a prime integer not greater than 2^256 + 297.
	 */
	ZInt HashToSmallPrime(ZInt g, ZInt T, ZInt f)
	{
		IXOF xof = new SHAKE128();
		xof.Update((byte)0x02); // domain separation byte
		xof.Update(GroupEncode(g));
		xof.Update(Nbuf);
		xof.Update(CounterEncode(T));
		xof.Update(GroupEncode(f));
		xof.Flip();
		byte[] ellb = new byte[ellLen];
		xof.Next(ellb);
		ZInt ell = ZInt.DecodeUnsignedBE(ellb);
		if (ell <= 2) {
			ell = 3;
		} else {
			if (!ell.TestBit(0)) {
				ell ++;
			}
			while (!ell.IsPrime) {
				ell += 2;
			}
		}
		return ell;
	}

	/*
	 * VDF-Eval.
	 */
	void VDFEval(ZInt T, byte[] ebuf, out ZInt f, out ZInt pi)
	{
		VDFEval(T, ebuf, 0, ebuf.Length, out f, out pi);
	}

	/*
	 * VDF-Eval.
	 */
	void VDFEval(ZInt T, byte[] ebuf, int eoff, int elen,
		out ZInt f, out ZInt pi)
	{
		// For tests, we forcibly truncate T to 128 bits. Normally,
		// we cannot have an input T that gets even close to 2^128
		// since a VDF proof using that T cannot be generated by
		// anyone; but we force that situation in the tests by using
		// a modulus for which we know the prime factors.
		T = T.Mod(ZInt.One << (clen * 8));

		// g = H(e || N)
		ZInt g = HashToGroup(ebuf, eoff, elen);

		// f = g^(2^T) mod N
		ZInt tf = g;
		ZInt rT = T;
		while (rT > 0) {
			// ModPow() optimizes things internally with
			// Montgomery representation, which works better
			// for big exponents; thus, we do the squarings
			// by chunks of at most 4096.
			int num;
			if (rT > 4096) {
				num = 4096;
				rT -= num;
			} else {
				num = rT.ToInt;
				rT = 0;
			}
			tf = ZInt.ModPow(tf, ZInt.One << num, N);
		}

		// ell = h(g || N || T || f)
		ZInt ell = HashToSmallPrime(g, rT, tf);

		// pi = g^q mod N, where q = floor(2^T / ell)
		ZInt r = 1;
		ZInt tpi = 1;
		while (T > 0) {
			// Algorithm is a bit-by-bit long division:
			//   pi <- 1
			//   r <- 1
			//   repeat T times:
			//      r <- 2*r
			//      b = floor(r / ell)
			//      r <- r mod ell
			//      pi <- pi^2*g^b mod N
			// We group the squarings and the multiplications
			// by g into chunks of at most 4096 in order to
			// leverage the optimized code in ZInt.
			int num;
			if (T > 4096) {
				num = 4096;
				T -= num;
			} else {
				num = T.ToInt;
				T = 0;
			}
			ZInt z = 0;
			for (int i = 0; i < num; i ++) {
				z <<= 1;
				r <<= 1;
				if (r >= ell) {
					r -= ell;
					z ++;
				}
			}
			tpi = ZInt.ModPow(tpi, ZInt.One << num, N);
			tpi = (tpi * ZInt.ModPow(g, z, N)).Mod(N);
		}

		f = tf;
		pi = tpi;
	}

	/*
	 * VDF-Verify.
	 */
	bool VDFVerify(ZInt T, byte[] ebuf, int eoff, int elen, ZInt f, ZInt pi)
	{
		// g = H(e || N)
		ZInt g = HashToGroup(ebuf, eoff, elen);

		// ell = h(g || N || T || f)
		ZInt ell = HashToSmallPrime(g, T, f);

		// r = 2^T mod ell
		ZInt r = ZInt.ModPow(2, T, ell);

		// f' = pi^ell*g^r mod N
		ZInt f2 = (ZInt.ModPow(pi, ell, N)
			* ZInt.ModPow(g, r, N)).Mod(N);

		// Proof is good if f = f'. Take care that we must compare
		// in the group, where values are normalized to 1..(N-1)/2.
		if (f > hN) {
			f = N - f;
		}
		if (f2 > hN) {
			f2 = N - f2;
		}
		return f == f2;
	}

	/*
	 * Apply the compression on the provided data. In some cases,
	 * the compressed output is identical to the input; the data[]
	 * array itself is then returned. Otherwise, a new array is
	 * created and returned. In all cases, data[] is unmodified.
	 */
	public byte[] Compress(byte[] data)
	{
		// Input files that are too small for our header are
		// left as is.
		if (data.Length <= clen + 2*Nlen) {
			return data;
		}

		// Try to compress with DEFLATE.
		MemoryStream m1 = new MemoryStream(data);
		MemoryStream m2 = new MemoryStream();
		using (DeflateStream ds =
			new DeflateStream(m2, CompressionMode.Compress))
		{
			m1.CopyTo(ds);
		}
		byte[] d = m2.ToArray();

		// If DEFLATE could gain enough room, add our header
		// and return.
		if (d.Length < data.Length - clen - 2*Nlen) {
			ZInt f, pi;
			VDFEval(0, d, out f, out pi);
			byte[] r = new byte[d.Length + clen + 2*Nlen];
			Array.Copy(d, 0, r, 0, d.Length);
			CounterEncode(0, r, d.Length);
			GroupEncode(f, r, d.Length + clen);
			GroupEncode(pi, r, d.Length + clen + Nlen);
			return r;
		}

		// If the input already contains a counter c and a
		// valid VDF proof for c, increment c and compute the
		// new VDF proof.
		int len = data.Length - clen - 2*Nlen;
		ZInt T = CounterParse(data, len);
		ZInt f1, pi1;
		if (GroupTryParse(data, len + clen, out f1)
			&& GroupTryParse(data, len + clen + Nlen, out pi1)
			&& VDFVerify(T, data, 0, len, f1, pi1))
		{
			T ++;
			ZInt f, pi;
			VDFEval(T, data, 0, len, out f, out pi);
			byte[] r = new byte[len + clen + 2*Nlen];
			Array.Copy(data, 0, r, 0, len);
			CounterEncode(T, r, len);
			GroupEncode(f, r, len + clen);
			GroupEncode(pi, r, len + clen + Nlen);
			return r;
		}

		// No valid compression header; we return the data as is.
		return data;
	}

	/*
	 * Apply the decompression on the provided data. In some cases,
	 * the decompressed output is identical to the input; the data[]
	 * array itself is then returned. Otherwise, a new array is
	 * created and returned. In all cases, data[] is unmodified.
	 *
	 * If the input data is not a valid compressed file, an
	 * appropriate IOException is thrown.
	 */
	public byte[] Decompress(byte[] data)
	{
		// Input files that are too small for our header are
		// left as is.
		if (data.Length <= clen + 2*Nlen) {
			return data;
		}

		// If there is no valid VDF proof in the header, then
		// the data is returned as is.
		int len = data.Length - clen - 2*Nlen;
		ZInt T = CounterParse(data, len);
		ZInt f, pi;
		if (!GroupTryParse(data, len + clen, out f)
			|| !GroupTryParse(data, len + clen + Nlen, out pi)
			|| !VDFVerify(T, data, 0, len, f, pi))
		{
			return data;
		}

		// If the counter is non-zero, decrement it and return the
		// data with the new VDF proof.
		if (T.Sign > 0) {
			T --;
			VDFEval(T, data, 0, len, out f, out pi);
			byte[] r = new byte[len + clen + 2*Nlen];
			Array.Copy(data, 0, r, 0, len);
			CounterEncode(T, r, len);
			GroupEncode(f, r, len + clen);
			GroupEncode(pi, r, len + clen + Nlen);
			return r;
		}

		// Counter is zero and proof is valid: this is supposed to
		// be DEFLATE data (if it is not correct, then it is not
		// the output of the compressor; the DeflateStream code will
		// throw an appropriate exception).
		MemoryStream m1 = new MemoryStream(data, 0, len);
		MemoryStream m2 = new MemoryStream();
		using (DeflateStream ds =
			new DeflateStream(m1, CompressionMode.Decompress))
		{
			ds.CopyTo(m2);
		}
		return m2.ToArray();
	}

	/* =============================================================== */
	/*
	 * Unit tests.
	 */

	/*
	 * Entry point for tests (when compiled as a command-line test tool).
	 */
	static void Main(string[] args)
	{
		ParadoxCompress pc = new ParadoxCompress();
		System.Security.Cryptography.RNGCryptoServiceProvider rng =
			new System.Security.Cryptography.RNGCryptoServiceProvider();

		// We try lengths of 0, 500, 1000, 1500 and 2000 bytes.
		// For each length, we try two messages, one with random
		// contents, the other with a single repeated byte value.
		// Then, we repeatedly compress the file (5 times), verifying
		// that none of the compression operations increases the
		// length, and then we decompress the result to check that
		// we can get back to the original file.
		for (int len = 0; len <= 2000; len += 500) {
			// Compress (repeatedly) a file with either random
			// contents (not readily compressible with DEFLATE)
			// or with repeated contents (which are very
			// compressible with DEFLATE).
			for (int k = 0; k < 2; k ++) {
				byte[] msg = new byte[len];
				if (k == 0) {
					rng.GetBytes(msg);
				} else {
					for (int i = 0; i < len; i ++) {
						msg[i] = (byte)len;
					}
				}

				byte[] d = new byte[len];
				Array.Copy(msg, 0, d, 0, len);
				byte[][] dd = new byte[5][];
				for (int i = 0; i < dd.Length; i ++) {
					int n1 = d.Length;
					d = pc.Compress(d);
					int n2 = d.Length;
					if (n2 > n1) {
						throw new Exception(string.Format("FAIL: length increase {0} -> {1}", n1, n2));
					}
					dd[i] = d;
				}
				for (int i = dd.Length - 1; i >= 0; i --) {
					CheckEquals(d, dd[i]);
					d = pc.Decompress(d);
				}
				CheckEquals(d, msg);
			}

			Console.Write(".");
		}
		Console.WriteLine();

		// We simulate the failure condition with a custom modulus
		// with known factorization. Using the knowledge of the prime
		// factors, we can assemble two messages that are compressed
		// to the same output.

		// p1 and p2 are 512-bit primes (generated randomly). Their
		// product is a 1024-bit composite integer.
		ZInt p1 = ZInt.Parse("0xE7334E5D77C15E0310171A491CEBEBDA7042AAD0D59204CD47FB3588B11E724909C29A0098C9167E6C1E18D7FA163018489F13DF06741B6CB01E02E6E8E5E697");
		ZInt p2 = ZInt.Parse("0xE35D429462F89842522AB7253D35B18D7BA99E1292DD9AE3DB375A88404FD09A278300BC7070C3723488F2E610861DFCC0C7B1FF9935EB1BEF261D025FC505DB");
		ZInt N = p1 * p2;
		pc = new ParadoxCompress(N);

		// Message 1: a kilobyte of zeros. This will compress well.
		// The extra header has size 16 + 2*128 = 272 bytes; we
		// extract the DEFLATE-compressed part.
		byte[] m1 = new byte[1000];
		byte[] cm1 = pc.Compress(m1);
		byte[] dfd = new byte[cm1.Length - pc.clen - 2*128];
		Array.Copy(cm1, 0, dfd, 0, dfd.Length);

		// Message 2: d || enc(2^128-1) || VDF-Eval(2^128-1, d)
		// VDF-Eval is:
		//   1. Compute g = H(e)
		//   2. Compute f = g^(2^T)
		//   3. Compute l = h(g, T, f)
		//   4. Compute pi = g^q where q = floor(2^T / l)
		//   5. Return (f, pi)
		//
		// Since we know the prime factors p1 and p2 of N, we
		// can compute f modulo p1 and modulo p2 and assemble
		// the result with the Chinese Remainder Theorem.
		//
		// For pi, we also work modulo p1 and modulo p2. Modulo p1,
		// we need to find pi such that pi^l*g^r = f, i.e.
		// pi = (f*g^(-r))^(1/l mod p1-1)
		ZInt crt = p2.ModInverse(p1);

		ZInt g = pc.HashToGroup(dfd, 0, dfd.Length);
		ZInt T = (ZInt.One << (8 * pc.clen)) - 1;
		ZInt T1 = ZInt.ModPow(2, T, p1 - 1);
		ZInt f1 = ZInt.ModPow(g, T1, p1);
		ZInt T2 = ZInt.ModPow(2, T, p2 - 1);
		ZInt f2 = ZInt.ModPow(g, T2, p2);
		ZInt f = f2 + p2 * (crt * (f1 - f2)).Mod(p1);

		ZInt ell = pc.HashToSmallPrime(g, T, f);
		ZInt r = ZInt.ModPow(2, T, ell);
		ZInt pi1 = ZInt.ModPow(f * ZInt.ModPow(g, p1 - 1 - r, p1),
			ell.ModInverse(p1 - 1), p1);
		ZInt pi2 = ZInt.ModPow(f * ZInt.ModPow(g, p2 - 1 - r, p2),
			ell.ModInverse(p2 - 1), p2);
		ZInt pi = pi2 + p2 * (crt * (pi1 - pi2)).Mod(p1);

		if (!pc.VDFVerify(T, dfd, 0, dfd.Length, f, pi)) {
			throw new Exception("FAIL: synthetic VDF not verified");
		}

		byte[] m2 = new byte[dfd.Length + pc.clen + 2*128];
		Array.Copy(dfd, 0, m2, 0, dfd.Length);
		pc.CounterEncode(T, m2, dfd.Length);
		pc.GroupEncode(f, m2, dfd.Length + pc.clen);
		pc.GroupEncode(pi, m2, dfd.Length + pc.clen + 128);
		byte[] cm2 = pc.Compress(m2);

		// Now, cm2 should be equal to cm1, since messages m1 and m2
		// compress to the same output; but only m1 can be obtained
		// when decompressing back.
		if (m1.Length == m2.Length) {
			throw new Exception("FAIL: all-zeros message did not srhink");
		}
		CheckEquals(cm1, cm2);
		byte[] m3 = pc.Decompress(cm1);
		CheckEquals(m1, m3);

		Console.WriteLine("Self-tests OK.");
	}

	static void CheckEquals(byte[] b1, byte[] b2)
	{
		bool good = b1.Length == b2.Length;
		if (good) {
			for (int i = 0; i < b1.Length; i ++) {
				if (b1[i] != b2[i]) {
					good = false;
					break;
				}
			}
		}
		if (!good) {
			StringBuilder sb = new StringBuilder();
			sb.Append("FAIL: b1 = ");
			foreach (byte b in b1) {
				sb.AppendFormat("{0:x2}", b);
			}
			sb.Append(", b2 = ");
			foreach (byte b in b2) {
				sb.AppendFormat("{0:x2}", b);
			}
			throw new Exception(sb.ToString());
		}
	}
}
