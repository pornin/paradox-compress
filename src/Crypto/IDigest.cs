using System;

namespace Crypto {

/*
 * This interface qualifies a hash function implementation.
 */

public interface IDigest {

	/*
	 * Add one byte to the current input.
	 */
	void Update(byte b);

	/*
	 * Add some bytes to the current input.
	 */
	void Update(byte[] buf);

	/*
	 * Add some bytes to the current input ('len' bytes from buf[],
	 * starting at offset 'off').
	 */
	void Update(byte[] buf, int off, int len);

	/*
	 * Finalize the hash computation and write the output in the
	 * provided outBuf[] array (starting at offset 'off'). This
	 * instance is also automatically reset (as if by a Reset() call).
	 */
	void DoFinal(byte[] outBuf, int off);

	/*
	 * Finalize the hash computation and write the output into a
	 * newly allocated buffer, which is returned. This instance
	 * is also automatically reset (as if by a Reset() call).
	 */
	byte[] DoFinal();

	/*
	 * Reset the internal state, to start a new computation. This
	 * can be called at any time.
	 */
	void Reset();
}

}
