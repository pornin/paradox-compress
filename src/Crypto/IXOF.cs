using System;

namespace Crypto {

public interface IXOF {

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
	 * Flip to output mode. Update() methods may be called only in
	 * input mode; Next() methods may be called only in output mode.
	 */
	void Flip();

	/*
	 * Get next output byte.
	 */
	byte Next();

	/*
	 * Get next output bytes.
	 */
	void Next(byte[] buf);

	/*
	 * Get next output bytes.
	 */
	void Next(byte[] buf, int off, int len);

	/*
	 * Reset the internal state, to start a new computation, in input
	 * mode. This can be called at any time.
	 */
	void Reset();
}

}
