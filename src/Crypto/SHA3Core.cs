using System;

namespace Crypto {

public abstract class SHA3Core : IDigest {

	int bitlen;
	KeccakCore core;

	internal SHA3Core(int bitlen)
	{
		this.bitlen = bitlen;
		core = new KeccakCore(bitlen << 1);
	}

	public void Reset()
	{
		core.Reset(bitlen << 1);
	}

	public void Update(byte x)
	{
		core.Update(x);
	}

	public void Update(byte[] buf)
	{
		core.Update(buf);
	}

	public void Update(byte[] buf, int off, int len)
	{
		core.Update(buf, off, len);
	}

	public byte[] DoFinal()
	{
		byte[] buf = new byte[bitlen >> 3];
		DoFinal(buf, 0);
		return buf;
	}

	public void DoFinal(byte[] buf, int off)
	{
		core.Flip(false);
		core.Next(buf, off, bitlen >> 3);
		core.Reset(bitlen << 1);
	}
}

}
