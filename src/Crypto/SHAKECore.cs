using System;

namespace Crypto {

public abstract class SHAKECore : IXOF {

	KeccakCore core;

	internal SHAKECore(int bitlen)
	{
		core = new KeccakCore(bitlen << 1);
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

	public void Flip()
	{
		core.Flip(true);
	}

	public byte Next()
	{
		return core.Next();
	}

	public void Next(byte[] buf)
	{
		core.Next(buf);
	}

	public void Next(byte[] buf, int off, int len)
	{
		core.Next(buf, off, len);
	}

	public void Reset()
	{
		core.Reset();
	}
}

}
