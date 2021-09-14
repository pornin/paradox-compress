using System;
using System.IO;

/*
 * Entry points for the command-line utilities Compress.exe and Decompress.exe.
 */

class CompressCLI {

	static void Main(string[] args)
	{
		if (args.Length != 2) {
			Console.WriteLine("usage: Compress.exe file_in file_out");
			Environment.Exit(1);
		}
		byte[] data = File.ReadAllBytes(args[0]);
		data = new ParadoxCompress().Compress(data);
		File.WriteAllBytes(args[1], data);
	}
}

class DecompressCLI {

	static void Main(string[] args)
	{
		if (args.Length != 2) {
			Console.WriteLine("usage: Decompress.exe file_in file_out");
			Environment.Exit(1);
		}
		byte[] data = File.ReadAllBytes(args[0]);
		data = new ParadoxCompress().Decompress(data);
		File.WriteAllBytes(args[1], data);
	}
}
