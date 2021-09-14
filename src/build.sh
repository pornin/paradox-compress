#! /bin/sh

CSC=$(which mono-csc || which dmcs || echo "none")

if [ "$CSC" = "none" ]; then
	echo "Error: Please install mono-devel."
	exit 1
fi

set -e

"$CSC" /debug+ /out:Compress.exe /main:CompressCLI *.cs BigInt/*.cs Crypto/*.cs
"$CSC" /debug+ /out:Decompress.exe /main:DecompressCLI *.cs BigInt/*.cs Crypto/*.cs
"$CSC" /debug+ /out:TestParadoxCompress.exe /main:ParadoxCompress *.cs BigInt/*.cs Crypto/*.cs
