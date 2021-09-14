%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe /nologo /target:exe /out:Compress.exe /main:CompressCLI *.cs BigInt\*.cs Crypto\*.cs
%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe /nologo /target:exe /out:Decompress.exe /main:DecompressCLI *.cs BigInt\*.cs Crypto\*.cs
%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe /nologo /target:exe /out:TestParadoxCompress.exe /main:ParadoxCompress *.cs BigInt\*.cs Crypto\*.cs
