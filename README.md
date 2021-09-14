# Paradoxical Compression

A lossless compression algorithm that can actually reduce the size of
at least one input file must also necessarily expand the size of at
least one other possible input file. This is a direct application of the
[pigeonhole principle](https://en.wikipedia.org/wiki/Pigeonhole_principle).
A compression algorithm that claims to never increase the size of any
input, while at the same time reducing the size of at least *some*
inputs (it's not the trivial do-nothing compression that, by definition,
preserves the length of the input), is called *paradoxical compression*.

Paradoxical compression is mathematically impossible. This repository
contains a [description](doc/paradox-compress.pdf) of how to nonetheless
achieve it, as well as [a demo implementation](src/).

Of course I am slightly cheating here, but the cheat is conceptually
interesting (and fun). The idea is that paradoxical compression might
have only a small density of problematic cases (inputs where the
algorithm misbehaves, e.g. by expanding the length or not decompressing
to the original input) and tools from the field of cryptography can be
used to "push away" these cases so that they mathematically exist but
nobody can find one with nonnegligible probability. In essence, this is
transforming the question from "is it mathematically possible?" to "can
I claim to do it and not being detected as a fraud?". This change of
model makes paradoxical compression possible.

**Warning:** "Paradoxical compression" is only about *not increasing*
the length of any input. This is NOT "infinite compression", in which it
is claimed that every possible input can be *reduced* in size. There
is no shortage of scammers who peddle bogus infinite compression
schemes; what I describe here will not help them. Infinite compression
is mathematically impossible, but a lot more impossible than paradoxical
compression (so to speak). Paradoxical compression can be achieved in
practice because problematic inputs (inputs where two pigeons must be
crammed into the same hole, in the pigeonhole metaphor) are rare and can
be hidden away with cryptographic tools: you won't find such an input
randomly, out of pure luck, the probability of hitting one is way too
low, and the crypto tools can even make it infeasible to find a bad
input on purpose. But with infinite compression, this is not the case:
at least half of all possible inputs are "problematic" (i.e. they reveal
that the claim is bogus, by not being preserved across a
compression/decompression cycle), and thus easy to find (just try random
values!). This is inescapable: one cannot achieve infinite compression
without being quickly detected as a fraud.

**Warning 2:** Paradoxical compression is, practically speaking,
useless. Data compression is useful if used in a context where some
advantage can be leveraged out of shortened data, i.e. in the presence
of some metadata that can identify the length of each individual
message. In almost all cases, an extra "compressed / not compressed"
flag can be smuggled somewhere in such metadata, which is enough to
avoid paylooad expansion through compression without using any of the
stuff described here. Thus, there should be little point in reusing the
methods and codes from this repository in any tangible software project.
As a mathematical recreation, though, paradoxical compression is sort of
fun.

## Mathematical Description

The [paper](doc/paradox-compress.pdf) includes a detailed description
of the concept and its realization. Two instantiations are described:

  - A simple instantiation requires the compressor and decompressor to
    share a secret key; this is a restrictive usage context, but it
    allows for an efficient, low-overhead implementation using only
    a MAC (message authentication code).

  - A more complex instantiation is keyless: no secret is needed, so that
    the compressor and decompressor may, for instance, be code that runs
    on anybody's machine. The cryptographic tool used here is a
    *verifiable delay function* (VDF), specifically the one [described
    by Wesolowski at Eurocrypt 2019](https://eprint.iacr.org/2018/623).

## Implementation

The [src/](src/) subdirectory contains a demo implementation of the
keyless method, with Wesolowski's VDF. It is written in pure C# and is
not especially efficient (it's just a demonstration). It can be built
and executed on Windows, macOS or Linux. On macOS and Linux, you need to
install some C#/.NET support, e.g. [Mono](https://www.mono-project.com/)
(on Ubuntu systems, just install the `mono-devel` package).

To build the code, use the `build.cmd` (on Windows) or `build.sh` (on
Linux and macOS) script. This produces three command-line executables,
`Compress.exe` (to compress a file), `Decompress.exe` (to decompress a
file), and `TestParadoxCompress.exe` (to run self-tests).

In the source code, the [BigInt/](src/BigInt/) directory contains a
general-purpose big integer implementation; it is somewhat faster than
the one that comes with .NET 4.0 in the specific case of big integer
values that happen to be small (i.e. they could fit on 32 bits). It also
offers integer primality tests, which the .NET implementation does not
have; this is used in the paradoxical compression implementation.

The [Crypto/](src/Crypto/) directory contains a straightforward pure C#
implementation of the SHA3 hash function, and the SHAKE extensible
output function (XOF), as specified in [FIPS
202](https://csrc.nist.gov/publications/detail/fips/202/final).

The real core of the implementation is in the
[ParadoxCompress.cs](src/ParadoxCompress.cs) file. I included comments.
Refer to the paper for details.

## License

If you think about reusing this code anywhere, read again the warnings
above.

The SHA3/SHAKE implementations, and the big integer code (`ZInt`
structure), can be useful. Feel free to reuse; license is, formally
speaking, MIT (see the [LICENSE](LICENSE) file), which I understand to
be sort of the default "no worry" license that allows anybody to reuse
the code without making me responsible for anything.
