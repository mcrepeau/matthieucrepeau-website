---
title: "Implementing the CubeHash hashing algorithm in Rust"
date: 2025-09-19
tags: ["rust", "hashing", "cryptography", "algorithms"]
---

## Background

Back during the dark gloomy days of the COVID pandemic, I set out to put my time to good use and teach myself Rust (among other, less esoteric endeavors like sourdough bread). My starting point was obviously to follow the Rust manual but I was eager to get my hands dirty and code something that would go beyond the canned examples provided in the guide without being overly complex to keep me motivated to follow through with my learning experience. At the same time, I was also digging into the technical details of how Bitcoin works which led me down a hashing algorithm rabbit hole that ended (or started, really) with looking at the submissions for the [NIST Hash Function Competition](https://en.wikipedia.org/wiki/NIST_hash_function_competition).

One of the submissions caught my attention because of its simplicity: [Cubehash](https://cubehash.cr.yp.to/). I don't have a background in cryptography and the intricate mathematical theory behind it often flies over my head but I found the Add-Rotate-XOR structure of Cubehash to be elegant and easy enough to understand that I could easily implement it (and debug it).
There are no field arithmetics, complex permutations, lookup tables or anything remotely exotic, there are 10 simple operations executed in the same order over multiple rounds on 32-byte words with just a few parameters: the number of initialization rounds, the number of rounds per block, the number of bytes per block, the number of finalization rounds and the number of output bits.

There was already [a C99 implementation](https://github.com/DennisMitchell/cubehash) itself based off of the original implementation by the author of CubeHash that could serve as a template for my Rust port. That implementation used 128-bit instructions which are particularly well suited to this since we are running operation on 32-byte words which fully utilizes the 128 bits registers that instruction set provides. However this means that, as-is, the code wouldn't run on anything other than x86 CPUs.

Therefore, my first step was to implement a generic version that could work on any architecture, using a struct of 4 unsigned integers to serve as the 32-byte word which implements the basic operations. I got a first version working well with this scalar implementation and I was able to easily port the C99 code since the SIMD operations are the same. The whole thing performed a bit slower than the C99 implementation and was rather basic, ingesting data piped in through stdin but I left it at that at the time.

## New beginnings

Fast forward to late last year and I decided to reprise this project and "complete" the vision I had initially by: 
- Adding support for streaming data
- Adding SIMD implementations for more architectures (most notably ARM NEON and AVX2)
- Optimizing performance & cleaning up the implementation
- Exposing an API and wrapper methods (CubeHash-256, CubeHash-384, CubeHash-512)

This would require a major refactor with feature and architecture flags to gate the different code paths as well as the implementation of a new pattern in order to be able to hash data as it is consumed when used as a library and of course exposing convenient APIs. As such, it is quite an expansion over the initial C99 implementation but it is also a great learning experience and to the best of my knowledge, this kind of implementation wasn't done for CubeHash before.

## The work ahead

### Making the code portable with a pure Rust implementation

In order to be able to compile this code on any architecture, we need to rewrite the hashing algorithm using common data structures and operations. One ground rule for me here is that this should also be written without using unsafe Rust.

Let's start by defining a struct of 4 unsigned integers to serve as the 32-byte word:

```Rust
#[derive(Clone, Copy)]
struct U32x4([u32; 4]);
```

We can then define basic operations using/implementing this struct:

```Rust
 #[inline(always)]
    fn add(v: U32x4, w: U32x4) -> U32x4 {
        U32x4([
            v.0[0].wrapping_add(w.0[0]),
            v.0[1].wrapping_add(w.0[1]),
            v.0[2].wrapping_add(w.0[2]),
            v.0[3].wrapping_add(w.0[3]),
        ])
    }

    #[inline(always)]
    fn xor(v: U32x4, w: U32x4) -> U32x4 {
        U32x4([v.0[0] ^ w.0[0], v.0[1] ^ w.0[1], v.0[2] ^ w.0[2], v.0[3] ^ w.0[3]])
    }

    #[inline(always)]
    fn shlxor<const N: u32>(v: U32x4) -> U32x4 {
        U32x4([
            (v.0[0].wrapping_shl(N)) ^ (v.0[0].wrapping_shr(32 - N)),
            (v.0[1].wrapping_shl(N)) ^ (v.0[1].wrapping_shr(32 - N)),
            (v.0[2].wrapping_shl(N)) ^ (v.0[2].wrapping_shr(32 - N)),
            (v.0[3].wrapping_shl(N)) ^ (v.0[3].wrapping_shr(32 - N)),
        ])
    }

    impl U32x4 {
        #[inline(always)]
        fn new(a: u32, b: u32, c: u32, d: u32) -> Self {
            U32x4([a, b, c, d])
        }

        #[inline(always)]
        fn permute_badc(self) -> U32x4 {
            U32x4([self.0[1], self.0[0], self.0[3], self.0[2]])
        }

        #[inline(always)]
        fn permute_cdab(self) -> U32x4 {
            U32x4([self.0[2], self.0[3], self.0[0], self.0[1]])
        }

        ...
    }
```

And finally we can use these operations to rewrite the CubeHash loop:

```Rust
#[inline(always)]
fn rounds(&mut self) {
    for _ in 0..ROUNDS {
        self.x4 = add(self.x0, self.x4.permute_badc());
        self.x5 = add(self.x1, self.x5.permute_badc());
        self.x6 = add(self.x2, self.x6.permute_badc());
        self.x7 = add(self.x3, self.x7.permute_badc());

        let t0 = shlxor::<7>(self.x2);
        let t1 = shlxor::<7>(self.x3);
        let t2 = shlxor::<7>(self.x0);
        let t3 = shlxor::<7>(self.x1);

        self.x0 = xor(t0, self.x4);
        self.x1 = xor(t1, self.x5);
        self.x2 = xor(t2, self.x6);
        self.x3 = xor(t3, self.x7);

        self.x4 = add(self.x0, self.x4.permute_cdab());
        self.x5 = add(self.x1, self.x5.permute_cdab());
        self.x6 = add(self.x2, self.x6.permute_cdab());
        self.x7 = add(self.x3, self.x7.permute_cdab());

        let u0 = shlxor::<11>(self.x1);
        let u1 = shlxor::<11>(self.x0);
        let u2 = shlxor::<11>(self.x3);
        let u3 = shlxor::<11>(self.x2);

        self.x0 = xor(u0, self.x4);
        self.x1 = xor(u1, self.x5);
        self.x2 = xor(u2, self.x6);
        self.x3 = xor(u3, self.x7);
    }
}
```

This not only guarantees that the code will compile on any platform but it also gives the opportunity for the Rust compiler to optimize this code as it sees fit, as we will see later.

### Decoupling the implementation to allow streaming data

The original implementation had a single function that would take a buffer, hash its content and return the hash. It can be summarized by the following flowchart: 

{{< mermaid >}}
flowchart TD
    O1[Input buffer] --> O2[Hash block] --> O3{More data?}
    O3 -- Yes --> O2
    O3 -- No --> O4[Pad + hash last block] --> O5[Set finalize flag + run final hash rounds]
    O5 --> O6([Digest])
{{< /mermaid >}}

It works well for a one-shot hashing operation but it makes it unsuitable for use as a library where we want to be able to stream the data to be hashed for efficiency. What we want is a method (update) that we can call repeatedly to feed the hasher with data and a finalize method to get the final hash. It would look something like this:

{{< mermaid >}}
flowchart TD
    U[/update/] --> S1[Make block with leftover bytes + new bytes] --> S2[Hash block]
    S2 --> S3{More data?}
    S3 -- Yes --> S4{Full block?}
    S3 -- No --> S6([End])
    S4 -- Yes --> S2
    S4 -- No --> S0([Store leftover bytes])

    F[/finalize/] --> S7[Pad + hash last block]
    S7 --> S8[Set finalize flag + run final hash rounds]
    S8 --> Done([Digest])
{{< /mermaid >}}

So now let's say we want to hash the string "hello world!", we can call:
```Rust
let mut hash = CubeHash::new()
hash.update(b"hello ");
hash.update(b"world!");
let digest = hash.finalize();
```
and we don't need to allocate the memory required to store the whole string if we don't want to.

And, for convenience, we can also define a digest method which handles the creation/update/finalization under the hood:

```Rust
let digest = CubeHash::digest(b"hello world");
```

### Supporting more architectures

Using feature/architecture gates, we can select certain code paths at compile time. For example, we can define:
```Rust
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2", not(feature = "force-scalar")))]
pub type CubeHashBest = CubeHash<crate::avx2::AVX2>;

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "avx2"), not(feature = "force-scalar")))]
pub type CubeHashBest = CubeHash<crate::sse2::SSE2>;
```

in order to use the AVX2 implementation if the target architecture supports it, and the SSE2 implementation otherwise.

#### AVX2

With AVX2 the width of the SIMD registers is increased from 128 bits to 256 bits, we could just keep the structure the same by replacing the 128-bit instructions with 256-bit ones and still get some performance benefit thanks to the compiler optimization but that would mean grossly underutilizing the 256-bit registers. These 256-bit instructions bring some interesting opportunities for speed improvements if we are willing to make some code changes -- the idea being that we can pack two 128-bit values into one 256-bit register and run operations on the whole thing, reducing the number of instructions necessary to perform each step.

For example, it means that the Add + Shuffle goes from:
```Rust
x4 = add(x0, shuffle(x4, 0xb1));
x5 = add(x1, shuffle(x5, 0xb1));
x6 = add(x2, shuffle(x6, 0xb1));
x7 = add(x3, shuffle(x7, 0xb1));
```
to:
```Rust
v45 = add(v01, shuffle(v45, 0xb1));
v67 = add(v23, shuffle(v67, 0xb1));
```

The same applies to the rotation and XOR operations. This greatly reduces the number of operations. However, shuffle operations only work inside each 128-bit lane - they cannot move data across the 128-bit boundary. To actually swap the low 128 bits ↔ high 128 bits, AVX2 only gives us `_mm256_permute2x128_si256` which is a particularly costly instruction but the overall performance gains on the rest of the code should more than make up for this.

#### NEON

The port using NEON instructions is relatively straightforward as it just requires importing the right operations and replacing them in the algorithm:

- add: `vaddq_u32`
- shift left: `vshlq_n_u32`
- shift right: `vshrq_n_u32`
- xor: `veorq_u32`

The only change is for the shuffle operation which is a bit different as far as the implementation goes. Instead of calling shuffle operations and using a control parameter to define the shuffles, we can use the following operations:
- reverse shuffle (ABCD -> CDBA): `vrev64q_u32`
- shuffle pairs (ABCD -> CDAB): `vextq_u32::<2>`

### Performance analysis on x86_64

- CPU: Intel Core Ultra 7 265K w/ 32GB RAM
- OS: Windows 11H25
- Software: CubeHash C99 & CubeHash 0.4.1 - 8KB buffer size

#### C99 Baseline

Let's use the C99 code to establish a baseline. Since I am running Windows and that code was written with POSIX functions, I had to [modify it a bit](https://github.com/DennisMitchell/cubehash/compare/master...mcrepeau:cubehash-c99:master) and I am using Zig to compile it, for convenience:
```bash
zig cc -O3 -std=c99 -o cubehash.exe main.c cubehash.c
```

I used dd on MinGW64 to generate the test files (1M, 10M, 100M, 256M, 512M, 1G, 2G):
```bash
dd if=/dev/zero bs=1M count=100 of=100M.file
```

And I wrote a bash script to run a hash 5 times per file size and time each run.

#### Rust with 128-bit instructions

In order to compare apples-to-apples, I used the same 128-bit SIMD instructions in Rust as in C99 and compiled in release mode with the following parameters in my `Cargo.toml`:
```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
```

And I am compiling using:
```bash
$env:RUSTFLAGS = "-C target-feature=-avx2,+avx"
cargo build --release
```
in order to bypass the AVX2 code path and force the SSE code path

| File size | C99 (128-bit SIMD) | Rust (128-bit SIMD) | Delta |
|-----|-----|-----|----|
| 1 MB | 58.82  | 58.14 | -1.2% |
| 10 MB | 301.20  | 295.86 | -1.7% |
| 100 MB | 528.54 | 526.32 | -0.4% |
| 256 MB | 575.02 | 579.71 | +0.8% |
| 512 MB | 587.83 | 591.22 | +0.6% |
| 1 GB | 598.05 | 598.09   | 0% |
| 2 GB | 603.76 | 603.72   | 0% |
*Methodology: average of 5 runs of Cubehash rev3 256bits. Throughput in MB/s*

We can see that the Rust code and the C99 implementations are neck and neck and the performance is within the margin of error. 

#### Rust with 256-bit instructions (AVX2)

In order to compile the AVX2 code path, I have to reset the Rust flags to use all the features available on my CPU:
```bash
$env:RUSTFLAGS = "-C target-cpu=native"
cargo build --release
```
And now the performance is much improved:
| File size | Rust (128-bit SIMD) | Rust (256-bit SIMD) | Delta |
|-----|-----|-----|----|
| 1 MB | 58.14  | 58.82 | +1.2% |
| 10 MB | 295.86  | 322.58 | +9% |
| 100 MB | 526.32 | 586.17 | +11.4% |
| 256 MB | 579.71 | 631.79 | +9% |
| 512 MB | 591.22 | 640.00 | +8.3% |
| 1 GB | 598.09 | 660.07 | +10.4% |
| 2 GB | 603.72 | 641.35 | +6.2% |

It looks like those expensive permutations are worth it for a 10% performance gain!

#### Pure Rust (Scalar)

Now let's see how the Rust compiler does when compiling the Pure Rust code path:
```bash
cargo build --release --features force-scalar
```

| File size | Rust (256-bit SIMD) | Pure Rust | Delta |
|-----|-----|-----|----|
| 1 MB | 58.82  | 60.24 | +2.4% |
| 10 MB | 322.58  | 316.46 | -1.9% |
| 100 MB | 586.17 | 563.06 | -3.9% |
| 256 MB | 631.79 | 607.50 | -3.8% |
| 512 MB | 640.00 | 623.63 | -2.6% |
| 1 GB | 660.07 | 635.65 | -3.7% |
| 2 GB | 641.35 | 631.43 | -1.5% |

The results are within the margin of error, which means that the compiler is able to optimize the pure Rust just as well as I am able to write the SIMD code directly.
And by de-compiling the code with `llvm-objdump`, we can see that the compiler is also using those permutations and hasn't found a way around it either:
```ASM
1400022fe: c4 e3 fd 00 d2 4e           	vpermq	$0x4e, %ymm2, %ymm2     # ymm2 = ymm2[2,3,0,1]
140002304: c5 e5 ef da                 	vpxor	%ymm2, %ymm3, %ymm3
140002308: c4 e3 fd 00 d4 4e           	vpermq	$0x4e, %ymm4, %ymm2     # ymm2 = ymm4[2,3,0,1]
14000230e: c5 d5 ef d2                 	vpxor	%ymm2, %ymm5, %ymm2
```

Plotting it all against the C99 data gives us the following chart:

{{< chart >}}
type: 'line',
options: {
  scales: {
    y: {
      display: true,
      title: {
        display: true,
        text: 'Throughput (MB/s)'
      }
    }
  }
},
data: {
  labels: ['1MB', '10MB', '100MB', '256MB', '512MB', '1GB', '2GB'],
  datasets: [{
    label: 'C99',
    data: [59, 301, 528, 575, 588, 598, 603],
    tension: 0.4,
    borderColor: 'red',
    backgroundColor: 'red'
  },
  {
    label: 'Rust (128-bit SIMD)',
    data: [58, 296, 526, 580, 591, 598, 604],
    tension: 0.4,
    borderColor: 'green',
    backgroundColor: 'green'
  },
  {
    label: 'Pure Rust',
    data: [60, 316, 563, 607, 624, 636, 631],
    tension: 0.4,
    borderColor: 'yellow',
    backgroundColor: 'yellow'
  }]
}
{{< /chart >}}


### Comparing performance to SHA3-256 (Keccak)

#### Windows 11

Back to the NIST Hash Function Competition, the victor was a hashing algorithm called Keccak. Keccak is a sponge-based cryptographic hash function that absorbs input data into a large internal state using XOR, then repeatedly applies a permutation to thoroughly scramble the bits. Once all input is absorbed, the algorithm “squeezes” out the hash by reading parts of the state. It is now included in most crypto tools and on Windows we can hash a file easily out of the box with SHA3-256 using certutil:
```bash
certutil -hashfile 100M.file SHA3-256
```

We can also install OpenSSL for Windows and run:
```bash
openssl.exe sha3-256 100M.file
```

Sadly we can't control what the input buffer size is but OpenSSL uses 8KB buffer which makes it fit for a direct comparison with the CubeHash benchmarks. It also has the added convenience of being available on Unix systems with the same syntax.
Let's see what the performance of certutil and OpenSSL look like:

{{< chart >}}
type: 'line',
options: {
  scales: {
    y: {
      display: true,
      title: {
        display: true,
        text: 'Throughput (MB/s)'
      }
    }
  }
},
data: {
  labels: ['1MB', '10MB', '100MB', '256MB', '512MB', '1GB', '2GB'],
  datasets: [{
    label: 'Certutil SHA3-256',
    data: [13, 130, 452, 541, 567, 583, 600],
    tension: 0.4,
    borderColor: 'red',
    backgroundColor: 'red'
  },
  {
    label: 'OpenSSL SHA3-256',
    data: [13, 140, 513, 578, 598, 624, 633],
    tension: 0.4,
    borderColor: 'green',
    backgroundColor: 'green'
  },
  {
    label: 'Pure Rust CubeHash',
    data: [60, 316, 563, 607, 624, 636, 631],
    tension: 0.4,
    borderColor: 'yellow',
    backgroundColor: 'yellow'
  }]
}
{{< /chart >}}

OpenSSL is faster than certutil for SHA3-256 and although both are much slower than Cubehash at small file sizes, they end up progressively closing the gap with OpenSSL, matching Cubehash's performance at 2GB file size. Of course OpenSSL was not compiled with the same level of optimization as CubeHash so the comparison isn't quite fair since x86_64 binaries typically ship with SSE2 instructions.
But even if we use CubeHash with 128-bit SIMD as the basis for comparison, it still fares better than certutil and hold its own compared to OpenSSL.

| File size | Pure Rust CubeHash | OpenSSL SHA3-256 | Certutil SHA3-256 |
|-----|-----|-----|----|
| 1 MB | 60.24  | 13.19 | 12.82 |
| 10 MB | 316.46  | 140.06 | 129.87 |
| 100 MB | 563.06 | 512.82 | 452.49 |
| 256 MB | 607.50 | 578.14 | 540.54 |
| 512 MB | 623.63 | 597.85 | 567.12 |
| 1 GB | 635.65 | 624.53 | 583.09 |
| 2 GB | 631.43 | 633.39 | 600.28 |


### Conclusion

The goal of this exercise, beyond the learning experience, was to see if I could write a hashing algorithm in Rust from scratch that could both match (or exceed) the performance of its reference implementation and also be competitive over readily available SHA3-256 alternatives.
On a PC, we have proven that this is the case, I have actually implemented something that could reasonably be used for small or large file hashing and I have decided to package it as a [library published on Crates.io](https://crates.io/crates/cubehash) with east-to-use wrapper methods.

You can also find the code [here](https://github.com/mcrepeau/cubehash)


### Future improvements

Potential follow ups to this work could be:

- Adding AVX-512 intrinsics: unfortunately, with the introduction of E-cores in Alder Lake processors, Intel removed support for the AVX-512 instructions it had introduced with its 11th generation so I'm out of luck for developing with AVX-512 SIMD, unless I get my hands on a Rocket Lake CPU or an AMD Zen one. Implementing AVX-512 efficiently would probably require a significant refactor and it is unclear how much performance we could gain from it but it would certainly be an interesting challenge!
- Compiling for WebAssembly: A WASM target would allow Cubehash to run client-side in a web browser which would allow us to serve a static website and provide Cubehash to a user without knowing anything about what is being hashed and still offering high performance. This is most likely what I will work on next!