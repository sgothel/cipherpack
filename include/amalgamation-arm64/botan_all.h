/*
* Botan 3.0.0-alpha0 Amalgamation
* (C) 1999-2020 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AMALGAMATION_H_
#define BOTAN_AMALGAMATION_H_

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <functional>
#include <iosfwd>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

/*
* Build configuration for Botan 3.0.0-alpha0
*
* Automatically generated from
* 'configure.py --cpu=aarch64 --prefix=/usr/local/projects/zafena/cipherpack/botan/dist-arm64-min --minimized-build --enable-modules=base,pubkey,rsa,x509,eme_oaep,eme_raw,emsa1,emsa_raw,pbes2,eme_pkcs1,emsa_pkcs1,chacha,chacha20poly1305,aead,stream,sha1,sha2_32,system_rng,sha1_armv8,sha2_32_armv8,simd,chacha_simd32,chacha_avx2,simd_avx2 --cxxflags= --ldflags= --amalgamation --with-doxygen'
*
* Target
*  - Compiler: g++ -fstack-protector -pthread -std=c++17 -D_REENTRANT -O3
*  - Arch: arm64
*  - OS: linux
*/

#define BOTAN_VERSION_MAJOR 3
#define BOTAN_VERSION_MINOR 0
#define BOTAN_VERSION_PATCH 0
#define BOTAN_VERSION_DATESTAMP 0

#define BOTAN_VERSION_SUFFIX -alpha0
#define BOTAN_VERSION_SUFFIX_STR "-alpha0"

#define BOTAN_VERSION_RELEASE_TYPE "unreleased"

#define BOTAN_VERSION_VC_REVISION "git:15228710faef1b85aaad0cad4f207b8b6dfcdf74"

#define BOTAN_DISTRIBUTION_INFO "unspecified"

/* How many bits per limb in a BigInt */
#define BOTAN_MP_WORD_BITS 64


#define BOTAN_INSTALL_PREFIX R"(/usr/local/projects/zafena/cipherpack/botan/dist-arm64-min)"
#define BOTAN_INSTALL_HEADER_DIR R"(include/botan-3)"
#define BOTAN_INSTALL_LIB_DIR R"(/usr/local/projects/zafena/cipherpack/botan/dist-arm64-min/lib)"
#define BOTAN_LIB_LINK ""
#define BOTAN_LINK_FLAGS "-fstack-protector -pthread"

#define BOTAN_SYSTEM_CERT_BUNDLE "/etc/ssl/certs/ca-certificates.crt"

#ifndef BOTAN_DLL
  #define BOTAN_DLL __attribute__((visibility("default")))
#endif

/* Target identification and feature test macros */

#define BOTAN_TARGET_OS_IS_LINUX

#define BOTAN_TARGET_OS_HAS_ATOMICS
#define BOTAN_TARGET_OS_HAS_CLOCK_GETTIME
#define BOTAN_TARGET_OS_HAS_DEV_RANDOM
#define BOTAN_TARGET_OS_HAS_FILESYSTEM
#define BOTAN_TARGET_OS_HAS_GETAUXVAL
#define BOTAN_TARGET_OS_HAS_POSIX1
#define BOTAN_TARGET_OS_HAS_POSIX_MLOCK
#define BOTAN_TARGET_OS_HAS_PRCTL
#define BOTAN_TARGET_OS_HAS_PROC_FS
#define BOTAN_TARGET_OS_HAS_SOCKETS
#define BOTAN_TARGET_OS_HAS_THREAD_LOCAL
#define BOTAN_TARGET_OS_HAS_THREADS


#define BOTAN_BUILD_COMPILER_IS_GCC




#define BOTAN_TARGET_ARCH_IS_ARM64
#define BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN
#define BOTAN_TARGET_CPU_IS_ARM_FAMILY
#define BOTAN_TARGET_CPU_HAS_NATIVE_64BIT

#define BOTAN_TARGET_SUPPORTS_ARMV8CRYPTO
#define BOTAN_TARGET_SUPPORTS_ARMV8SHA3
#define BOTAN_TARGET_SUPPORTS_ARMV8SHA512
#define BOTAN_TARGET_SUPPORTS_ARMV8SM3
#define BOTAN_TARGET_SUPPORTS_ARMV8SM4
#define BOTAN_TARGET_SUPPORTS_NEON





/*
* Module availability definitions
*/
#define BOTAN_HAS_AEAD_CHACHA20_POLY1305 20180807
#define BOTAN_HAS_AEAD_MODES 20131128
#define BOTAN_HAS_ASN1 20201106
#define BOTAN_HAS_BASE64_CODEC 20131128
#define BOTAN_HAS_BIGINT 20210423
#define BOTAN_HAS_BIGINT_MP 20151225
#define BOTAN_HAS_BLOCK_CIPHER 20131128
#define BOTAN_HAS_CHACHA 20180807
#define BOTAN_HAS_CHACHA_SIMD32 20181104
#define BOTAN_HAS_CIPHER_MODES 20180124
#define BOTAN_HAS_CIPHER_MODE_PADDING 20131128
#define BOTAN_HAS_CPUID 20170917
#define BOTAN_HAS_EME_OAEP 20180305
#define BOTAN_HAS_EME_PKCS1 20190426
#define BOTAN_HAS_EME_PKCS1v15 20131128
#define BOTAN_HAS_EME_RAW 20150313
#define BOTAN_HAS_EMSA1 20131128
#define BOTAN_HAS_EMSA_PKCS1 20140118
#define BOTAN_HAS_EMSA_PSSR 20131128
#define BOTAN_HAS_EMSA_RAW 20131128
#define BOTAN_HAS_ENTROPY_SOURCE 20151120
#define BOTAN_HAS_HASH 20180112
#define BOTAN_HAS_HASH_ID 20131128
#define BOTAN_HAS_HEX_CODEC 20131128
#define BOTAN_HAS_HMAC 20131128
#define BOTAN_HAS_KDF_BASE 20131128
#define BOTAN_HAS_MAC 20150626
#define BOTAN_HAS_MDX_HASH_FUNCTION 20131128
#define BOTAN_HAS_MGF1 20140118
#define BOTAN_HAS_MODES 20150626
#define BOTAN_HAS_MODE_CBC 20131128
#define BOTAN_HAS_NUMBERTHEORY 20201108
#define BOTAN_HAS_OCSP 20201106
#define BOTAN_HAS_PASSWORD_HASHING 20210419
#define BOTAN_HAS_PBKDF 20180902
#define BOTAN_HAS_PBKDF2 20180902
#define BOTAN_HAS_PEM_CODEC 20131128
#define BOTAN_HAS_PKCS5_PBES2 20141119
#define BOTAN_HAS_PK_PADDING 20131128
#define BOTAN_HAS_POLY1305 20141227
#define BOTAN_HAS_PUBLIC_KEY_CRYPTO 20131128
#define BOTAN_HAS_RSA 20160730
#define BOTAN_HAS_SHA1 20131128
#define BOTAN_HAS_SHA1_ARMV8 20170117
#define BOTAN_HAS_SHA2_32 20131128
#define BOTAN_HAS_SHA2_32_ARMV8 20170117
#define BOTAN_HAS_SIMD_32 20131128
#define BOTAN_HAS_STREAM_CIPHER 20131128
#define BOTAN_HAS_SYSTEM_RNG 20141202
#define BOTAN_HAS_UTIL_FUNCTIONS 20180903
#define BOTAN_HAS_X509 20201106
#define BOTAN_HAS_X509_CERTIFICATES 20201106


/*
* Local/misc configuration options (if any) follow
*/


/*
* Things you can edit (but probably shouldn't)
*/

/* How much to allocate for a buffer of no particular size */
#define BOTAN_DEFAULT_BUFFER_SIZE 1024

/*
* Total maximum amount of RAM (in KiB) we will lock into memory, even
* if the OS would let us lock more
*/
#define BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB 512

/*
* If BOTAN_MEM_POOL_USE_MMU_PROTECTIONS is defined, the Memory_Pool
* class used for mlock'ed memory will use OS calls to set page
* permissions so as to prohibit access to pages on the free list, then
* enable read/write access when the page is set to be used. This will
* turn (some) use after free bugs into a crash.
*
* The additional syscalls have a substantial performance impact, which
* is why this option is not enabled by default.
*/
#if defined(BOTAN_HAS_VALGRIND) || defined(BOTAN_ENABLE_DEBUG_ASSERTS)
   #define BOTAN_MEM_POOL_USE_MMU_PROTECTIONS
#endif

/*
* If enabled uses memset via volatile function pointer to zero memory,
* otherwise does a byte at a time write via a volatile pointer.
*/
#define BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO 1

/*
* Normally blinding is performed by choosing a random starting point (plus
* its inverse, of a form appropriate to the algorithm being blinded), and
* then choosing new blinding operands by successive squaring of both
* values. This is much faster than computing a new starting point but
* introduces some possible corelation
*
* To avoid possible leakage problems in long-running processes, the blinder
* periodically reinitializes the sequence. This value specifies how often
* a new sequence should be started.
*/
#define BOTAN_BLINDING_REINIT_INTERVAL 64

/*
* Userspace RNGs like HMAC_DRBG will reseed after a specified number
* of outputs are generated. Set to zero to disable automatic reseeding.
*/
#define BOTAN_RNG_DEFAULT_RESEED_INTERVAL 1024
#define BOTAN_RNG_RESEED_POLL_BITS 256

#define BOTAN_RNG_AUTO_RESEED_TIMEOUT std::chrono::milliseconds(10)
#define BOTAN_RNG_RESEED_DEFAULT_TIMEOUT std::chrono::milliseconds(50)

/*
* Specifies (in order) the list of entropy sources that will be used
* to seed an in-memory RNG.
*/
#define BOTAN_ENTROPY_DEFAULT_SOURCES \
   { "rdseed", "hwrng", "getentropy", "system_rng", "system_stats" }

/* Multiplier on a block cipher's native parallelism */
#define BOTAN_BLOCK_CIPHER_PAR_MULT 4

/*
* This directory will be monitored by ProcWalking_EntropySource and
* the contents provided as entropy inputs to the RNG. May also be
* usefully set to something like "/sys", depending on the system being
* deployed to. Set to an empty string to disable.
*/
#define BOTAN_ENTROPY_PROC_FS_PATH "/proc"

/*
* These paramaters control how many bytes to read from the system
* PRNG, and how long to block if applicable. The timeout only applies
* to reading /dev/urandom and company.
*/
#define BOTAN_SYSTEM_RNG_POLL_REQUEST 64
#define BOTAN_SYSTEM_RNG_POLL_TIMEOUT_MS 20

/*
* When a PBKDF is self-tuning parameters, it will attempt to take about this
* amount of time to self-benchmark.
*/
#define BOTAN_PBKDF_TUNING_TIME std::chrono::milliseconds(10)

/*
* If no way of dynamically determining the cache line size for the
* system exists, this value is used as the default. Used by the side
* channel countermeasures rather than for alignment purposes, so it is
* better to be on the smaller side if the exact value cannot be
* determined. Typically 32 or 64 bytes on modern CPUs.
*/
#if !defined(BOTAN_TARGET_CPU_DEFAULT_CACHE_LINE_SIZE)
  #define BOTAN_TARGET_CPU_DEFAULT_CACHE_LINE_SIZE 32
#endif

/**
* Controls how AutoSeeded_RNG is instantiated
*/
#if !defined(BOTAN_AUTO_RNG_HMAC)

  #if defined(BOTAN_HAS_SHA2_64)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-384)"
  #elif defined(BOTAN_HAS_SHA2_32)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-256)"
  #elif defined(BOTAN_HAS_SHA3)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-3(256))"
  #elif defined(BOTAN_HAS_SHA1)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-1)"
  #endif
  /* Otherwise, no hash found: leave BOTAN_AUTO_RNG_HMAC undefined */

#endif

/* Check for a common build problem */

#if defined(BOTAN_TARGET_ARCH_IS_X86_64) && ((defined(_MSC_VER) && !defined(_WIN64)) || \
                                             (defined(__clang__) && !defined(__x86_64__)) || \
                                             (defined(__GNUG__) && !defined(__x86_64__)))
    #error "Trying to compile Botan configured as x86_64 with non-x86_64 compiler."
#endif

#if defined(BOTAN_TARGET_ARCH_IS_X86_32) && ((defined(_MSC_VER) && defined(_WIN64)) || \
                                             (defined(__clang__) && !defined(__i386__)) || \
                                             (defined(__GNUG__) && !defined(__i386__)))

    #error "Trying to compile Botan configured as x86_32 with non-x86_32 compiler."
#endif

/* Should we use GCC-style inline assembler? */
#if defined(BOTAN_BUILD_COMPILER_IS_GCC) || \
   defined(BOTAN_BUILD_COMPILER_IS_CLANG) || \
   defined(BOTAN_BUILD_COMPILER_IS_XLC) || \
   defined(BOTAN_BUILD_COMPILER_IS_SUN_STUDIO)

  #define BOTAN_USE_GCC_INLINE_ASM
#endif

/**
* Used to annotate API exports which are public and supported.
* These APIs will not be broken/removed unless strictly required for
* functionality or security, and only in new major versions.
* @param maj The major version this public API was released in
* @param min The minor version this public API was released in
*/
#define BOTAN_PUBLIC_API(maj,min) BOTAN_DLL

/**
* Used to annotate API exports which are public, but are now deprecated
* and which will be removed in a future major release.
*/
#define BOTAN_DEPRECATED_API(msg) BOTAN_DLL BOTAN_DEPRECATED(msg)

/**
* Used to annotate API exports which are public and can be used by
* applications if needed, but which are intentionally not documented,
* and which may change incompatibly in a future major version.
*/
#define BOTAN_UNSTABLE_API BOTAN_DLL

/**
* Used to annotate API exports which are exported but only for the
* purposes of testing. They should not be used by applications and
* may be removed or changed without notice.
*/
#define BOTAN_TEST_API BOTAN_DLL

/*
* Define BOTAN_FUNC_ISA
*/
#if defined(__GNUC__) || defined(__clang__)
  #define BOTAN_FUNC_ISA(isa) __attribute__ ((target(isa)))
#else
  #define BOTAN_FUNC_ISA(isa)
#endif

/*
* Define BOTAN_MALLOC_FN
*/
#if defined(__ibmxl__)
  /* XLC pretends to be both Clang and GCC, but is neither */
  #define BOTAN_MALLOC_FN __attribute__ ((malloc))
#elif defined(__GNUC__)
  #define BOTAN_MALLOC_FN __attribute__ ((malloc, alloc_size(1,2)))
#elif defined(_MSC_VER)
  #define BOTAN_MALLOC_FN __declspec(restrict)
#else
  #define BOTAN_MALLOC_FN
#endif

/*
* Define BOTAN_DEPRECATED
*/
#if !defined(BOTAN_NO_DEPRECATED_WARNINGS) && !defined(BOTAN_AMALGAMATION_H_)

  #if defined(__cplusplus)
    #define BOTAN_DEPRECATED(msg) [[deprecated(msg)]]
  #elif defined(__clang__) || defined(__GNUC__)
    #define BOTAN_DEPRECATED(msg) __attribute__ ((deprecated(msg)))
  #elif defined(_MSC_VER)
    #define BOTAN_DEPRECATED(msg) __declspec(deprecated(msg))
  #endif

  #if !defined(BOTAN_IS_BEING_BUILT)
    #if defined(__clang__)
      #define BOTAN_DEPRECATED_HEADER(hdr) _Pragma("message \"this header is deprecated\"")
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) _Pragma("message \"this header will be made internal in the future\"")
    #elif defined(_MSC_VER)
      #define BOTAN_DEPRECATED_HEADER(hdr) __pragma(message("this header is deprecated"))
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) __pragma(message("this header will be made internal in the future"))
    #elif defined(__GNUC__)
      #define BOTAN_DEPRECATED_HEADER(hdr) _Pragma("GCC warning \"this header is deprecated\"")
      #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) _Pragma("GCC warning \"this header will be made internal in the future\"")
    #endif
  #endif

#endif

#if !defined(BOTAN_DEPRECATED)
  #define BOTAN_DEPRECATED(msg)
#endif

#if !defined(BOTAN_DEPRECATED_HEADER)
  #define BOTAN_DEPRECATED_HEADER(hdr)
#endif

#if !defined(BOTAN_FUTURE_INTERNAL_HEADER)
  #define BOTAN_FUTURE_INTERNAL_HEADER(hdr)
#endif

/*
* Define BOTAN_FORCE_INLINE
*/
#if !defined(BOTAN_FORCE_INLINE)

  #if defined (__clang__) || defined (__GNUC__)
    #define BOTAN_FORCE_INLINE __attribute__ ((__always_inline__)) inline

  #elif defined (_MSC_VER)
    #define BOTAN_FORCE_INLINE __forceinline

  #else
    #define BOTAN_FORCE_INLINE inline
  #endif

#endif

/*
* Define BOTAN_PARALLEL_SIMD_FOR
*/
#if !defined(BOTAN_PARALLEL_SIMD_FOR)

#if defined(BOTAN_BUILD_COMPILER_IS_GCC)
  #define BOTAN_PARALLEL_SIMD_FOR _Pragma("GCC ivdep") for
#else
  #define BOTAN_PARALLEL_SIMD_FOR for
#endif

#endif

#if defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)

  #if defined(BOTAN_BUILD_COMPILER_IS_GCC)
    #define BOTAN_DIAGNOSTIC_PUSH          	_Pragma("GCC diagnostic push")
    #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED  _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
    #define BOTAN_DIAGNOSTIC_POP           	_Pragma("GCC diagnostic pop")
  #elif defined(BOTAN_BUILD_COMPILER_IS_CLANG)
    #define BOTAN_DIAGNOSTIC_PUSH          	_Pragma("clang diagnostic push")
    #define BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED  _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
    #define BOTAN_DIAGNOSTIC_POP           	_Pragma("clang diagnostic pop")
  #endif

#endif

namespace Botan {

/**
* Called when an assertion fails
* Throws an Exception object
*/
[[noreturn]] void BOTAN_PUBLIC_API(2,0)
   assertion_failure(const char* expr_str,
                     const char* assertion_made,
                     const char* func,
                     const char* file,
                     int line);

/**
* Called when an invalid argument is used
* Throws Invalid_Argument
*/
[[noreturn]] void BOTAN_UNSTABLE_API throw_invalid_argument(const char* message,
                                                            const char* func,
                                                            const char* file);


#define BOTAN_ARG_CHECK(expr, msg)                                      \
   do { if(!(expr)) Botan::throw_invalid_argument(msg, __func__, __FILE__); } while(0)

/**
* Called when an invalid state is encountered
* Throws Invalid_State
*/
[[noreturn]] void BOTAN_UNSTABLE_API throw_invalid_state(const char* message,
                                                         const char* func,
                                                         const char* file);


#define BOTAN_STATE_CHECK(expr)                                     \
   do { if(!(expr)) Botan::throw_invalid_state(#expr, __func__, __FILE__); } while(0)

/**
* Make an assertion
*/
#define BOTAN_ASSERT(expr, assertion_made)                \
   do {                                                   \
      if(!(expr))                                         \
         Botan::assertion_failure(#expr,                  \
                                  assertion_made,         \
                                  __func__,               \
                                  __FILE__,               \
                                  __LINE__);              \
   } while(0)

/**
* Make an assertion
*/
#define BOTAN_ASSERT_NOMSG(expr)                          \
   do {                                                   \
      if(!(expr))                                         \
         Botan::assertion_failure(#expr,                  \
                                  "",                     \
                                  __func__,               \
                                  __FILE__,               \
                                  __LINE__);              \
   } while(0)

/**
* Assert that value1 == value2
*/
#define BOTAN_ASSERT_EQUAL(expr1, expr2, assertion_made)   \
   do {                                                    \
     if((expr1) != (expr2))                                \
       Botan::assertion_failure(#expr1 " == " #expr2,      \
                                assertion_made,            \
                                __func__,                  \
                                __FILE__,                  \
                                __LINE__);                 \
   } while(0)

/**
* Assert that expr1 (if true) implies expr2 is also true
*/
#define BOTAN_ASSERT_IMPLICATION(expr1, expr2, msg)        \
   do {                                                    \
     if((expr1) && !(expr2))                               \
       Botan::assertion_failure(#expr1 " implies " #expr2, \
                                msg,                       \
                                __func__,                  \
                                __FILE__,                  \
                                __LINE__);                 \
   } while(0)

/**
* Assert that a pointer is not null
*/
#define BOTAN_ASSERT_NONNULL(ptr)                          \
   do {                                                    \
     if((ptr) == nullptr)                                  \
         Botan::assertion_failure(#ptr " is not null",     \
                                  "",                      \
                                  __func__,                \
                                  __FILE__,                \
                                  __LINE__);               \
   } while(0)

#if defined(BOTAN_ENABLE_DEBUG_ASSERTS)

#define BOTAN_DEBUG_ASSERT(expr) BOTAN_ASSERT_NOMSG(expr)

#else

#define BOTAN_DEBUG_ASSERT(expr) do {} while(0)

#endif

/**
* Mark variable as unused. Takes between 1 and 9 arguments and marks all as unused,
* e.g. BOTAN_UNUSED(a); or BOTAN_UNUSED(x, y, z);
*/
#define _BOTAN_UNUSED_IMPL1(a)                         static_cast<void>(a)
#define _BOTAN_UNUSED_IMPL2(a, b)                      static_cast<void>(a); _BOTAN_UNUSED_IMPL1(b)
#define _BOTAN_UNUSED_IMPL3(a, b, c)                   static_cast<void>(a); _BOTAN_UNUSED_IMPL2(b, c)
#define _BOTAN_UNUSED_IMPL4(a, b, c, d)                static_cast<void>(a); _BOTAN_UNUSED_IMPL3(b, c, d)
#define _BOTAN_UNUSED_IMPL5(a, b, c, d, e)             static_cast<void>(a); _BOTAN_UNUSED_IMPL4(b, c, d, e)
#define _BOTAN_UNUSED_IMPL6(a, b, c, d, e, f)          static_cast<void>(a); _BOTAN_UNUSED_IMPL5(b, c, d, e, f)
#define _BOTAN_UNUSED_IMPL7(a, b, c, d, e, f, g)       static_cast<void>(a); _BOTAN_UNUSED_IMPL6(b, c, d, e, f, g)
#define _BOTAN_UNUSED_IMPL8(a, b, c, d, e, f, g, h)    static_cast<void>(a); _BOTAN_UNUSED_IMPL7(b, c, d, e, f, g, h)
#define _BOTAN_UNUSED_IMPL9(a, b, c, d, e, f, g, h, i) static_cast<void>(a); _BOTAN_UNUSED_IMPL8(b, c, d, e, f, g, h, i)
#define _BOTAN_UNUSED_GET_IMPL(_1, _2, _3, _4, _5, _6, _7, _8, _9, IMPL_NAME, ...) IMPL_NAME

#define BOTAN_UNUSED(...) _BOTAN_UNUSED_GET_IMPL(__VA_ARGS__,                      \
                                                 _BOTAN_UNUSED_IMPL9,              \
                                                 _BOTAN_UNUSED_IMPL8,              \
                                                 _BOTAN_UNUSED_IMPL7,              \
                                                 _BOTAN_UNUSED_IMPL6,              \
                                                 _BOTAN_UNUSED_IMPL5,              \
                                                 _BOTAN_UNUSED_IMPL4,              \
                                                 _BOTAN_UNUSED_IMPL3,              \
                                                 _BOTAN_UNUSED_IMPL2,              \
                                                 _BOTAN_UNUSED_IMPL1,              \
                                                 unused dummy rest value           \
                          ) /* we got an one of _BOTAN_UNUSED_IMPL*, now call it */ (__VA_ARGS__)

/*
* Define Botan::unreachable()
*
* There is a pending WG21 proposal for `std::unreachable()`
*   http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/p0627r3.pdf
*/
[[noreturn]] BOTAN_FORCE_INLINE void unreachable()
   {
#if defined(__GNUC__) // GCC 4.8+, Clang, Intel and other compilers compatible with GCC (-std=c++0x or above)
   __builtin_unreachable();
#elif defined(_MSC_VER) // MSVC
   __assume(false);
#else
   return; // undefined behaviour, just like the others...
#endif
   }

}

namespace Botan {

/**
* @mainpage Botan Crypto Library API Reference
*
* <dl>
* <dt>Abstract Base Classes<dd>
*        BlockCipher, HashFunction, KDF, MessageAuthenticationCode, RandomNumberGenerator,
*        StreamCipher, SymmetricAlgorithm, AEAD_Mode, Cipher_Mode
* <dt>Public Key Interface Classes<dd>
*        PK_Key_Agreement, PK_Signer, PK_Verifier, PK_Encryptor, PK_Decryptor
* <dt>Authenticated Encryption Modes<dd>
*        @ref CCM_Mode "CCM", @ref ChaCha20Poly1305_Mode "ChaCha20Poly1305", @ref EAX_Mode "EAX",
*        @ref GCM_Mode "GCM", @ref OCB_Mode "OCB", @ref SIV_Mode "SIV"
* <dt>Block Ciphers<dd>
*        @ref aria.h "ARIA", @ref aes.h "AES", @ref Blowfish, @ref camellia.h "Camellia", @ref Cascade_Cipher "Cascade",
*        @ref CAST_128 "CAST-128", @ref CAST_128 DES, @ref TripleDES "3DES",
*        @ref GOST_28147_89 "GOST 28147-89", IDEA, Lion, Noekeon, SEED, Serpent, SHACAL2, SM4,
*        @ref Threefish_512 "Threefish", Twofish
* <dt>Stream Ciphers<dd>
*        ChaCha, @ref CTR_BE "CTR", OFB, RC4, Salsa20
* <dt>Hash Functions<dd>
*        BLAKE2b, @ref GOST_34_11 "GOST 34.11", @ref Keccak_1600 "Keccak", MD4, MD5, @ref RIPEMD_160 "RIPEMD-160",
*        @ref SHA_160 "SHA-1", @ref SHA_224 "SHA-224", @ref SHA_256 "SHA-256", @ref SHA_384 "SHA-384",
*        @ref SHA_512 "SHA-512", @ref Skein_512 "Skein-512", SM3, Streebog, Whirlpool
* <dt>Non-Cryptographic Checksums<dd>
*        Adler32, CRC24, CRC32
* <dt>Message Authentication Codes<dd>
*        CMAC, HMAC, Poly1305, SipHash, ANSI_X919_MAC
* <dt>Random Number Generators<dd>
*        AutoSeeded_RNG, HMAC_DRBG, Processor_RNG, System_RNG
* <dt>Key Derivation<dd>
*        HKDF, @ref KDF1 "KDF1 (IEEE 1363)", @ref KDF1_18033 "KDF1 (ISO 18033-2)", @ref KDF2 "KDF2 (IEEE 1363)",
*        @ref sp800_108.h "SP800-108", @ref SP800_56C "SP800-56C", @ref PKCS5_PBKDF2 "PBKDF2 (PKCS#5)"
* <dt>Password Hashing<dd>
*        @ref argon2.h "Argon2", @ref scrypt.h "scrypt", @ref bcrypt.h "bcrypt", @ref passhash9.h "passhash9"
* <dt>Public Key Cryptosystems<dd>
*        @ref dlies.h "DLIES", @ref ecies.h "ECIES", @ref elgamal.h "ElGamal"
*        @ref rsa.h "RSA", @ref newhope.h "NewHope", @ref mceliece.h "McEliece"
*        @ref sm2.h "SM2"
* <dt>Public Key Signature Schemes<dd>
*        @ref dsa.h "DSA", @ref ecdsa.h "ECDSA", @ref ecgdsa.h "ECGDSA", @ref eckcdsa.h "ECKCDSA",
*        @ref gost_3410.h "GOST 34.10-2001", @ref sm2.h "SM2", @ref xmss.h "XMSS"
* <dt>Key Agreement<dd>
*        @ref dh.h "DH", @ref ecdh.h "ECDH"
* <dt>Compression<dd>
*        @ref bzip2.h "bzip2", @ref lzma.h "lzma", @ref zlib.h "zlib"
* <dt>TLS<dd>
*        TLS::Client, TLS::Server, TLS::Policy, TLS::Protocol_Version, TLS::Callbacks, TLS::Ciphersuite,
*        TLS::Session, TLS::Session_Manager, Credentials_Manager
* <dt>X.509<dd>
*        X509_Certificate, X509_CRL, X509_CA, Certificate_Extension, PKCS10_Request, X509_Cert_Options,
*        Certificate_Store, Certificate_Store_In_SQL, Certificate_Store_In_SQLite
* </dl>
*/

using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;
using std::int32_t;
using std::int64_t;
using std::size_t;

#if !defined(BOTAN_IS_BEING_BUILT)
/*
* These typedefs are no longer used within the library headers
* or code. They are kept only for compatability with software
* written against older versions.
*/
using byte   = std::uint8_t;
using u16bit = std::uint16_t;
using u32bit = std::uint32_t;
using u64bit = std::uint64_t;
using s32bit = std::int32_t;
#endif

#if (BOTAN_MP_WORD_BITS == 32)
  typedef uint32_t word;
#elif (BOTAN_MP_WORD_BITS == 64)
  typedef uint64_t word;
#else
  #error BOTAN_MP_WORD_BITS must be 32 or 64
#endif

/*
* Should this assert fail on your system please contact the developers
* for assistance in porting.
*/
static_assert(sizeof(std::size_t) == 8 || sizeof(std::size_t) == 4,
              "This platform has an unexpected size for size_t");

}

namespace Botan {

/**
* Allocate a memory buffer by some method. This should only be used for
* primitive types (uint8_t, uint32_t, etc).
*
* @param elems the number of elements
* @param elem_size the size of each element
* @return pointer to allocated and zeroed memory, or throw std::bad_alloc on failure
*/
BOTAN_PUBLIC_API(2,3) BOTAN_MALLOC_FN void* allocate_memory(size_t elems, size_t elem_size);

/**
* Free a pointer returned by allocate_memory
* @param p the pointer returned by allocate_memory
* @param elems the number of elements, as passed to allocate_memory
* @param elem_size the size of each element, as passed to allocate_memory
*/
BOTAN_PUBLIC_API(2,3) void deallocate_memory(void* p, size_t elems, size_t elem_size);

/**
* Ensure the allocator is initialized
*/
void BOTAN_UNSTABLE_API initialize_allocator();

class Allocator_Initializer
   {
   public:
      Allocator_Initializer() { initialize_allocator(); }
   };

/**
* Scrub memory contents in a way that a compiler should not elide,
* using some system specific technique. Note that this function might
* not zero the memory (for example, in some hypothetical
* implementation it might combine the memory contents with the output
* of a system PRNG), but if you can detect any difference in behavior
* at runtime then the clearing is side-effecting and you can just
* use `clear_mem`.
*
* Use this function to scrub memory just before deallocating it, or on
* a stack buffer before returning from the function.
*
* @param ptr a pointer to memory to scrub
* @param n the number of bytes pointed to by ptr
*/
BOTAN_PUBLIC_API(2,0) void secure_scrub_memory(void* ptr, size_t n);

/**
* Memory comparison, input insensitive
* @param x a pointer to an array
* @param y a pointer to another array
* @param len the number of Ts in x and y
* @return 0xFF iff x[i] == y[i] forall i in [0...n) or 0x00 otherwise
*/
BOTAN_PUBLIC_API(2,9) uint8_t ct_compare_u8(const uint8_t x[],
                                            const uint8_t y[],
                                            size_t len);

/**
* Memory comparison, input insensitive
* @param x a pointer to an array
* @param y a pointer to another array
* @param len the number of Ts in x and y
* @return true iff x[i] == y[i] forall i in [0...n)
*/
inline bool constant_time_compare(const uint8_t x[],
                                  const uint8_t y[],
                                  size_t len)
   {
   return ct_compare_u8(x, y, len) == 0xFF;
   }

/**
* Zero out some bytes. Warning: use secure_scrub_memory instead if the
* memory is about to be freed or otherwise the compiler thinks it can
* elide the writes.
*
* @param ptr a pointer to memory to zero
* @param bytes the number of bytes to zero in ptr
*/
inline constexpr void clear_bytes(void* ptr, size_t bytes)
   {
   if(bytes > 0)
      {
      std::memset(ptr, 0, bytes);
      }
   }

/**
* Zero memory before use. This simply calls memset and should not be
* used in cases where the compiler cannot see the call as a
* side-effecting operation (for example, if calling clear_mem before
* deallocating memory, the compiler would be allowed to omit the call
* to memset entirely under the as-if rule.)
*
* @param ptr a pointer to an array of Ts to zero
* @param n the number of Ts pointed to by ptr
*/
template<typename T> inline constexpr void clear_mem(T* ptr, size_t n)
   {
   clear_bytes(ptr, sizeof(T)*n);
   }

/**
* Copy memory
* @param out the destination array
* @param in the source array
* @param n the number of elements of in/out
*/
template<typename T> inline constexpr void copy_mem(T* out, const T* in, size_t n)
   {
   static_assert(std::is_trivial<typename std::decay<T>::type>::value, "");
   BOTAN_ASSERT_IMPLICATION(n > 0, in != nullptr && out != nullptr,
                            "If n > 0 then args are not null");

   if(in != nullptr && out != nullptr && n > 0)
      {
      std::memmove(out, in, sizeof(T)*n);
      }
   }

template<typename T> inline constexpr void typecast_copy(uint8_t out[], T in[], size_t N)
   {
   static_assert(std::is_trivially_copyable<T>::value, "Safe to memcpy");
   std::memcpy(out, in, sizeof(T)*N);
   }

template<typename T> inline constexpr void typecast_copy(T out[], const uint8_t in[], size_t N)
   {
   static_assert(std::is_trivial<T>::value, "Safe to memcpy");
   std::memcpy(out, in, sizeof(T)*N);
   }

template<typename T> inline constexpr void typecast_copy(uint8_t out[], T in)
   {
   typecast_copy(out, &in, 1);
   }

template<typename T> inline constexpr void typecast_copy(T& out, const uint8_t in[])
   {
   static_assert(std::is_trivial<typename std::decay<T>::type>::value, "Safe case");
   typecast_copy(&out, in, 1);
   }

template <class To, class From> inline constexpr To typecast_copy(const From *src) noexcept
   {
   static_assert(std::is_trivially_copyable<From>::value && std::is_trivial<To>::value, "Safe for memcpy");
   To dst;
   std::memcpy(&dst, src, sizeof(To));
   return dst;
   }

/**
* Set memory to a fixed value
* @param ptr a pointer to an array of bytes
* @param n the number of Ts pointed to by ptr
* @param val the value to set each byte to
*/
inline constexpr void set_mem(uint8_t* ptr, size_t n, uint8_t val)
   {
   if(n > 0)
      {
      std::memset(ptr, val, n);
      }
   }

inline const uint8_t* cast_char_ptr_to_uint8(const char* s)
   {
   return reinterpret_cast<const uint8_t*>(s);
   }

inline const char* cast_uint8_ptr_to_char(const uint8_t* b)
   {
   return reinterpret_cast<const char*>(b);
   }

inline uint8_t* cast_char_ptr_to_uint8(char* s)
   {
   return reinterpret_cast<uint8_t*>(s);
   }

inline char* cast_uint8_ptr_to_char(uint8_t* b)
   {
   return reinterpret_cast<char*>(b);
   }

/**
* Memory comparison, input insensitive
* @param p1 a pointer to an array
* @param p2 a pointer to another array
* @param n the number of Ts in p1 and p2
* @return true iff p1[i] == p2[i] forall i in [0...n)
*/
template<typename T> inline bool same_mem(const T* p1, const T* p2, size_t n)
   {
   volatile T difference = 0;

   for(size_t i = 0; i != n; ++i)
      difference = difference | (p1[i] ^ p2[i]);

   return difference == 0;
   }

template<typename T, typename Alloc>
size_t buffer_insert(std::vector<T, Alloc>& buf,
                     size_t buf_offset,
                     const T input[],
                     size_t input_length)
   {
   BOTAN_ASSERT_NOMSG(buf_offset <= buf.size());
   const size_t to_copy = std::min(input_length, buf.size() - buf_offset);
   if(to_copy > 0)
      {
      copy_mem(&buf[buf_offset], input, to_copy);
      }
   return to_copy;
   }

template<typename T, typename Alloc, typename Alloc2>
size_t buffer_insert(std::vector<T, Alloc>& buf,
                     size_t buf_offset,
                     const std::vector<T, Alloc2>& input)
   {
   BOTAN_ASSERT_NOMSG(buf_offset <= buf.size());
   const size_t to_copy = std::min(input.size(), buf.size() - buf_offset);
   if(to_copy > 0)
      {
      copy_mem(&buf[buf_offset], input.data(), to_copy);
      }
   return to_copy;
   }

/**
* XOR arrays. Postcondition out[i] = in[i] ^ out[i] forall i = 0...length
* @param out the input/output buffer
* @param in the read-only input buffer
* @param length the length of the buffers
*/
inline void xor_buf(uint8_t out[],
                    const uint8_t in[],
                    size_t length)
   {
   const size_t blocks = length - (length % 32);

   for(size_t i = 0; i != blocks; i += 32)
      {
      uint64_t x[4];
      uint64_t y[4];

      typecast_copy(x, out + i, 4);
      typecast_copy(y, in + i, 4);

      x[0] ^= y[0];
      x[1] ^= y[1];
      x[2] ^= y[2];
      x[3] ^= y[3];

      typecast_copy(out + i, x, 4);
      }

   for(size_t i = blocks; i != length; ++i)
      {
      out[i] ^= in[i];
      }
   }

/**
* XOR arrays. Postcondition out[i] = in[i] ^ in2[i] forall i = 0...length
* @param out the output buffer
* @param in the first input buffer
* @param in2 the second output buffer
* @param length the length of the three buffers
*/
inline void xor_buf(uint8_t out[],
                    const uint8_t in[],
                    const uint8_t in2[],
                    size_t length)
   {
   const size_t blocks = length - (length % 32);

   for(size_t i = 0; i != blocks; i += 32)
      {
      uint64_t x[4];
      uint64_t y[4];

      typecast_copy(x, in + i, 4);
      typecast_copy(y, in2 + i, 4);

      x[0] ^= y[0];
      x[1] ^= y[1];
      x[2] ^= y[2];
      x[3] ^= y[3];

      typecast_copy(out + i, x, 4);
      }

   for(size_t i = blocks; i != length; ++i)
      {
      out[i] = in[i] ^ in2[i];
      }
   }

template<typename Alloc, typename Alloc2>
void xor_buf(std::vector<uint8_t, Alloc>& out,
             const std::vector<uint8_t, Alloc2>& in,
             size_t n)
   {
   xor_buf(out.data(), in.data(), n);
   }

template<typename Alloc>
void xor_buf(std::vector<uint8_t, Alloc>& out,
             const uint8_t* in,
             size_t n)
   {
   xor_buf(out.data(), in, n);
   }

template<typename Alloc, typename Alloc2>
void xor_buf(std::vector<uint8_t, Alloc>& out,
             const uint8_t* in,
             const std::vector<uint8_t, Alloc2>& in2,
             size_t n)
   {
   xor_buf(out.data(), in, in2.data(), n);
   }

template<typename Alloc, typename Alloc2>
std::vector<uint8_t, Alloc>&
operator^=(std::vector<uint8_t, Alloc>& out,
           const std::vector<uint8_t, Alloc2>& in)
   {
   if(out.size() < in.size())
      out.resize(in.size());

   xor_buf(out.data(), in.data(), in.size());
   return out;
   }

}

namespace Botan {

template<typename T>
class secure_allocator
   {
   public:
      /*
      * Assert exists to prevent someone from doing something that will
      * probably crash anyway (like secure_vector<non_POD_t> where ~non_POD_t
      * deletes a member pointer which was zeroed before it ran).
      * MSVC in debug mode uses non-integral proxy types in container types
      * like std::vector, thus we disable the check there.
      */
#if !defined(_ITERATOR_DEBUG_LEVEL) || _ITERATOR_DEBUG_LEVEL == 0
      static_assert(std::is_integral<T>::value, "secure_allocator supports only integer types");
#endif

      typedef T          value_type;
      typedef std::size_t size_type;

      secure_allocator() noexcept = default;
      secure_allocator(const secure_allocator&) noexcept = default;
      secure_allocator& operator=(const secure_allocator&) noexcept = default;
      ~secure_allocator() noexcept = default;

      template<typename U>
      secure_allocator(const secure_allocator<U>&) noexcept {}

      T* allocate(std::size_t n)
         {
         return static_cast<T*>(allocate_memory(n, sizeof(T)));
         }

      void deallocate(T* p, std::size_t n)
         {
         deallocate_memory(p, n, sizeof(T));
         }
   };

template<typename T, typename U> inline bool
operator==(const secure_allocator<T>&, const secure_allocator<U>&)
   { return true; }

template<typename T, typename U> inline bool
operator!=(const secure_allocator<T>&, const secure_allocator<U>&)
   { return false; }

template<typename T> using secure_vector = std::vector<T, secure_allocator<T>>;
template<typename T> using secure_deque = std::deque<T, secure_allocator<T>>;

// For better compatibility with 1.10 API
template<typename T> using SecureVector = secure_vector<T>;

template<typename T>
std::vector<T> unlock(const secure_vector<T>& in)
   {
   return std::vector<T>(in.begin(), in.end());
   }

template<typename T, typename Alloc, typename Alloc2>
std::vector<T, Alloc>&
operator+=(std::vector<T, Alloc>& out,
           const std::vector<T, Alloc2>& in)
   {
   out.insert(out.end(), in.begin(), in.end());
   return out;
   }

template<typename T, typename Alloc>
std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, T in)
   {
   out.push_back(in);
   return out;
   }

template<typename T, typename Alloc, typename L>
std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out,
                                  const std::pair<const T*, L>& in)
   {
   out.insert(out.end(), in.first, in.first + in.second);
   return out;
   }

template<typename T, typename Alloc, typename L>
std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out,
                                  const std::pair<T*, L>& in)
   {
   out.insert(out.end(), in.first, in.first + in.second);
   return out;
   }

/**
* Zeroise the values; length remains unchanged
* @param vec the vector to zeroise
*/
template<typename T, typename Alloc>
void zeroise(std::vector<T, Alloc>& vec)
   {
   clear_mem(vec.data(), vec.size());
   }

/**
* Zeroise the values then free the memory
* @param vec the vector to zeroise and free
*/
template<typename T, typename Alloc>
void zap(std::vector<T, Alloc>& vec)
   {
   zeroise(vec);
   vec.clear();
   vec.shrink_to_fit();
   }

}

namespace Botan {

class RandomNumberGenerator;

/**
* Octet String
*/
class BOTAN_PUBLIC_API(2,0) OctetString final
   {
   public:
      /**
      * @return size of this octet string in bytes
      */
      size_t length() const { return m_data.size(); }
      size_t size() const { return m_data.size(); }

      /**
      * @return this object as a secure_vector<uint8_t>
      */
      secure_vector<uint8_t> bits_of() const { return m_data; }

      /**
      * @return start of this string
      */
      const uint8_t* begin() const { return m_data.data(); }

      /**
      * @return end of this string
      */
      const uint8_t* end() const   { return begin() + m_data.size(); }

      /**
      * @return this encoded as hex
      */
      std::string to_string() const;

      /**
      * XOR the contents of another octet string into this one
      * @param other octet string
      * @return reference to this
      */
      OctetString& operator^=(const OctetString& other);

      /**
      * Force to have odd parity
      *
      * Deprecated. There is no reason to use this outside of interacting with
      * some very old or weird system which requires DES and also which do not
      * automatically ignore the parity bits.
      */
      BOTAN_DEPRECATED("Why would you need to do this")
      void set_odd_parity();

      /**
      * Create a new OctetString
      * @param str is a hex encoded string
      */
      explicit OctetString(const std::string& str = "");

      /**
      * Create a new random OctetString
      * @param rng is a random number generator
      * @param len is the desired length in bytes
      */
      OctetString(RandomNumberGenerator& rng, size_t len);

      /**
      * Create a new OctetString
      * @param in is an array
      * @param len is the length of in in bytes
      */
      OctetString(const uint8_t in[], size_t len);

      /**
      * Create a new OctetString
      * @param in a bytestring
      */
      OctetString(const secure_vector<uint8_t>& in) : m_data(in) {}

      /**
      * Create a new OctetString
      * @param in a bytestring
      */
      OctetString(const std::vector<uint8_t>& in) : m_data(in.begin(), in.end()) {}

   private:
      secure_vector<uint8_t> m_data;
   };

/**
* Compare two strings
* @param x an octet string
* @param y an octet string
* @return if x is equal to y
*/
BOTAN_PUBLIC_API(2,0) bool operator==(const OctetString& x,
                          const OctetString& y);

/**
* Compare two strings
* @param x an octet string
* @param y an octet string
* @return if x is not equal to y
*/
BOTAN_PUBLIC_API(2,0) bool operator!=(const OctetString& x,
                          const OctetString& y);

/**
* Concatenate two strings
* @param x an octet string
* @param y an octet string
* @return x concatenated with y
*/
BOTAN_PUBLIC_API(2,0) OctetString operator+(const OctetString& x,
                                const OctetString& y);

/**
* XOR two strings
* @param x an octet string
* @param y an octet string
* @return x XORed with y
*/
BOTAN_PUBLIC_API(2,0) OctetString operator^(const OctetString& x,
                                const OctetString& y);


/**
* Alternate name for octet string showing intent to use as a key
*/
using SymmetricKey = OctetString;

/**
* Alternate name for octet string showing intent to use as an IV
*/
using InitializationVector = OctetString;

}

namespace Botan {

/**
* Represents the length requirements on an algorithm key
*/
class BOTAN_PUBLIC_API(2,0) Key_Length_Specification final
   {
   public:
      /**
      * Constructor for fixed length keys
      * @param keylen the supported key length
      */
      explicit Key_Length_Specification(size_t keylen) :
         m_min_keylen(keylen),
         m_max_keylen(keylen),
         m_keylen_mod(1)
         {
         }

      /**
      * Constructor for variable length keys
      * @param min_k the smallest supported key length
      * @param max_k the largest supported key length
      * @param k_mod the number of bytes the key must be a multiple of
      */
      Key_Length_Specification(size_t min_k,
                               size_t max_k,
                               size_t k_mod = 1) :
         m_min_keylen(min_k),
         m_max_keylen(max_k ? max_k : min_k),
         m_keylen_mod(k_mod)
         {
         }

      /**
      * @param length is a key length in bytes
      * @return true iff this length is a valid length for this algo
      */
      bool valid_keylength(size_t length) const
         {
         return ((length >= m_min_keylen) &&
                 (length <= m_max_keylen) &&
                 (length % m_keylen_mod == 0));
         }

      /**
      * @return minimum key length in bytes
      */
      size_t minimum_keylength() const
         {
         return m_min_keylen;
         }

      /**
      * @return maximum key length in bytes
      */
      size_t maximum_keylength() const
         {
         return m_max_keylen;
         }

      /**
      * @return key length multiple in bytes
      */
      size_t keylength_multiple() const
         {
         return m_keylen_mod;
         }

      /*
      * Multiplies all length requirements with the given factor
      * @param n the multiplication factor
      * @return a key length specification multiplied by the factor
      */
      Key_Length_Specification multiple(size_t n) const
         {
         return Key_Length_Specification(n * m_min_keylen,
                                         n * m_max_keylen,
                                         n * m_keylen_mod);
         }

   private:
      size_t m_min_keylen, m_max_keylen, m_keylen_mod;
   };

/**
* This class represents a symmetric algorithm object.
*/
class BOTAN_PUBLIC_API(2,0) SymmetricAlgorithm
   {
   public:
      virtual ~SymmetricAlgorithm() = default;

      /**
      * Reset the state.
      */
      virtual void clear() = 0;

      /**
      * @return object describing limits on key size
      */
      virtual Key_Length_Specification key_spec() const = 0;

      /**
      * @return maximum allowed key length
      */
      size_t maximum_keylength() const
         {
         return key_spec().maximum_keylength();
         }

      /**
      * @return minimum allowed key length
      */
      size_t minimum_keylength() const
         {
         return key_spec().minimum_keylength();
         }

      /**
      * Check whether a given key length is valid for this algorithm.
      * @param length the key length to be checked.
      * @return true if the key length is valid.
      */
      bool valid_keylength(size_t length) const
         {
         return key_spec().valid_keylength(length);
         }

      /**
      * Set the symmetric key of this object.
      * @param key the SymmetricKey to be set.
      */
      void set_key(const SymmetricKey& key)
         {
         set_key(key.begin(), key.length());
         }

      template<typename Alloc>
      void set_key(const std::vector<uint8_t, Alloc>& key)
         {
         set_key(key.data(), key.size());
         }

      /**
      * Set the symmetric key of this object.
      * @param key the to be set as a byte array.
      * @param length in bytes of key param
      */
      void set_key(const uint8_t key[], size_t length);

      /**
      * @return the algorithm name
      */
      virtual std::string name() const = 0;

   protected:
      void verify_key_set(bool cond) const
         {
         if(cond == false)
            throw_key_not_set_error();
         }

   private:
      void throw_key_not_set_error() const;

      /**
      * Run the key schedule
      * @param key the key
      * @param length of key
      */
      virtual void key_schedule(const uint8_t key[], size_t length) = 0;
   };

}

namespace Botan {

/**
* Different types of errors that might occur
*/
enum class ErrorType {
   /** Some unknown error */
   Unknown = 1,
   /** An error while calling a system interface */
   SystemError,
   /** An operation seems valid, but not supported by the current version */
   NotImplemented,
   /** Memory allocation failure */
   OutOfMemory,
   /** An internal error occurred */
   InternalError,
   /** An I/O error occurred */
   IoError,

   /** Invalid object state */
   InvalidObjectState = 100,
   /** A key was not set on an object when this is required */
   KeyNotSet,
   /** The application provided an argument which is invalid */
   InvalidArgument,
   /** A key with invalid length was provided */
   InvalidKeyLength,
   /** A nonce with invalid length was provided */
   InvalidNonceLength,
   /** An object type was requested but cannot be found */
   LookupError,
   /** Encoding a message or datum failed */
   EncodingFailure,
   /** Decoding a message or datum failed */
   DecodingFailure,
   /** A TLS error (error_code will be the alert type) */
   TLSError,
   /** An error during an HTTP operation */
   HttpError,
   /** A message with an invalid authentication tag was detected */
   InvalidTag,
   /** An error during Roughtime validation */
   RoughtimeError,

   /** An error when interacting with CommonCrypto API */
   CommonCryptoError = 201,
   /** An error when interacting with a PKCS11 device */
   Pkcs11Error,
   /** An error when interacting with a TPM device */
   TPMError,
   /** An error when interacting with a database */
   DatabaseError,

   /** An error when interacting with zlib */
   ZlibError = 300,
   /** An error when interacting with bzip2 */
   Bzip2Error,
   /** An error when interacting with lzma */
   LzmaError,

};

//! \brief Convert an ErrorType to string
std::string BOTAN_PUBLIC_API(2,11) to_string(ErrorType type);

/**
* Base class for all exceptions thrown by the library
*/
class BOTAN_PUBLIC_API(2,0) Exception : public std::exception
   {
   public:
      /**
      * Return a descriptive string which is hopefully comprehensible to
      * a developer. It will likely not be useful for an end user.
      *
      * The string has no particular format, and the content of exception
      * messages may change from release to release. Thus the main use of this
      * function is for logging or debugging.
      */
      const char* what() const noexcept override { return m_msg.c_str(); }

      /**
      * Return the "type" of error which occurred.
      */
      virtual ErrorType error_type() const noexcept { return Botan::ErrorType::Unknown; }

      /**
      * Return an error code associated with this exception, or otherwise 0.
      *
      * The domain of this error varies depending on the source, for example on
      * POSIX systems it might be errno, while on a Windows system it might be
      * the result of GetLastError or WSAGetLastError.
      */
      virtual int error_code() const noexcept { return 0; }

      /**
      * Avoid throwing base Exception, use a subclass
      */
      explicit Exception(const std::string& msg);

      /**
      * Avoid throwing base Exception, use a subclass
      */
      Exception(const char* prefix, const std::string& msg);

      /**
      * Avoid throwing base Exception, use a subclass
      */
      Exception(const std::string& msg, const std::exception& e);

   private:
      std::string m_msg;
   };

/**
* An invalid argument was provided to an API call.
*/
class BOTAN_PUBLIC_API(2,0) Invalid_Argument : public Exception
   {
   public:
      explicit Invalid_Argument(const std::string& msg);

      explicit Invalid_Argument(const std::string& msg, const std::string& where);

      Invalid_Argument(const std::string& msg, const std::exception& e);

      ErrorType error_type() const noexcept override { return ErrorType::InvalidArgument; }
   };

/**
* An invalid key length was used
*/
class BOTAN_PUBLIC_API(2,0) Invalid_Key_Length final : public Invalid_Argument
   {
   public:
      Invalid_Key_Length(const std::string& name, size_t length);
      ErrorType error_type() const noexcept override { return ErrorType::InvalidKeyLength; }
   };

/**
* An invalid nonce length was used
*/
class BOTAN_PUBLIC_API(2,0) Invalid_IV_Length final : public Invalid_Argument
   {
   public:
      Invalid_IV_Length(const std::string& mode, size_t bad_len);
      ErrorType error_type() const noexcept override { return ErrorType::InvalidNonceLength; }
   };

/**
* Invalid_Algorithm_Name Exception
*/
class BOTAN_PUBLIC_API(2,0) Invalid_Algorithm_Name final : public Invalid_Argument
   {
   public:
      explicit Invalid_Algorithm_Name(const std::string& name);
   };

/**
* Encoding_Error Exception
*/
class BOTAN_PUBLIC_API(2,0) Encoding_Error final : public Exception
   {
   public:
      explicit Encoding_Error(const std::string& name);

      ErrorType error_type() const noexcept override { return ErrorType::EncodingFailure; }
   };

/**
* A decoding error occurred.
*/
class BOTAN_PUBLIC_API(2,0) Decoding_Error : public Exception
   {
   public:
      explicit Decoding_Error(const std::string& name);

      Decoding_Error(const std::string& name, const char* exception_message);

      Decoding_Error(const std::string& msg, const std::exception& e);

      ErrorType error_type() const noexcept override { return ErrorType::DecodingFailure; }
   };

/**
* Invalid state was encountered. A request was made on an object while the
* object was in a state where the operation cannot be performed.
*/
class BOTAN_PUBLIC_API(2,0) Invalid_State : public Exception
   {
   public:
      explicit Invalid_State(const std::string& err) : Exception(err) {}

      ErrorType error_type() const noexcept override { return ErrorType::InvalidObjectState; }
   };

/**
* A PRNG was called on to produce output while still unseeded
*/
class BOTAN_PUBLIC_API(2,0) PRNG_Unseeded final : public Invalid_State
   {
   public:
      explicit PRNG_Unseeded(const std::string& algo);
   };

/**
* The key was not set on an object. This occurs with symmetric objects where
* an operation which requires the key is called prior to set_key being called.
*/
class BOTAN_PUBLIC_API(2,4) Key_Not_Set : public Invalid_State
   {
   public:
      explicit Key_Not_Set(const std::string& algo);

      ErrorType error_type() const noexcept override { return ErrorType::KeyNotSet; }
   };

/**
* A request was made for some kind of object which could not be located
*/
class BOTAN_PUBLIC_API(2,0) Lookup_Error : public Exception
   {
   public:
      explicit Lookup_Error(const std::string& err) : Exception(err) {}

      Lookup_Error(const std::string& type,
                   const std::string& algo,
                   const std::string& provider);

      ErrorType error_type() const noexcept override { return ErrorType::LookupError; }
   };

/**
* Algorithm_Not_Found Exception
*
* @warning This exception type will be removed in the future. Instead
* just catch Lookup_Error.
*/
class BOTAN_PUBLIC_API(2,0) Algorithm_Not_Found final : public Lookup_Error
   {
   public:
      explicit Algorithm_Not_Found(const std::string& name);
   };

/**
* Provider_Not_Found is thrown when a specific provider was requested
* but that provider is not available.
*
* @warning This exception type will be removed in the future. Instead
* just catch Lookup_Error.
*/
class BOTAN_PUBLIC_API(2,0) Provider_Not_Found final : public Lookup_Error
   {
   public:
      Provider_Not_Found(const std::string& algo, const std::string& provider);
   };

/**
* An AEAD or MAC check detected a message modification
*
* In versions before 2.10, Invalid_Authentication_Tag was named
* Integrity_Failure, it was renamed to make its usage more clear.
*/
class BOTAN_PUBLIC_API(2,0) Invalid_Authentication_Tag final : public Exception
   {
   public:
      explicit Invalid_Authentication_Tag(const std::string& msg);

      ErrorType error_type() const noexcept override { return ErrorType::InvalidTag; }
   };

/**
* For compatability with older versions
*/
typedef Invalid_Authentication_Tag Integrity_Failure;

/**
* An error occurred while operating on an IO stream
*/
class BOTAN_PUBLIC_API(2,0) Stream_IO_Error final : public Exception
   {
   public:
      explicit Stream_IO_Error(const std::string& err);

      ErrorType error_type() const noexcept override { return ErrorType::IoError; }
   };

/**
* System_Error
*
* This exception is thrown in the event of an error related to interacting
* with the operating system.
*
* This exception type also (optionally) captures an integer error code eg
* POSIX errno or Windows GetLastError.
*/
class BOTAN_PUBLIC_API(2,9) System_Error : public Exception
   {
   public:
      System_Error(const std::string& msg) : Exception(msg), m_error_code(0) {}

      System_Error(const std::string& msg, int err_code);

      ErrorType error_type() const noexcept override { return ErrorType::SystemError; }

      int error_code() const noexcept override { return m_error_code; }

   private:
      int m_error_code;
   };

/**
* An internal error occurred. If observed, please file a bug.
*/
class BOTAN_PUBLIC_API(2,0) Internal_Error : public Exception
   {
   public:
      explicit Internal_Error(const std::string& err);

      ErrorType error_type() const noexcept override { return ErrorType::InternalError; }
   };

/**
* Not Implemented Exception
*
* This is thrown in the situation where a requested operation is
* logically valid but is not implemented by this version of the library.
*/
class BOTAN_PUBLIC_API(2,0) Not_Implemented final : public Exception
   {
   public:
      explicit Not_Implemented(const std::string& err);

      ErrorType error_type() const noexcept override { return ErrorType::NotImplemented; }
   };

template<typename E, typename... Args>
inline void do_throw_error(const char* file, int line, const char* func, Args... args)
   {
   throw E(file, line, func, args...);
   }

}

namespace Botan {

/**
* The two possible directions for cipher filters, determining whether they
* actually perform encryption or decryption.
*/
enum Cipher_Dir : int { ENCRYPTION, DECRYPTION };

/**
* Interface for cipher modes
*/
class BOTAN_PUBLIC_API(2,0) Cipher_Mode : public SymmetricAlgorithm
   {
   public:
      /**
      * @return list of available providers for this algorithm, empty if not available
      * @param algo_spec algorithm name
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      /**
      * Create an AEAD mode
      * @param algo the algorithm to create
      * @param direction specify if this should be an encryption or decryption AEAD
      * @param provider optional specification for provider to use
      * @return an AEAD mode or a null pointer if not available
      */
      static std::unique_ptr<Cipher_Mode> create(const std::string& algo,
                                                 Cipher_Dir direction,
                                                 const std::string& provider = "");

      /**
      * Create an AEAD mode, or throw
      * @param algo the algorithm to create
      * @param direction specify if this should be an encryption or decryption AEAD
      * @param provider optional specification for provider to use
      * @return an AEAD mode, or throw an exception
      */
      static std::unique_ptr<Cipher_Mode> create_or_throw(const std::string& algo,
                                                          Cipher_Dir direction,
                                                          const std::string& provider = "");

      /*
      * Prepare for processing a message under the specified nonce
      */
      virtual void start_msg(const uint8_t nonce[], size_t nonce_len) = 0;

      /**
      * Begin processing a message.
      * @param nonce the per message nonce
      */
      template<typename Alloc>
      void start(const std::vector<uint8_t, Alloc>& nonce)
         {
         start_msg(nonce.data(), nonce.size());
         }

      /**
      * Begin processing a message.
      * @param nonce the per message nonce
      * @param nonce_len length of nonce
      */
      void start(const uint8_t nonce[], size_t nonce_len)
         {
         start_msg(nonce, nonce_len);
         }

      /**
      * Begin processing a message.
      */
      void start()
         {
         return start_msg(nullptr, 0);
         }

      /**
      * Process message blocks
      *
      * Input must be a multiple of update_granularity
      *
      * Processes msg in place and returns bytes written. Normally
      * this will be either msg_len (indicating the entire message was
      * processed) or for certain AEAD modes zero (indicating that the
      * mode requires the entire message be processed in one pass).
      *
      * @param msg the message to be processed
      * @param msg_len length of the message in bytes
      */
      virtual size_t process(uint8_t msg[], size_t msg_len) = 0;

      /**
      * Process some data. Input must be in size update_granularity() uint8_t blocks.
      * @param buffer in/out parameter which will possibly be resized
      * @param offset an offset into blocks to begin processing
      */
      void update(secure_vector<uint8_t>& buffer, size_t offset = 0)
         {
         BOTAN_ASSERT(buffer.size() >= offset, "Offset ok");
         uint8_t* buf = buffer.data() + offset;
         const size_t buf_size = buffer.size() - offset;

         const size_t written = process(buf, buf_size);
         buffer.resize(offset + written);
         }

      /**
      * Complete processing of a message.
      *
      * @param final_block in/out parameter which must be at least
      *        minimum_final_size() bytes, and will be set to any final output
      * @param offset an offset into final_block to begin processing
      */
      virtual void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) = 0;

      /**
      * Returns the size of the output if this transform is used to process a
      * message with input_length bytes. In most cases the answer is precise.
      * If it is not possible to precise (namely for CBC decryption) instead a
      * lower bound is returned.
      */
      virtual size_t output_length(size_t input_length) const = 0;

      /**
      * @return size of required blocks to update
      */
      virtual size_t update_granularity() const = 0;

      /**
      * @return required minimium size to finalize() - may be any
      *         length larger than this.
      */
      virtual size_t minimum_final_size() const = 0;

      /**
      * @return the default size for a nonce
      */
      virtual size_t default_nonce_length() const = 0;

      /**
      * @return true iff nonce_len is a valid length for the nonce
      */
      virtual bool valid_nonce_length(size_t nonce_len) const = 0;

      /**
      * Resets just the message specific state and allows encrypting again under the existing key
      */
      virtual void reset() = 0;

      /**
      * @return true iff this mode provides authentication as well as
      * confidentiality.
      */
      bool authenticated() const { return this->tag_size() > 0; }

      /**
      * @return the size of the authentication tag used (in bytes)
      */
      virtual size_t tag_size() const { return 0; }

      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }
   };

/**
* Get a cipher mode by name (eg "AES-128/CBC" or "Serpent/XTS")
* @param algo_spec cipher name
* @param direction ENCRYPTION or DECRYPTION
* @param provider provider implementation to choose
*/
inline Cipher_Mode* get_cipher_mode(const std::string& algo_spec,
                                    Cipher_Dir direction,
                                    const std::string& provider = "")
   {
   return Cipher_Mode::create(algo_spec, direction, provider).release();
   }

}

namespace Botan {

/**
* Interface for AEAD (Authenticated Encryption with Associated Data)
* modes. These modes provide both encryption and message
* authentication, and can authenticate additional per-message data
* which is not included in the ciphertext (for instance a sequence
* number).
*/
class BOTAN_PUBLIC_API(2,0) AEAD_Mode : public Cipher_Mode
   {
   public:
      /**
      * Create an AEAD mode
      * @param algo the algorithm to create
      * @param direction specify if this should be an encryption or decryption AEAD
      * @param provider optional specification for provider to use
      * @return an AEAD mode or a null pointer if not available
      */
      static std::unique_ptr<AEAD_Mode> create(const std::string& algo,
                                               Cipher_Dir direction,
                                               const std::string& provider = "");

      /**
      * Create an AEAD mode, or throw
      * @param algo the algorithm to create
      * @param direction specify if this should be an encryption or decryption AEAD
      * @param provider optional specification for provider to use
      * @return an AEAD mode, or throw an exception
      */
      static std::unique_ptr<AEAD_Mode> create_or_throw(const std::string& algo,
                                                        Cipher_Dir direction,
                                                        const std::string& provider = "");

      /**
      * Set associated data that is not included in the ciphertext but
      * that should be authenticated. Must be called after set_key and
      * before start.
      *
      * Unless reset by another call, the associated data is kept
      * between messages. Thus, if the AD does not change, calling
      * once (after set_key) is the optimum.
      *
      * @param ad the associated data
      * @param ad_len length of add in bytes
      */
      virtual void set_associated_data(const uint8_t ad[], size_t ad_len) = 0;

      /**
      * Set associated data that is not included in the ciphertext but
      * that should be authenticated. Must be called after set_key and
      * before start.
      *
      * Unless reset by another call, the associated data is kept
      * between messages. Thus, if the AD does not change, calling
      * once (after set_key) is the optimum.
      *
      * Some AEADs (namely SIV) support multiple AD inputs. For
      * all other modes only nominal AD input 0 is supported; all
      * other values of i will cause an exception.
      *
      * @param ad the associated data
      * @param ad_len length of add in bytes
      */
      virtual void set_associated_data_n(size_t i, const uint8_t ad[], size_t ad_len);

      /**
      * Returns the maximum supported number of associated data inputs which
      * can be provided to set_associated_data_n
      *
      * If returns 0, then no associated data is supported.
      */
      virtual size_t maximum_associated_data_inputs() const { return 1; }

      /**
      * Most AEADs require the key to be set prior to setting the AD
      * A few allow the AD to be set even before the cipher is keyed.
      * Such ciphers would return false from this function.
      */
      virtual bool associated_data_requires_key() const { return true; }

      /**
      * Set associated data that is not included in the ciphertext but
      * that should be authenticated. Must be called after set_key and
      * before start.
      *
      * See @ref set_associated_data().
      *
      * @param ad the associated data
      */
      template<typename Alloc>
      void set_associated_data_vec(const std::vector<uint8_t, Alloc>& ad)
         {
         set_associated_data(ad.data(), ad.size());
         }

      /**
      * Set associated data that is not included in the ciphertext but
      * that should be authenticated. Must be called after set_key and
      * before start.
      *
      * See @ref set_associated_data().
      *
      * @param ad the associated data
      */
      template<typename Alloc>
      void set_ad(const std::vector<uint8_t, Alloc>& ad)
         {
         set_associated_data(ad.data(), ad.size());
         }

      /**
      * @return default AEAD nonce size (a commonly supported value among AEAD
      * modes, and large enough that random collisions are unlikely)
      */
      size_t default_nonce_length() const override { return 12; }

      virtual ~AEAD_Mode() = default;
   };

/**
* Get an AEAD mode by name (eg "AES-128/GCM" or "Serpent/EAX")
* @param name AEAD name
* @param direction ENCRYPTION or DECRYPTION
*/
inline AEAD_Mode* get_aead(const std::string& name, Cipher_Dir direction)
   {
   return AEAD_Mode::create(name, direction, "").release();
   }

}

namespace Botan {

class BER_Decoder;
class DER_Encoder;

/**
* ASN.1 Class Tags
*/
enum class ASN1_Class : uint32_t {
   Universal        = 0b0000'0000,
   Application      = 0b0100'0000,
   ContextSpecific  = 0b1000'0000,
   Private          = 0b1100'0000,

   Constructed      = 0b0010'0000,
   ExplicitContextSpecific = Constructed | ContextSpecific,

   NoObject        = 0xFF00
};

/**
* ASN.1 Type Tags
*/
enum class ASN1_Type : uint32_t {
   Eoc              = 0x00,
   Boolean          = 0x01,
   Integer          = 0x02,
   BitString        = 0x03,
   OctetString      = 0x04,
   Null             = 0x05,
   ObjectId         = 0x06,
   Enumerated       = 0x0A,
   Sequence         = 0x10,
   Set              = 0x11,

   Utf8String       = 0x0C,
   NumericString    = 0x12,
   PrintableString  = 0x13,
   TeletexString    = 0x14,
   Ia5String        = 0x16,
   VisibleString    = 0x1A,
   UniversalString  = 0x1C,
   BmpString        = 0x1E,

   UtcTime          = 0x17,
   GeneralizedTime  = 0x18,

   NoObject         = 0xFF00,
};

inline bool intersects(ASN1_Class x, ASN1_Class y)
   {
   return static_cast<uint32_t>(x) & static_cast<uint32_t>(y);
   }

inline ASN1_Type operator|(ASN1_Type x, ASN1_Type y)
   {
   return static_cast<ASN1_Type>(static_cast<uint32_t>(x) | static_cast<uint32_t>(y));
   }

inline ASN1_Class operator|(ASN1_Class x, ASN1_Class y)
   {
   return static_cast<ASN1_Class>(static_cast<uint32_t>(x) | static_cast<uint32_t>(y));
   }

inline uint32_t operator|(ASN1_Type x, ASN1_Class y)
   {
   return static_cast<uint32_t>(x) | static_cast<uint32_t>(y);
   }

inline uint32_t operator|(ASN1_Class x, ASN1_Type y)
   {
    return static_cast<uint32_t>(x) | static_cast<uint32_t>(y);
   }

std::string BOTAN_UNSTABLE_API asn1_tag_to_string(ASN1_Type type);
std::string BOTAN_UNSTABLE_API asn1_class_to_string(ASN1_Class type);

/**
* Basic ASN.1 Object Interface
*/
class BOTAN_PUBLIC_API(2,0) ASN1_Object
   {
   public:
      /**
      * Encode whatever this object is into to
      * @param to the DER_Encoder that will be written to
      */
      virtual void encode_into(DER_Encoder& to) const = 0;

      /**
      * Decode whatever this object is from from
      * @param from the BER_Decoder that will be read from
      */
      virtual void decode_from(BER_Decoder& from) = 0;

      /**
      * Return the encoding of this object. This is a convenience
      * method when just one object needs to be serialized. Use
      * DER_Encoder for complicated encodings.
      */
      std::vector<uint8_t> BER_encode() const;

      ASN1_Object() = default;
      ASN1_Object(const ASN1_Object&) = default;
      ASN1_Object & operator=(const ASN1_Object&) = default;
      virtual ~ASN1_Object() = default;
   };

/**
* BER Encoded Object
*/
class BOTAN_PUBLIC_API(2,0) BER_Object final
   {
   public:
      BER_Object() : m_type_tag(ASN1_Type::NoObject), m_class_tag(ASN1_Class::Universal) {}

      BER_Object(const BER_Object& other) = default;

      BER_Object& operator=(const BER_Object& other) = default;

      BER_Object(BER_Object&& other) = default;

      BER_Object& operator=(BER_Object&& other) = default;

      bool is_set() const { return m_type_tag != ASN1_Type::NoObject; }

      uint32_t tagging() const { return type_tag() | class_tag(); }

      ASN1_Type type_tag() const { return m_type_tag; }
      ASN1_Class class_tag() const { return m_class_tag; }

      ASN1_Type type() const { return m_type_tag; }
      ASN1_Class get_class() const { return m_class_tag; }

      const uint8_t* bits() const { return m_value.data(); }

      size_t length() const { return m_value.size(); }

      void assert_is_a(ASN1_Type type_tag, ASN1_Class class_tag,
                       const std::string& descr = "object") const;

      bool is_a(ASN1_Type type_tag, ASN1_Class class_tag) const;

      bool is_a(int type_tag, ASN1_Class class_tag) const;

   private:
      ASN1_Type m_type_tag;
      ASN1_Class m_class_tag;
      secure_vector<uint8_t> m_value;

      friend class BER_Decoder;

      void set_tagging(ASN1_Type type_tag, ASN1_Class class_tag);

      uint8_t* mutable_bits(size_t length)
         {
         m_value.resize(length);
         return m_value.data();
         }
   };

/*
* ASN.1 Utility Functions
*/
class DataSource;

namespace ASN1 {

std::vector<uint8_t> put_in_sequence(const std::vector<uint8_t>& val);
std::vector<uint8_t> put_in_sequence(const uint8_t bits[], size_t len);
std::string to_string(const BER_Object& obj);

/**
* Heuristics tests; is this object possibly BER?
* @param src a data source that will be peeked at but not modified
*/
bool maybe_BER(DataSource& src);

}

/**
* General BER Decoding Error Exception
*/
class BOTAN_PUBLIC_API(2,0) BER_Decoding_Error : public Decoding_Error
   {
   public:
      explicit BER_Decoding_Error(const std::string&);
   };

/**
* Exception For Incorrect BER Taggings
*/
class BOTAN_PUBLIC_API(2,0) BER_Bad_Tag final : public BER_Decoding_Error
   {
   public:
      BER_Bad_Tag(const std::string& msg, uint32_t tagging);
   };

/**
* This class represents ASN.1 object identifiers.
*/
class BOTAN_PUBLIC_API(2,0) OID final : public ASN1_Object
   {
   public:

      /**
      * Create an uninitialied OID object
      */
      explicit OID() {}

      /**
      * Construct an OID from a string.
      * @param str a string in the form "a.b.c" etc., where a,b,c are numbers
      */
      explicit OID(const std::string& str);

      /**
      * Initialize an OID from a sequence of integer values
      */
      explicit OID(std::initializer_list<uint32_t> init) : m_id(init) {}

      /**
      * Initialize an OID from a vector of integer values
      */
      explicit OID(std::vector<uint32_t>&& init) : m_id(init) {}

      /**
      * Construct an OID from a string.
      * @param str a string in the form "a.b.c" etc., where a,b,c are numbers
      *        or any known OID name (for example "RSA" or "X509v3.SubjectKeyIdentifier")
      */
      static OID from_string(const std::string& str);

      void encode_into(DER_Encoder&) const override;
      void decode_from(BER_Decoder&) override;

      /**
      * Find out whether this OID is empty
      * @return true is no OID value is set
      */
      bool empty() const { return m_id.empty(); }

      /**
      * Find out whether this OID has a value
      * @return true is this OID has a value
      */
      bool has_value() const { return (m_id.empty() == false); }

      /**
      * Get this OID as list (vector) of its components.
      * @return vector representing this OID
      */
      const std::vector<uint32_t>& get_components() const { return m_id; }

      const std::vector<uint32_t>& get_id() const { return get_components(); }

      /**
      * Get this OID as a dotted-decimal string
      * @return string representing this OID
      */
      std::string to_string() const;

      /**
      * If there is a known name associated with this OID, return that.
      * Otherwise return the result of to_string
      */
      std::string to_formatted_string() const;

      /**
      * Compare two OIDs.
      * @return true if they are equal, false otherwise
      */
      bool operator==(const OID& other) const
         {
         return m_id == other.m_id;
         }

   private:
      std::vector<uint32_t> m_id;
   };

/**
* Append another component onto the OID.
* @param oid the OID to add the new component to
* @param new_comp the new component to add
*/
OID BOTAN_PUBLIC_API(2,0) operator+(const OID& oid, uint32_t new_comp);

/**
* Compare two OIDs.
* @param a the first OID
* @param b the second OID
* @return true if a is not equal to b
*/
inline bool operator!=(const OID& a, const OID& b)
   {
   return !(a == b);
   }

/**
* Compare two OIDs.
* @param a the first OID
* @param b the second OID
* @return true if a is lexicographically smaller than b
*/
bool BOTAN_PUBLIC_API(2,0) operator<(const OID& a, const OID& b);

/**
* Time (GeneralizedTime/UniversalTime)
*/
class BOTAN_PUBLIC_API(2,0) ASN1_Time final : public ASN1_Object
   {
   public:
      /// DER encode a ASN1_Time
      void encode_into(DER_Encoder&) const override;

      // Decode a BER encoded ASN1_Time
      void decode_from(BER_Decoder&) override;

      /// Return an internal string representation of the time
      std::string to_string() const;

      /// Returns a human friendly string replesentation of no particular formatting
      std::string readable_string() const;

      /// Return if the time has been set somehow
      bool time_is_set() const;

      ///  Compare this time against another
      int32_t cmp(const ASN1_Time& other) const;

      /// Create an invalid ASN1_Time
      ASN1_Time() = default;

      /// Create a ASN1_Time from a time point
      explicit ASN1_Time(const std::chrono::system_clock::time_point& time);

      /// Create an ASN1_Time from string
      ASN1_Time(const std::string& t_spec);

      /// Create an ASN1_Time from string and a specified tagging (Utc or Generalized)
      ASN1_Time(const std::string& t_spec, ASN1_Type tag);

      /// Returns a STL timepoint object
      std::chrono::system_clock::time_point to_std_timepoint() const;

      /// Return time since epoch
      uint64_t time_since_epoch() const;

   private:
      void set_to(const std::string& t_spec, ASN1_Type type);
      bool passes_sanity_check() const;

      uint32_t m_year = 0;
      uint32_t m_month = 0;
      uint32_t m_day = 0;
      uint32_t m_hour = 0;
      uint32_t m_minute = 0;
      uint32_t m_second = 0;
      ASN1_Type m_tag = ASN1_Type::NoObject;
   };

/*
* Comparison Operations
*/
bool BOTAN_PUBLIC_API(2,0) operator==(const ASN1_Time&, const ASN1_Time&);
bool BOTAN_PUBLIC_API(2,0) operator!=(const ASN1_Time&, const ASN1_Time&);
bool BOTAN_PUBLIC_API(2,0) operator<=(const ASN1_Time&, const ASN1_Time&);
bool BOTAN_PUBLIC_API(2,0) operator>=(const ASN1_Time&, const ASN1_Time&);
bool BOTAN_PUBLIC_API(2,0) operator<(const ASN1_Time&, const ASN1_Time&);
bool BOTAN_PUBLIC_API(2,0) operator>(const ASN1_Time&, const ASN1_Time&);

typedef ASN1_Time X509_Time;

/**
* ASN.1 string type
* This class normalizes all inputs to a UTF-8 std::string
*/
class BOTAN_PUBLIC_API(2,0) ASN1_String final : public ASN1_Object
   {
   public:
      void encode_into(DER_Encoder&) const override;
      void decode_from(BER_Decoder&) override;

      ASN1_Type tagging() const { return m_tag; }

      const std::string& value() const { return m_utf8_str; }

      size_t size() const { return value().size(); }

      bool empty() const { return m_utf8_str.empty(); }

      /**
      * Return true iff this is a tag for a known string type we can handle.
      */
      static bool is_string_type(ASN1_Type tag);

      bool operator==(const ASN1_String& other) const
         { return value() == other.value(); }

      explicit ASN1_String(const std::string& utf8 = "");
      ASN1_String(const std::string& utf8, ASN1_Type tag);
   private:
      std::vector<uint8_t> m_data;
      std::string m_utf8_str;
      ASN1_Type m_tag;
   };

/**
* Algorithm Identifier
*/
class BOTAN_PUBLIC_API(2,0) AlgorithmIdentifier final : public ASN1_Object
   {
   public:
      enum Encoding_Option { USE_NULL_PARAM, USE_EMPTY_PARAM };

      void encode_into(DER_Encoder&) const override;
      void decode_from(BER_Decoder&) override;

      AlgorithmIdentifier() = default;

      AlgorithmIdentifier(const OID& oid, Encoding_Option enc);
      AlgorithmIdentifier(const std::string& oid_name, Encoding_Option enc);

      AlgorithmIdentifier(const OID& oid, const std::vector<uint8_t>& params);
      AlgorithmIdentifier(const std::string& oid_name, const std::vector<uint8_t>& params);

      const OID& oid() const { return m_oid; }
      const std::vector<uint8_t>& parameters() const { return m_parameters; }

      const OID& get_oid() const { return m_oid; }
      const std::vector<uint8_t>& get_parameters() const { return m_parameters; }

      bool parameters_are_null() const;
      bool parameters_are_empty() const { return m_parameters.empty(); }

      bool parameters_are_null_or_empty() const
         {
         return parameters_are_empty() || parameters_are_null();
         }

   private:
      OID m_oid;
      std::vector<uint8_t> m_parameters;
   };

/*
* Comparison Operations
*/
bool BOTAN_PUBLIC_API(2,0) operator==(const AlgorithmIdentifier&,
                                      const AlgorithmIdentifier&);
bool BOTAN_PUBLIC_API(2,0) operator!=(const AlgorithmIdentifier&,
                                      const AlgorithmIdentifier&);

}

namespace Botan {

class BigInt;
class BER_Decoder;

/**
* Format ASN.1 data and call a virtual to format
*/
class BOTAN_PUBLIC_API(2,4) ASN1_Formatter
   {
   public:
      virtual ~ASN1_Formatter() = default;

      /**
      * @param print_context_specific if true, try to parse nested context specific data.
      * @param max_depth do not recurse more than this many times. If zero, recursion
      *        is unbounded.
      */
      ASN1_Formatter(bool print_context_specific, size_t max_depth) :
         m_print_context_specific(print_context_specific),
         m_max_depth(max_depth)
         {}

      void print_to_stream(std::ostream& out,
                           const uint8_t in[],
                           size_t len) const;

      std::string print(const uint8_t in[], size_t len) const;

      template<typename Alloc>
      std::string print(const std::vector<uint8_t, Alloc>& vec) const
         {
         return print(vec.data(), vec.size());
         }

   protected:
      /**
      * This is called for each element
      */
      virtual std::string format(ASN1_Type type_tag,
                                 ASN1_Class class_tag,
                                 size_t level,
                                 size_t length,
                                 const std::string& value) const = 0;

      /**
      * This is called to format binary elements that we don't know how to
      * convert to a string. The result will be passed as value to format; the
      * tags are included as a hint to aid decoding.
      */
      virtual std::string format_bin(ASN1_Type type_tag,
                                     ASN1_Class class_tag,
                                     const std::vector<uint8_t>& vec) const = 0;

      /**
      * This is called to format integers
      */
      virtual std::string format_bn(const BigInt& bn) const = 0;

   private:
      void decode(std::ostream& output,
                  BER_Decoder& decoder,
                  size_t level) const;

      const bool m_print_context_specific;
      const size_t m_max_depth;
   };

/**
* Format ASN.1 data into human readable output. The exact form of the output for
* any particular input is not guaranteed and may change from release to release.
*/
class BOTAN_PUBLIC_API(2,4) ASN1_Pretty_Printer final : public ASN1_Formatter
   {
   public:
      /**
      * @param print_limit strings larger than this are not printed
      * @param print_binary_limit binary strings larger than this are not printed
      * @param print_context_specific if true, try to parse nested context specific data.
      * @param initial_level the initial depth (0 or 1 are the only reasonable values)
      * @param value_column ASN.1 values are lined up at this column in output
      * @param max_depth do not recurse more than this many times. If zero, recursion
      *        is unbounded.
      */
      ASN1_Pretty_Printer(size_t print_limit = 4096,
                          size_t print_binary_limit = 2048,
                          bool print_context_specific = true,
                          size_t initial_level = 0,
                          size_t value_column = 60,
                          size_t max_depth = 64) :
         ASN1_Formatter(print_context_specific, max_depth),
         m_print_limit(print_limit),
         m_print_binary_limit(print_binary_limit),
         m_initial_level(initial_level),
         m_value_column(value_column)
         {}

   private:
      std::string format(ASN1_Type type_tag,
                         ASN1_Class class_tag,
                         size_t level,
                         size_t length,
                         const std::string& value) const override;

      std::string format_bin(ASN1_Type type_tag,
                             ASN1_Class class_tag,
                             const std::vector<uint8_t>& vec) const override;

      std::string format_bn(const BigInt& bn) const override;

      const size_t m_print_limit;
      const size_t m_print_binary_limit;
      const size_t m_initial_level;
      const size_t m_value_column;
   };

}

namespace Botan {

/**
* Perform base64 encoding
* @param output an array of at least base64_encode_max_output bytes
* @param input is some binary data
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*        bytes of input were actually consumed. If less than
*        input_length, then the range input[consumed:length]
*        should be passed in later along with more input.
* @param final_inputs true iff this is the last input, in which case
         padding chars will be applied if needed
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2,0) base64_encode(char output[],
                               const uint8_t input[],
                               size_t input_length,
                               size_t& input_consumed,
                               bool final_inputs);

/**
* Perform base64 encoding
* @param input some input
* @param input_length length of input in bytes
* @return base64adecimal representation of input
*/
std::string BOTAN_PUBLIC_API(2,0) base64_encode(const uint8_t input[],
                                    size_t input_length);

/**
* Perform base64 encoding
* @param input some input
* @return base64adecimal representation of input
*/
template<typename Alloc>
std::string base64_encode(const std::vector<uint8_t, Alloc>& input)
   {
   return base64_encode(input.data(), input.size());
   }

/**
* Perform base64 decoding
* @param output an array of at least base64_decode_max_output bytes
* @param input some base64 input
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*        bytes of input were actually consumed. If less than
*        input_length, then the range input[consumed:length]
*        should be passed in later along with more input.
* @param final_inputs true iff this is the last input, in which case
         padding is allowed
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2,0) base64_decode(uint8_t output[],
                               const char input[],
                               size_t input_length,
                               size_t& input_consumed,
                               bool final_inputs,
                               bool ignore_ws = true);

/**
* Perform base64 decoding
* @param output an array of at least base64_decode_max_output bytes
* @param input some base64 input
* @param input_length length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2,0) base64_decode(uint8_t output[],
                               const char input[],
                               size_t input_length,
                               bool ignore_ws = true);

/**
* Perform base64 decoding
* @param output an array of at least base64_decode_max_output bytes
* @param input some base64 input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2,0) base64_decode(uint8_t output[],
                               const std::string& input,
                               bool ignore_ws = true);

/**
* Perform base64 decoding
* @param input some base64 input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded base64 output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(2,0) base64_decode(const char input[],
                                           size_t input_length,
                                           bool ignore_ws = true);

/**
* Perform base64 decoding
* @param input some base64 input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded base64 output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(2,0) base64_decode(const std::string& input,
                                           bool ignore_ws = true);

/**
* Calculate the size of output buffer for base64_encode
* @param input_length the length of input in bytes
* @return the size of output buffer in bytes
*/
size_t BOTAN_PUBLIC_API(2,1) base64_encode_max_output(size_t input_length);

/**
* Calculate the size of output buffer for base64_decode
* @param input_length the length of input in bytes
* @return the size of output buffer in bytes
*/
size_t BOTAN_PUBLIC_API(2,1) base64_decode_max_output(size_t input_length);

}

namespace Botan {

/**
* This class represents an abstract data source object.
*/
class BOTAN_PUBLIC_API(2,0) DataSource
   {
   public:
      /**
      * Read from the source. Moves the internal offset so that every
      * call to read will return a new portion of the source.
      *
      * @param out the byte array to write the result to
      * @param length the length of the byte array out
      * @return length in bytes that was actually read and put
      * into out
      */
      [[nodiscard]] virtual size_t read(uint8_t out[], size_t length) = 0;

      virtual bool check_available(size_t n) = 0;

      /**
      * Read from the source but do not modify the internal
      * offset. Consecutive calls to peek() will return portions of
      * the source starting at the same position.
      *
      * @param out the byte array to write the output to
      * @param length the length of the byte array out
      * @param peek_offset the offset into the stream to read at
      * @return length in bytes that was actually read and put
      * into out
      */
      [[nodiscard]] virtual size_t peek(uint8_t out[], size_t length, size_t peek_offset) const = 0;

      /**
      * Test whether the source still has data that can be read.
      * @return true if there is no more data to read, false otherwise
      */
      virtual bool end_of_data() const = 0;
      /**
      * return the id of this data source
      * @return std::string representing the id of this data source
      */
      virtual std::string id() const { return ""; }

      /**
      * Read one byte.
      * @param out the byte to read to
      * @return length in bytes that was actually read and put
      * into out
      */
      size_t read_byte(uint8_t& out);

      /**
      * Peek at one byte.
      * @param out an output byte
      * @return length in bytes that was actually read and put
      * into out
      */
      size_t peek_byte(uint8_t& out) const;

      /**
      * Discard the next N bytes of the data
      * @param N the number of bytes to discard
      * @return number of bytes actually discarded
      */
      size_t discard_next(size_t N);

      /**
      * @return number of bytes read so far.
      */
      virtual size_t get_bytes_read() const = 0;

      DataSource() = default;
      virtual ~DataSource() = default;
      DataSource& operator=(const DataSource&) = delete;
      DataSource(const DataSource&) = delete;
   };

/**
* This class represents a Memory-Based DataSource
*/
class BOTAN_PUBLIC_API(2,0) DataSource_Memory final : public DataSource
   {
   public:
      size_t read(uint8_t[], size_t) override;
      size_t peek(uint8_t[], size_t, size_t) const override;
      bool check_available(size_t n) override;
      bool end_of_data() const override;

      /**
      * Construct a memory source that reads from a string
      * @param in the string to read from
      */
      explicit DataSource_Memory(const std::string& in);

      /**
      * Construct a memory source that reads from a byte array
      * @param in the byte array to read from
      * @param length the length of the byte array
      */
      DataSource_Memory(const uint8_t in[], size_t length) :
         m_source(in, in + length), m_offset(0) {}

      /**
      * Construct a memory source that reads from a secure_vector
      * @param in the MemoryRegion to read from
      */
      explicit DataSource_Memory(const secure_vector<uint8_t>& in) :
         m_source(in), m_offset(0) {}

      /**
      * Construct a memory source that reads from a std::vector
      * @param in the MemoryRegion to read from
      */
      explicit DataSource_Memory(const std::vector<uint8_t>& in) :
         m_source(in.begin(), in.end()), m_offset(0) {}

      size_t get_bytes_read() const override { return m_offset; }
   private:
      secure_vector<uint8_t> m_source;
      size_t m_offset;
   };

/**
* This class represents a Stream-Based DataSource.
*/
class BOTAN_PUBLIC_API(2,0) DataSource_Stream final : public DataSource
   {
   public:
      size_t read(uint8_t[], size_t) override;
      size_t peek(uint8_t[], size_t, size_t) const override;
      bool check_available(size_t n) override;
      bool end_of_data() const override;
      std::string id() const override;

      DataSource_Stream(std::istream&,
                        const std::string& id = "<std::istream>");

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      /**
      * Construct a Stream-Based DataSource from filesystem path
      * @param file the path to the file
      * @param use_binary whether to treat the file as binary or not
      */
      DataSource_Stream(const std::string& file, bool use_binary = false);
#endif

      DataSource_Stream(const DataSource_Stream&) = delete;

      DataSource_Stream& operator=(const DataSource_Stream&) = delete;

      ~DataSource_Stream();

      size_t get_bytes_read() const override { return m_total_read; }
   private:
      const std::string m_identifier;

      std::unique_ptr<std::istream> m_source_memory;
      std::istream& m_source;
      size_t m_total_read;
   };

}

namespace Botan {

class BigInt;

/**
* BER Decoding Object
*/
class BOTAN_PUBLIC_API(2,0) BER_Decoder final
   {
   public:
      /**
      * Set up to BER decode the data in buf of length len
      */
      BER_Decoder(const uint8_t buf[], size_t len);

      /**
      * Set up to BER decode the data in vec
      */
      explicit BER_Decoder(const secure_vector<uint8_t>& vec);

      /**
      * Set up to BER decode the data in vec
      */
      explicit BER_Decoder(const std::vector<uint8_t>& vec);

      /**
      * Set up to BER decode the data in src
      */
      explicit BER_Decoder(DataSource& src);

      /**
      * Set up to BER decode the data in obj
      */
      BER_Decoder(const BER_Object& obj) :
         BER_Decoder(obj.bits(), obj.length()) {}

      /**
      * Set up to BER decode the data in obj
      */
      BER_Decoder(BER_Object&& obj) :
         BER_Decoder(std::move(obj), nullptr) {}

      BER_Decoder(const BER_Decoder& other);

      BER_Decoder& operator=(const BER_Decoder&) = delete;

      /**
      * Get the next object in the data stream.
      * If EOF, returns an object with type NO_OBJECT.
      */
      BER_Object get_next_object();

      BER_Decoder& get_next(BER_Object& ber)
         {
         ber = get_next_object();
         return (*this);
         }

      /**
      * Push an object back onto the stream. Throws if another
      * object was previously pushed and has not been subsequently
      * read out.
      */
      void push_back(const BER_Object& obj);

      /**
      * Push an object back onto the stream. Throws if another
      * object was previously pushed and has not been subsequently
      * read out.
      */
      void push_back(BER_Object&& obj);

      /**
      * Return true if there is at least one more item remaining
      */
      bool more_items() const;

      /**
      * Verify the stream is concluded, throws otherwise.
      * Returns (*this)
      */
      BER_Decoder& verify_end();

      /**
      * Verify the stream is concluded, throws otherwise.
      * Returns (*this)
      */
      BER_Decoder& verify_end(const std::string& err_msg);

      /**
      * Discard any data that remains unread
      * Returns (*this)
      */
      BER_Decoder& discard_remaining();

      BER_Decoder start_cons(ASN1_Type type_tag, ASN1_Class class_tag);

      BER_Decoder start_sequence()
         {
         return start_cons(ASN1_Type::Sequence, ASN1_Class::Universal);
         }

      BER_Decoder start_set()
         {
         return start_cons(ASN1_Type::Set, ASN1_Class::Universal);
         }

      BER_Decoder start_context_specific(uint32_t tag)
         {
         return start_cons(ASN1_Type(tag), ASN1_Class::ContextSpecific);
         }

      BER_Decoder start_explicit_context_specific(uint32_t tag)
         {
         return start_cons(ASN1_Type(tag), ASN1_Class::ExplicitContextSpecific);
         }

      /**
      * Finish decoding a constructed data, throws if any data remains.
      * Returns the parent of *this (ie the object on which start_cons was called).
      */
      BER_Decoder& end_cons();

      /**
      * Get next object and copy value to POD type
      * Asserts value length is equal to POD type sizeof.
      * Asserts Type tag and optional Class tag according to parameters.
      * Copy value to POD type (struct, union, C-style array, std::array, etc.).
      * @param out POD type reference where to copy object value
      * @param type_tag ASN1_Type enum to assert type on object read
      * @param class_tag ASN1_Type enum to assert class on object read (default: CONTEXT_SPECIFIC)
      * @return this reference
      */
      template <typename T>
         BER_Decoder& get_next_value(T &out,
                                     ASN1_Type type_tag,
                                     ASN1_Class class_tag = ASN1_Class::ContextSpecific)
         {
         static_assert(std::is_standard_layout<T>::value && std::is_trivial<T>::value, "Type must be POD");

         BER_Object obj = get_next_object();
         obj.assert_is_a(type_tag, class_tag);

         if (obj.length() != sizeof(T))
            throw BER_Decoding_Error(
                    "Size mismatch. Object value size is " +
                    std::to_string(obj.length()) +
                    "; Output type size is " +
                    std::to_string(sizeof(T)));

         copy_mem(reinterpret_cast<uint8_t*>(&out), obj.bits(), obj.length());

         return (*this);
         }

      /*
      * Save all the bytes remaining in the source
      */
      template<typename Alloc>
      BER_Decoder& raw_bytes(std::vector<uint8_t, Alloc>& out)
         {
         out.clear();
         uint8_t buf;
         while(m_source->read_byte(buf))
            out.push_back(buf);
         return (*this);
         }

      BER_Decoder& decode_null();

      /**
      * Decode a BER encoded BOOLEAN
      */
      BER_Decoder& decode(bool& out)
         {
         return decode(out, ASN1_Type::Boolean, ASN1_Class::Universal);
         }

      /*
      * Decode a small BER encoded INTEGER
      */
      BER_Decoder& decode(size_t& out)
         {
         return decode(out, ASN1_Type::Integer, ASN1_Class::Universal);
         }

      /*
      * Decode a BER encoded INTEGER
      */
      BER_Decoder& decode(BigInt& out)
         {
         return decode(out, ASN1_Type::Integer, ASN1_Class::Universal);
         }

      std::vector<uint8_t> get_next_octet_string()
         {
         std::vector<uint8_t> out_vec;
         decode(out_vec, ASN1_Type::OctetString);
         return out_vec;
         }

      /*
      * BER decode a BIT STRING or OCTET STRING
      */
      template<typename Alloc>
      BER_Decoder& decode(std::vector<uint8_t, Alloc>& out, ASN1_Type real_type)
         {
         return decode(out, real_type, real_type, ASN1_Class::Universal);
         }

      BER_Decoder& decode(bool& v,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      BER_Decoder& decode(size_t& v,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      BER_Decoder& decode(BigInt& v,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      BER_Decoder& decode(std::vector<uint8_t>& v,
                          ASN1_Type real_type,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      BER_Decoder& decode(secure_vector<uint8_t>& v,
                          ASN1_Type real_type,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      BER_Decoder& decode(ASN1_Object& obj,
                          ASN1_Type type_tag = ASN1_Type::NoObject,
                          ASN1_Class class_tag = ASN1_Class::NoObject);

      /**
      * Decode an integer value which is typed as an octet string
      */
      BER_Decoder& decode_octet_string_bigint(BigInt& b);

      uint64_t decode_constrained_integer(ASN1_Type type_tag,
                                          ASN1_Class class_tag,
                                          size_t T_bytes);

      template<typename T> BER_Decoder& decode_integer_type(T& out)
         {
         return decode_integer_type<T>(out, ASN1_Type::Integer, ASN1_Class::Universal);
         }

      template<typename T>
         BER_Decoder& decode_integer_type(T& out,
                                          ASN1_Type type_tag,
                                          ASN1_Class class_tag = ASN1_Class::ContextSpecific)
         {
         out = static_cast<T>(decode_constrained_integer(type_tag, class_tag, sizeof(out)));
         return (*this);
         }

      template<typename T>
         BER_Decoder& decode_optional(T& out,
                                      ASN1_Type type_tag,
                                      ASN1_Class class_tag,
                                      const T& default_value = T());

      template<typename T>
         BER_Decoder& decode_optional_implicit(
            T& out,
            ASN1_Type type_tag,
            ASN1_Class class_tag,
            ASN1_Type real_type,
            ASN1_Class real_class,
            const T& default_value = T());

      template<typename T>
         BER_Decoder& decode_list(std::vector<T>& out,
                                  ASN1_Type type_tag = ASN1_Type::Sequence,
                                  ASN1_Class class_tag = ASN1_Class::Universal);

      template<typename T>
         BER_Decoder& decode_and_check(const T& expected,
                                       const std::string& error_msg)
         {
         T actual;
         decode(actual);

         if(actual != expected)
            throw Decoding_Error(error_msg);

         return (*this);
         }

      /*
      * Decode an OPTIONAL string type
      */
      template<typename Alloc>
      BER_Decoder& decode_optional_string(std::vector<uint8_t, Alloc>& out,
                                          ASN1_Type real_type,
                                          uint32_t expected_tag,
                                          ASN1_Class class_tag = ASN1_Class::ContextSpecific)
         {
         BER_Object obj = get_next_object();

         ASN1_Type type_tag = static_cast<ASN1_Type>(expected_tag);

         if(obj.is_a(type_tag, class_tag))
            {
            if(class_tag == ASN1_Class::ExplicitContextSpecific)
               {
               BER_Decoder(std::move(obj)).decode(out, real_type).verify_end();
               }
            else
               {
               push_back(std::move(obj));
               decode(out, real_type, type_tag, class_tag);
               }
            }
         else
            {
            out.clear();
            push_back(std::move(obj));
            }

         return (*this);
         }

      template<typename Alloc>
      BER_Decoder& decode_optional_string(std::vector<uint8_t, Alloc>& out,
                                          ASN1_Type real_type,
                                          ASN1_Type expected_tag,
                                          ASN1_Class class_tag = ASN1_Class::ContextSpecific)
         {
         return decode_optional_string(out, real_type,
                                       static_cast<uint32_t>(expected_tag),
                                       class_tag);
         }

   private:
      BER_Decoder(BER_Object&& obj, BER_Decoder* parent);

      BER_Decoder* m_parent = nullptr;
      BER_Object m_pushed;
      // either m_data_src.get() or an unowned pointer
      DataSource* m_source;
      mutable std::unique_ptr<DataSource> m_data_src;
   };

/*
* Decode an OPTIONAL or DEFAULT element
*/
template<typename T>
BER_Decoder& BER_Decoder::decode_optional(T& out,
                                          ASN1_Type type_tag,
                                          ASN1_Class class_tag,
                                          const T& default_value)
   {
   BER_Object obj = get_next_object();

   if(obj.is_a(type_tag, class_tag))
      {
      if(class_tag == ASN1_Class::ExplicitContextSpecific)
         {
         BER_Decoder(std::move(obj)).decode(out).verify_end();
         }
      else
         {
         push_back(std::move(obj));
         decode(out, type_tag, class_tag);
         }
      }
   else
      {
      out = default_value;
      push_back(std::move(obj));
      }

   return (*this);
   }

/*
* Decode an OPTIONAL or DEFAULT element
*/
template<typename T>
BER_Decoder& BER_Decoder::decode_optional_implicit(
   T& out,
   ASN1_Type type_tag,
   ASN1_Class class_tag,
   ASN1_Type real_type,
   ASN1_Class real_class,
   const T& default_value)
   {
   BER_Object obj = get_next_object();

   if(obj.is_a(type_tag, class_tag))
      {
      obj.set_tagging(real_type, real_class);
      push_back(std::move(obj));
      decode(out, real_type, real_class);
      }
   else
      {
      // Not what we wanted, push it back on the stream
      out = default_value;
      push_back(std::move(obj));
      }

   return (*this);
   }
/*
* Decode a list of homogenously typed values
*/
template<typename T>
BER_Decoder& BER_Decoder::decode_list(std::vector<T>& vec,
                                      ASN1_Type type_tag,
                                      ASN1_Class class_tag)
   {
   BER_Decoder list = start_cons(type_tag, class_tag);

   while(list.more_items())
      {
      T value;
      list.decode(value);
      vec.push_back(std::move(value));
      }

   list.end_cons();

   return (*this);
   }

}

namespace Botan {

class RandomNumberGenerator;

/**
* Arbitrary precision integer
*/
class BOTAN_PUBLIC_API(2,0) BigInt final
   {
   public:
     /**
     * Base enumerator for encoding and decoding
     */
     enum Base { Decimal = 10, Hexadecimal = 16, Binary = 256 };

     /**
     * Sign symbol definitions for positive and negative numbers
     */
     enum Sign { Negative = 0, Positive = 1 };

     /**
     * Create empty (zero) BigInt
     */
     BigInt() = default;

     /**
     * Create a 0-value BigInt
     */
     static BigInt zero() { return BigInt(); }

     /**
     * Create a 1-value BigInt
     */
     static BigInt one() { return BigInt::from_word(1); }

     /**
     * Create BigInt from an unsigned 64 bit integer
     * @param n initial value of this BigInt
     */
     static BigInt from_u64(uint64_t n);

     /**
     * Create BigInt from a word (limb)
     * @param n initial value of this BigInt
     */
     static BigInt from_word(word n);

     /**
     * Create BigInt from a signed 32 bit integer
     * @param n initial value of this BigInt
     */
     static BigInt from_s32(int32_t n);

     /**
     * Create BigInt from an unsigned 64 bit integer
     * @param n initial value of this BigInt
     */
     BigInt(uint64_t n);

     /**
     * Copy Constructor
     * @param other the BigInt to copy
     */
     BigInt(const BigInt& other) = default;

     /**
     * Create BigInt from a string. If the string starts with 0x the
     * rest of the string will be interpreted as hexadecimal digits.
     * Otherwise, it will be interpreted as a decimal number.
     *
     * @param str the string to parse for an integer value
     */
     explicit BigInt(const std::string& str);

     /**
     * Create a BigInt from an integer in a byte array
     * @param buf the byte array holding the value
     * @param length size of buf
     */
     BigInt(const uint8_t buf[], size_t length);

     /**
     * Create a BigInt from an integer in a byte array
     * @param vec the byte vector holding the value
     */
     template<typename Alloc>
     explicit BigInt(const std::vector<uint8_t, Alloc>& vec) : BigInt(vec.data(), vec.size()) {}

     /**
     * Create a BigInt from an integer in a byte array
     * @param buf the byte array holding the value
     * @param length size of buf
     * @param base is the number base of the integer in buf
     */
     BigInt(const uint8_t buf[], size_t length, Base base);

     /**
     * Create a BigInt from an integer in a byte array
     * @param buf the byte array holding the value
     * @param length size of buf
     * @param max_bits if the resulting integer is more than max_bits,
     *        it will be shifted so it is at most max_bits in length.
     */
     static BigInt from_bytes_with_max_bits(const uint8_t buf[], size_t length,
                                            size_t max_bits);

     /**
     * \brief Create a random BigInt of the specified size
     *
     * @param rng random number generator
     * @param bits size in bits
     * @param set_high_bit if true, the highest bit is always set
     *
     * @see randomize
     */
     BigInt(RandomNumberGenerator& rng, size_t bits, bool set_high_bit = true);

     /**
     * Create BigInt of specified size, all zeros
     * @param n size of the internal register in words
     */
     static BigInt with_capacity(size_t n);

     /**
     * Move constructor
     */
     BigInt(BigInt&& other)
        {
        this->swap(other);
        }

     ~BigInt() { const_time_unpoison(); }

     /**
     * Move assignment
     */
     BigInt& operator=(BigInt&& other)
        {
        if(this != &other)
           this->swap(other);

        return (*this);
        }

     /**
     * Copy assignment
     */
     BigInt& operator=(const BigInt&) = default;

     /**
     * Swap this value with another
     * @param other BigInt to swap values with
     */
     void swap(BigInt& other)
        {
        m_data.swap(other.m_data);
        std::swap(m_signedness, other.m_signedness);
        }

     void swap_reg(secure_vector<word>& reg)
        {
        m_data.swap(reg);
        // sign left unchanged
        }

     /**
     * += operator
     * @param y the BigInt to add to this
     */
     BigInt& operator+=(const BigInt& y)
        {
        return add(y.data(), y.sig_words(), y.sign());
        }

     /**
     * += operator
     * @param y the word to add to this
     */
     BigInt& operator+=(word y)
        {
        return add(&y, 1, Positive);
        }

     /**
     * -= operator
     * @param y the BigInt to subtract from this
     */
     BigInt& operator-=(const BigInt& y)
        {
        return sub(y.data(), y.sig_words(), y.sign());
        }

     /**
     * -= operator
     * @param y the word to subtract from this
     */
     BigInt& operator-=(word y)
        {
        return sub(&y, 1, Positive);
        }

     /**
     * *= operator
     * @param y the BigInt to multiply with this
     */
     BigInt& operator*=(const BigInt& y);

     /**
     * *= operator
     * @param y the word to multiply with this
     */
     BigInt& operator*=(word y);

     /**
     * /= operator
     * @param y the BigInt to divide this by
     */
     BigInt& operator/=(const BigInt& y);

     /**
     * Modulo operator
     * @param y the modulus to reduce this by
     */
     BigInt& operator%=(const BigInt& y);

     /**
     * Modulo operator
     * @param y the modulus (word) to reduce this by
     */
     word    operator%=(word y);

     /**
     * Left shift operator
     * @param shift the number of bits to shift this left by
     */
     BigInt& operator<<=(size_t shift);

     /**
     * Right shift operator
     * @param shift the number of bits to shift this right by
     */
     BigInt& operator>>=(size_t shift);

     /**
     * Increment operator
     */
     BigInt& operator++() { return (*this += 1); }

     /**
     * Decrement operator
     */
     BigInt& operator--() { return (*this -= 1); }

     /**
     * Postfix increment operator
     */
     BigInt  operator++(int) { BigInt x = (*this); ++(*this); return x; }

     /**
     * Postfix decrement operator
     */
     BigInt  operator--(int) { BigInt x = (*this); --(*this); return x; }

     /**
     * Unary negation operator
     * @return negative this
     */
     BigInt operator-() const;

     /**
     * ! operator
     * @return true iff this is zero, otherwise false
     */
     bool operator !() const { return (!is_nonzero()); }

     static BigInt add2(const BigInt& x, const word y[], size_t y_words, Sign y_sign);

     BigInt& add(const word y[], size_t y_words, Sign sign);

     BigInt& sub(const word y[], size_t y_words, Sign sign)
        {
        return add(y, y_words, sign == Positive ? Negative : Positive);
        }

     /**
     * Multiply this with y
     * @param y the BigInt to multiply with this
     * @param ws a temp workspace
     */
     BigInt& mul(const BigInt& y, secure_vector<word>& ws);

     /**
     * Square value of *this
     * @param ws a temp workspace
     */
     BigInt& square(secure_vector<word>& ws);

     /**
     * Set *this to y - *this
     * @param y the BigInt to subtract from as a sequence of words
     * @param y_words length of y in words
     * @param ws a temp workspace
     */
     BigInt& rev_sub(const word y[], size_t y_words, secure_vector<word>& ws);

     /**
     * Set *this to (*this + y) % mod
     * This function assumes *this is >= 0 && < mod
     * @param y the BigInt to add - assumed y >= 0 and y < mod
     * @param mod the positive modulus
     * @param ws a temp workspace
     */
     BigInt& mod_add(const BigInt& y, const BigInt& mod, secure_vector<word>& ws);

     /**
     * Set *this to (*this - y) % mod
     * This function assumes *this is >= 0 && < mod
     * @param y the BigInt to subtract - assumed y >= 0 and y < mod
     * @param mod the positive modulus
     * @param ws a temp workspace
     */
     BigInt& mod_sub(const BigInt& y, const BigInt& mod, secure_vector<word>& ws);

     /**
     * Set *this to (*this * y) % mod
     * This function assumes *this is >= 0 && < mod
     * y should be small, less than 16
     * @param y the small integer to multiply by
     * @param mod the positive modulus
     * @param ws a temp workspace
     */
     BigInt& mod_mul(uint8_t y, const BigInt& mod, secure_vector<word>& ws);

     /**
     * Return *this % mod
     *
     * Assumes that *this is (if anything) only slightly larger than
     * mod and performs repeated subtractions. It should not be used if
     * *this is much larger than mod, instead use modulo operator.
     */
     size_t reduce_below(const BigInt& mod, secure_vector<word> &ws);

     /**
     * Return *this % mod
     *
     * Assumes that *this is (if anything) only slightly larger than mod and
     * performs repeated subtractions. It should not be used if *this is much
     * larger than mod, instead use modulo operator.
     *
     * Performs exactly bound subtractions, so if *this is >= bound*mod then the
     * result will not be fully reduced. If bound is zero, nothing happens.
     */
     void ct_reduce_below(const BigInt& mod, secure_vector<word> &ws, size_t bound);

     /**
     * Zeroize the BigInt. The size of the underlying register is not
     * modified.
     */
     void clear() { m_data.set_to_zero(); m_signedness = Positive; }

     /**
     * Compare this to another BigInt
     * @param n the BigInt value to compare with
     * @param check_signs include sign in comparison?
     * @result if (this<n) return -1, if (this>n) return 1, if both
     * values are identical return 0 [like Perl's <=> operator]
     */
     int32_t cmp(const BigInt& n, bool check_signs = true) const;

     /**
     * Compare this to another BigInt
     * @param n the BigInt value to compare with
     * @result true if this == n or false otherwise
     */
     bool is_equal(const BigInt& n) const;

     /**
     * Compare this to another BigInt
     * @param n the BigInt value to compare with
     * @result true if this < n or false otherwise
     */
     bool is_less_than(const BigInt& n) const;

     /**
     * Compare this to an integer
     * @param n the value to compare with
     * @result if (this<n) return -1, if (this>n) return 1, if both
     * values are identical return 0 [like Perl's <=> operator]
     */
     int32_t cmp_word(word n) const;

     /**
     * Test if the integer has an even value
     * @result true if the integer is even, false otherwise
     */
     bool is_even() const { return (get_bit(0) == 0); }

     /**
     * Test if the integer has an odd value
     * @result true if the integer is odd, false otherwise
     */
     bool is_odd()  const { return (get_bit(0) == 1); }

     /**
     * Test if the integer is not zero
     * @result true if the integer is non-zero, false otherwise
     */
     bool is_nonzero() const { return (!is_zero()); }

     /**
     * Test if the integer is zero
     * @result true if the integer is zero, false otherwise
     */
     bool is_zero() const
        {
        return (sig_words() == 0);
        }

     /**
     * Set bit at specified position
     * @param n bit position to set
     */
     void set_bit(size_t n)
        {
        conditionally_set_bit(n, true);
        }

     /**
     * Conditionally set bit at specified position. Note if set_it is
     * false, nothing happens, and if the bit is already set, it
     * remains set.
     *
     * @param n bit position to set
     * @param set_it if the bit should be set
     */
     void conditionally_set_bit(size_t n, bool set_it)
        {
        const size_t which = n / BOTAN_MP_WORD_BITS;
        const word mask = static_cast<word>(set_it) << (n % BOTAN_MP_WORD_BITS);
        m_data.set_word_at(which, word_at(which) | mask);
        }

     /**
     * Clear bit at specified position
     * @param n bit position to clear
     */
     void clear_bit(size_t n);

     /**
     * Clear all but the lowest n bits
     * @param n amount of bits to keep
     */
     void mask_bits(size_t n)
        {
        m_data.mask_bits(n);
        }

     /**
     * Return bit value at specified position
     * @param n the bit offset to test
     * @result true, if the bit at position n is set, false otherwise
     */
     bool get_bit(size_t n) const
        {
        return ((word_at(n / BOTAN_MP_WORD_BITS) >> (n % BOTAN_MP_WORD_BITS)) & 1);
        }

     /**
     * Return (a maximum of) 32 bits of the complete value
     * @param offset the offset to start extracting
     * @param length amount of bits to extract (starting at offset)
     * @result the integer extracted from the register starting at
     * offset with specified length
     */
     uint32_t get_substring(size_t offset, size_t length) const;

     /**
     * Convert this value into a uint32_t, if it is in the range
     * [0 ... 2**32-1], or otherwise throw an exception.
     * @result the value as a uint32_t if conversion is possible
     */
     uint32_t to_u32bit() const;

     /**
     * Convert this value to a decimal string.
     * Warning: decimal conversions are relatively slow
     */
     std::string to_dec_string() const;

     /**
     * Convert this value to a hexadecimal string.
     */
     std::string to_hex_string() const;

     /**
     * @param n the offset to get a byte from
     * @result byte at offset n
     */
     uint8_t byte_at(size_t n) const;

     /**
     * Return the word at a specified position of the internal register
     * @param n position in the register
     * @return value at position n
     */
     word word_at(size_t n) const
        {
        return m_data.get_word_at(n);
        }

     void set_word_at(size_t i, word w)
        {
        m_data.set_word_at(i, w);
        }

     void set_words(const word w[], size_t len)
        {
        m_data.set_words(w, len);
        }

     /**
     * Tests if the sign of the integer is negative
     * @result true, iff the integer has a negative sign
     */
     bool is_negative() const { return (sign() == Negative); }

     /**
     * Tests if the sign of the integer is positive
     * @result true, iff the integer has a positive sign
     */
     bool is_positive() const { return (sign() == Positive); }

     /**
     * Return the sign of the integer
     * @result the sign of the integer
     */
     Sign sign() const { return (m_signedness); }

     /**
     * @result the opposite sign of the represented integer value
     */
     Sign reverse_sign() const
        {
        if(sign() == Positive)
           return Negative;
        return Positive;
        }

     /**
     * Flip the sign of this BigInt
     */
     void flip_sign()
        {
        set_sign(reverse_sign());
        }

     /**
     * Set sign of the integer
     * @param sign new Sign to set
     */
     void set_sign(Sign sign)
        {
        if(sign == Negative && is_zero())
           sign = Positive;

        m_signedness = sign;
        }

     /**
     * @result absolute (positive) value of this
     */
     BigInt abs() const;

     /**
     * Give size of internal register
     * @result size of internal register in words
     */
     size_t size() const { return m_data.size(); }

     /**
     * Return how many words we need to hold this value
     * @result significant words of the represented integer value
     */
     size_t sig_words() const
        {
        return m_data.sig_words();
        }

     /**
     * Give byte length of the integer
     * @result byte length of the represented integer value
     */
     size_t bytes() const;

     /**
     * Get the bit length of the integer
     * @result bit length of the represented integer value
     */
     size_t bits() const;

     /**
     * Get the number of high bits unset in the top (allocated) word
     * of this integer. Returns BOTAN_MP_WORD_BITS only iff *this is
     * zero. Ignores sign.
     */
     size_t top_bits_free() const;

     /**
     * Return a mutable pointer to the register
     * @result a pointer to the start of the internal register
     */
     word* mutable_data() { return m_data.mutable_data(); }

     /**
     * Return a const pointer to the register
     * @result a pointer to the start of the internal register
     */
     const word* data() const { return m_data.const_data(); }

     /**
     * Don't use this function in application code
     */
     secure_vector<word>& get_word_vector() { return m_data.mutable_vector(); }

     /**
     * Don't use this function in application code
     */
     const secure_vector<word>& get_word_vector() const { return m_data.const_vector(); }

     /**
     * Increase internal register buffer to at least n words
     * @param n new size of register
     */
     void grow_to(size_t n) const { m_data.grow_to(n); }

     void resize(size_t s) { m_data.resize(s); }

     /**
     * Fill BigInt with a random number with size of bitsize
     *
     * If \p set_high_bit is true, the highest bit will be set, which causes
     * the entropy to be \a bits-1. Otherwise the highest bit is randomly chosen
     * by the rng, causing the entropy to be \a bits.
     *
     * @param rng the random number generator to use
     * @param bitsize number of bits the created random value should have
     * @param set_high_bit if true, the highest bit is always set
     */
     void randomize(RandomNumberGenerator& rng, size_t bitsize, bool set_high_bit = true);

     /**
     * Store BigInt-value in a given byte array
     * @param buf destination byte array for the integer value
     */
     void binary_encode(uint8_t buf[]) const;

     /**
     * Store BigInt-value in a given byte array. If len is less than
     * the size of the value, then it will be truncated. If len is
     * greater than the size of the value, it will be zero-padded.
     * If len exactly equals this->bytes(), this function behaves identically
     * to binary_encode.
     *
     * @param buf destination byte array for the integer value
     * @param len how many bytes to write
     */
     void binary_encode(uint8_t buf[], size_t len) const;

     /**
     * Read integer value from a byte array with given size
     * @param buf byte array buffer containing the integer
     * @param length size of buf
     */
     void binary_decode(const uint8_t buf[], size_t length);

     /**
     * Read integer value from a byte vector
     * @param buf the vector to load from
     */
     template<typename Alloc>
     void binary_decode(const std::vector<uint8_t, Alloc>& buf)
        {
        binary_decode(buf.data(), buf.size());
        }

     /**
     * Place the value into out, zero-padding up to size words
     * Throw if *this cannot be represented in size words
     */
     void encode_words(word out[], size_t size) const;

     /**
     * If predicate is true assign other to *this
     * Uses a masked operation to avoid side channels
     */
     void ct_cond_assign(bool predicate, const BigInt& other);

     /**
     * If predicate is true swap *this and other
     * Uses a masked operation to avoid side channels
     */
     void ct_cond_swap(bool predicate, BigInt& other);

     /**
     * If predicate is true add value to *this
     */
     void ct_cond_add(bool predicate, const BigInt& value);

     /**
     * If predicate is true flip the sign of *this
     */
     void cond_flip_sign(bool predicate);

#if defined(BOTAN_HAS_VALGRIND)
     void const_time_poison() const;
     void const_time_unpoison() const;
#else
     void const_time_poison() const {}
     void const_time_unpoison() const {}
#endif

     /**
     * @param rng a random number generator
     * @param min the minimum value (must be non-negative)
     * @param max the maximum value (must be non-negative and > min)
     * @return random integer in [min,max)
     */
     static BigInt random_integer(RandomNumberGenerator& rng,
                                  const BigInt& min,
                                  const BigInt& max);

     /**
     * Create a power of two
     * @param n the power of two to create
     * @return bigint representing 2^n
     */
     static BigInt power_of_2(size_t n)
        {
        BigInt b;
        b.set_bit(n);
        return b;
        }

     /**
     * Encode the integer value from a BigInt to a std::vector of bytes
     * @param n the BigInt to use as integer source
     * @result secure_vector of bytes containing the bytes of the integer
     */
     static std::vector<uint8_t> encode(const BigInt& n)
        {
        std::vector<uint8_t> output(n.bytes());
        n.binary_encode(output.data());
        return output;
        }

     /**
     * Encode the integer value from a BigInt to a secure_vector of bytes
     * @param n the BigInt to use as integer source
     * @result secure_vector of bytes containing the bytes of the integer
     */
     static secure_vector<uint8_t> encode_locked(const BigInt& n)
        {
        secure_vector<uint8_t> output(n.bytes());
        n.binary_encode(output.data());
        return output;
        }

     /**
     * Create a BigInt from an integer in a byte array
     * @param buf the binary value to load
     * @param length size of buf
     * @result BigInt representing the integer in the byte array
     */
     static BigInt decode(const uint8_t buf[], size_t length)
        {
        return BigInt(buf, length);
        }

     /**
     * Create a BigInt from an integer in a byte array
     * @param buf the binary value to load
     * @result BigInt representing the integer in the byte array
     */
     template<typename Alloc>
     static BigInt decode(const std::vector<uint8_t, Alloc>& buf)
        {
        return BigInt(buf);
        }

     /**
     * Create a BigInt from an integer in a byte array
     * @param buf the binary value to load
     * @param length size of buf
     * @param base number-base of the integer in buf
     * @result BigInt representing the integer in the byte array
     */
     static BigInt decode(const uint8_t buf[], size_t length,
                          Base base);

     /**
     * Create a BigInt from an integer in a byte array
     * @param buf the binary value to load
     * @param base number-base of the integer in buf
     * @result BigInt representing the integer in the byte array
     */
     template<typename Alloc>
     static BigInt decode(const std::vector<uint8_t, Alloc>& buf, Base base)
        {
        if(base == Binary)
           return BigInt(buf);
        return BigInt::decode(buf.data(), buf.size(), base);
        }

     /**
     * Encode a BigInt to a byte array according to IEEE 1363
     * @param n the BigInt to encode
     * @param bytes the length of the resulting secure_vector<uint8_t>
     * @result a secure_vector<uint8_t> containing the encoded BigInt
     */
     static secure_vector<uint8_t> encode_1363(const BigInt& n, size_t bytes);

     static void encode_1363(uint8_t out[], size_t bytes, const BigInt& n);

     /**
     * Encode two BigInt to a byte array according to IEEE 1363
     * @param n1 the first BigInt to encode
     * @param n2 the second BigInt to encode
     * @param bytes the length of the encoding of each single BigInt
     * @result a secure_vector<uint8_t> containing the concatenation of the two encoded BigInt
     */
     static secure_vector<uint8_t> encode_fixed_length_int_pair(const BigInt& n1, const BigInt& n2, size_t bytes);

   private:

     class Data
        {
        public:
           word* mutable_data()
              {
              invalidate_sig_words();
              return m_reg.data();
              }

           const word* const_data() const
              {
              return m_reg.data();
              }

           secure_vector<word>& mutable_vector()
              {
              invalidate_sig_words();
              return m_reg;
              }

           const secure_vector<word>& const_vector() const
              {
              return m_reg;
              }

           word get_word_at(size_t n) const
              {
              if(n < m_reg.size())
                 return m_reg[n];
              return 0;
              }

           void set_word_at(size_t i, word w)
              {
              invalidate_sig_words();
              if(i >= m_reg.size())
                 {
                 if(w == 0)
                    return;
                 grow_to(i + 1);
                 }
              m_reg[i] = w;
              }

           void set_words(const word w[], size_t len)
              {
              invalidate_sig_words();
              m_reg.assign(w, w + len);
              }

           void set_to_zero()
              {
              m_reg.resize(m_reg.capacity());
              clear_mem(m_reg.data(), m_reg.size());
              m_sig_words = 0;
              }

           void set_size(size_t s)
              {
              invalidate_sig_words();
              clear_mem(m_reg.data(), m_reg.size());
              m_reg.resize(s + (8 - (s % 8)));
              }

           void mask_bits(size_t n)
              {
              if(n == 0) { return set_to_zero(); }

              const size_t top_word = n / BOTAN_MP_WORD_BITS;

              // if(top_word < sig_words()) ?
              if(top_word < size())
                 {
                 const word mask = (static_cast<word>(1) << (n % BOTAN_MP_WORD_BITS)) - 1;
                 const size_t len = size() - (top_word + 1);
                 if(len > 0)
                    {
                    clear_mem(&m_reg[top_word+1], len);
                    }
                 m_reg[top_word] &= mask;
                 invalidate_sig_words();
                 }
              }

           void grow_to(size_t n) const
              {
              if(n > size())
                 {
                 if(n <= m_reg.capacity())
                    m_reg.resize(n);
                 else
                    m_reg.resize(n + (8 - (n % 8)));
                 }
              }

           size_t size() const { return m_reg.size(); }

           void shrink_to_fit(size_t min_size = 0)
              {
              const size_t words = std::max(min_size, sig_words());
              m_reg.resize(words);
              }

           void resize(size_t s)
              {
              m_reg.resize(s);
              }

           void swap(Data& other)
              {
              m_reg.swap(other.m_reg);
              std::swap(m_sig_words, other.m_sig_words);
              }

           void swap(secure_vector<word>& reg)
              {
              m_reg.swap(reg);
              invalidate_sig_words();
              }

           void invalidate_sig_words() const
              {
              m_sig_words = sig_words_npos;
              }

           size_t sig_words() const
              {
              if(m_sig_words == sig_words_npos)
                 {
                 m_sig_words = calc_sig_words();
                 }
              else
                 {
                 BOTAN_DEBUG_ASSERT(m_sig_words == calc_sig_words());
                 }
              return m_sig_words;
              }
        private:
           static const size_t sig_words_npos = static_cast<size_t>(-1);

           size_t calc_sig_words() const;

           mutable secure_vector<word> m_reg;
           mutable size_t m_sig_words = sig_words_npos;
        };

      Data m_data;
      Sign m_signedness = Positive;
   };

/*
* Arithmetic Operators
*/
inline BigInt operator+(const BigInt& x, const BigInt& y)
   {
   return BigInt::add2(x, y.data(), y.sig_words(), y.sign());
   }

inline BigInt operator+(const BigInt& x, word y)
   {
   return BigInt::add2(x, &y, 1, BigInt::Positive);
   }

inline BigInt operator+(word x, const BigInt& y)
   {
   return y + x;
   }

inline BigInt operator-(const BigInt& x, const BigInt& y)
   {
   return BigInt::add2(x, y.data(), y.sig_words(), y.reverse_sign());
   }

inline BigInt operator-(const BigInt& x, word y)
   {
   return BigInt::add2(x, &y, 1, BigInt::Negative);
   }

BigInt BOTAN_PUBLIC_API(2,0) operator*(const BigInt& x, const BigInt& y);
BigInt BOTAN_PUBLIC_API(2,8) operator*(const BigInt& x, word y);
inline BigInt operator*(word x, const BigInt& y) { return y*x; }

BigInt BOTAN_PUBLIC_API(2,0) operator/(const BigInt& x, const BigInt& d);
BigInt BOTAN_PUBLIC_API(2,0) operator/(const BigInt& x, word m);
BigInt BOTAN_PUBLIC_API(2,0) operator%(const BigInt& x, const BigInt& m);
word   BOTAN_PUBLIC_API(2,0) operator%(const BigInt& x, word m);
BigInt BOTAN_PUBLIC_API(2,0) operator<<(const BigInt& x, size_t n);
BigInt BOTAN_PUBLIC_API(2,0) operator>>(const BigInt& x, size_t n);

/*
* Comparison Operators
*/
inline bool operator==(const BigInt& a, const BigInt& b)
   { return a.is_equal(b); }
inline bool operator!=(const BigInt& a, const BigInt& b)
   { return !a.is_equal(b); }
inline bool operator<=(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) <= 0); }
inline bool operator>=(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) >= 0); }
inline bool operator<(const BigInt& a, const BigInt& b)
   { return a.is_less_than(b); }
inline bool operator>(const BigInt& a, const BigInt& b)
   { return b.is_less_than(a); }

inline bool operator==(const BigInt& a, word b)
   { return (a.cmp_word(b) == 0); }
inline bool operator!=(const BigInt& a, word b)
   { return (a.cmp_word(b) != 0); }
inline bool operator<=(const BigInt& a, word b)
   { return (a.cmp_word(b) <= 0); }
inline bool operator>=(const BigInt& a, word b)
   { return (a.cmp_word(b) >= 0); }
inline bool operator<(const BigInt& a, word b)
   { return (a.cmp_word(b) < 0); }
inline bool operator>(const BigInt& a, word b)
   { return (a.cmp_word(b) > 0); }

/*
* I/O Operators
*/
BOTAN_PUBLIC_API(2,0) std::ostream& operator<<(std::ostream&, const BigInt&);
BOTAN_PUBLIC_API(2,0) std::istream& operator>>(std::istream&, BigInt&);

}

namespace std {

template<>
inline void swap<Botan::BigInt>(Botan::BigInt& x, Botan::BigInt& y)
   {
   x.swap(y);
   }

}

namespace Botan {

/**
* This class represents a block cipher object.
*/
class BOTAN_PUBLIC_API(2,0) BlockCipher : public SymmetricAlgorithm
   {
   public:

      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to choose
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<BlockCipher>
         create(const std::string& algo_spec,
                const std::string& provider = "");

      /**
      * Create an instance based on a name, or throw if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<BlockCipher>
         create_or_throw(const std::string& algo_spec,
                         const std::string& provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      * @param algo_spec algorithm name
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      /**
      * @return block size of this algorithm
      */
      virtual size_t block_size() const = 0;

      /**
      * @return native parallelism of this cipher in blocks
      */
      virtual size_t parallelism() const { return 1; }

      /**
      * @return prefererred parallelism of this cipher in bytes
      */
      size_t parallel_bytes() const
         {
         return parallelism() * block_size() * BOTAN_BLOCK_CIPHER_PAR_MULT;
         }

      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }

      /**
      * Encrypt a block.
      * @param in The plaintext block to be encrypted as a byte array.
      * Must be of length block_size().
      * @param out The byte array designated to hold the encrypted block.
      * Must be of length block_size().
      */
      void encrypt(const uint8_t in[], uint8_t out[]) const
         { encrypt_n(in, out, 1); }

      /**
      * Decrypt a block.
      * @param in The ciphertext block to be decypted as a byte array.
      * Must be of length block_size().
      * @param out The byte array designated to hold the decrypted block.
      * Must be of length block_size().
      */
      void decrypt(const uint8_t in[], uint8_t out[]) const
         { decrypt_n(in, out, 1); }

      /**
      * Encrypt a block.
      * @param block the plaintext block to be encrypted
      * Must be of length block_size(). Will hold the result when the function
      * has finished.
      */
      void encrypt(uint8_t block[]) const { encrypt_n(block, block, 1); }

      /**
      * Decrypt a block.
      * @param block the ciphertext block to be decrypted
      * Must be of length block_size(). Will hold the result when the function
      * has finished.
      */
      void decrypt(uint8_t block[]) const { decrypt_n(block, block, 1); }

      /**
      * Encrypt one or more blocks
      * @param block the input/output buffer (multiple of block_size())
      */
      template<typename Alloc>
      void encrypt(std::vector<uint8_t, Alloc>& block) const
         {
         return encrypt_n(block.data(), block.data(), block.size() / block_size());
         }

      /**
      * Decrypt one or more blocks
      * @param block the input/output buffer (multiple of block_size())
      */
      template<typename Alloc>
      void decrypt(std::vector<uint8_t, Alloc>& block) const
         {
         return decrypt_n(block.data(), block.data(), block.size() / block_size());
         }

      /**
      * Encrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      */
      template<typename Alloc, typename Alloc2>
      void encrypt(const std::vector<uint8_t, Alloc>& in,
                   std::vector<uint8_t, Alloc2>& out) const
         {
         return encrypt_n(in.data(), out.data(), in.size() / block_size());
         }

      /**
      * Decrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      */
      template<typename Alloc, typename Alloc2>
      void decrypt(const std::vector<uint8_t, Alloc>& in,
                   std::vector<uint8_t, Alloc2>& out) const
         {
         return decrypt_n(in.data(), out.data(), in.size() / block_size());
         }

      /**
      * Encrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      * @param blocks the number of blocks to process
      */
      virtual void encrypt_n(const uint8_t in[], uint8_t out[],
                             size_t blocks) const = 0;

      /**
      * Decrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      * @param blocks the number of blocks to process
      */
      virtual void decrypt_n(const uint8_t in[], uint8_t out[],
                             size_t blocks) const = 0;

      virtual void encrypt_n_xex(uint8_t data[],
                                 const uint8_t mask[],
                                 size_t blocks) const
         {
         const size_t BS = block_size();
         xor_buf(data, mask, blocks * BS);
         encrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
         }

      virtual void decrypt_n_xex(uint8_t data[],
                                 const uint8_t mask[],
                                 size_t blocks) const
         {
         const size_t BS = block_size();
         xor_buf(data, mask, blocks * BS);
         decrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
         }

      /**
      * @return new object representing the same algorithm as *this
      */
      virtual std::unique_ptr<BlockCipher> new_object() const = 0;

      BlockCipher* clone() const
         {
         return this->new_object().release();
         }

      virtual ~BlockCipher() = default;
   };

/**
* Tweakable block ciphers allow setting a tweak which is a non-keyed
* value which affects the encryption/decryption operation.
*/
class BOTAN_PUBLIC_API(2,8) Tweakable_Block_Cipher : public BlockCipher
   {
   public:
      /**
      * Set the tweak value. This must be called after setting a key. The value
      * persists until either set_tweak, set_key, or clear is called.
      * Different algorithms support different tweak length(s). If called with
      * an unsupported length, Invalid_Argument will be thrown.
      */
      virtual void set_tweak(const uint8_t tweak[], size_t len) = 0;
   };

/**
* Represents a block cipher with a single fixed block size
*/
template<size_t BS, size_t KMIN, size_t KMAX = 0, size_t KMOD = 1, typename BaseClass = BlockCipher>
class Block_Cipher_Fixed_Params : public BaseClass
   {
   public:
      enum { BLOCK_SIZE = BS };
      size_t block_size() const final override { return BS; }

      // override to take advantage of compile time constant block size
      void encrypt_n_xex(uint8_t data[],
                         const uint8_t mask[],
                         size_t blocks) const final override
         {
         xor_buf(data, mask, blocks * BS);
         this->encrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
         }

      void decrypt_n_xex(uint8_t data[],
                         const uint8_t mask[],
                         size_t blocks) const final override
         {
         xor_buf(data, mask, blocks * BS);
         this->decrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
         }

      Key_Length_Specification key_spec() const final override
         {
         return Key_Length_Specification(KMIN, KMAX, KMOD);
         }
   };

}

namespace Botan {

/**
* This class represents any kind of computation which uses an internal
* state, such as hash functions or MACs
*/
class BOTAN_PUBLIC_API(2,0) Buffered_Computation
   {
   public:
      /**
      * @return length of the output of this function in bytes
      */
      virtual size_t output_length() const = 0;

      /**
      * Add new input to process.
      * @param in the input to process as a byte array
      * @param length of param in in bytes
      */
      void update(const uint8_t in[], size_t length) { add_data(in, length); }

      /**
      * Add new input to process.
      * @param in the input to process as a secure_vector
      */
      void update(const secure_vector<uint8_t>& in)
         {
         add_data(in.data(), in.size());
         }

      /**
      * Add new input to process.
      * @param in the input to process as a std::vector
      */
      void update(const std::vector<uint8_t>& in)
         {
         add_data(in.data(), in.size());
         }

      void update_be(uint16_t val);
      void update_be(uint32_t val);
      void update_be(uint64_t val);

      void update_le(uint16_t val);
      void update_le(uint32_t val);
      void update_le(uint64_t val);

      /**
      * Add new input to process.
      * @param str the input to process as a std::string. Will be interpreted
      * as a byte array based on the strings encoding.
      */
      void update(const std::string& str)
         {
         add_data(cast_char_ptr_to_uint8(str.data()), str.size());
         }

      /**
      * Process a single byte.
      * @param in the byte to process
      */
      void update(uint8_t in) { add_data(&in, 1); }

      /**
      * Complete the computation and retrieve the
      * final result.
      * @param out The byte array to be filled with the result.
      * Must be of length output_length()
      */
      void final(uint8_t out[]) { final_result(out); }

      /**
      * Complete the computation and retrieve the
      * final result.
      * @return secure_vector holding the result
      */
      secure_vector<uint8_t> final()
         {
         secure_vector<uint8_t> output(output_length());
         final_result(output.data());
         return output;
         }

      std::vector<uint8_t> final_stdvec()
         {
         std::vector<uint8_t> output(output_length());
         final_result(output.data());
         return output;
         }

      template<typename Alloc>
         void final(std::vector<uint8_t, Alloc>& out)
         {
         out.resize(output_length());
         final_result(out.data());
         }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process as a byte array
      * @param length the length of the byte array
      * @result the result of the call to final()
      */
      secure_vector<uint8_t> process(const uint8_t in[], size_t length)
         {
         add_data(in, length);
         return final();
         }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process
      * @result the result of the call to final()
      */
      secure_vector<uint8_t> process(const secure_vector<uint8_t>& in)
         {
         add_data(in.data(), in.size());
         return final();
         }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process
      * @result the result of the call to final()
      */
      secure_vector<uint8_t> process(const std::vector<uint8_t>& in)
         {
         add_data(in.data(), in.size());
         return final();
         }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process as a string
      * @result the result of the call to final()
      */
      secure_vector<uint8_t> process(const std::string& in)
         {
         update(in);
         return final();
         }

      virtual ~Buffered_Computation() = default;
   private:
      /**
      * Add more data to the computation
      * @param input is an input buffer
      * @param length is the length of input in bytes
      */
      virtual void add_data(const uint8_t input[], size_t length) = 0;

      /**
      * Write the final output to out
      * @param out is an output buffer of output_length()
      */
      virtual void final_result(uint8_t out[]) = 0;
   };

}

namespace Botan {

/**
* Certificate validation status code
*/
enum class Certificate_Status_Code {
   OK = 0,
   VERIFIED = 0,

   // Revocation status
   OCSP_RESPONSE_GOOD = 1,
   OCSP_SIGNATURE_OK = 2,
   VALID_CRL_CHECKED = 3,
   OCSP_NO_HTTP = 4,

   // Warnings
   FIRST_WARNING_STATUS = 500,
   CERT_SERIAL_NEGATIVE = 500,
   DN_TOO_LONG = 501,
   OCSP_NO_REVOCATION_URL = 502,
   OCSP_SERVER_NOT_AVAILABLE = 503,

   // Typo versions of above - will be removed in future major release
   OSCP_NO_REVOCATION_URL = 502,
   OSCP_SERVER_NOT_AVAILABLE = 503,

   // Errors
   FIRST_ERROR_STATUS = 1000,

   SIGNATURE_METHOD_TOO_WEAK = 1000,
   UNTRUSTED_HASH = 1001,
   NO_REVOCATION_DATA = 1002,
   NO_MATCHING_CRLDP = 1003,

   // Time problems
   CERT_NOT_YET_VALID = 2000,
   CERT_HAS_EXPIRED = 2001,
   OCSP_NOT_YET_VALID = 2002,
   OCSP_HAS_EXPIRED = 2003,
   CRL_NOT_YET_VALID = 2004,
   CRL_HAS_EXPIRED = 2005,
   OCSP_IS_TOO_OLD = 2006,

   // Chain generation problems
   CERT_ISSUER_NOT_FOUND = 3000,
   CANNOT_ESTABLISH_TRUST = 3001,
   CERT_CHAIN_LOOP = 3002,
   CHAIN_LACKS_TRUST_ROOT = 3003,
   CHAIN_NAME_MISMATCH = 3004,

   // Validation errors
   POLICY_ERROR = 4000,
   INVALID_USAGE = 4001,
   CERT_CHAIN_TOO_LONG = 4002,
   CA_CERT_NOT_FOR_CERT_ISSUER = 4003,
   NAME_CONSTRAINT_ERROR = 4004,

   // Revocation errors
   CA_CERT_NOT_FOR_CRL_ISSUER = 4005,
   OCSP_CERT_NOT_LISTED = 4006,
   OCSP_BAD_STATUS = 4007,

   // Other problems
   CERT_NAME_NOMATCH = 4008,
   UNKNOWN_CRITICAL_EXTENSION = 4009,
   DUPLICATE_CERT_EXTENSION = 4010,
   OCSP_SIGNATURE_ERROR = 4501,
   OCSP_ISSUER_NOT_FOUND = 4502,
   OCSP_RESPONSE_MISSING_KEYUSAGE = 4503,
   OCSP_RESPONSE_INVALID = 4504,
   EXT_IN_V1_V2_CERT = 4505,
   DUPLICATE_CERT_POLICY = 4506,
   V2_IDENTIFIERS_IN_V1_CERT = 4507,

   // Hard failures
   CERT_IS_REVOKED = 5000,
   CRL_BAD_SIGNATURE = 5001,
   SIGNATURE_ERROR = 5002,
   CERT_PUBKEY_INVALID = 5003,
   SIGNATURE_ALGO_UNKNOWN = 5004,
   SIGNATURE_ALGO_BAD_PARAMS = 5005
};

/**
* Convert a status code to a human readable diagnostic message
* @param code the certifcate status
* @return string literal constant, or nullptr if code unknown
*/
BOTAN_PUBLIC_API(2,0) const char* to_string(Certificate_Status_Code code);

/**
* X.509v3 Key Constraints.
* If updating update copy in ffi.h
*/
enum Key_Constraints {
   NO_CONSTRAINTS     = 0,
   DIGITAL_SIGNATURE  = 1 << 15,
   NON_REPUDIATION    = 1 << 14,
   KEY_ENCIPHERMENT   = 1 << 13,
   DATA_ENCIPHERMENT  = 1 << 12,
   KEY_AGREEMENT      = 1 << 11,
   KEY_CERT_SIGN      = 1 << 10,
   CRL_SIGN           = 1 << 9,
   ENCIPHER_ONLY      = 1 << 8,
   DECIPHER_ONLY      = 1 << 7
};

/**
* X.509v2 CRL Reason Code.
*/
enum class CRL_Code : uint32_t {
   UNSPECIFIED            = 0,
   KEY_COMPROMISE         = 1,
   CA_COMPROMISE          = 2,
   AFFILIATION_CHANGED    = 3,
   SUPERSEDED             = 4,
   CESSATION_OF_OPERATION = 5,
   CERTIFICATE_HOLD       = 6,
   REMOVE_FROM_CRL        = 8,
   PRIVLEDGE_WITHDRAWN    = 9,
   PRIVILEGE_WITHDRAWN    = 9,
   AA_COMPROMISE          = 10,

   DELETE_CRL_ENTRY       = 0xFF00,
   OCSP_GOOD              = 0xFF01,
   OCSP_UNKNOWN           = 0xFF02
};

}

namespace Botan {

class Public_Key;
class Private_Key;
class RandomNumberGenerator;
class PK_Signer;

/**
* This class represents abstract X.509 signed objects as in the X.500
* SIGNED macro
*/
class BOTAN_PUBLIC_API(2,0) X509_Object : public ASN1_Object
   {
   public:
      /**
      * The underlying data that is to be or was signed
      * @return data that is or was signed
      */
      std::vector<uint8_t> tbs_data() const;

      /**
      * @return signature on tbs_data()
      */
      const std::vector<uint8_t>& signature() const { return m_sig; }

      /**
      * @return signed body
      */
      const std::vector<uint8_t>& signed_body() const { return m_tbs_bits; }

      /**
      * @return signature algorithm that was used to generate signature
      */
      const AlgorithmIdentifier& signature_algorithm() const { return m_sig_algo; }

      /**
      * @return hash algorithm that was used to generate signature
      */
      std::string hash_used_for_signature() const;

      /**
      * Create a signed X509 object.
      * @param signer the signer used to sign the object
      * @param rng the random number generator to use
      * @param alg_id the algorithm identifier of the signature scheme
      * @param tbs the tbs bits to be signed
      * @return signed X509 object
      */
      static std::vector<uint8_t> make_signed(PK_Signer* signer,
                                              RandomNumberGenerator& rng,
                                              const AlgorithmIdentifier& alg_id,
                                              const secure_vector<uint8_t>& tbs);

      /**
      * Check the signature on this data
      * @param key the public key purportedly used to sign this data
      * @return status of the signature - OK if verified or otherwise an indicator of
      *         the problem preventing verification.
      */
      Certificate_Status_Code verify_signature(const Public_Key& key) const;

      /**
      * Check the signature on this data
      * @param key the public key purportedly used to sign this data
      * @return true if the signature is valid, otherwise false
      */
      bool check_signature(const Public_Key& key) const;

      /**
      * Check the signature on this data
      * @param key the public key purportedly used to sign this data
      *        the object will be deleted after use (this should have
      *        been a std::unique_ptr<Public_Key>)
      * @return true if the signature is valid, otherwise false
      */
      bool check_signature(const Public_Key* key) const;

      /**
      * DER encode an X509_Object
      * See @ref ASN1_Object::encode_into()
      */
      void encode_into(DER_Encoder& to) const override;

      /**
      * Decode a BER encoded X509_Object
      * See @ref ASN1_Object::decode_from()
      */
      void decode_from(BER_Decoder& from) override;

      /**
      * @return PEM encoding of this
      */
      std::string PEM_encode() const;

      X509_Object(const X509_Object&) = default;
      X509_Object& operator=(const X509_Object&) = default;

      virtual std::string PEM_label() const = 0;

      virtual std::vector<std::string> alternate_PEM_labels() const
         { return std::vector<std::string>(); }

      virtual ~X509_Object() = default;

      static std::unique_ptr<PK_Signer>
         choose_sig_format(AlgorithmIdentifier& sig_algo,
                           const Private_Key& key,
                           RandomNumberGenerator& rng,
                           const std::string& hash_fn,
                           const std::string& padding_algo);

   protected:

      X509_Object() = default;

      /**
      * Decodes from src as either DER or PEM data, then calls force_decode()
      */
      void load_data(DataSource& src);

   private:
      virtual void force_decode() = 0;

      AlgorithmIdentifier m_sig_algo;
      std::vector<uint8_t> m_tbs_bits;
      std::vector<uint8_t> m_sig;
   };

}

namespace Botan {

class Public_Key;
class X509_DN;
class Extensions;
class AlternativeName;
class NameConstraints;

enum class Usage_Type
   {
   UNSPECIFIED, // no restrictions
   TLS_SERVER_AUTH,
   TLS_CLIENT_AUTH,
   CERTIFICATE_AUTHORITY,
   OCSP_RESPONDER,
   ENCRYPTION
   };

struct X509_Certificate_Data;

/**
* This class represents an X.509 Certificate
*/
class BOTAN_PUBLIC_API(2,0) X509_Certificate : public X509_Object
   {
   public:
      /**
      * Return a newly allocated copy of the public key associated
      * with the subject of this certificate. This object is owned
      * by the caller.
      *
      * Prefer load_subject_public_key in new code
      *
      * @return public key
      */
      Public_Key* subject_public_key() const;

      /**
      * Create a public key object associated with the public key bits in this
      * certificate. If the public key bits was valid for X.509 encoding
      * purposes but invalid algorithmically (for example, RSA with an even
      * modulus) that will be detected at this point, and an exception will be
      * thrown.
      *
      * @return subject public key of this certificate
      */
      std::unique_ptr<Public_Key> load_subject_public_key() const;

      /**
      * Get the public key associated with this certificate. This includes the
      * outer AlgorithmIdentifier
      * @return subject public key of this certificate
      */
      const std::vector<uint8_t>& subject_public_key_bits() const;

      /**
      * Get the SubjectPublicKeyInfo associated with this certificate.
      * @return subject public key info of this certificate
      */
      const std::vector<uint8_t>& subject_public_key_info() const;

      /**
      * Return the algorithm identifier of the public key
      */
      const AlgorithmIdentifier& subject_public_key_algo() const;

      /**
      * Get the bit string of the public key associated with this certificate
      * @return public key bits
      */
      const std::vector<uint8_t>& subject_public_key_bitstring() const;

      /**
      * Get the SHA-1 bit string of the public key associated with this certificate.
      * This is used for OCSP among other protocols.
      * This function will throw if SHA-1 is not available.
      * @return hash of subject public key of this certificate
      */
      const std::vector<uint8_t>& subject_public_key_bitstring_sha1() const;

      /**
      * Get the certificate's issuer distinguished name (DN).
      * @return issuer DN of this certificate
      */
      const X509_DN& issuer_dn() const;

      /**
      * Get the certificate's subject distinguished name (DN).
      * @return subject DN of this certificate
      */
      const X509_DN& subject_dn() const;

      /**
      * Get a value for a specific subject_info parameter name.
      * @param name the name of the parameter to look up. Possible names include
      * "X509.Certificate.version", "X509.Certificate.serial",
      * "X509.Certificate.start", "X509.Certificate.end",
      * "X509.Certificate.v2.key_id", "X509.Certificate.public_key",
      * "X509v3.BasicConstraints.path_constraint",
      * "X509v3.BasicConstraints.is_ca", "X509v3.NameConstraints",
      * "X509v3.ExtendedKeyUsage", "X509v3.CertificatePolicies",
      * "X509v3.SubjectKeyIdentifier", "X509.Certificate.serial",
      * "X520.CommonName", "X520.Organization", "X520.Country",
      * "RFC822" (Email in SAN) or "PKCS9.EmailAddress" (Email in DN).
      * @return value(s) of the specified parameter
      */
      std::vector<std::string> subject_info(const std::string& name) const;

      /**
      * Get a value for a specific subject_info parameter name.
      * @param name the name of the parameter to look up. Possible names are
      * "X509.Certificate.v2.key_id" or "X509v3.AuthorityKeyIdentifier".
      * @return value(s) of the specified parameter
      */
      std::vector<std::string> issuer_info(const std::string& name) const;

      /**
      * Raw issuer DN bits
      */
      const std::vector<uint8_t>& raw_issuer_dn() const;

      /**
      * SHA-256 of Raw issuer DN
      */
      std::vector<uint8_t> raw_issuer_dn_sha256() const;

      /**
      * Raw subject DN
      */
      const std::vector<uint8_t>& raw_subject_dn() const;

      /**
      * SHA-256 of Raw subject DN
      */
      std::vector<uint8_t> raw_subject_dn_sha256() const;

      /**
      * Get the notBefore of the certificate as X509_Time
      * @return notBefore of the certificate
      */
      const X509_Time& not_before() const;

      /**
      * Get the notAfter of the certificate as X509_Time
      * @return notAfter of the certificate
      */
      const X509_Time& not_after() const;

      /**
      * Get the X509 version of this certificate object.
      * @return X509 version
      */
      uint32_t x509_version() const;

      /**
      * Get the serial number of this certificate.
      * @return certificates serial number
      */
      const std::vector<uint8_t>& serial_number() const;

      /**
      * Get the serial number's sign
      * @return 1 iff the serial is negative.
      */
      bool is_serial_negative() const;

      /**
      * Get the DER encoded AuthorityKeyIdentifier of this certificate.
      * @return DER encoded AuthorityKeyIdentifier
      */
      const std::vector<uint8_t>& authority_key_id() const;

      /**
      * Get the DER encoded SubjectKeyIdentifier of this certificate.
      * @return DER encoded SubjectKeyIdentifier
      */
      const std::vector<uint8_t>& subject_key_id() const;

      /**
      * Check whether this certificate is self signed.
      * If the DN issuer and subject agree,
      * @return true if this certificate is self signed
      */
      bool is_self_signed() const;

      /**
      * Check whether this certificate is a CA certificate.
      * @return true if this certificate is a CA certificate
      */
      bool is_CA_cert() const;

      /**
      * Returns true if the specified @param usage is set in the key usage extension
      * or if no key usage constraints are set at all.
      * To check if a certain key constraint is set in the certificate
      * use @see X509_Certificate#has_constraints.
      */
      bool allowed_usage(Key_Constraints usage) const;

      /**
      * Returns true if the specified @param usage is set in the extended key usage extension
      * or if no extended key usage constraints are set at all.
      * To check if a certain extended key constraint is set in the certificate
      * use @see X509_Certificate#has_ex_constraint.
      */
      bool allowed_extended_usage(const std::string& usage) const;

      /**
      * Returns true if the specified usage is set in the extended key usage extension,
      * or if no extended key usage constraints are set at all.
      * To check if a certain extended key constraint is set in the certificate
      * use @see X509_Certificate#has_ex_constraint.
      */
      bool allowed_extended_usage(const OID& usage) const;

      /**
      * Returns true if the required key and extended key constraints are set in the certificate
      * for the specified @param usage or if no key constraints are set in both the key usage
      * and extended key usage extension.
      */
      bool allowed_usage(Usage_Type usage) const;

      /**
      * Returns true if the specified @param constraints are included in the key
      * usage extension.
      */
      bool has_constraints(Key_Constraints constraints) const;

      /**
      * Returns true if and only if OID @param ex_constraint is
      * included in the extended key extension.
      */
      bool has_ex_constraint(const OID& ex_constraint) const;

      /**
      * Get the path limit as defined in the BasicConstraints extension of
      * this certificate.
      * @return path limit
      */
      uint32_t path_limit() const;

      /**
      * Check whenever a given X509 Extension is marked critical in this
      * certificate.
      */
      bool is_critical(const std::string& ex_name) const;

      /**
      * Get the key constraints as defined in the KeyUsage extension of this
      * certificate.
      * @return key constraints
      */
      Key_Constraints constraints() const;

      /**
      * Get the key usage as defined in the ExtendedKeyUsage extension
      * of this certificate, or else an empty vector.
      * @return key usage
      */
      const std::vector<OID>& extended_key_usage() const;

      /**
      * Get the name constraints as defined in the NameConstraints
      * extension of this certificate.
      * @return name constraints
      */
      const NameConstraints& name_constraints() const;

      /**
      * Get the policies as defined in the CertificatePolicies extension
      * of this certificate.
      * @return certificate policies
      */
      const std::vector<OID>& certificate_policy_oids() const;

      /**
      * Get all extensions of this certificate.
      * @return certificate extensions
      */
      const Extensions& v3_extensions() const;

      /**
      * Return the v2 issuer key ID. v2 key IDs are almost never used,
      * instead see v3_subject_key_id.
      */
      const std::vector<uint8_t>& v2_issuer_key_id() const;

      /**
      * Return the v2 subject key ID. v2 key IDs are almost never used,
      * instead see v3_subject_key_id.
      */
      const std::vector<uint8_t>& v2_subject_key_id() const;

      /**
      * Return the subject alternative names (DNS, IP, ...)
      */
      const AlternativeName& subject_alt_name() const;

      /**
      * Return the issuer alternative names (DNS, IP, ...)
      */
      const AlternativeName& issuer_alt_name() const;

      /**
      * Return the listed address of an OCSP responder, or empty if not set
      */
      std::string ocsp_responder() const;

      /**
      * Return the listed addresses of ca issuers, or empty if not set
      */
      std::vector<std::string> ca_issuers() const;

      /**
      * Return the CRL distribution point, or empty if not set
      */
      std::string crl_distribution_point() const;

      /**
      * @return a free-form string describing the certificate
      */
      std::string to_string() const;

      /**
      * @return a fingerprint of the certificate
      * @param hash_name hash function used to calculate the fingerprint
      */
      std::string fingerprint(const std::string& hash_name = "SHA-1") const;

      /**
      * Check if a certain DNS name matches up with the information in
      * the cert
      * @param name DNS name to match
      */
      bool matches_dns_name(const std::string& name) const;

      /**
      * Check to certificates for equality.
      * @return true both certificates are (binary) equal
      */
      bool operator==(const X509_Certificate& other) const;

      /**
      * Impose an arbitrary (but consistent) ordering, eg to allow sorting
      * a container of certificate objects.
      * @return true if this is less than other by some unspecified criteria
      */
      bool operator<(const X509_Certificate& other) const;

      /**
      * Create a certificate from a data source providing the DER or
      * PEM encoded certificate.
      * @param source the data source
      */
      explicit X509_Certificate(DataSource& source);

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      /**
      * Create a certificate from a file containing the DER or PEM
      * encoded certificate.
      * @param filename the name of the certificate file
      */
      explicit X509_Certificate(const std::string& filename);
#endif

      /**
      * Create a certificate from a buffer
      * @param in the buffer containing the DER-encoded certificate
      */
      explicit X509_Certificate(const std::vector<uint8_t>& in);

      /**
      * Create a certificate from a buffer
      * @param data the buffer containing the DER-encoded certificate
      * @param length length of data in bytes
      */
      X509_Certificate(const uint8_t data[], size_t length);

      /**
      * Create an uninitialized certificate object. Any attempts to
      * access this object will throw an exception.
      */
      X509_Certificate() = default;

      X509_Certificate(const X509_Certificate& other) = default;

      X509_Certificate& operator=(const X509_Certificate& other) = default;

   private:
      std::string PEM_label() const override;

      std::vector<std::string> alternate_PEM_labels() const override;

      void force_decode() override;

      const X509_Certificate_Data& data() const;

      std::shared_ptr<X509_Certificate_Data> m_data;
   };

/**
* Check two certificates for inequality
* @param cert1 The first certificate
* @param cert2 The second certificate
* @return true if the arguments represent different certificates,
* false if they are binary identical
*/
BOTAN_PUBLIC_API(2,0) bool operator!=(const X509_Certificate& cert1, const X509_Certificate& cert2);

}

namespace Botan {

class Extensions;
class X509_Certificate;
class X509_DN;

struct CRL_Entry_Data;
struct CRL_Data;

/**
* This class represents CRL entries
*/
class BOTAN_PUBLIC_API(2,0) CRL_Entry final : public ASN1_Object
   {
   public:
      void encode_into(DER_Encoder&) const override;
      void decode_from(BER_Decoder&) override;

      /**
      * Get the serial number of the certificate associated with this entry.
      * @return certificate's serial number
      */
      const std::vector<uint8_t>& serial_number() const;

      /**
      * Get the revocation date of the certificate associated with this entry
      * @return certificate's revocation date
      */
      const X509_Time& expire_time() const;

      /**
      * Get the entries reason code
      * @return reason code
      */
      CRL_Code reason_code() const;

      /**
      * Get the extensions on this CRL entry
      */
      const Extensions& extensions() const;

      /**
      * Create uninitialized CRL_Entry object
      */
      CRL_Entry() = default;

      /**
      * Construct an CRL entry.
      * @param cert the certificate to revoke
      * @param reason the reason code to set in the entry
      */
      CRL_Entry(const X509_Certificate& cert,
                CRL_Code reason = CRL_Code::UNSPECIFIED);

   private:
      friend class X509_CRL;

      const CRL_Entry_Data& data() const;

      std::shared_ptr<CRL_Entry_Data> m_data;
   };

/**
* Test two CRL entries for equality in all fields.
*/
BOTAN_PUBLIC_API(2,0) bool operator==(const CRL_Entry&, const CRL_Entry&);

/**
* Test two CRL entries for inequality in at least one field.
*/
BOTAN_PUBLIC_API(2,0) bool operator!=(const CRL_Entry&, const CRL_Entry&);

/**
* This class represents X.509 Certificate Revocation Lists (CRLs).
*/
class BOTAN_PUBLIC_API(2,0) X509_CRL final : public X509_Object
   {
   public:
      /**
      * Check if this particular certificate is listed in the CRL
      */
      bool is_revoked(const X509_Certificate& cert) const;

      /**
      * Get the entries of this CRL in the form of a vector.
      * @return vector containing the entries of this CRL.
      */
      const std::vector<CRL_Entry>& get_revoked() const;

      /**
      * Get the issuer DN of this CRL.
      * @return CRLs issuer DN
      */
      const X509_DN& issuer_dn() const;

      /**
      * @return extension data for this CRL
      */
      const Extensions& extensions() const;

      /**
      * Get the AuthorityKeyIdentifier of this CRL.
      * @return this CRLs AuthorityKeyIdentifier
      */
      const std::vector<uint8_t>& authority_key_id() const;

      /**
      * Get the serial number of this CRL.
      * @return CRLs serial number
      */
      uint32_t crl_number() const;

      /**
      * Get the CRL's thisUpdate value.
      * @return CRLs thisUpdate
      */
      const X509_Time& this_update() const;

      /**
      * Get the CRL's nextUpdate value.
      * @return CRLs nextdUpdate
      */
      const X509_Time& next_update() const;

      /**
      * Get the CRL's distribution point
      */
      std::string crl_issuing_distribution_point() const;

      /**
      * Create an uninitialized CRL object. Any attempts to access
      * this object will throw an exception.
      */
      X509_CRL() = default;

      /**
      * Construct a CRL from a data source.
      * @param source the data source providing the DER or PEM encoded CRL.
      */
      X509_CRL(DataSource& source);

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      /**
      * Construct a CRL from a file containing the DER or PEM encoded CRL.
      * @param filename the name of the CRL file
      */
      X509_CRL(const std::string& filename);
#endif

      /**
      * Construct a CRL from a binary vector
      * @param vec the binary (DER) representation of the CRL
      */
      X509_CRL(const std::vector<uint8_t>& vec);

      /**
      * Construct a CRL
      * @param issuer issuer of this CRL
      * @param thisUpdate valid from
      * @param nextUpdate valid until
      * @param revoked entries to be included in the CRL
      */
      X509_CRL(const X509_DN& issuer, const X509_Time& thisUpdate,
               const X509_Time& nextUpdate, const std::vector<CRL_Entry>& revoked);

   private:
      std::string PEM_label() const override;

      std::vector<std::string> alternate_PEM_labels() const override;

      void force_decode() override;

      const CRL_Data& data() const;

      std::shared_ptr<CRL_Data> m_data;
   };

}

namespace Botan {

/**
* Certificate Store Interface
*/
class BOTAN_PUBLIC_API(2,0) Certificate_Store
   {
   public:
      virtual ~Certificate_Store();

      /**
      * Find a certificate by Subject DN and (optionally) key identifier
      * @param subject_dn the subject's distinguished name
      * @param key_id an optional key id
      * @return a matching certificate or nullopt otherwise
      * If more than one certificate in the certificate store matches, then
      * a single value is selected arbitrarily.
      */
      virtual std::optional<X509_Certificate>
         find_cert(const X509_DN& subject_dn, const std::vector<uint8_t>& key_id) const;

      /**
      * Find all certificates with a given Subject DN.
      * Subject DN and even the key identifier might not be unique.
      */
      virtual std::vector<X509_Certificate> find_all_certs(
         const X509_DN& subject_dn, const std::vector<uint8_t>& key_id) const = 0;


      /**
      * Find a certificate by searching for one with a matching SHA-1 hash of
      * public key. Used for OCSP.
      * @param key_hash SHA-1 hash of the subject's public key
      * @return a matching certificate or nullopt otherwise
      */
      virtual std::optional<X509_Certificate>
         find_cert_by_pubkey_sha1(const std::vector<uint8_t>& key_hash) const = 0;

      /**
      * Find a certificate by searching for one with a matching SHA-256 hash of
      * raw subject name. Used for OCSP.
      * @param subject_hash SHA-256 hash of the subject's raw name
      * @return a matching certificate or nullopt otherwise
      */
      virtual std::optional<X509_Certificate>
         find_cert_by_raw_subject_dn_sha256(const std::vector<uint8_t>& subject_hash) const = 0;

      /**
      * Finds a CRL for the given certificate
      * @param subject the subject certificate
      * @return the CRL for subject or nullopt otherwise
      */
      virtual std::optional<X509_CRL> find_crl_for(const X509_Certificate& subject) const;

      /**
      * @return whether the certificate is known
      * @param cert certififcate to be searched
      */
      bool certificate_known(const X509_Certificate& cert) const
         {
         return find_cert(cert.subject_dn(), cert.subject_key_id()).has_value();
         }

      // remove this (used by TLS::Server)
      virtual std::vector<X509_DN> all_subjects() const = 0;
   };

/**
* In Memory Certificate Store
*/
class BOTAN_PUBLIC_API(2,0) Certificate_Store_In_Memory final : public Certificate_Store
   {
   public:
      /**
      * Attempt to parse all files in dir (including subdirectories)
      * as certificates. Ignores errors.
      */
      explicit Certificate_Store_In_Memory(const std::string& dir);

      /**
      * Adds given certificate to the store.
      */
      explicit Certificate_Store_In_Memory(const X509_Certificate& cert);

      /**
      * Create an empty store.
      */
      Certificate_Store_In_Memory() = default;

      /**
      * Add a certificate to the store.
      * @param cert certificate to be added
      */
      void add_certificate(const X509_Certificate& cert);

      /**
      * Add a certificate revocation list (CRL) to the store.
      * @param crl CRL to be added
      */
      void add_crl(const X509_CRL& crl);

      /**
      * @return DNs for all certificates managed by the store
      */
      std::vector<X509_DN> all_subjects() const override;

      /*
      * Find a certificate by Subject DN and (optionally) key identifier
      * @return the first certificate that matches
      */
      std::optional<X509_Certificate> find_cert(
         const X509_DN& subject_dn,
         const std::vector<uint8_t>& key_id) const override;

      /*
      * Find all certificates with a given Subject DN.
      * Subject DN and even the key identifier might not be unique.
      */
      std::vector<X509_Certificate> find_all_certs(
         const X509_DN& subject_dn, const std::vector<uint8_t>& key_id) const override;

      std::optional<X509_Certificate>
         find_cert_by_pubkey_sha1(const std::vector<uint8_t>& key_hash) const override;

      std::optional<X509_Certificate>
         find_cert_by_raw_subject_dn_sha256(const std::vector<uint8_t>& subject_hash) const override;

      /**
      * Finds a CRL for the given certificate
      */
      std::optional<X509_CRL> find_crl_for(const X509_Certificate& subject) const override;
   private:
      // TODO: Add indexing on the DN and key id to avoid linear search
      std::vector<X509_Certificate> m_certs;
      std::vector<X509_CRL> m_crls;
   };

}

namespace Botan {

class BOTAN_PUBLIC_API(2,0) SQL_Database
   {
   public:

      class BOTAN_PUBLIC_API(2,0) SQL_DB_Error final : public Exception
         {
         public:
            explicit SQL_DB_Error(const std::string& what) :
               Exception("SQL database", what),
               m_rc(0)
               {}

            SQL_DB_Error(const std::string& what, int rc) :
               Exception("SQL database", what),
               m_rc(rc)
               {}

            ErrorType error_type() const noexcept override { return Botan::ErrorType::DatabaseError; }

            int error_code() const noexcept override { return m_rc; }
         private:
            int m_rc;
         };

      class BOTAN_PUBLIC_API(2,0) Statement
         {
         public:
            /* Bind statement parameters */
            virtual void bind(int column, const std::string& str) = 0;

            virtual void bind(int column, size_t i) = 0;

            virtual void bind(int column, std::chrono::system_clock::time_point time) = 0;

            virtual void bind(int column, const std::vector<uint8_t>& blob) = 0;

            virtual void bind(int column, const uint8_t* data, size_t len) = 0;

            /* Get output */
            virtual std::pair<const uint8_t*, size_t> get_blob(int column) = 0;

            virtual std::string get_str(int column) = 0;

            virtual size_t get_size_t(int column) = 0;

            /* Run to completion */
            virtual size_t spin() = 0;

            /* Maybe update */
            virtual bool step() = 0;

            virtual ~Statement() = default;
         };

      /*
      * Create a new statement for execution.
      * Use ?1, ?2, ?3, etc for parameters to set later with bind
      */
      virtual std::shared_ptr<Statement> new_statement(const std::string& base_sql) const = 0;

      virtual size_t row_count(const std::string& table_name) = 0;

      virtual void create_table(const std::string& table_schema) = 0;

      virtual ~SQL_Database() = default;
};

}

namespace Botan {

class BigInt;

/**
* General DER Encoding Object
*/
class BOTAN_PUBLIC_API(2,0) DER_Encoder final
   {
   public:
      typedef std::function<void (const uint8_t[], size_t)> append_fn;

      /**
      * DER encode, writing to an internal buffer
      * Use get_contents or get_contents_unlocked to read the results
      * after all encoding is completed.
      */
      DER_Encoder() = default;

      /**
      * DER encode, writing to @param vec
      * If this constructor is used, get_contents* may not be called.
      */
      DER_Encoder(secure_vector<uint8_t>& vec);

      /**
      * DER encode, writing to @param vec
      * If this constructor is used, get_contents* may not be called.
      */
      DER_Encoder(std::vector<uint8_t>& vec);

      /**
      * DER encode, calling append to write output
      * If this constructor is used, get_contents* may not be called.
      */
      DER_Encoder(append_fn append) : m_append_output(append) {}

      secure_vector<uint8_t> get_contents();

      /**
      * Return the encoded contents as a std::vector
      *
      * If using this function, instead pass a std::vector to the
      * contructor of DER_Encoder where the output will be placed. This
      * avoids several unecessary copies.
      */
      BOTAN_DEPRECATED("Use DER_Encoder(vector) instead")
      std::vector<uint8_t> get_contents_unlocked();

      DER_Encoder& start_cons(ASN1_Type type_tag, ASN1_Class class_tag);

      DER_Encoder& start_sequence()
         {
         return start_cons(ASN1_Type::Sequence, ASN1_Class::Universal);
         }

      DER_Encoder& start_set()
         {
         return start_cons(ASN1_Type::Set, ASN1_Class::Universal);
         }

      DER_Encoder& start_context_specific(uint32_t tag)
         {
         return start_cons(ASN1_Type(tag), ASN1_Class::ContextSpecific);
         }

      DER_Encoder& start_explicit_context_specific(uint32_t tag)
         {
         return start_cons(ASN1_Type(tag), ASN1_Class::ExplicitContextSpecific);
         }

      DER_Encoder& end_cons();

      DER_Encoder& start_explicit(uint16_t type_tag);
      DER_Encoder& end_explicit();

      /**
      * Insert raw bytes directly into the output stream
      */
      DER_Encoder& raw_bytes(const uint8_t val[], size_t len);

      template<typename Alloc>
      DER_Encoder& raw_bytes(const std::vector<uint8_t, Alloc>& val)
         {
         return raw_bytes(val.data(), val.size());
         }

      DER_Encoder& encode_null();
      DER_Encoder& encode(bool b);
      DER_Encoder& encode(size_t s);
      DER_Encoder& encode(const BigInt& n);
      DER_Encoder& encode(const uint8_t val[], size_t len, ASN1_Type real_type);

      template<typename Alloc>
      DER_Encoder& encode(const std::vector<uint8_t, Alloc>& vec, ASN1_Type real_type)
         {
         return encode(vec.data(), vec.size(), real_type);
         }

      DER_Encoder& encode(bool b,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      DER_Encoder& encode(size_t s,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      DER_Encoder& encode(const BigInt& n,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      DER_Encoder& encode(const uint8_t v[], size_t len,
                          ASN1_Type real_type,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      template<typename Alloc>
      DER_Encoder& encode(const std::vector<uint8_t, Alloc>& bytes,
                          ASN1_Type real_type,
                          ASN1_Type type_tag, ASN1_Class class_tag)
         {
         return encode(bytes.data(), bytes.size(),
                       real_type, type_tag, class_tag);
         }

      template<typename T>
      DER_Encoder& encode_optional(const T& value, const T& default_value)
         {
         if(value != default_value)
            encode(value);
         return (*this);
         }

      template<typename T>
      DER_Encoder& encode_list(const std::vector<T>& values)
         {
         for(size_t i = 0; i != values.size(); ++i)
            encode(values[i]);
         return (*this);
         }

      /*
      * Request for an object to encode itself to this stream
      */
      DER_Encoder& encode(const ASN1_Object& obj);

      /*
      * Conditionally write some values to the stream
      */
      DER_Encoder& encode_if(bool pred, DER_Encoder& enc)
         {
         if(pred)
            return raw_bytes(enc.get_contents());
         return (*this);
         }

      DER_Encoder& encode_if(bool pred, const ASN1_Object& obj)
         {
         if(pred)
            encode(obj);
         return (*this);
         }

      DER_Encoder& add_object(ASN1_Type type_tag, ASN1_Class class_tag,
                              const uint8_t rep[], size_t length);

      DER_Encoder& add_object(ASN1_Type type_tag, ASN1_Class class_tag,
                              const std::vector<uint8_t>& rep)
         {
         return add_object(type_tag, class_tag, rep.data(), rep.size());
         }

      DER_Encoder& add_object(ASN1_Type type_tag, ASN1_Class class_tag,
                              const secure_vector<uint8_t>& rep)
         {
         return add_object(type_tag, class_tag, rep.data(), rep.size());
         }

      DER_Encoder& add_object(ASN1_Type type_tag, ASN1_Class class_tag,
                              const std::string& str);

      DER_Encoder& add_object(ASN1_Type type_tag, ASN1_Class class_tag,
                              uint8_t val);

   private:
      class DER_Sequence final
         {
         public:
            uint32_t tag_of() const;

            void push_contents(DER_Encoder& der);

            void add_bytes(const uint8_t val[], size_t len);

            void add_bytes(const uint8_t hdr[], size_t hdr_len,
                           const uint8_t val[], size_t val_len);

            DER_Sequence(ASN1_Type, ASN1_Class);

            DER_Sequence(DER_Sequence&& seq)
               {
               std::swap(m_type_tag, seq.m_type_tag);
               std::swap(m_class_tag, seq.m_class_tag);
               std::swap(m_contents, seq.m_contents);
               std::swap(m_set_contents, seq.m_set_contents);
               }

            DER_Sequence& operator=(DER_Sequence&& seq)
               {
               std::swap(m_type_tag, seq.m_type_tag);
               std::swap(m_class_tag, seq.m_class_tag);
               std::swap(m_contents, seq.m_contents);
               std::swap(m_set_contents, seq.m_set_contents);
               return (*this);
               }

            DER_Sequence(const DER_Sequence& seq) = default;

            DER_Sequence& operator=(const DER_Sequence& seq) = default;

         private:
             ASN1_Type m_type_tag;
             ASN1_Class m_class_tag;
            secure_vector<uint8_t> m_contents;
            std::vector< secure_vector<uint8_t> > m_set_contents;
         };

      append_fn m_append_output;
      secure_vector<uint8_t> m_default_outbuf;
      std::vector<DER_Sequence> m_subsequences;
   };

}

#if defined(BOTAN_TARGET_OS_HAS_THREADS)


namespace Botan {

template<typename T> using lock_guard_type = std::lock_guard<T>;
typedef std::mutex mutex_type;
typedef std::recursive_mutex recursive_mutex_type;

}

#else

// No threads

namespace Botan {

template<typename Mutex>
class lock_guard final
   {
   public:
      explicit lock_guard(Mutex& m) : m_mutex(m)
         { m_mutex.lock(); }

      ~lock_guard() { m_mutex.unlock(); }

      lock_guard(const lock_guard& other) = delete;
      lock_guard& operator=(const lock_guard& other) = delete;
   private:
      Mutex& m_mutex;
   };

class noop_mutex final
   {
   public:
      void lock() {}
      void unlock() {}
   };

typedef noop_mutex mutex_type;
typedef noop_mutex recursive_mutex_type;
template<typename T> using lock_guard_type = lock_guard<T>;

}

#endif

namespace Botan {

class Entropy_Sources;

/**
* An interface to a cryptographic random number generator
*/
class BOTAN_PUBLIC_API(2,0) RandomNumberGenerator
   {
   public:
      virtual ~RandomNumberGenerator() = default;

      RandomNumberGenerator() = default;

      /*
      * Never copy a RNG, create a new one
      */
      RandomNumberGenerator(const RandomNumberGenerator& rng) = delete;
      RandomNumberGenerator& operator=(const RandomNumberGenerator& rng) = delete;

      /**
      * Randomize a byte array.
      *
      * May block shortly if e.g. the RNG is not yet initialized
      * or a retry because of insufficient entropy is needed.
      *
      * @param output the byte array to hold the random output.
      * @param length the length of the byte array output in bytes.
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      */
      virtual void randomize(uint8_t output[], size_t length) = 0;

      /**
      * Returns false if it is known that this RNG object is not able to accept
      * externally provided inputs (via add_entropy, randomize_with_input, etc).
      * In this case, any such provided inputs are ignored.
      *
      * If this function returns true, then inputs may or may not be accepted.
      */
      virtual bool accepts_input() const = 0;

      /**
      * Incorporate some additional data into the RNG state. For
      * example adding nonces or timestamps from a peer's protocol
      * message can help hedge against VM state rollback attacks.
      * A few RNG types do not accept any externally provided input,
      * in which case this function is a no-op.
      *
      * @param input a byte array containg the entropy to be added
      * @param length the length of the byte array in
      * @throws Exception may throw if the RNG accepts input, but adding the entropy failed.
      */
      virtual void add_entropy(const uint8_t input[], size_t length) = 0;

      /**
      * Incorporate some additional data into the RNG state.
      */
      template<typename T> void add_entropy_T(const T& t)
         {
         static_assert(std::is_standard_layout<T>::value && std::is_trivial<T>::value, "add_entropy_T data must be POD");
         this->add_entropy(reinterpret_cast<const uint8_t*>(&t), sizeof(T));
         }

      /**
      * Incorporate entropy into the RNG state then produce output.
      * Some RNG types implement this using a single operation, default
      * calls add_entropy + randomize in sequence.
      *
      * Use this to further bind the outputs to your current
      * process/protocol state. For instance if generating a new key
      * for use in a session, include a session ID or other such
      * value. See NIST SP 800-90 A, B, C series for more ideas.
      *
      * @param output buffer to hold the random output
      * @param output_len size of the output buffer in bytes
      * @param input entropy buffer to incorporate
      * @param input_len size of the input buffer in bytes
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      * @throws Exception may throw if the RNG accepts input, but adding the entropy failed.
      */
      virtual void randomize_with_input(uint8_t output[], size_t output_len,
                                        const uint8_t input[], size_t input_len);

      /**
      * This calls `randomize_with_input` using some timestamps as extra input.
      *
      * For a stateful RNG using non-random but potentially unique data the
      * extra input can help protect against problems with fork, VM state
      * rollback, or other cases where somehow an RNG state is duplicated. If
      * both of the duplicated RNG states later incorporate a timestamp (and the
      * timestamps don't themselves repeat), their outputs will diverge.
      *
      * @param output buffer to hold the random output
      * @param output_len size of the output buffer in bytes
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      * @throws Exception may throw if the RNG accepts input, but adding the entropy failed.
      */
      virtual void randomize_with_ts_input(uint8_t output[], size_t output_len);

      /**
      * @return the name of this RNG type
      */
      virtual std::string name() const = 0;

      /**
      * Clear all internally held values of this RNG
      * @post is_seeded() == false if the RNG has an internal state that can be cleared.
      */
      virtual void clear() = 0;

      /**
      * Check whether this RNG is seeded.
      * @return true if this RNG was already seeded, false otherwise.
      */
      virtual bool is_seeded() const = 0;

      /**
      * Poll provided sources for up to poll_bits bits of entropy
      * or until the timeout expires. Returns estimate of the number
      * of bits collected.
      *
      * Sets the seeded state to true if enough entropy was added.
      */
      virtual size_t reseed(Entropy_Sources& srcs,
                            size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS,
                            std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT);

      /**
      * Reseed by reading specified bits from the RNG
      *
      * Sets the seeded state to true if enough entropy was added.
      *
      * @throws Exception if RNG accepts input but reseeding failed.
      */
      virtual void reseed_from_rng(RandomNumberGenerator& rng,
                                   size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS);

      // Some utility functions built on the interface above:

      /**
      * Return a random vector
      * @param bytes number of bytes in the result
      * @return randomized vector of length bytes
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      */
      secure_vector<uint8_t> random_vec(size_t bytes)
         {
         secure_vector<uint8_t> output;
         random_vec(output, bytes);
         return output;
         }

      template<typename Alloc>
         void random_vec(std::vector<uint8_t, Alloc>& v, size_t bytes)
         {
         v.resize(bytes);
         this->randomize(v.data(), v.size());
         }

      /**
      * Return a random byte
      * @return random byte
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      */
      uint8_t next_byte()
         {
         uint8_t b;
         this->randomize(&b, 1);
         return b;
         }

      /**
      * @return a random byte that is greater than zero
      * @throws PRNG_Unseeded if the RNG fails because it has not enough entropy
      * @throws Exception if the RNG fails
      */
      uint8_t next_nonzero_byte()
         {
         uint8_t b = this->next_byte();
         while(b == 0)
            b = this->next_byte();
         return b;
         }
   };

/**
* Convenience typedef
*/
typedef RandomNumberGenerator RNG;

/**
* Hardware_RNG exists to tag hardware RNG types (PKCS11_RNG, TPM_RNG, Processor_RNG)
*/
class BOTAN_PUBLIC_API(2,0) Hardware_RNG : public RandomNumberGenerator
   {
   public:
      virtual void clear() final override { /* no way to clear state of hardware RNG */ }
   };

/**
* Null/stub RNG - fails if you try to use it for anything
* This is not generally useful except for in certain tests
*/
class BOTAN_PUBLIC_API(2,0) Null_RNG final : public RandomNumberGenerator
   {
   public:
      bool is_seeded() const override { return false; }

      bool accepts_input() const override { return false; }

      void clear() override {}

      void randomize(uint8_t[], size_t) override
         {
         throw PRNG_Unseeded("Null_RNG called");
         }

      void add_entropy(const uint8_t[], size_t) override {}

      std::string name() const override { return "Null_RNG"; }
   };

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
/**
* Wraps access to a RNG in a mutex
* Note that most of the time it's much better to use a RNG per thread
* otherwise the RNG will act as an unnecessary contention point
*
* Since 2.16.0 all Stateful_RNG instances have an internal lock, so
* this class is no longer needed. It will be removed in a future major
* release.
*/
class BOTAN_PUBLIC_API(2,0) Serialized_RNG final : public RandomNumberGenerator
   {
   public:
      void randomize(uint8_t out[], size_t len) override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         m_rng->randomize(out, len);
         }

      bool accepts_input() const override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_rng->accepts_input();
         }

      bool is_seeded() const override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_rng->is_seeded();
         }

      void clear() override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         m_rng->clear();
         }

      std::string name() const override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_rng->name();
         }

      size_t reseed(Entropy_Sources& src,
                    size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS,
                    std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT) override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_rng->reseed(src, poll_bits, poll_timeout);
         }

      void add_entropy(const uint8_t in[], size_t len) override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         m_rng->add_entropy(in, len);
         }

      /**
      * Since 2.16.0 this is no longer needed for any RNG type. This
      * class will be removed in a future major release.
      */
      BOTAN_DEPRECATED("Use version accepting a unique_ptr")
      explicit Serialized_RNG(RandomNumberGenerator* rng) : m_rng(rng) {}

      /**
      * Since 2.16.0 this is no longer needed for any RNG type. This
      * class will be removed in a future major release.
      */
      explicit Serialized_RNG(std::unique_ptr<RandomNumberGenerator> rng) : m_rng(std::move(rng)) {}

   private:
      mutable mutex_type m_mutex;
      std::unique_ptr<RandomNumberGenerator> m_rng;
   };
#endif

}

namespace Botan {

class RandomNumberGenerator;

/**
* Abstract interface to a source of entropy
*/
class BOTAN_PUBLIC_API(2,0) Entropy_Source
   {
   public:
      /**
      * Return a new entropy source of a particular type, or null
      * Each entropy source may require substantial resources (eg, a file handle
      * or socket instance), so try to share them among multiple RNGs, or just
      * use the preconfigured global list accessed by Entropy_Sources::global_sources()
      */
      static std::unique_ptr<Entropy_Source> create(const std::string& type);

      /**
      * @return name identifying this entropy source
      */
      virtual std::string name() const = 0;

      /**
      * Perform an entropy gathering poll
      * @param rng will be provided with entropy via calls to add_entropy
      * @return conservative estimate of actual entropy added to rng during poll
      */
      virtual size_t poll(RandomNumberGenerator& rng) = 0;

      Entropy_Source() = default;
      Entropy_Source(const Entropy_Source& other) = delete;
      Entropy_Source(Entropy_Source&& other) = delete;
      Entropy_Source& operator=(const Entropy_Source& other) = delete;

      virtual ~Entropy_Source() = default;
   };

class BOTAN_PUBLIC_API(2,0) Entropy_Sources final
   {
   public:
      static Entropy_Sources& global_sources();

      void add_source(std::unique_ptr<Entropy_Source> src);

      std::vector<std::string> enabled_sources() const;

      size_t poll(RandomNumberGenerator& rng,
                  size_t bits,
                  std::chrono::milliseconds timeout);

      /**
      * Poll just a single named source. Ordinally only used for testing
      */
      size_t poll_just(RandomNumberGenerator& rng, const std::string& src);

      Entropy_Sources() = default;
      explicit Entropy_Sources(const std::vector<std::string>& sources);

      Entropy_Sources(const Entropy_Sources& other) = delete;
      Entropy_Sources(Entropy_Sources&& other) = delete;
      Entropy_Sources& operator=(const Entropy_Sources& other) = delete;

   private:
      std::vector<std::unique_ptr<Entropy_Source>> m_srcs;
   };

}

namespace Botan {

/**
* This class represents hash function (message digest) objects
*/
class BOTAN_PUBLIC_API(2,0) HashFunction : public Buffered_Computation
   {
   public:
      /**
      * Create an instance based on a name, or return null if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<HashFunction>
         create(const std::string& algo_spec,
                const std::string& provider = "");

      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to use
      * Throws Lookup_Error if not found.
      */
      static std::unique_ptr<HashFunction>
         create_or_throw(const std::string& algo_spec,
                         const std::string& provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      * @param algo_spec algorithm name
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }

      virtual ~HashFunction() = default;

      /**
      * Reset the state.
      */
      virtual void clear() = 0;

      /**
      * @return the hash function name
      */
      virtual std::string name() const = 0;

      /**
      * @return hash block size as defined for this algorithm
      */
      virtual size_t hash_block_size() const { return 0; }

      /**
      * Return a new hash object with the same state as *this. This
      * allows computing the hash of several messages with a common
      * prefix more efficiently than would otherwise be possible.
      *
      * This function should be called `clone` but that was already
      * used for the case of returning an uninitialized object.
      * @return new hash object
      */
      virtual std::unique_ptr<HashFunction> copy_state() const = 0;

      /**
      * @return new object representing the same algorithm as *this
      */
      virtual std::unique_ptr<HashFunction> new_object() const = 0;

      /**
      * @return new object representing the same algorithm as *this
      */
      HashFunction* clone() const
         {
         return this->new_object().release();
         }
   };

}

namespace Botan {

/**
* Perform hex encoding
* @param output an array of at least input_length*2 bytes
* @param input is some binary data
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
*/
void BOTAN_PUBLIC_API(2,0) hex_encode(char output[],
                          const uint8_t input[],
                          size_t input_length,
                          bool uppercase = true);

/**
* Perform hex encoding
* @param input some input
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
std::string BOTAN_PUBLIC_API(2,0) hex_encode(const uint8_t input[],
                                 size_t input_length,
                                 bool uppercase = true);

/**
* Perform hex encoding
* @param input some input
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
template<typename Alloc>
std::string hex_encode(const std::vector<uint8_t, Alloc>& input,
                       bool uppercase = true)
   {
   return hex_encode(input.data(), input.size(), uppercase);
   }

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*        bytes of input were actually consumed. If less than
*        input_length, then the range input[consumed:length]
*        should be passed in later along with more input.
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2,0) hex_decode(uint8_t output[],
                            const char input[],
                            size_t input_length,
                            size_t& input_consumed,
                            bool ignore_ws = true);

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2,0) hex_decode(uint8_t output[],
                            const char input[],
                            size_t input_length,
                            bool ignore_ws = true);

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2,0) hex_decode(uint8_t output[],
                            const std::string& input,
                            bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
std::vector<uint8_t> BOTAN_PUBLIC_API(2,0)
hex_decode(const char input[],
           size_t input_length,
           bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
std::vector<uint8_t> BOTAN_PUBLIC_API(2,0)
hex_decode(const std::string& input,
           bool ignore_ws = true);


/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(2,0)
hex_decode_locked(const char input[],
                  size_t input_length,
                  bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(2,0)
hex_decode_locked(const std::string& input,
                  bool ignore_ws = true);

}

namespace Botan {

/**
* Key Derivation Function
*/
class BOTAN_PUBLIC_API(2,0) KDF
   {
   public:
      virtual ~KDF() = default;

      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to choose
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<KDF>
         create(const std::string& algo_spec,
                const std::string& provider = "");

      /**
      * Create an instance based on a name, or throw if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<KDF>
         create_or_throw(const std::string& algo_spec,
                         const std::string& provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      /**
      * @return KDF name
      */
      virtual std::string name() const = 0;

      /**
      * Derive a key
      * @param key buffer holding the derived key, must be of length key_len
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param secret_len size of secret in bytes
      * @param salt a diversifier
      * @param salt_len size of salt in bytes
      * @param label purpose for the derived keying material
      * @param label_len size of label in bytes
      */
      virtual void kdf(uint8_t key[], size_t key_len,
                       const uint8_t secret[], size_t secret_len,
                       const uint8_t salt[], size_t salt_len,
                       const uint8_t label[], size_t label_len) const = 0;

      /**
      * Derive a key
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param secret_len size of secret in bytes
      * @param salt a diversifier
      * @param salt_len size of salt in bytes
      * @param label purpose for the derived keying material
      * @param label_len size of label in bytes
      * @return the derived key
      */
      secure_vector<uint8_t> derive_key(size_t key_len,
                                    const uint8_t secret[],
                                    size_t secret_len,
                                    const uint8_t salt[],
                                    size_t salt_len,
                                    const uint8_t label[] = nullptr,
                                    size_t label_len = 0) const
         {
         secure_vector<uint8_t> key(key_len);
         kdf(key.data(), key.size(), secret, secret_len, salt, salt_len, label, label_len);
         return key;
         }

      /**
      * Derive a key
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param salt a diversifier
      * @param label purpose for the derived keying material
      * @return the derived key
      */
      secure_vector<uint8_t> derive_key(size_t key_len,
                                    const secure_vector<uint8_t>& secret,
                                    const std::string& salt = "",
                                    const std::string& label = "") const
         {
         return derive_key(key_len, secret.data(), secret.size(),
                           cast_char_ptr_to_uint8(salt.data()),
                           salt.length(),
                           cast_char_ptr_to_uint8(label.data()),
                           label.length());

         }

      /**
      * Derive a key
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param salt a diversifier
      * @param label purpose for the derived keying material
      * @return the derived key
      */
      template<typename Alloc, typename Alloc2, typename Alloc3>
      secure_vector<uint8_t> derive_key(size_t key_len,
                                     const std::vector<uint8_t, Alloc>& secret,
                                     const std::vector<uint8_t, Alloc2>& salt,
                                     const std::vector<uint8_t, Alloc3>& label) const
         {
         return derive_key(key_len,
                           secret.data(), secret.size(),
                           salt.data(), salt.size(),
                           label.data(), label.size());
         }

      /**
      * Derive a key
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param salt a diversifier
      * @param salt_len size of salt in bytes
      * @param label purpose for the derived keying material
      * @return the derived key
      */
      secure_vector<uint8_t> derive_key(size_t key_len,
                                    const secure_vector<uint8_t>& secret,
                                    const uint8_t salt[],
                                    size_t salt_len,
                                    const std::string& label = "") const
         {
         return derive_key(key_len,
                           secret.data(), secret.size(),
                           salt, salt_len,
                           cast_char_ptr_to_uint8(label.data()),
                           label.size());
         }

      /**
      * Derive a key
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param secret_len size of secret in bytes
      * @param salt a diversifier
      * @param label purpose for the derived keying material
      * @return the derived key
      */
      secure_vector<uint8_t> derive_key(size_t key_len,
                                    const uint8_t secret[],
                                    size_t secret_len,
                                    const std::string& salt = "",
                                    const std::string& label = "") const
         {
         return derive_key(key_len, secret, secret_len,
                           cast_char_ptr_to_uint8(salt.data()),
                           salt.length(),
                           cast_char_ptr_to_uint8(label.data()),
                           label.length());
         }

      /**
      * @return new object representing the same algorithm as *this
      */
      virtual std::unique_ptr<KDF> new_object() const = 0;

      /**
      * @return new object representing the same algorithm as *this
      */
      KDF* clone() const
         {
         return this->new_object().release();
         }
   };

/**
* Factory method for KDF (key derivation function)
* @param algo_spec the name of the KDF to create
* @return pointer to newly allocated object of that type
*
* Prefer KDF::create
*/
inline KDF* get_kdf(const std::string& algo_spec)
   {
   auto kdf = KDF::create(algo_spec);
   if(kdf)
      return kdf.release();

   if(algo_spec == "Raw")
      return nullptr;

   throw Algorithm_Not_Found(algo_spec);
   }

}

namespace Botan {

/**
* This class represents Message Authentication Code (MAC) objects.
*/
class BOTAN_PUBLIC_API(2,0) MessageAuthenticationCode : public Buffered_Computation,
                                            public SymmetricAlgorithm
   {
   public:
      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to use
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<MessageAuthenticationCode>
         create(const std::string& algo_spec,
                const std::string& provider = "");

      /*
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to use
      * Throws a Lookup_Error if algo/provider combination cannot be found
      */
      static std::unique_ptr<MessageAuthenticationCode>
         create_or_throw(const std::string& algo_spec,
                         const std::string& provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      virtual ~MessageAuthenticationCode() = default;

      /**
      * Prepare for processing a message under the specified nonce
      *
      * Most MACs neither require nor support a nonce; for these algorithms
      * calling `start_msg` is optional and calling it with anything other than
      * an empty string is an error. One MAC which *requires* a per-message
      * nonce be specified is GMAC.
      *
      * @param nonce the message nonce bytes
      * @param nonce_len the size of len in bytes
      * Default implementation simply rejects all non-empty nonces
      * since most hash/MAC algorithms do not support randomization
      */
      virtual void start_msg(const uint8_t nonce[], size_t nonce_len);

      /**
      * Begin processing a message with a nonce
      *
      * @param nonce the per message nonce
      */
      template<typename Alloc>
      void start(const std::vector<uint8_t, Alloc>& nonce)
         {
         start_msg(nonce.data(), nonce.size());
         }

      /**
      * Begin processing a message.
      * @param nonce the per message nonce
      * @param nonce_len length of nonce
      */
      void start(const uint8_t nonce[], size_t nonce_len)
         {
         start_msg(nonce, nonce_len);
         }

      /**
      * Begin processing a message.
      */
      void start()
         {
         return start_msg(nullptr, 0);
         }

      /**
      * Verify a MAC.
      * @param in the MAC to verify as a byte array
      * @param length the length of param in
      * @return true if the MAC is valid, false otherwise
      */
      virtual bool verify_mac(const uint8_t in[], size_t length);

      /**
      * Verify a MAC.
      * @param in the MAC to verify as a byte array
      * @return true if the MAC is valid, false otherwise
      */
      virtual bool verify_mac(const std::vector<uint8_t>& in)
         {
         return verify_mac(in.data(), in.size());
         }

      /**
      * Verify a MAC.
      * @param in the MAC to verify as a byte array
      * @return true if the MAC is valid, false otherwise
      */
      virtual bool verify_mac(const secure_vector<uint8_t>& in)
         {
         return verify_mac(in.data(), in.size());
         }

      /**
      * @return new object representing the same algorithm as *this
      */
      virtual std::unique_ptr<MessageAuthenticationCode> new_object() const = 0;

      /**
      * Get a new object representing the same algorithm as *this
      */
      MessageAuthenticationCode* clone() const
         {
         return this->new_object().release();
         }

      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }

      /**
      * @return if a fresh key must be set for each message that is processed.
      *
      * This is required for certain polynomial-based MACs which are insecure
      * if a key is ever reused for two different messages.
      */
      virtual bool fresh_key_required_per_message() const { return false; }
   };

typedef MessageAuthenticationCode MAC;

}

namespace Botan {

class RandomNumberGenerator;

/**
* Return the absolute value
* @param n an integer
* @return absolute value of n
*/
inline BigInt abs(const BigInt& n) { return n.abs(); }

/**
* Compute the greatest common divisor
* @param x a positive integer
* @param y a positive integer
* @return gcd(x,y)
*/
BigInt BOTAN_PUBLIC_API(2,0) gcd(const BigInt& x, const BigInt& y);

/**
* Least common multiple
* @param x a positive integer
* @param y a positive integer
* @return z, smallest integer such that z % x == 0 and z % y == 0
*/
BigInt BOTAN_PUBLIC_API(2,0) lcm(const BigInt& x, const BigInt& y);

/**
* @param x an integer
* @return (x*x)
*/
BigInt BOTAN_PUBLIC_API(2,0) square(const BigInt& x);

/**
* Modular inversion. This algorithm is const time with respect to x,
* as long as x is less than modulus. It also avoids leaking
* information about the modulus, except that it does leak which of 3
* categories the modulus is in: an odd integer, a power of 2, or some
* other even number, and if the modulus is even, leaks the power of 2
* which divides the modulus.
*
* @param x a positive integer
* @param modulus a positive integer
* @return y st (x*y) % modulus == 1 or 0 if no such value
*/
BigInt BOTAN_PUBLIC_API(2,0) inverse_mod(const BigInt& x,
                                         const BigInt& modulus);

/**
* Compute the Jacobi symbol. If n is prime, this is equivalent
* to the Legendre symbol.
* @see http://mathworld.wolfram.com/JacobiSymbol.html
*
* @param a is a non-negative integer
* @param n is an odd integer > 1
* @return (n / m)
*/
int32_t BOTAN_PUBLIC_API(2,0) jacobi(const BigInt& a, const BigInt& n);

/**
* Modular exponentation
* @param b an integer base
* @param x a positive exponent
* @param m a positive modulus
* @return (b^x) % m
*/
BigInt BOTAN_PUBLIC_API(2,0) power_mod(const BigInt& b,
                                       const BigInt& x,
                                       const BigInt& m);

/**
* Compute the square root of x modulo a prime using the Tonelli-Shanks
* algorithm. This algorithm is primarily used for EC point
* decompression which takes only public inputs, as a consequence it is
* not written to be constant-time and may leak side-channel information
* about its arguments.
*
* @param x the input
* @param p the prime
* @return y such that (y*y)%p == x, or -1 if no such integer
*/
BigInt BOTAN_PUBLIC_API(2,0) ressol(const BigInt& x, const BigInt& p);

/**
* @param x an integer
* @return count of the low zero bits in x, or, equivalently, the
*         largest value of n such that 2^n divides x evenly. Returns
*         zero if x is equal to zero.
*/
size_t BOTAN_PUBLIC_API(2,0) low_zero_bits(const BigInt& x);

/**
* Check for primality
* @param n a positive integer to test for primality
* @param rng a random number generator
* @param prob chance of false positive is bounded by 1/2**prob
* @param is_random true if n was randomly chosen by us
* @return true if all primality tests passed, otherwise false
*/
bool BOTAN_PUBLIC_API(2,0) is_prime(const BigInt& n,
                                    RandomNumberGenerator& rng,
                                    size_t prob = 64,
                                    bool is_random = false);

/**
* Test if the positive integer x is a perfect square ie if there
* exists some positive integer y st y*y == x
* See FIPS 186-4 sec C.4
* @return 0 if the integer is not a perfect square, otherwise
*         returns the positive y st y*y == x
*/
BigInt BOTAN_PUBLIC_API(2,8) is_perfect_square(const BigInt& x);

/**
* Randomly generate a prime suitable for discrete logarithm parameters
* @param rng a random number generator
* @param bits how large the resulting prime should be in bits
* @param coprime a positive integer that (prime - 1) should be coprime to
* @param equiv a non-negative number that the result should be
               equivalent to modulo equiv_mod
* @param equiv_mod the modulus equiv should be checked against
* @param prob use test so false positive is bounded by 1/2**prob
* @return random prime with the specified criteria
*/
BigInt BOTAN_PUBLIC_API(2,0) random_prime(RandomNumberGenerator& rng,
                                          size_t bits,
                                          const BigInt& coprime = BigInt::from_u64(0),
                                          size_t equiv = 1,
                                          size_t equiv_mod = 2,
                                          size_t prob = 128);

/**
* Generate a prime suitable for RSA p/q
* @param keygen_rng a random number generator
* @param prime_test_rng a random number generator
* @param bits how large the resulting prime should be in bits (must be >= 512)
* @param coprime a positive integer that (prime - 1) should be coprime to
* @param prob use test so false positive is bounded by 1/2**prob
* @return random prime with the specified criteria
*/
BigInt BOTAN_PUBLIC_API(2,7) generate_rsa_prime(RandomNumberGenerator& keygen_rng,
                                                RandomNumberGenerator& prime_test_rng,
                                                size_t bits,
                                                const BigInt& coprime,
                                                size_t prob = 128);

/**
* Return a 'safe' prime, of the form p=2*q+1 with q prime
* @param rng a random number generator
* @param bits is how long the resulting prime should be
* @return prime randomly chosen from safe primes of length bits
*/
BigInt BOTAN_PUBLIC_API(2,0) random_safe_prime(RandomNumberGenerator& rng,
                                               size_t bits);

/**
* The size of the PRIMES[] array
*/
const size_t PRIME_TABLE_SIZE = 6541;

/**
* A const array of all odd primes less than 65535
*/
extern const uint16_t BOTAN_PUBLIC_API(2,0) PRIMES[];

}

namespace Botan {

class X509_Certificate;
class Public_Key;

/**
* Check that key constraints are permitted for a specific public key.
* @param pub_key the public key on which the constraints shall be enforced on
* @param constraints the constraints that shall be enforced on the key
* @throw Invalid_Argument if the given constraints are not permitted for this key
*/
BOTAN_PUBLIC_API(2,0) void verify_cert_constraints_valid_for_key_type(const Public_Key& pub_key,
                                                                      Key_Constraints constraints);

std::string BOTAN_PUBLIC_API(2,0) key_constraints_to_string(Key_Constraints);

/**
* Distinguished Name
*/
class BOTAN_PUBLIC_API(2,0) X509_DN final : public ASN1_Object
   {
   public:
      X509_DN() = default;

      explicit X509_DN(const std::multimap<OID, std::string>& args)
         {
         for(auto i : args)
            add_attribute(i.first, i.second);
         }

      explicit X509_DN(const std::multimap<std::string, std::string>& args)
         {
         for(auto i : args)
            add_attribute(i.first, i.second);
         }

      void encode_into(DER_Encoder&) const override;
      void decode_from(BER_Decoder&) override;

      bool has_field(const OID& oid) const;
      ASN1_String get_first_attribute(const OID& oid) const;

      /*
      * Return the BER encoded data, if any
      */
      const std::vector<uint8_t>& get_bits() const { return m_dn_bits; }

      std::vector<uint8_t> DER_encode() const;

      bool empty() const { return m_rdn.empty(); }

      std::string to_string() const;

      const std::vector<std::pair<OID,ASN1_String>>& dn_info() const { return m_rdn; }

      std::multimap<OID, std::string> get_attributes() const;
      std::multimap<std::string, std::string> contents() const;

      bool has_field(const std::string& attr) const;
      std::vector<std::string> get_attribute(const std::string& attr) const;
      std::string get_first_attribute(const std::string& attr) const;

      void add_attribute(const std::string& key, const std::string& val);

      void add_attribute(const OID& oid, const std::string& val)
         {
         add_attribute(oid, ASN1_String(val));
         }

      void add_attribute(const OID& oid, const ASN1_String& val);

      static std::string deref_info_field(const std::string& key);

      /**
      * Lookup upper bounds in characters for the length of distinguished name fields
      * as given in RFC 5280, Appendix A.
      *
      * @param oid the oid of the DN to lookup
      * @return the upper bound, or zero if no ub is known to Botan
      */
      static size_t lookup_ub(const OID& oid);

   private:
      std::vector<std::pair<OID,ASN1_String>> m_rdn;
      std::vector<uint8_t> m_dn_bits;
   };

bool BOTAN_PUBLIC_API(2,0) operator==(const X509_DN& dn1, const X509_DN& dn2);
bool BOTAN_PUBLIC_API(2,0) operator!=(const X509_DN& dn1, const X509_DN& dn2);

/*
The ordering here is arbitrary and may change from release to release.
It is intended for allowing DNs as keys in std::map and similiar containers
*/
bool BOTAN_PUBLIC_API(2,0) operator<(const X509_DN& dn1, const X509_DN& dn2);

BOTAN_PUBLIC_API(2,0) std::ostream& operator<<(std::ostream& out, const X509_DN& dn);
BOTAN_PUBLIC_API(2,0) std::istream& operator>>(std::istream& in, X509_DN& dn);

/**
* Alternative Name
*/
class BOTAN_PUBLIC_API(2,0) AlternativeName final : public ASN1_Object
   {
   public:
      void encode_into(DER_Encoder&) const override;
      void decode_from(BER_Decoder&) override;

      std::multimap<std::string, std::string> contents() const;

      bool has_field(const std::string& attr) const;
      std::vector<std::string> get_attribute(const std::string& attr) const;

      std::string get_first_attribute(const std::string& attr) const;

      void add_attribute(const std::string& type, const std::string& value);
      void add_othername(const OID& oid, const std::string& value, ASN1_Type type);

      const std::multimap<std::string, std::string>& get_attributes() const
         {
         return m_alt_info;
         }

      const std::multimap<OID, ASN1_String>& get_othernames() const
         {
         return m_othernames;
         }

      X509_DN dn() const;

      bool has_items() const;

      AlternativeName(const std::string& email_addr = "",
                      const std::string& uri = "",
                      const std::string& dns = "",
                      const std::string& ip_address = "");
   private:
      std::multimap<std::string, std::string> m_alt_info;
      std::multimap<OID, ASN1_String> m_othernames;
   };

/**
* Attribute
*/
class BOTAN_PUBLIC_API(2,0) Attribute final : public ASN1_Object
   {
   public:
      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;

      Attribute() = default;
      Attribute(const OID& oid, const std::vector<uint8_t>& params);
      Attribute(const std::string& oid_str, const std::vector<uint8_t>& params);

      const OID& oid() const { return m_oid; }
      const std::vector<uint8_t>& parameters() const { return m_parameters; }

      const OID& get_oid() const { return m_oid; }
      const std::vector<uint8_t>& get_parameters() const { return m_parameters; }

   private:
      OID m_oid;
      std::vector<uint8_t> m_parameters;
   };

/**
* @brief X.509 GeneralName Type
*
* Handles parsing GeneralName types in their BER and canonical string
* encoding. Allows matching GeneralNames against each other using
* the rules laid out in the RFC 5280, sec. 4.2.1.10 (Name Contraints).
*/
class BOTAN_PUBLIC_API(2,0) GeneralName final : public ASN1_Object
   {
   public:
      enum MatchResult : int
            {
            All,
            Some,
            None,
            NotFound,
            UnknownType,
            };

      /**
      * Creates an empty GeneralName.
      */
      GeneralName() = default;

      /**
      * Creates a new GeneralName for its string format.
      * @param str type and name, colon-separated, e.g., "DNS:google.com"
      */
      GeneralName(const std::string& str);

      void encode_into(DER_Encoder&) const override;

      void decode_from(BER_Decoder&) override;

      /**
      * @return Type of the name. Can be DN, DNS, IP, RFC822 or URI.
      */
      const std::string& type() const { return m_type; }

      /**
      * @return The name as string. Format depends on type.
      */
      const std::string& name() const { return m_name; }

      /**
      * Checks whether a given certificate (partially) matches this name.
      * @param cert certificate to be matched
      * @return the match result
      */
      MatchResult matches(const X509_Certificate& cert) const;

   private:
      std::string m_type;
      std::string m_name;

      bool matches_dns(const std::string&) const;
      bool matches_dn(const std::string&) const;
      bool matches_ip(const std::string&) const;
   };

std::ostream& operator<<(std::ostream& os, const GeneralName& gn);

/**
* @brief A single Name Constraint
*
* The Name Constraint extension adds a minimum and maximum path
* length to a GeneralName to form a constraint. The length limits
* are currently unused.
*/
class BOTAN_PUBLIC_API(2,0) GeneralSubtree final : public ASN1_Object
   {
   public:
      /**
      * Creates an empty name constraint.
      */
      GeneralSubtree() : m_base(), m_minimum(0), m_maximum(std::numeric_limits<std::size_t>::max())
      {}

      /***
      * Creates a new name constraint.
      * @param base name
      * @param min minimum path length
      * @param max maximum path length
      */
      GeneralSubtree(const GeneralName& base, size_t min, size_t max)
      : m_base(base), m_minimum(min), m_maximum(max)
      {}

      /**
      * Creates a new name constraint for its string format.
      * @param str name constraint
      */
      GeneralSubtree(const std::string& str);

      void encode_into(DER_Encoder&) const override;

      void decode_from(BER_Decoder&) override;

      /**
      * @return name
      */
      const GeneralName& base() const { return m_base; }

      /**
      * @return minimum path length
      */
      size_t minimum() const { return m_minimum; }

      /**
      * @return maximum path length
      */
      size_t maximum() const { return m_maximum; }

   private:
      GeneralName m_base;
      size_t m_minimum;
      size_t m_maximum;
   };

std::ostream& operator<<(std::ostream& os, const GeneralSubtree& gs);

/**
* @brief Name Constraints
*
* Wraps the Name Constraints associated with a certificate.
*/
class BOTAN_PUBLIC_API(2,0) NameConstraints final
   {
   public:
      /**
      * Creates an empty name NameConstraints.
      */
      NameConstraints() : m_permitted_subtrees(), m_excluded_subtrees() {}

      /**
      * Creates NameConstraints from a list of permitted and excluded subtrees.
      * @param permitted_subtrees names for which the certificate is permitted
      * @param excluded_subtrees names for which the certificate is not permitted
      */
      NameConstraints(std::vector<GeneralSubtree>&& permitted_subtrees,
                    std::vector<GeneralSubtree>&& excluded_subtrees)
      : m_permitted_subtrees(permitted_subtrees), m_excluded_subtrees(excluded_subtrees)
      {}

      /**
      * @return permitted names
      */
      const std::vector<GeneralSubtree>& permitted() const { return m_permitted_subtrees; }

      /**
      * @return excluded names
      */
      const std::vector<GeneralSubtree>& excluded() const { return m_excluded_subtrees; }

   private:
      std::vector<GeneralSubtree> m_permitted_subtrees;
      std::vector<GeneralSubtree> m_excluded_subtrees;
   };

/**
* X.509 Certificate Extension
*/
class BOTAN_PUBLIC_API(2,0) Certificate_Extension
   {
   public:
      /**
      * @return OID representing this extension
      */
      virtual OID oid_of() const = 0;

      /*
      * @return specific OID name
      * If possible OIDS table should match oid_name to OIDS, ie
      * OID::from_string(ext->oid_name()) == ext->oid_of()
      * Should return empty string if OID is not known
      */
      virtual std::string oid_name() const = 0;

      /**
      * Make a copy of this extension
      * @return copy of this
      */

      virtual std::unique_ptr<Certificate_Extension> copy() const = 0;

      /*
      * Callback visited during path validation.
      *
      * An extension can implement this callback to inspect
      * the path during path validation.
      *
      * If an error occurs during validation of this extension,
      * an appropriate status code shall be added to cert_status.
      *
      * @param subject Subject certificate that contains this extension
      * @param issuer Issuer certificate
      * @param status Certificate validation status codes for subject certificate
      * @param cert_path Certificate path which is currently validated
      * @param pos Position of subject certificate in cert_path
      */
      virtual void validate(const X509_Certificate& subject, const X509_Certificate& issuer,
            const std::vector<X509_Certificate>& cert_path,
            std::vector<std::set<Certificate_Status_Code>>& cert_status,
            size_t pos);

      virtual ~Certificate_Extension() = default;
   protected:
      friend class Extensions;
      virtual bool should_encode() const { return true; }
      virtual std::vector<uint8_t> encode_inner() const = 0;
      virtual void decode_inner(const std::vector<uint8_t>&) = 0;
   };

/**
* X.509 Certificate Extension List
*/
class BOTAN_PUBLIC_API(2,0) Extensions final : public ASN1_Object
   {
   public:
      /**
      * Look up an object in the extensions, based on OID Returns
      * nullptr if not set, if the extension was either absent or not
      * handled. The pointer returned is owned by the Extensions
      * object.
      * This would be better with an optional<T> return value
      */
      const Certificate_Extension* get_extension_object(const OID& oid) const;

      template<typename T>
      const T* get_extension_object_as(const OID& oid = T::static_oid()) const
         {
         if(const Certificate_Extension* extn = get_extension_object(oid))
            {
            // Unknown_Extension oid_name is empty
            if(extn->oid_name().empty())
               {
               return nullptr;
               }
            else if(const T* extn_as_T = dynamic_cast<const T*>(extn))
               {
               return extn_as_T;
               }
            else
               {
               throw Decoding_Error("Exception::get_extension_object_as dynamic_cast failed");
               }
            }

         return nullptr;
         }

      /**
      * Return the set of extensions in the order they appeared in the certificate
      * (or as they were added, if constructed)
      */
      const std::vector<OID>& get_extension_oids() const
         {
         return m_extension_oids;
         }

      /**
      * Return true if an extension was set
      */
      bool extension_set(const OID& oid) const;

      /**
      * Return true if an extesion was set and marked critical
      */
      bool critical_extension_set(const OID& oid) const;

      /**
      * Return the raw bytes of the extension
      * Will throw if OID was not set as an extension.
      */
      std::vector<uint8_t> get_extension_bits(const OID& oid) const;

      void encode_into(DER_Encoder&) const override;
      void decode_from(BER_Decoder&) override;

      /**
      * Adds a new extension to the list.
      * @param extn pointer to the certificate extension (Extensions takes ownership)
      * @param critical whether this extension should be marked as critical
      * @throw Invalid_Argument if the extension is already present in the list
      */
      void add(std::unique_ptr<Certificate_Extension> extn, bool critical = false);

      /**
      * Adds a new extension to the list unless it already exists. If the extension
      * already exists within the Extensions object, the extn pointer will be deleted.
      *
      * @param extn pointer to the certificate extension (Extensions takes ownership)
      * @param critical whether this extension should be marked as critical
      * @return true if the object was added false if the extension was already used
      */
      bool add_new(std::unique_ptr<Certificate_Extension> extn, bool critical = false);

      /**
      * Adds an extension to the list or replaces it.
      * @param extn the certificate extension
      * @param critical whether this extension should be marked as critical
      */
      void replace(std::unique_ptr<Certificate_Extension> extn, bool critical = false);

      /**
      * Remove an extension from the list. Returns true if the
      * extension had been set, false otherwise.
      */
      bool remove(const OID& oid);

      /**
      * Searches for an extension by OID and returns the result.
      * Only the known extensions types declared in this header
      * are searched for by this function.
      * @return Copy of extension with oid, nullptr if not found.
      * Can avoid creating a copy by using get_extension_object function
      */
      std::unique_ptr<Certificate_Extension> get(const OID& oid) const;

      /**
      * Searches for an extension by OID and returns the result decoding
      * it to some arbitrary extension type chosen by the application.
      *
      * Only the unknown extensions, that is, extensions types that
      * are not declared in this header, are searched for by this
      * function.
      *
      * @return Pointer to new extension with oid, nullptr if not found.
      */
      template<typename T>
      std::unique_ptr<T> get_raw(const OID& oid) const
         {
         auto extn_info = m_extension_info.find(oid);

         if(extn_info != m_extension_info.end())
            {
            // Unknown_Extension oid_name is empty
            if(extn_info->second.obj().oid_name() == "")
               {
               auto ext = std::make_unique<T>();
               ext->decode_inner(extn_info->second.bits());
               return ext;
               }
            }
         return nullptr;
         }

      /**
      * Returns a copy of the list of extensions together with the corresponding
      * criticality flag. All extensions are encoded as some object, falling back
      * to Unknown_Extension class which simply allows reading the bytes as well
      * as the criticality flag.
      */
      std::vector<std::pair<std::unique_ptr<Certificate_Extension>, bool>> extensions() const;

      /**
      * Returns the list of extensions as raw, encoded bytes
      * together with the corresponding criticality flag.
      * Contains all extensions, including any extensions encoded as Unknown_Extension
      */
      std::map<OID, std::pair<std::vector<uint8_t>, bool>> extensions_raw() const;

      Extensions() {}

      Extensions(const Extensions&) = default;
      Extensions& operator=(const Extensions&) = default;

      Extensions(Extensions&&) = default;
      Extensions& operator=(Extensions&&) = default;

   private:
      static std::unique_ptr<Certificate_Extension>
         create_extn_obj(const OID& oid,
                         bool critical,
                         const std::vector<uint8_t>& body);

      class Extensions_Info
         {
         public:
            Extensions_Info(bool critical,
                            std::unique_ptr<Certificate_Extension> ext) :
               m_obj(std::move(ext)),
               m_bits(m_obj->encode_inner()),
               m_critical(critical)
               {
               }

            Extensions_Info(bool critical,
                            const std::vector<uint8_t>& encoding,
                            std::unique_ptr<Certificate_Extension> ext) :
               m_obj(std::move(ext)),
               m_bits(encoding),
               m_critical(critical)
               {
               }

            bool is_critical() const { return m_critical; }
            const std::vector<uint8_t>& bits() const { return m_bits; }
            const Certificate_Extension& obj() const
               {
               BOTAN_ASSERT_NONNULL(m_obj.get());
               return *m_obj.get();
               }

         private:
            std::shared_ptr<Certificate_Extension> m_obj;
            std::vector<uint8_t> m_bits;
            bool m_critical = false;
         };

      std::vector<OID> m_extension_oids;
      std::map<OID, Extensions_Info> m_extension_info;
   };

}

namespace Botan {

class Certificate_Store;

namespace OCSP {

class BOTAN_PUBLIC_API(2,0) CertID final : public ASN1_Object
   {
   public:
      CertID() = default;

      CertID(const X509_Certificate& issuer,
             const BigInt& subject_serial);

      bool is_id_for(const X509_Certificate& issuer,
                     const X509_Certificate& subject) const;

      void encode_into(DER_Encoder& to) const override;

      void decode_from(BER_Decoder& from) override;

      const std::vector<uint8_t>& issuer_key_hash() const { return m_issuer_key_hash; }

   private:
      AlgorithmIdentifier m_hash_id;
      std::vector<uint8_t> m_issuer_dn_hash;
      std::vector<uint8_t> m_issuer_key_hash;
      BigInt m_subject_serial;
   };

class BOTAN_PUBLIC_API(2,0) SingleResponse final : public ASN1_Object
   {
   public:
      const CertID& certid() const { return m_certid; }

      size_t cert_status() const { return m_cert_status; }

      X509_Time this_update() const { return m_thisupdate; }

      X509_Time next_update() const { return m_nextupdate; }

      void encode_into(DER_Encoder& to) const override;

      void decode_from(BER_Decoder& from) override;
   private:
      CertID m_certid;
      size_t m_cert_status = 2; // unknown
      X509_Time m_thisupdate;
      X509_Time m_nextupdate;
   };

/**
* An OCSP request.
*/
class BOTAN_PUBLIC_API(2,0) Request final
   {
   public:
      /**
      * Create an OCSP request.
      * @param issuer_cert issuer certificate
      * @param subject_cert subject certificate
      */
      Request(const X509_Certificate& issuer_cert,
              const X509_Certificate& subject_cert);

      Request(const X509_Certificate& issuer_cert,
              const BigInt& subject_serial);

      /**
      * @return BER-encoded OCSP request
      */
      std::vector<uint8_t> BER_encode() const;

      /**
      * @return Base64-encoded OCSP request
      */
      std::string base64_encode() const;

      /**
      * @return issuer certificate
      */
      const X509_Certificate& issuer() const { return m_issuer; }

      /**
      * @return subject certificate
      */
      const X509_Certificate& subject() const { throw Not_Implemented("Method have been deprecated"); }

      const std::vector<uint8_t>& issuer_key_hash() const
         { return m_certid.issuer_key_hash(); }
   private:
      X509_Certificate m_issuer;
      CertID m_certid;
   };

/**
* OCSP response status.
*
* see https://tools.ietf.org/html/rfc6960#section-4.2.1
*/
enum class Response_Status_Code {
   Successful = 0,
   Malformed_Request = 1,
   Internal_Error = 2,
   Try_Later = 3,
   Sig_Required = 5,
   Unauthorized = 6
};

/**
* OCSP response.
*
* Note this class is only usable as an OCSP client
*/
class BOTAN_PUBLIC_API(2,0) Response final
   {
   public:
      /**
      * Creates an empty OCSP response.
      */
      Response() = default;

      /**
      * Create a fake OCSP response from a given status code.
      * @param status the status code the check functions will return
      */
      Response(Certificate_Status_Code status);

      /**
      * Parses an OCSP response.
      * @param response_bits response bits received
      */
      Response(const std::vector<uint8_t>& response_bits) :
         Response(response_bits.data(), response_bits.size())
         {}

      /**
      * Parses an OCSP response.
      * @param response_bits response bits received
      * @param response_bits_len length of response in bytes
      */
      Response(const uint8_t response_bits[],
               size_t response_bits_len);

      /**
      * Check signature and return status
      * The optional cert_path is the (already validated!) certificate path of
      * the end entity which is being inquired about
      * @param trust_roots list of certstores containing trusted roots
      * @param cert_path optionally, the (already verified!) certificate path for the certificate
      * this is an OCSP response for. This is necessary to find the correct intermediate CA in
      * some cases.
      */
      Certificate_Status_Code check_signature(const std::vector<Certificate_Store*>& trust_roots,
                                              const std::vector<X509_Certificate>& cert_path = {}) const;

      /**
      * Verify that issuer's key signed this response
      * @param issuer certificate of issuer
      * @return if signature valid OCSP_SIGNATURE_OK else an error code
      */
      Certificate_Status_Code verify_signature(const X509_Certificate& issuer) const;

      /**
      * @return the status of the response
      */
      Response_Status_Code status() const { return m_status; }

      /**
      * @return the time this OCSP response was supposedly produced at
      */
      const X509_Time& produced_at() const { return m_produced_at; }

      /**
      * @return DN of signer, if provided in response (may be empty)
      */
      const X509_DN& signer_name() const { return m_signer_name; }

      /**
      * @return key hash, if provided in response (may be empty)
      */
      const std::vector<uint8_t>& signer_key_hash() const { return m_key_hash; }

      const std::vector<uint8_t>& raw_bits() const { return m_response_bits; }

      /**
       * Searches the OCSP response for issuer and subject certificate.
       * @param issuer issuer certificate
       * @param subject subject certificate
       * @param ref_time the reference time
       * @param max_age the maximum age the response should be considered valid
       *                if next_update is not set
       * @return OCSP status code, possible values:
       *         CERT_IS_REVOKED,
       *         OCSP_NOT_YET_VALID,
       *         OCSP_HAS_EXPIRED,
       *         OCSP_IS_TOO_OLD,
       *         OCSP_RESPONSE_GOOD,
       *         OCSP_BAD_STATUS,
       *         OCSP_CERT_NOT_LISTED
       */
      Certificate_Status_Code status_for(const X509_Certificate& issuer,
                                         const X509_Certificate& subject,
                                         std::chrono::system_clock::time_point ref_time = std::chrono::system_clock::now(),
                                         std::chrono::seconds max_age = std::chrono::seconds::zero()) const;

      /**
       * @return the certificate chain, if provided in response
       */
      const std::vector<X509_Certificate> &certificates() const { return  m_certs; }

   private:
      Response_Status_Code m_status;
      std::vector<uint8_t> m_response_bits;
      X509_Time m_produced_at;
      X509_DN m_signer_name;
      std::vector<uint8_t> m_key_hash;
      std::vector<uint8_t> m_tbs_bits;
      AlgorithmIdentifier m_sig_algo;
      std::vector<uint8_t> m_signature;
      std::vector<X509_Certificate> m_certs;

      std::vector<SingleResponse> m_responses;

      Certificate_Status_Code m_dummy_response_status;
   };

#if defined(BOTAN_HAS_HTTP_UTIL)

/**
* Makes an online OCSP request via HTTP and returns the OCSP response.
* @param issuer issuer certificate
* @param subject_serial the subject's serial number
* @param ocsp_responder the OCSP responder to query
* @param trusted_roots trusted roots for the OCSP response
* @param timeout a timeout on the HTTP request
* @return OCSP response
*/
BOTAN_PUBLIC_API(2,1)
Response online_check(const X509_Certificate& issuer,
                      const BigInt& subject_serial,
                      const std::string& ocsp_responder,
                      Certificate_Store* trusted_roots,
                      std::chrono::milliseconds timeout = std::chrono::milliseconds(3000));

/**
* Makes an online OCSP request via HTTP and returns the OCSP response.
* @param issuer issuer certificate
* @param subject subject certificate
* @param trusted_roots trusted roots for the OCSP response
* @param timeout a timeout on the HTTP request
* @return OCSP response
*/
BOTAN_PUBLIC_API(2,0)
Response online_check(const X509_Certificate& issuer,
                      const X509_Certificate& subject,
                      Certificate_Store* trusted_roots,
                      std::chrono::milliseconds timeout = std::chrono::milliseconds(3000));

#endif

}

}

namespace Botan {

namespace OIDS {

/**
* Register an OID to string mapping.
* @param oid the oid to register
* @param name the name to be associated with the oid
*/
BOTAN_UNSTABLE_API void add_oid(const OID& oid, const std::string& name);

BOTAN_UNSTABLE_API void add_oid2str(const OID& oid, const std::string& name);
BOTAN_UNSTABLE_API void add_str2oid(const OID& oid, const std::string& name);

BOTAN_UNSTABLE_API void add_oidstr(const char* oidstr, const char* name);

std::unordered_map<std::string, std::string> load_oid2str_map();
std::unordered_map<std::string, OID> load_str2oid_map();

/**
* Resolve an OID
* @param oid the OID to look up
* @return name associated with this OID, or an empty string
*/
BOTAN_UNSTABLE_API std::string oid2str_or_empty(const OID& oid);

/**
* Find the OID to a name. The lookup will be performed in the
* general OID section of the configuration.
* @param name the name to resolve
* @return OID associated with the specified name
*/
BOTAN_UNSTABLE_API OID str2oid_or_empty(const std::string& name);

BOTAN_UNSTABLE_API std::string oid2str_or_throw(const OID& oid);

}

}

namespace Botan {

/**
* Base class for PBKDF (password based key derivation function)
* implementations. Converts a password into a key using a salt
* and iterated hashing to make brute force attacks harder.
*
* Starting in 2.8 this functionality is also offered by PasswordHash.
* The PBKDF interface may be removed in a future release.
*/
class BOTAN_PUBLIC_API(2,0) PBKDF
   {
   public:
      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to choose
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<PBKDF> create(const std::string& algo_spec,
                                           const std::string& provider = "");

      /**
      * Create an instance based on a name, or throw if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<PBKDF>
         create_or_throw(const std::string& algo_spec,
                         const std::string& provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      /**
      * @return new instance of this same algorithm
      */
      virtual std::unique_ptr<PBKDF> new_object() const = 0;

      /**
      * @return new instance of this same algorithm
      */
      PBKDF* clone() const
         {
         return this->new_object().release();
         }

      /**
      * @return name of this PBKDF
      */
      virtual std::string name() const = 0;

      virtual ~PBKDF() = default;

      /**
      * Derive a key from a passphrase for a number of iterations
      * specified by either iterations or if iterations == 0 then
      * running until msec time has elapsed.
      *
      * @param out buffer to store the derived key, must be of out_len bytes
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param iterations the number of iterations to use (use 10K or more)
      * @param msec if iterations is zero, then instead the PBKDF is
      *        run until msec milliseconds has passed.
      * @return the number of iterations performed
      */
      virtual size_t pbkdf(uint8_t out[], size_t out_len,
                           const std::string& passphrase,
                           const uint8_t salt[], size_t salt_len,
                           size_t iterations,
                           std::chrono::milliseconds msec) const = 0;

      /**
      * Derive a key from a passphrase for a number of iterations.
      *
      * @param out buffer to store the derived key, must be of out_len bytes
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param iterations the number of iterations to use (use 10K or more)
      */
      void pbkdf_iterations(uint8_t out[], size_t out_len,
                            const std::string& passphrase,
                            const uint8_t salt[], size_t salt_len,
                            size_t iterations) const;

      /**
      * Derive a key from a passphrase, running until msec time has elapsed.
      *
      * @param out buffer to store the derived key, must be of out_len bytes
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param msec if iterations is zero, then instead the PBKDF is
      *        run until msec milliseconds has passed.
      * @param iterations set to the number iterations executed
      */
      void pbkdf_timed(uint8_t out[], size_t out_len,
                         const std::string& passphrase,
                         const uint8_t salt[], size_t salt_len,
                         std::chrono::milliseconds msec,
                         size_t& iterations) const;

      /**
      * Derive a key from a passphrase for a number of iterations.
      *
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param iterations the number of iterations to use (use 10K or more)
      * @return the derived key
      */
      secure_vector<uint8_t> pbkdf_iterations(size_t out_len,
                                           const std::string& passphrase,
                                           const uint8_t salt[], size_t salt_len,
                                           size_t iterations) const;

      /**
      * Derive a key from a passphrase, running until msec time has elapsed.
      *
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param msec if iterations is zero, then instead the PBKDF is
      *        run until msec milliseconds has passed.
      * @param iterations set to the number iterations executed
      * @return the derived key
      */
      secure_vector<uint8_t> pbkdf_timed(size_t out_len,
                                      const std::string& passphrase,
                                      const uint8_t salt[], size_t salt_len,
                                      std::chrono::milliseconds msec,
                                      size_t& iterations) const;

      // Following kept for compat with 1.10:

      /**
      * Derive a key from a passphrase
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param iterations the number of iterations to use (use 10K or more)
      */
      OctetString derive_key(size_t out_len,
                             const std::string& passphrase,
                             const uint8_t salt[], size_t salt_len,
                             size_t iterations) const
         {
         return pbkdf_iterations(out_len, passphrase, salt, salt_len, iterations);
         }

      /**
      * Derive a key from a passphrase
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param iterations the number of iterations to use (use 10K or more)
      */
      template<typename Alloc>
      OctetString derive_key(size_t out_len,
                             const std::string& passphrase,
                             const std::vector<uint8_t, Alloc>& salt,
                             size_t iterations) const
         {
         return pbkdf_iterations(out_len, passphrase, salt.data(), salt.size(), iterations);
         }

      /**
      * Derive a key from a passphrase
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param msec is how long to run the PBKDF
      * @param iterations is set to the number of iterations used
      */
      OctetString derive_key(size_t out_len,
                             const std::string& passphrase,
                             const uint8_t salt[], size_t salt_len,
                             std::chrono::milliseconds msec,
                             size_t& iterations) const
         {
         return pbkdf_timed(out_len, passphrase, salt, salt_len, msec, iterations);
         }

      /**
      * Derive a key from a passphrase using a certain amount of time
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param msec is how long to run the PBKDF
      * @param iterations is set to the number of iterations used
      */
      template<typename Alloc>
      OctetString derive_key(size_t out_len,
                             const std::string& passphrase,
                             const std::vector<uint8_t, Alloc>& salt,
                             std::chrono::milliseconds msec,
                             size_t& iterations) const
         {
         return pbkdf_timed(out_len, passphrase, salt.data(), salt.size(), msec, iterations);
         }
   };

/*
* Compatibility typedef
*/
typedef PBKDF S2K;

/**
* Password based key derivation function factory method
* @param algo_spec the name of the desired PBKDF algorithm
* @param provider the provider to use
* @return pointer to newly allocated object of that type
*/
inline PBKDF* get_pbkdf(const std::string& algo_spec,
                        const std::string& provider = "")
   {
   return PBKDF::create_or_throw(algo_spec, provider).release();
   }

inline PBKDF* get_s2k(const std::string& algo_spec)
   {
   return get_pbkdf(algo_spec);
   }


}

namespace Botan {

/**
* Base class for password based key derivation functions.
*
* Converts a password into a key using a salt and iterated hashing to
* make brute force attacks harder.
*/
class BOTAN_PUBLIC_API(2,8) PasswordHash
   {
   public:
      virtual ~PasswordHash() = default;

      virtual std::string to_string() const = 0;

      /**
      * Most password hashes have some notion of iterations.
      */
      virtual size_t iterations() const = 0;

      /**
      * Some password hashing algorithms have a parameter which controls how
      * much memory is used. If not supported by some algorithm, returns 0.
      */
      virtual size_t memory_param() const { return 0; }

      /**
      * Some password hashing algorithms have a parallelism parameter.
      * If the algorithm does not support this notion, then the
      * function returns zero. This allows distinguishing between a
      * password hash which just does not support parallel operation,
      * vs one that does support parallel operation but which has been
      * configured to use a single lane.
      */
      virtual size_t parallelism() const { return 0; }

      /**
      * Returns an estimate of the total number of bytes required to perform this
      * key derivation.
      *
      * If this algorithm uses a small and constant amount of memory, with no
      * effort made towards being memory hard, this function returns 0.
      */
      virtual size_t total_memory_usage() const { return 0; }

      /**
      * Derive a key from a password
      *
      * @param out buffer to store the derived key, must be of out_len bytes
      * @param out_len the desired length of the key to produce
      * @param password the password to derive the key from
      * @param password_len the length of password in bytes
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      *
      * This function is const, but is not thread safe. Different threads should
      * either use unique objects, or serialize all access.
      */
      virtual void derive_key(uint8_t out[], size_t out_len,
                              const char* password, size_t password_len,
                              const uint8_t salt[], size_t salt_len) const = 0;

      /**
      * Derive a key from a password plus additional data and/or a secret key
      *
      * Currently this is only supported for Argon2. Using a non-empty AD or key
      * with other algorithms will cause a Not_Implemented exception.
      *
      * @param out buffer to store the derived key, must be of out_len bytes
      * @param out_len the desired length of the key to produce
      * @param password the password to derive the key from
      * @param password_len the length of password in bytes
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param ad some additional data
      * @param ad_len length of ad in bytes
      * @param key a secret key
      * @param key_len length of key in bytes
      *
      * This function is const, but is not thread safe. Different threads should
      * either use unique objects, or serialize all access.
      */
      virtual void derive_key(uint8_t out[], size_t out_len,
                              const char* password, size_t password_len,
                              const uint8_t salt[], size_t salt_len,
                              const uint8_t ad[], size_t ad_len,
                              const uint8_t key[], size_t key_len) const;
   };

class BOTAN_PUBLIC_API(2,8) PasswordHashFamily
   {
   public:
      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to choose
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<PasswordHashFamily> create(const std::string& algo_spec,
                                                        const std::string& provider = "");

      /**
      * Create an instance based on a name, or throw if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<PasswordHashFamily>
         create_or_throw(const std::string& algo_spec,
                         const std::string& provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      virtual ~PasswordHashFamily() = default;

      /**
      * @return name of this PasswordHash
      */
      virtual std::string name() const = 0;

      /**
      * Return a new parameter set tuned for this machine
      * @param output_length how long the output length will be
      * @param msec the desired execution time in milliseconds
      *
      * @param max_memory_usage_mb some password hash functions can use a tunable
      * amount of memory, in this case max_memory_usage limits the amount of RAM
      * the returned parameters will require, in mebibytes (2**20 bytes). It may
      * require some small amount above the request. Set to zero to place no
      * limit at all.
      */
      virtual std::unique_ptr<PasswordHash> tune(size_t output_length,
                                                 std::chrono::milliseconds msec,
                                                 size_t max_memory_usage_mb = 0) const = 0;

      /**
      * Return some default parameter set for this PBKDF that should be good
      * enough for most users. The value returned may change over time as
      * processing power and attacks improve.
      */
      virtual std::unique_ptr<PasswordHash> default_params() const = 0;

      /**
      * Return a parameter chosen based on a rough approximation with the
      * specified iteration count. The exact value this returns for a particular
      * algorithm may change from over time. Think of it as an alternative to
      * tune, where time is expressed in terms of PBKDF2 iterations rather than
      * milliseconds.
      */
      virtual std::unique_ptr<PasswordHash> from_iterations(size_t iterations) const = 0;

      /**
      * Create a password hash using some scheme specific format. Parameters are as follows:
      * - For PBKDF2, PGP-S2K, and Bcrypt-PBKDF, i1 is iterations
      * - Scrypt uses N, r, p for i{1-3}
      * - Argon2 family uses memory (in KB), iterations, and parallelism for i{1-3}
      *
      * All unneeded parameters should be set to 0 or left blank.
      */
      virtual std::unique_ptr<PasswordHash> from_params(
         size_t i1,
         size_t i2 = 0,
         size_t i3 = 0) const = 0;
   };

}

BOTAN_FUTURE_INTERNAL_HEADER(pbkdf2.h)

namespace Botan {

BOTAN_PUBLIC_API(2,0) size_t pbkdf2(MessageAuthenticationCode& prf,
                        uint8_t out[],
                        size_t out_len,
                        const std::string& passphrase,
                        const uint8_t salt[], size_t salt_len,
                        size_t iterations,
                        std::chrono::milliseconds msec);

/**
* Perform PBKDF2. The prf is assumed to be keyed already.
*/
BOTAN_PUBLIC_API(2,8) void pbkdf2(MessageAuthenticationCode& prf,
                                  uint8_t out[], size_t out_len,
                                  const uint8_t salt[], size_t salt_len,
                                  size_t iterations);

/**
* PBKDF2
*/
class BOTAN_PUBLIC_API(2,8) PBKDF2 final : public PasswordHash
   {
   public:
      PBKDF2(const MessageAuthenticationCode& prf, size_t iter) :
         m_prf(prf.new_object()),
         m_iterations(iter)
         {}

      PBKDF2(const MessageAuthenticationCode& prf, size_t olen, std::chrono::milliseconds msec);

      size_t iterations() const override { return m_iterations; }

      std::string to_string() const override;

      void derive_key(uint8_t out[], size_t out_len,
                      const char* password, size_t password_len,
                      const uint8_t salt[], size_t salt_len) const override;
   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
      size_t m_iterations;
   };

/**
* Family of PKCS #5 PBKDF2 operations
*/
class BOTAN_PUBLIC_API(2,8) PBKDF2_Family final : public PasswordHashFamily
   {
   public:
      PBKDF2_Family(MessageAuthenticationCode* prf) : m_prf(prf) {}

      std::string name() const override;

      std::unique_ptr<PasswordHash> tune(size_t output_len,
                                         std::chrono::milliseconds msec,
                                         size_t max_memory) const override;

      /**
      * Return some default parameter set for this PBKDF that should be good
      * enough for most users. The value returned may change over time as
      * processing power and attacks improve.
      */
      std::unique_ptr<PasswordHash> default_params() const override;

      std::unique_ptr<PasswordHash> from_iterations(size_t iter) const override;

      std::unique_ptr<PasswordHash> from_params(
         size_t iter, size_t, size_t) const override;
   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
   };

/**
* PKCS #5 PBKDF2 (old interface)
*/
class BOTAN_PUBLIC_API(2,0) PKCS5_PBKDF2 final : public PBKDF
   {
   public:
      std::string name() const override;

      std::unique_ptr<PBKDF> new_object() const override;

      size_t pbkdf(uint8_t output_buf[], size_t output_len,
                   const std::string& passphrase,
                   const uint8_t salt[], size_t salt_len,
                   size_t iterations,
                   std::chrono::milliseconds msec) const override;

      /**
      * Create a PKCS #5 instance using the specified message auth code
      * @param mac_fn the MAC object to use as PRF
      */
      explicit PKCS5_PBKDF2(MessageAuthenticationCode* mac_fn) : m_mac(mac_fn) {}
   private:
      std::unique_ptr<MessageAuthenticationCode> m_mac;
   };

}

namespace Botan {

class DataSource;

namespace PEM_Code {

/**
* Encode some binary data in PEM format
* @param data binary data to encode
* @param data_len length of binary data in bytes
* @param label PEM label put after BEGIN and END
* @param line_width after this many characters, a new line is inserted
*/
BOTAN_PUBLIC_API(2,0) std::string encode(const uint8_t data[],
                                         size_t data_len,
                                         const std::string& label,
                                         size_t line_width = 64);

/**
* Encode some binary data in PEM format
* @param data binary data to encode
* @param label PEM label
* @param line_width after this many characters, a new line is inserted
*/
template<typename Alloc>
std::string encode(const std::vector<uint8_t, Alloc>& data,
                   const std::string& label,
                   size_t line_width = 64)
   {
   return encode(data.data(), data.size(), label, line_width);
   }

/**
* Decode PEM data
* @param pem a datasource containing PEM encoded data
* @param label is set to the PEM label found for later inspection
*/
BOTAN_PUBLIC_API(2,0) secure_vector<uint8_t> decode(DataSource& pem,
                                                    std::string& label);

/**
* Decode PEM data
* @param pem a string containing PEM encoded data
* @param label is set to the PEM label found for later inspection
*/
BOTAN_PUBLIC_API(2,0) secure_vector<uint8_t> decode(const std::string& pem,
                                                    std::string& label);

/**
* Decode PEM data
* @param pem a datasource containing PEM encoded data
* @param label is what we expect the label to be
*/
BOTAN_PUBLIC_API(2,0)
secure_vector<uint8_t> decode_check_label(DataSource& pem,
                                          const std::string& label);

/**
* Decode PEM data
* @param pem a string containing PEM encoded data
* @param label is what we expect the label to be
*/
BOTAN_PUBLIC_API(2,0)
secure_vector<uint8_t> decode_check_label(const std::string& pem,
                                          const std::string& label);

/**
* Heuristic test for PEM data.
*/
BOTAN_PUBLIC_API(2,0) bool matches(DataSource& source,
                                   const std::string& extra = "",
                                   size_t search_range = 4096);

}

}
namespace Botan {

namespace PK_Ops {

class Encryption;
class Decryption;
class Verification;
class Signature;
class Key_Agreement;
class KEM_Encryption;
class KEM_Decryption;

}

}

namespace Botan {

class RandomNumberGenerator;

/**
* The two types of signature format supported by Botan.
*/
enum Signature_Format { IEEE_1363, DER_SEQUENCE };

/**
* Public Key Base Class.
*/
class BOTAN_PUBLIC_API(2,0) Public_Key
   {
   public:
      Public_Key() = default;
      Public_Key(const Public_Key& other) = default;
      Public_Key& operator=(const Public_Key& other) = default;
      virtual ~Public_Key() = default;

      /**
      * Get the name of the underlying public key scheme.
      * @return name of the public key scheme
      */
      virtual std::string algo_name() const = 0;

      /**
      * Return the estimated strength of the underlying key against
      * the best currently known attack. Note that this ignores anything
      * but pure attacks against the key itself and do not take into
      * account padding schemes, usage mistakes, etc which might reduce
      * the strength. However it does suffice to provide an upper bound.
      *
      * @return estimated strength in bits
      */
      virtual size_t estimated_strength() const = 0;

      /**
      * Return an integer value best approximating the length of the
      * primary security parameter. For example for RSA this will be
      * the size of the modulus, for ECDSA the size of the ECC group,
      * and for McEliece the size of the code will be returned.
      */
      virtual size_t key_length() const = 0;

      /**
      * Get the OID of the underlying public key scheme.
      * @return OID of the public key scheme
      */
      virtual OID get_oid() const;

      /**
      * Test the key values for consistency.
      * @param rng rng to use
      * @param strong whether to perform strong and lengthy version
      * of the test
      * @return true if the test is passed
      */
      virtual bool check_key(RandomNumberGenerator& rng,
                             bool strong) const = 0;


      /**
      * @return X.509 AlgorithmIdentifier for this key
      */
      virtual AlgorithmIdentifier algorithm_identifier() const = 0;

      /**
      * @return BER encoded public key bits
      */
      virtual std::vector<uint8_t> public_key_bits() const = 0;

      /**
      * @return X.509 subject key encoding for this key object
      */
      std::vector<uint8_t> subject_public_key() const;

      /**
       * @return Hash of the subject public key
       */
      std::string fingerprint_public(const std::string& alg = "SHA-256") const;

      // Internal or non-public declarations follow

      /**
      * Returns more than 1 if the output of this algorithm
      * (ciphertext, signature) should be treated as more than one
      * value. This is used for algorithms like DSA and ECDSA, where
      * the (r,s) output pair can be encoded as either a plain binary
      * list or a TLV tagged DER encoding depending on the protocol.
      *
      * This function is public but applications should have few
      * reasons to ever call this.
      *
      * @return number of message parts
      */
      virtual size_t message_parts() const { return 1; }

      /**
      * Returns how large each of the message parts refered to
      * by message_parts() is
      *
      * This function is public but applications should have few
      * reasons to ever call this.
      *
      * @return size of the message parts in bits
      */
      virtual size_t message_part_size() const { return 0; }

      virtual Signature_Format default_x509_signature_format() const
         {
         return (this->message_parts() >= 2) ? DER_SEQUENCE : IEEE_1363;
         }

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return an encryption operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      * @param params additional parameters
      * @param provider the provider to use
      */
      virtual std::unique_ptr<PK_Ops::Encryption>
         create_encryption_op(RandomNumberGenerator& rng,
                              const std::string& params,
                              const std::string& provider) const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return a KEM encryption operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      * @param params additional parameters
      * @param provider the provider to use
      */
      virtual std::unique_ptr<PK_Ops::KEM_Encryption>
         create_kem_encryption_op(RandomNumberGenerator& rng,
                                  const std::string& params,
                                  const std::string& provider) const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return a verification operation for this key/params or throw
      * @param params additional parameters
      * @param provider the provider to use
      */
      virtual std::unique_ptr<PK_Ops::Verification>
         create_verification_op(const std::string& params,
                                const std::string& provider) const;
   };

/**
* Private Key Base Class
*/
class BOTAN_PUBLIC_API(2,0) Private_Key : public virtual Public_Key
   {
   public:
      Private_Key() = default;
      Private_Key(const Private_Key& other) = default;
      Private_Key& operator=(const Private_Key& other) = default;
      virtual ~Private_Key() = default;

      virtual bool stateful_operation() const { return false; }

      /**
      * @return BER encoded private key bits
      */
      virtual secure_vector<uint8_t> private_key_bits() const = 0;

      /**
      * Allocate a new object for the public key associated with this
      * private key.
      *
      * @return public key
      */
      virtual std::unique_ptr<Public_Key> public_key() const = 0;

      /**
      * @return PKCS #8 private key encoding for this key object
      */
      secure_vector<uint8_t> private_key_info() const;

      /**
      * @return PKCS #8 AlgorithmIdentifier for this key
      * Might be different from the X.509 identifier, but normally is not
      */
      virtual AlgorithmIdentifier pkcs8_algorithm_identifier() const
         { return algorithm_identifier(); }

      // Internal or non-public declarations follow

      /**
       * @return Hash of the PKCS #8 encoding for this key object
       */
      std::string fingerprint_private(const std::string& alg) const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return an decryption operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      * @param params additional parameters
      * @param provider the provider to use
      *
      */
      virtual std::unique_ptr<PK_Ops::Decryption>
         create_decryption_op(RandomNumberGenerator& rng,
                              const std::string& params,
                              const std::string& provider) const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return a KEM decryption operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      * @param params additional parameters
      * @param provider the provider to use
      */
      virtual std::unique_ptr<PK_Ops::KEM_Decryption>
         create_kem_decryption_op(RandomNumberGenerator& rng,
                                  const std::string& params,
                                  const std::string& provider) const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return a signature operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      * @param params additional parameters
      * @param provider the provider to use
      */
      virtual std::unique_ptr<PK_Ops::Signature>
         create_signature_op(RandomNumberGenerator& rng,
                             const std::string& params,
                             const std::string& provider) const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return a key agreement operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      * @param params additional parameters
      * @param provider the provider to use
      */
      virtual std::unique_ptr<PK_Ops::Key_Agreement>
         create_key_agreement_op(RandomNumberGenerator& rng,
                                 const std::string& params,
                                 const std::string& provider) const;
   };

/**
* PK Secret Value Derivation Key
*/
class BOTAN_PUBLIC_API(2,0) PK_Key_Agreement_Key : public virtual Private_Key
   {
   public:
      /*
      * @return public component of this key
      */
      virtual std::vector<uint8_t> public_value() const = 0;

      PK_Key_Agreement_Key() = default;
      PK_Key_Agreement_Key(const PK_Key_Agreement_Key&) = default;
      PK_Key_Agreement_Key& operator=(const PK_Key_Agreement_Key&) = default;
      virtual ~PK_Key_Agreement_Key() = default;
   };

/*
* Old compat typedefs
* TODO: remove these?
*/
typedef PK_Key_Agreement_Key PK_KA_Key;
typedef Public_Key X509_PublicKey;
typedef Private_Key PKCS8_PrivateKey;

std::string BOTAN_PUBLIC_API(2,4)
   create_hex_fingerprint(const uint8_t bits[], size_t len,
                          const std::string& hash_name);

template<typename Alloc>
std::string create_hex_fingerprint(const std::vector<uint8_t, Alloc>& vec,
                                   const std::string& hash_name)
   {
   return create_hex_fingerprint(vec.data(), vec.size(), hash_name);
   }


}

namespace Botan {

BOTAN_PUBLIC_API(2,0) std::unique_ptr<Public_Key>
load_public_key(const AlgorithmIdentifier& alg_id,
                const std::vector<uint8_t>& key_bits);

BOTAN_PUBLIC_API(2,0) std::unique_ptr<Private_Key>
load_private_key(const AlgorithmIdentifier& alg_id,
                 const secure_vector<uint8_t>& key_bits);

/**
* Create a new key
* For ECC keys, algo_params specifies EC group (eg, "secp256r1")
* For DH/DSA/ElGamal keys, algo_params is DL group (eg, "modp/ietf/2048")
* For RSA, algo_params is integer keylength
* For McEliece, algo_params is n,t
* If algo_params is left empty, suitable default parameters are chosen.
*/
BOTAN_PUBLIC_API(2,0) std::unique_ptr<Private_Key>
create_private_key(const std::string& algo_name,
                   RandomNumberGenerator& rng,
                   const std::string& algo_params = "",
                   const std::string& provider = "");


/**
* Create a new ECC key
*/
class EC_Group;

BOTAN_PUBLIC_API(3,0) std::unique_ptr<Private_Key>
create_ec_private_key(const std::string& algo_name,
                      const EC_Group& group,
                      RandomNumberGenerator& rng);

BOTAN_PUBLIC_API(2,2)
std::vector<std::string>
probe_provider_private_key(const std::string& algo_name,
                           const std::vector<std::string>& possible);

}

namespace Botan {

struct PKCS10_Data;

class Private_Key;
class Extensions;
class X509_DN;
class AlternativeName;

/**
* PKCS #10 Certificate Request.
*/
class BOTAN_PUBLIC_API(2,0) PKCS10_Request final : public X509_Object
   {
   public:
      /**
      * Get the subject public key.
      * @return subject public key
      */
      Public_Key* subject_public_key() const;

      /**
      * Get the raw DER encoded public key.
      * @return raw DER encoded public key
      */
      const std::vector<uint8_t>& raw_public_key() const;

      /**
      * Get the subject DN.
      * @return subject DN
      */
      const X509_DN& subject_dn() const;

      /**
      * Get the subject alternative name.
      * @return subject alternative name.
      */
      const AlternativeName& subject_alt_name() const;

      /**
      * Get the key constraints for the key associated with this
      * PKCS#10 object.
      * @return key constraints
      */
      Key_Constraints constraints() const;

      /**
      * Get the extendend key constraints (if any).
      * @return extended key constraints
      */
      std::vector<OID> ex_constraints() const;

      /**
      * Find out whether this is a CA request.
      * @result true if it is a CA request, false otherwise.
      */
      bool is_CA() const;

      /**
      * Return the constraint on the path length defined
      * in the BasicConstraints extension.
      * @return path limit
      */
      size_t path_limit() const;

      /**
      * Get the challenge password for this request
      * @return challenge password for this request
      */
      std::string challenge_password() const;

      /**
      * Get the X509v3 extensions.
      * @return X509v3 extensions
      */
      const Extensions& extensions() const;

      /**
      * Create a PKCS#10 Request from a data source.
      * @param source the data source providing the DER encoded request
      */
      explicit PKCS10_Request(DataSource& source);

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      /**
      * Create a PKCS#10 Request from a file.
      * @param filename the name of the file containing the DER or PEM
      * encoded request file
      */
      explicit PKCS10_Request(const std::string& filename);
#endif

      /**
      * Create a PKCS#10 Request from binary data.
      * @param vec a std::vector containing the DER value
      */
      explicit PKCS10_Request(const std::vector<uint8_t>& vec);

      /**
      * Create a new PKCS10 certificate request
      * @param key the key that will be included in the certificate request
      * @param subject_dn the DN to be placed in the request
      * @param extensions extensions to include in the request
      * @param hash_fn the hash function to use to create the signature
      * @param rng a random number generator
      * @param padding_scheme if set specifies the padding scheme, otherwise an
      *        algorithm-specific default is used.
      * @param challenge a challenge string to be included in the PKCS10 request,
      *        sometimes used for revocation purposes.
      */
      static PKCS10_Request create(const Private_Key& key,
                                   const X509_DN& subject_dn,
                                   const Extensions& extensions,
                                   const std::string& hash_fn,
                                   RandomNumberGenerator& rng,
                                   const std::string& padding_scheme = "",
                                   const std::string& challenge = "");

   private:
      std::string PEM_label() const override;

      std::vector<std::string> alternate_PEM_labels() const override;

      void force_decode() override;

      const PKCS10_Data& data() const;

      std::shared_ptr<PKCS10_Data> m_data;
   };

}

namespace Botan {

class RandomNumberGenerator;

/**
* PKCS #8 General Exception
*/
class BOTAN_PUBLIC_API(2,0) PKCS8_Exception final : public Decoding_Error
   {
   public:
      explicit PKCS8_Exception(const std::string& error) :
         Decoding_Error("PKCS #8: " + error) {}
   };

/**
* This namespace contains functions for handling PKCS #8 private keys
*/
namespace PKCS8 {

/**
* BER encode a private key
* @param key the private key to encode
* @return BER encoded key
*/
inline secure_vector<uint8_t> BER_encode(const Private_Key& key)
   {
   return key.private_key_info();
   }

/**
* Get a string containing a PEM encoded private key.
* @param key the key to encode
* @return encoded key
*/
BOTAN_PUBLIC_API(2,0) std::string PEM_encode(const Private_Key& key);

/**
* Encrypt a key using PKCS #8 encryption
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param msec number of milliseconds to run the password derivation
* @param pbe_algo the name of the desired password-based encryption
*        algorithm; if empty ("") a reasonable (portable/secure)
*        default will be chosen.
* @return encrypted key in binary BER form
*/
BOTAN_PUBLIC_API(2,0) std::vector<uint8_t>
BER_encode(const Private_Key& key,
           RandomNumberGenerator& rng,
           const std::string& pass,
           std::chrono::milliseconds msec = std::chrono::milliseconds(300),
           const std::string& pbe_algo = "");

/**
* Get a string containing a PEM encoded private key, encrypting it with a
* password.
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param msec number of milliseconds to run the password derivation
* @param pbe_algo the name of the desired password-based encryption
*        algorithm; if empty ("") a reasonable (portable/secure)
*        default will be chosen.
* @return encrypted key in PEM form
*/
BOTAN_PUBLIC_API(2,0) std::string
PEM_encode(const Private_Key& key,
           RandomNumberGenerator& rng,
           const std::string& pass,
           std::chrono::milliseconds msec = std::chrono::milliseconds(300),
           const std::string& pbe_algo = "");

/**
* Encrypt a key using PKCS #8 encryption and a fixed iteration count
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param pbkdf_iter number of interations to run PBKDF2
* @param cipher if non-empty specifies the cipher to use. CBC and GCM modes
*   are supported, for example "AES-128/CBC", "AES-256/GCM", "Serpent/CBC".
*   If empty a suitable default is chosen.
* @param pbkdf_hash if non-empty specifies the PBKDF hash function to use.
*   For example "SHA-256" or "SHA-384". If empty a suitable default is chosen.
* @return encrypted key in binary BER form
*/
BOTAN_PUBLIC_API(2,1) std::vector<uint8_t>
BER_encode_encrypted_pbkdf_iter(const Private_Key& key,
                                RandomNumberGenerator& rng,
                                const std::string& pass,
                                size_t pbkdf_iter,
                                const std::string& cipher = "",
                                const std::string& pbkdf_hash = "");

/**
* Get a string containing a PEM encoded private key, encrypting it with a
* password.
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param pbkdf_iter number of iterations to run PBKDF
* @param cipher if non-empty specifies the cipher to use. CBC and GCM modes
*   are supported, for example "AES-128/CBC", "AES-256/GCM", "Serpent/CBC".
*   If empty a suitable default is chosen.
* @param pbkdf_hash if non-empty specifies the PBKDF hash function to use.
*   For example "SHA-256" or "SHA-384". If empty a suitable default is chosen.
* @return encrypted key in PEM form
*/
BOTAN_PUBLIC_API(2,1) std::string
PEM_encode_encrypted_pbkdf_iter(const Private_Key& key,
                                RandomNumberGenerator& rng,
                                const std::string& pass,
                                size_t pbkdf_iter,
                                const std::string& cipher = "",
                                const std::string& pbkdf_hash = "");

/**
* Encrypt a key using PKCS #8 encryption and a variable iteration count
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param pbkdf_msec how long to run PBKDF2
* @param pbkdf_iterations if non-null, set to the number of iterations used
* @param cipher if non-empty specifies the cipher to use. CBC and GCM modes
*   are supported, for example "AES-128/CBC", "AES-256/GCM", "Serpent/CBC".
*   If empty a suitable default is chosen.
* @param pbkdf_hash if non-empty specifies the PBKDF hash function to use.
*   For example "SHA-256" or "SHA-384". If empty a suitable default is chosen.
* @return encrypted key in binary BER form
*/
BOTAN_PUBLIC_API(2,1) std::vector<uint8_t>
BER_encode_encrypted_pbkdf_msec(const Private_Key& key,
                                RandomNumberGenerator& rng,
                                const std::string& pass,
                                std::chrono::milliseconds pbkdf_msec,
                                size_t* pbkdf_iterations,
                                const std::string& cipher = "",
                                const std::string& pbkdf_hash = "");

/**
* Get a string containing a PEM encoded private key, encrypting it with a
* password.
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param pbkdf_msec how long in milliseconds to run PBKDF2
* @param pbkdf_iterations (output argument) number of iterations of PBKDF
*  that ended up being used
* @param cipher if non-empty specifies the cipher to use. CBC and GCM modes
*   are supported, for example "AES-128/CBC", "AES-256/GCM", "Serpent/CBC".
*   If empty a suitable default is chosen.
* @param pbkdf_hash if non-empty specifies the PBKDF hash function to use.
*   For example "SHA-256" or "SHA-384". If empty a suitable default is chosen.
* @return encrypted key in PEM form
*/
BOTAN_PUBLIC_API(2,1) std::string
PEM_encode_encrypted_pbkdf_msec(const Private_Key& key,
                                RandomNumberGenerator& rng,
                                const std::string& pass,
                                std::chrono::milliseconds pbkdf_msec,
                                size_t* pbkdf_iterations,
                                const std::string& cipher = "",
                                const std::string& pbkdf_hash = "");

/**
* Load an encrypted key from a data source.
* @param source the data source providing the encoded key
* @param get_passphrase a function that returns passphrases
* @return loaded private key object
*/
BOTAN_PUBLIC_API(2,3)
std::unique_ptr<Private_Key> load_key(DataSource& source,
                                      const std::function<std::string ()>& get_passphrase);

/** Load an encrypted key from a data source.
* @param source the data source providing the encoded key
* @param pass the passphrase to decrypt the key
* @return loaded private key object
*/
BOTAN_PUBLIC_API(2,3)
std::unique_ptr<Private_Key> load_key(DataSource& source,
                                      const std::string& pass);

/** Load an unencrypted key from a data source.
* @param source the data source providing the encoded key
* @return loaded private key object
*/
BOTAN_PUBLIC_API(2,3)
std::unique_ptr<Private_Key> load_key(DataSource& source);

/**
* Copy an existing encoded key object.
* @param key the key to copy
* @return new copy of the key
*/
inline std::unique_ptr<Private_Key> copy_key(const Private_Key& key)
   {
   DataSource_Memory source(key.private_key_info());
   return PKCS8::load_key(source);
   }

// Deprecated functions follow

/**
* Load an encrypted key from a data source.
* @param source the data source providing the encoded key
* @param rng ignored for compatibility
* @param get_passphrase a function that returns passphrases
* @return loaded private key object
*/
BOTAN_DEPRECATED("Use version that doesn't take an RNG")
inline Private_Key* load_key(DataSource& source,
                             RandomNumberGenerator& rng,
                             std::function<std::string ()> get_passphrase)
   {
   BOTAN_UNUSED(rng);
   return PKCS8::load_key(source, get_passphrase).release();
   }

/** Load an encrypted key from a data source.
* @param source the data source providing the encoded key
* @param rng ignored for compatibility
* @param pass the passphrase to decrypt the key
* @return loaded private key object
*/
BOTAN_DEPRECATED("Use version that doesn't take an RNG")
inline Private_Key* load_key(DataSource& source,
                             RandomNumberGenerator& rng,
                             const std::string& pass)
   {
   BOTAN_UNUSED(rng);
   return PKCS8::load_key(source, pass).release();
   }

/** Load an unencrypted key from a data source.
* @param source the data source providing the encoded key
* @param rng ignored for compatibility
* @return loaded private key object
*/
BOTAN_DEPRECATED("Use version that doesn't take an RNG")
inline Private_Key* load_key(DataSource& source,
                             RandomNumberGenerator& rng)
   {
   BOTAN_UNUSED(rng);
   return PKCS8::load_key(source).release();
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
/**
* Load an encrypted key from a file.
* @param filename the path to the file containing the encoded key
* @param rng ignored for compatibility
* @param get_passphrase a function that returns passphrases
* @return loaded private key object
*/
BOTAN_DEPRECATED("Use DataSource_Stream and another load_key variant")
inline Private_Key* load_key(const std::string& filename,
                             RandomNumberGenerator& rng,
                             std::function<std::string ()> get_passphrase)
   {
   BOTAN_UNUSED(rng);
   DataSource_Stream in(filename);
   return PKCS8::load_key(in, get_passphrase).release();
   }

/** Load an encrypted key from a file.
* @param filename the path to the file containing the encoded key
* @param rng ignored for compatibility
* @param pass the passphrase to decrypt the key
* @return loaded private key object
*/
BOTAN_DEPRECATED("Use DataSource_Stream and another load_key variant")
inline Private_Key* load_key(const std::string& filename,
                             RandomNumberGenerator& rng,
                             const std::string& pass)
   {
   BOTAN_UNUSED(rng);
   DataSource_Stream in(filename);
   // We need to use bind rather than a lambda capturing `pass` here in order to avoid a Clang 8 bug.
   // See https://github.com/randombit/botan/issues/2255.
   return PKCS8::load_key(in, std::bind([](const std::string p) { return p; }, pass)).release();
   }

/** Load an unencrypted key from a file.
* @param filename the path to the file containing the encoded key
* @param rng ignored for compatibility
* @return loaded private key object
*/
BOTAN_DEPRECATED("Use DataSource_Stream and another load_key variant")
inline Private_Key* load_key(const std::string& filename,
                             RandomNumberGenerator& rng)
   {
   BOTAN_UNUSED(rng);
   DataSource_Stream in(filename);
   return PKCS8::load_key(in).release();
   }
#endif

/**
* Copy an existing encoded key object.
* @param key the key to copy
* @param rng ignored for compatibility
* @return new copy of the key
*/
BOTAN_DEPRECATED("Use version that doesn't take an RNG")
inline Private_Key* copy_key(const Private_Key& key,
                             RandomNumberGenerator& rng)
   {
   BOTAN_UNUSED(rng);
   return PKCS8::copy_key(key).release();
   }

}

}

namespace Botan {

class RandomNumberGenerator;

/**
* Public Key Encryptor
* This is the primary interface for public key encryption
*/
class BOTAN_PUBLIC_API(2,0) PK_Encryptor
   {
   public:

      /**
      * Encrypt a message.
      * @param in the message as a byte array
      * @param length the length of the above byte array
      * @param rng the random number source to use
      * @return encrypted message
      */
      std::vector<uint8_t> encrypt(const uint8_t in[], size_t length,
                                 RandomNumberGenerator& rng) const
         {
         return enc(in, length, rng);
         }

      /**
      * Encrypt a message.
      * @param in the message
      * @param rng the random number source to use
      * @return encrypted message
      */
      template<typename Alloc>
      std::vector<uint8_t> encrypt(const std::vector<uint8_t, Alloc>& in,
                                RandomNumberGenerator& rng) const
         {
         return enc(in.data(), in.size(), rng);
         }

      /**
      * Return the maximum allowed message size in bytes.
      * @return maximum message size in bytes
      */
      virtual size_t maximum_input_size() const = 0;

      /**
      * Return an upper bound on the ciphertext length
      */
      virtual size_t ciphertext_length(size_t ctext_len) const = 0;

      PK_Encryptor() = default;
      virtual ~PK_Encryptor() = default;

      PK_Encryptor(const PK_Encryptor&) = delete;
      PK_Encryptor(PK_Encryptor&&) noexcept = delete;
      PK_Encryptor& operator=(const PK_Encryptor&) = delete;
      PK_Encryptor& operator=(PK_Encryptor&&) noexcept = delete;

   private:
      virtual std::vector<uint8_t> enc(const uint8_t[], size_t,
                                    RandomNumberGenerator&) const = 0;
   };

/**
* Public Key Decryptor
*/
class BOTAN_PUBLIC_API(2,0) PK_Decryptor
   {
   public:
      /**
      * Decrypt a ciphertext, throwing an exception if the input
      * seems to be invalid (eg due to an accidental or malicious
      * error in the ciphertext).
      *
      * @param in the ciphertext as a byte array
      * @param length the length of the above byte array
      * @return decrypted message
      */
      secure_vector<uint8_t> decrypt(const uint8_t in[], size_t length) const;

      /**
      * Same as above, but taking a vector
      * @param in the ciphertext
      * @return decrypted message
      */
      template<typename Alloc>
      secure_vector<uint8_t> decrypt(const std::vector<uint8_t, Alloc>& in) const
         {
         return decrypt(in.data(), in.size());
         }

      /**
      * Decrypt a ciphertext. If the ciphertext is invalid (eg due to
      * invalid padding) or is not the expected length, instead
      * returns a random string of the expected length. Use to avoid
      * oracle attacks, especially against PKCS #1 v1.5 decryption.
      */
      secure_vector<uint8_t>
      decrypt_or_random(const uint8_t in[],
                        size_t length,
                        size_t expected_pt_len,
                        RandomNumberGenerator& rng) const;

      /**
      * Decrypt a ciphertext. If the ciphertext is invalid (eg due to
      * invalid padding) or is not the expected length, instead
      * returns a random string of the expected length. Use to avoid
      * oracle attacks, especially against PKCS #1 v1.5 decryption.
      *
      * Additionally checks (also in const time) that:
      *    contents[required_content_offsets[i]] == required_content_bytes[i]
      * for 0 <= i < required_contents
      *
      * Used for example in TLS, which encodes the client version in
      * the content bytes: if there is any timing variation the version
      * check can be used as an oracle to recover the key.
      */
      secure_vector<uint8_t>
      decrypt_or_random(const uint8_t in[],
                        size_t length,
                        size_t expected_pt_len,
                        RandomNumberGenerator& rng,
                        const uint8_t required_content_bytes[],
                        const uint8_t required_content_offsets[],
                        size_t required_contents) const;

      /**
      * Return an upper bound on the plaintext length for a particular
      * ciphertext input length
      */
      virtual size_t plaintext_length(size_t ctext_len) const = 0;

      PK_Decryptor() = default;
      virtual ~PK_Decryptor() = default;

      PK_Decryptor(const PK_Decryptor&) = delete;
      PK_Decryptor(PK_Decryptor&&) noexcept = delete;
      PK_Decryptor& operator=(const PK_Decryptor&) = delete;
      PK_Decryptor& operator=(PK_Decryptor&&) noexcept = delete;

   private:
      virtual secure_vector<uint8_t> do_decrypt(uint8_t& valid_mask,
                                             const uint8_t in[], size_t in_len) const = 0;
   };

/**
* Public Key Signer. Use the sign_message() functions for small
* messages. Use multiple calls update() to process large messages and
* generate the signature by finally calling signature().
*/
class BOTAN_PUBLIC_API(2,0) PK_Signer final
   {
   public:

      /**
      * Construct a PK Signer.
      * @param key the key to use inside this signer
      * @param rng the random generator to use
      * @param emsa the EMSA to use
      * An example would be "EMSA1(SHA-224)".
      * @param format the signature format to use
      * @param provider the provider to use
      */
      PK_Signer(const Private_Key& key,
                RandomNumberGenerator& rng,
                const std::string& emsa,
                Signature_Format format = IEEE_1363,
                const std::string& provider = "");

      ~PK_Signer();

      PK_Signer(const PK_Signer&) = delete;
      PK_Signer(PK_Signer&&) noexcept = delete;
      PK_Signer& operator=(const PK_Signer&) = delete;
      PK_Signer& operator=(PK_Signer&&) noexcept = delete;

      /**
      * Sign a message all in one go
      * @param in the message to sign as a byte array
      * @param length the length of the above byte array
      * @param rng the rng to use
      * @return signature
      */
      std::vector<uint8_t> sign_message(const uint8_t in[], size_t length,
                                     RandomNumberGenerator& rng)
         {
         this->update(in, length);
         return this->signature(rng);
         }

      /**
      * Sign a message.
      * @param in the message to sign
      * @param rng the rng to use
      * @return signature
      */
      template<typename Alloc>
         std::vector<uint8_t> sign_message(const std::vector<uint8_t, Alloc>& in,
                                           RandomNumberGenerator& rng)
         {
         return sign_message(in.data(), in.size(), rng);
         }

      /**
      * Add a message part (single byte).
      * @param in the byte to add
      */
      void update(uint8_t in) { update(&in, 1); }

      /**
      * Add a message part.
      * @param in the message part to add as a byte array
      * @param length the length of the above byte array
      */
      void update(const uint8_t in[], size_t length);

      /**
      * Add a message part.
      * @param in the message part to add
      */
      template<typename Alloc>
      void update(const std::vector<uint8_t, Alloc>& in)
         {
         update(in.data(), in.size());
         }

      /**
      * Add a message part.
      * @param in the message part to add
      */
      void update(const std::string& in)
         {
         update(cast_char_ptr_to_uint8(in.data()), in.size());
         }

      /**
      * Get the signature of the so far processed message (provided by the
      * calls to update()).
      * @param rng the rng to use
      * @return signature of the total message
      */
      std::vector<uint8_t> signature(RandomNumberGenerator& rng);


      /**
      * Set the output format of the signature.
      * @param format the signature format to use
      */
      void set_output_format(Signature_Format format) { m_sig_format = format; }

      /**
      * Return an upper bound on the length of the signatures this
      * PK_Signer will produce
      */
      size_t signature_length() const;

   private:
      std::unique_ptr<PK_Ops::Signature> m_op;
      Signature_Format m_sig_format;
      size_t m_parts, m_part_size;
   };

/**
* Public Key Verifier. Use the verify_message() functions for small
* messages. Use multiple calls update() to process large messages and
* verify the signature by finally calling check_signature().
*/
class BOTAN_PUBLIC_API(2,0) PK_Verifier final
   {
   public:
      /**
      * Construct a PK Verifier.
      * @param pub_key the public key to verify against
      * @param emsa the EMSA to use (eg "EMSA3(SHA-1)")
      * @param format the signature format to use
      * @param provider the provider to use
      */
      PK_Verifier(const Public_Key& pub_key,
                  const std::string& emsa,
                  Signature_Format format = IEEE_1363,
                  const std::string& provider = "");

      ~PK_Verifier();

      PK_Verifier(const PK_Verifier&) = delete;
      PK_Verifier(PK_Verifier&&) noexcept = delete;
      PK_Verifier& operator=(const PK_Verifier&) = delete;
      PK_Verifier& operator=(PK_Verifier&&) noexcept = delete;

      /**
      * Verify a signature.
      * @param msg the message that the signature belongs to, as a byte array
      * @param msg_length the length of the above byte array msg
      * @param sig the signature as a byte array
      * @param sig_length the length of the above byte array sig
      * @return true if the signature is valid
      */
      bool verify_message(const uint8_t msg[], size_t msg_length,
                          const uint8_t sig[], size_t sig_length);
      /**
      * Verify a signature.
      * @param msg the message that the signature belongs to
      * @param sig the signature
      * @return true if the signature is valid
      */
      template<typename Alloc, typename Alloc2>
      bool verify_message(const std::vector<uint8_t, Alloc>& msg,
                          const std::vector<uint8_t, Alloc2>& sig)
         {
         return verify_message(msg.data(), msg.size(),
                               sig.data(), sig.size());
         }

      /**
      * Add a message part (single byte) of the message corresponding to the
      * signature to be verified.
      * @param in the byte to add
      */
      void update(uint8_t in) { update(&in, 1); }

      /**
      * Add a message part of the message corresponding to the
      * signature to be verified.
      * @param msg_part the new message part as a byte array
      * @param length the length of the above byte array
      */
      void update(const uint8_t msg_part[], size_t length);

      /**
      * Add a message part of the message corresponding to the
      * signature to be verified.
      * @param in the new message part
      */
      template<typename Alloc>
         void update(const std::vector<uint8_t, Alloc>& in)
         {
         update(in.data(), in.size());
         }

      /**
      * Add a message part of the message corresponding to the
      * signature to be verified.
      */
      void update(const std::string& in)
         {
         update(cast_char_ptr_to_uint8(in.data()), in.size());
         }

      /**
      * Check the signature of the buffered message, i.e. the one build
      * by successive calls to update.
      * @param sig the signature to be verified as a byte array
      * @param length the length of the above byte array
      * @return true if the signature is valid, false otherwise
      */
      bool check_signature(const uint8_t sig[], size_t length);

      /**
      * Check the signature of the buffered message, i.e. the one build
      * by successive calls to update.
      * @param sig the signature to be verified
      * @return true if the signature is valid, false otherwise
      */
      template<typename Alloc>
      bool check_signature(const std::vector<uint8_t, Alloc>& sig)
         {
         return check_signature(sig.data(), sig.size());
         }

      /**
      * Set the format of the signatures fed to this verifier.
      * @param format the signature format to use
      */
      void set_input_format(Signature_Format format);

   private:
      std::unique_ptr<PK_Ops::Verification> m_op;
      Signature_Format m_sig_format;
      size_t m_parts, m_part_size;
   };

/**
* Object used for key agreement
*/
class BOTAN_PUBLIC_API(2,0) PK_Key_Agreement final
   {
   public:

      /**
      * Construct a PK Key Agreement.
      * @param key the key to use
      * @param rng the random generator to use
      * @param kdf name of the KDF to use (or 'Raw' for no KDF)
      * @param provider the algo provider to use (or empty for default)
      */
      PK_Key_Agreement(const Private_Key& key,
                       RandomNumberGenerator& rng,
                       const std::string& kdf,
                       const std::string& provider = "");

      ~PK_Key_Agreement();

      PK_Key_Agreement(const PK_Key_Agreement&) = delete;
      PK_Key_Agreement& operator=(const PK_Key_Agreement&) = delete;
      PK_Key_Agreement& operator=(PK_Key_Agreement&&) = delete;

      // For ECIES
      PK_Key_Agreement(PK_Key_Agreement&&) noexcept;

      /**
      * Perform Key Agreement Operation
      * @param key_len the desired key output size (ignored if "Raw" KDF is used)
      * @param in the other parties key
      * @param in_len the length of in in bytes
      * @param params extra derivation params
      * @param params_len the length of params in bytes
      */
      SymmetricKey derive_key(size_t key_len,
                              const uint8_t in[],
                              size_t in_len,
                              const uint8_t params[],
                              size_t params_len) const;

      /**
      * Perform Key Agreement Operation
      * @param key_len the desired key output size (ignored if "Raw" KDF is used)
      * @param in the other parties key
      * @param params extra derivation params
      * @param params_len the length of params in bytes
      */
      SymmetricKey derive_key(size_t key_len,
                              const std::vector<uint8_t>& in,
                              const uint8_t params[],
                              size_t params_len) const
         {
         return derive_key(key_len, in.data(), in.size(),
                           params, params_len);
         }

      /**
      * Perform Key Agreement Operation
      * @param key_len the desired key output size (ignored if "Raw" KDF is used)
      * @param in the other parties key
      * @param in_len the length of in in bytes
      * @param params extra derivation params
      */
      SymmetricKey derive_key(size_t key_len,
                              const uint8_t in[], size_t in_len,
                              const std::string& params = "") const
         {
         return derive_key(key_len, in, in_len,
                           cast_char_ptr_to_uint8(params.data()),
                           params.length());
         }

      /**
      * Perform Key Agreement Operation
      * @param key_len the desired key output size (ignored if "Raw" KDF is used)
      * @param in the other parties key
      * @param params extra derivation params
      */
      SymmetricKey derive_key(size_t key_len,
                              const std::vector<uint8_t>& in,
                              const std::string& params = "") const
         {
         return derive_key(key_len, in.data(), in.size(),
                           cast_char_ptr_to_uint8(params.data()),
                           params.length());
         }

      /**
      * Return the underlying size of the value that is agreed.
      * If derive_key is called with a length of 0 with a "Raw"
      * KDF, it will return a value of this size.
      */
      size_t agreed_value_size() const;

   private:
      std::unique_ptr<PK_Ops::Key_Agreement> m_op;
   };

/**
* Encryption using a standard message recovery algorithm like RSA or
* ElGamal, paired with an encoding scheme like OAEP.
*/
class BOTAN_PUBLIC_API(2,0) PK_Encryptor_EME final : public PK_Encryptor
   {
   public:
      size_t maximum_input_size() const override;

      /**
      * Construct an instance.
      * @param key the key to use inside the encryptor
      * @param rng the RNG to use
      * @param padding the message encoding scheme to use (eg "OAEP(SHA-256)")
      * @param provider the provider to use
      */
      PK_Encryptor_EME(const Public_Key& key,
                       RandomNumberGenerator& rng,
                       const std::string& padding,
                       const std::string& provider = "");

      ~PK_Encryptor_EME();

      PK_Encryptor_EME(const PK_Encryptor_EME&) = delete;
      PK_Encryptor_EME(PK_Encryptor_EME&&) = delete;
      PK_Encryptor_EME& operator=(const PK_Encryptor_EME&) = delete;
      PK_Encryptor_EME& operator=(PK_Encryptor_EME&&) = delete;

      /**
      * Return an upper bound on the ciphertext length for a particular
      * plaintext input length
      */
      size_t ciphertext_length(size_t ptext_len) const override;
   private:
      std::vector<uint8_t> enc(const uint8_t[], size_t,
                             RandomNumberGenerator& rng) const override;

      std::unique_ptr<PK_Ops::Encryption> m_op;
   };

/**
* Decryption with an MR algorithm and an EME.
*/
class BOTAN_PUBLIC_API(2,0) PK_Decryptor_EME final : public PK_Decryptor
   {
   public:
     /**
      * Construct an instance.
      * @param key the key to use inside the decryptor
      * @param rng the random generator to use
      * @param eme the EME to use
      * @param provider the provider to use
      */
      PK_Decryptor_EME(const Private_Key& key,
                       RandomNumberGenerator& rng,
                       const std::string& eme,
                       const std::string& provider = "");

      size_t plaintext_length(size_t ptext_len) const override;

      ~PK_Decryptor_EME();
      PK_Decryptor_EME(const PK_Decryptor_EME&) = delete;
      PK_Decryptor_EME(PK_Decryptor_EME&&) = delete;
      PK_Decryptor_EME& operator=(const PK_Decryptor_EME&) = delete;
      PK_Decryptor_EME& operator=(PK_Decryptor_EME&&) = delete;
   private:
      secure_vector<uint8_t> do_decrypt(uint8_t& valid_mask,
                                     const uint8_t in[],
                                     size_t in_len) const override;

      std::unique_ptr<PK_Ops::Decryption> m_op;
   };

/**
* Public Key Key Encapsulation Mechanism Encryption.
*/
class BOTAN_PUBLIC_API(2,0) PK_KEM_Encryptor final
   {
   public:
      /**
      * Construct an instance.
      * @param key the key to use inside the encryptor
      * @param rng the RNG to use
      * @param kem_param additional KEM parameters
      * @param provider the provider to use
      */
      PK_KEM_Encryptor(const Public_Key& key,
                       RandomNumberGenerator& rng,
                       const std::string& kem_param = "",
                       const std::string& provider = "");

      ~PK_KEM_Encryptor();

      PK_KEM_Encryptor(const PK_KEM_Encryptor&) = delete;
      PK_KEM_Encryptor(PK_KEM_Encryptor&&) = delete;
      PK_KEM_Encryptor& operator=(const PK_KEM_Encryptor&) = delete;
      PK_KEM_Encryptor& operator=(PK_KEM_Encryptor&&) = delete;

      /**
      * Generate a shared key for data encryption.
      * @param out_encapsulated_key the generated encapsulated key
      * @param out_shared_key the generated shared key
      * @param desired_shared_key_len desired size of the shared key in bytes
      * @param rng the RNG to use
      * @param salt a salt value used in the KDF
      * @param salt_len size of the salt value in bytes
      */
      void encrypt(secure_vector<uint8_t>& out_encapsulated_key,
                   secure_vector<uint8_t>& out_shared_key,
                   size_t desired_shared_key_len,
                   Botan::RandomNumberGenerator& rng,
                   const uint8_t salt[],
                   size_t salt_len);

      /**
      * Generate a shared key for data encryption.
      * @param out_encapsulated_key the generated encapsulated key
      * @param out_shared_key the generated shared key
      * @param desired_shared_key_len desired size of the shared key in bytes
      * @param rng the RNG to use
      * @param salt a salt value used in the KDF
      */
      template<typename Alloc>
         void encrypt(secure_vector<uint8_t>& out_encapsulated_key,
                      secure_vector<uint8_t>& out_shared_key,
                      size_t desired_shared_key_len,
                      Botan::RandomNumberGenerator& rng,
                      const std::vector<uint8_t, Alloc>& salt)
         {
         this->encrypt(out_encapsulated_key,
                       out_shared_key,
                       desired_shared_key_len,
                       rng,
                       salt.data(), salt.size());
         }


      /**
      * Generate a shared key for data encryption.
      * @param out_encapsulated_key the generated encapsulated key
      * @param out_shared_key the generated shared key
      * @param desired_shared_key_len desired size of the shared key in bytes
      * @param rng the RNG to use
      */
      void encrypt(secure_vector<uint8_t>& out_encapsulated_key,
                   secure_vector<uint8_t>& out_shared_key,
                   size_t desired_shared_key_len,
                   Botan::RandomNumberGenerator& rng)
         {
         this->encrypt(out_encapsulated_key,
                       out_shared_key,
                       desired_shared_key_len,
                       rng,
                       nullptr,
                       0);
         }

   private:
      std::unique_ptr<PK_Ops::KEM_Encryption> m_op;
   };

/**
* Public Key Key Encapsulation Mechanism Decryption.
*/
class BOTAN_PUBLIC_API(2,0) PK_KEM_Decryptor final
   {
   public:
      /**
      * Construct an instance.
      * @param key the key to use inside the decryptor
      * @param rng the RNG to use
      * @param kem_param additional KEM parameters
      * @param provider the provider to use
      */
      PK_KEM_Decryptor(const Private_Key& key,
                       RandomNumberGenerator& rng,
                       const std::string& kem_param = "",
                       const std::string& provider = "");

      ~PK_KEM_Decryptor();
      PK_KEM_Decryptor(const PK_KEM_Decryptor&) = delete;
      PK_KEM_Decryptor(PK_KEM_Decryptor&&) = delete;
      PK_KEM_Decryptor& operator=(const PK_KEM_Decryptor&) = delete;
      PK_KEM_Decryptor& operator=(PK_KEM_Decryptor&&) = delete;

      /**
      * Decrypts the shared key for data encryption.
      * @param encap_key the encapsulated key
      * @param encap_key_len size of the encapsulated key in bytes
      * @param desired_shared_key_len desired size of the shared key in bytes
      * @param salt a salt value used in the KDF
      * @param salt_len size of the salt value in bytes
      * @return the shared data encryption key
      */
      secure_vector<uint8_t> decrypt(const uint8_t encap_key[],
                                  size_t encap_key_len,
                                  size_t desired_shared_key_len,
                                  const uint8_t salt[],
                                  size_t salt_len);

      /**
      * Decrypts the shared key for data encryption.
      * @param encap_key the encapsulated key
      * @param encap_key_len size of the encapsulated key in bytes
      * @param desired_shared_key_len desired size of the shared key in bytes
      * @return the shared data encryption key
      */
      secure_vector<uint8_t> decrypt(const uint8_t encap_key[],
                                  size_t encap_key_len,
                                  size_t desired_shared_key_len)
         {
         return this->decrypt(encap_key, encap_key_len,
                              desired_shared_key_len,
                              nullptr, 0);
         }

      /**
      * Decrypts the shared key for data encryption.
      * @param encap_key the encapsulated key
      * @param desired_shared_key_len desired size of the shared key in bytes
      * @param salt a salt value used in the KDF
      * @return the shared data encryption key
      */
      template<typename Alloc1, typename Alloc2>
         secure_vector<uint8_t> decrypt(const std::vector<uint8_t, Alloc1>& encap_key,
                                     size_t desired_shared_key_len,
                                     const std::vector<uint8_t, Alloc2>& salt)
         {
         return this->decrypt(encap_key.data(), encap_key.size(),
                              desired_shared_key_len,
                              salt.data(), salt.size());
         }

   private:
      std::unique_ptr<PK_Ops::KEM_Decryption> m_op;
   };

}

namespace Botan {

/**
* Modular Reducer (using Barrett's technique)
*/
class BOTAN_PUBLIC_API(2,0) Modular_Reducer
   {
   public:
      const BigInt& get_modulus() const { return m_modulus; }

      BigInt reduce(const BigInt& x) const;

      /**
      * Multiply mod p
      * @param x the first operand
      * @param y the second operand
      * @return (x * y) % p
      */
      BigInt multiply(const BigInt& x, const BigInt& y) const
         { return reduce(x * y); }

      /**
      * Multiply mod p
      * @return (x * y * z) % p
      */
      BigInt multiply(const BigInt& x, const BigInt& y, const BigInt& z) const
         { return multiply(x, multiply(y, z)); }

      /**
      * Square mod p
      * @param x the value to square
      * @return (x * x) % p
      */
      BigInt square(const BigInt& x) const
         { return reduce(Botan::square(x)); }

      /**
      * Cube mod p
      * @param x the value to cube
      * @return (x * x * x) % p
      */
      BigInt cube(const BigInt& x) const
         { return multiply(x, this->square(x)); }

      /**
      * Low level reduction function. Mostly for internal use.
      * Sometimes useful for performance by reducing temporaries
      * Reduce x mod p and place the output in out. ** X and out must not reference each other **
      * ws is a temporary workspace.
      */
      void reduce(BigInt& out, const BigInt& x, secure_vector<word>& ws) const;

      bool initialized() const { return (m_mod_words != 0); }

      Modular_Reducer() { m_mod_words = 0; }
      explicit Modular_Reducer(const BigInt& mod);
   private:
      BigInt m_modulus, m_mu;
      size_t m_mod_words;
   };

}

namespace Botan {

class RSA_Public_Data;
class RSA_Private_Data;

/**
* RSA Public Key
*/
class BOTAN_PUBLIC_API(2,0) RSA_PublicKey : public virtual Public_Key
   {
   public:
      /**
      * Load a public key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits DER encoded public key bits
      */
      RSA_PublicKey(const AlgorithmIdentifier& alg_id,
                    const std::vector<uint8_t>& key_bits);

      /**
      * Create a public key.
      * @arg n the modulus
      * @arg e the exponent
      */
      RSA_PublicKey(const BigInt& n, const BigInt& e);

      std::string algo_name() const override { return "RSA"; }

      bool check_key(RandomNumberGenerator& rng, bool) const override;

      AlgorithmIdentifier algorithm_identifier() const override;

      std::vector<uint8_t> public_key_bits() const override;

      /**
      * @return public modulus
      */
      const BigInt& get_n() const;

      /**
      * @return public exponent
      */
      const BigInt& get_e() const;

      size_t key_length() const override;
      size_t estimated_strength() const override;

      // internal functions:
      std::shared_ptr<const RSA_Public_Data> public_data() const;

      std::unique_ptr<PK_Ops::Encryption>
         create_encryption_op(RandomNumberGenerator& rng,
                              const std::string& params,
                              const std::string& provider) const override;

      std::unique_ptr<PK_Ops::KEM_Encryption>
         create_kem_encryption_op(RandomNumberGenerator& rng,
                                  const std::string& params,
                                  const std::string& provider) const override;

      std::unique_ptr<PK_Ops::Verification>
         create_verification_op(const std::string& params,
                                const std::string& provider) const override;

   protected:
      RSA_PublicKey() = default;

      void init(BigInt&& n, BigInt&& e);

      std::shared_ptr<const RSA_Public_Data> m_public;
   };

/**
* RSA Private Key
*/
class BOTAN_PUBLIC_API(2,0) RSA_PrivateKey final : public Private_Key, public RSA_PublicKey
   {
   public:
      /**
      * Load a private key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits PKCS#1 RSAPrivateKey bits
      */
      RSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                     const secure_vector<uint8_t>& key_bits);

      /**
      * Construct a private key from the specified parameters.
      * @param p the first prime
      * @param q the second prime
      * @param e the exponent
      * @param d if specified, this has to be d with
      * exp * d = 1 mod (p - 1, q - 1). Leave it as 0 if you wish to
      * the constructor to calculate it.
      * @param n if specified, this must be n = p * q. Leave it as 0
      * if you wish to the constructor to calculate it.
      */
      RSA_PrivateKey(const BigInt& p, const BigInt& q, const BigInt& e,
                     const BigInt& d = BigInt::zero(),
                     const BigInt& n = BigInt::zero());

      /**
      * Create a new private key with the specified bit length
      * @param rng the random number generator to use
      * @param bits the desired bit length of the private key
      * @param exp the public exponent to be used
      */
      RSA_PrivateKey(RandomNumberGenerator& rng,
                     size_t bits, size_t exp = 65537);

      std::unique_ptr<Public_Key> public_key() const override;

      bool check_key(RandomNumberGenerator& rng, bool) const override;

      /**
      * Get the first prime p.
      * @return prime p
      */
      const BigInt& get_p() const;

      /**
      * Get the second prime q.
      * @return prime q
      */
      const BigInt& get_q() const;

      /**
      * Get d with exp * d = 1 mod (p - 1, q - 1).
      * @return d
      */
      const BigInt& get_d() const;

      const BigInt& get_c() const;
      const BigInt& get_d1() const;
      const BigInt& get_d2() const;

      secure_vector<uint8_t> private_key_bits() const override;

      // internal functions:
      std::shared_ptr<const RSA_Private_Data> private_data() const;

      std::unique_ptr<PK_Ops::Decryption>
         create_decryption_op(RandomNumberGenerator& rng,
                              const std::string& params,
                              const std::string& provider) const override;

      std::unique_ptr<PK_Ops::KEM_Decryption>
         create_kem_decryption_op(RandomNumberGenerator& rng,
                                  const std::string& params,
                                  const std::string& provider) const override;

      std::unique_ptr<PK_Ops::Signature>
         create_signature_op(RandomNumberGenerator& rng,
                             const std::string& params,
                             const std::string& provider) const override;

   private:

      void init(BigInt&& d, BigInt&& p, BigInt&& q, BigInt&& d1, BigInt&& d2, BigInt&& c);

      std::shared_ptr<const RSA_Private_Data> m_private;
   };

}

namespace Botan {

/**
* Base class for all stream ciphers
*/
class BOTAN_PUBLIC_API(2,0) StreamCipher : public SymmetricAlgorithm
   {
   public:
      virtual ~StreamCipher() = default;

      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to use
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<StreamCipher>
         create(const std::string& algo_spec,
                const std::string& provider = "");

      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to use
      * Throws a Lookup_Error if the algo/provider combination cannot be found
      */
      static std::unique_ptr<StreamCipher>
         create_or_throw(const std::string& algo_spec,
                         const std::string& provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      /**
      * Encrypt or decrypt a message
      * @param in the plaintext
      * @param out the byte array to hold the output, i.e. the ciphertext
      * @param len the length of both in and out in bytes
      */
      virtual void cipher(const uint8_t in[], uint8_t out[], size_t len) = 0;

      /**
      * Write keystream bytes to a buffer
      * @param out the byte array to hold the keystream
      * @param len the length of out in bytes
      */
      virtual void write_keystream(uint8_t out[], size_t len)
         {
         clear_mem(out, len);
         cipher1(out, len);
         }

      /**
      * Encrypt or decrypt a message
      * The message is encrypted/decrypted in place.
      * @param buf the plaintext / ciphertext
      * @param len the length of buf in bytes
      */
      void cipher1(uint8_t buf[], size_t len)
         { cipher(buf, buf, len); }

      /**
      * Encrypt a message
      * The message is encrypted/decrypted in place.
      * @param inout the plaintext / ciphertext
      */
      template<typename Alloc>
         void encipher(std::vector<uint8_t, Alloc>& inout)
         { cipher(inout.data(), inout.data(), inout.size()); }

      /**
      * Encrypt a message
      * The message is encrypted in place.
      * @param inout the plaintext / ciphertext
      */
      template<typename Alloc>
         void encrypt(std::vector<uint8_t, Alloc>& inout)
         { cipher(inout.data(), inout.data(), inout.size()); }

      /**
      * Decrypt a message in place
      * The message is decrypted in place.
      * @param inout the plaintext / ciphertext
      */
      template<typename Alloc>
         void decrypt(std::vector<uint8_t, Alloc>& inout)
         { cipher(inout.data(), inout.data(), inout.size()); }

      /**
      * Resync the cipher using the IV
      * @param iv the initialization vector
      * @param iv_len the length of the IV in bytes
      */
      virtual void set_iv(const uint8_t iv[], size_t iv_len) = 0;

      /**
      * Return the default (preferred) nonce length
      * If this function returns 0, then this cipher does not support nonces
      */
      virtual size_t default_iv_length() const { return 0; }

      /**
      * @param iv_len the length of the IV in bytes
      * @return if the length is valid for this algorithm
      */
      virtual bool valid_iv_length(size_t iv_len) const { return (iv_len == 0); }

      /**
      * @return a new object representing the same algorithm as *this
      */
      StreamCipher* clone() const
         {
         return this->new_object().release();
         }

      /**
      * @return new object representing the same algorithm as *this
      */
      virtual std::unique_ptr<StreamCipher> new_object() const = 0;

      /**
      * Set the offset and the state used later to generate the keystream
      * @param offset the offset where we begin to generate the keystream
      */
      virtual void seek(uint64_t offset) = 0;

      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2" or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }
   };

}

namespace Botan {

/**
* Return a shared reference to a global PRNG instance provided by the
* operating system. For instance might be instantiated by /dev/urandom
* or CryptGenRandom.
*/
BOTAN_PUBLIC_API(2,0) RandomNumberGenerator& system_rng();

/*
* Instantiable reference to the system RNG.
*/
class BOTAN_PUBLIC_API(2,0) System_RNG final : public RandomNumberGenerator
   {
   public:
      std::string name() const override { return system_rng().name(); }

      void randomize(uint8_t out[], size_t len) override { system_rng().randomize(out, len); }

      void add_entropy(const uint8_t in[], size_t length) override { system_rng().add_entropy(in, length); }

      bool is_seeded() const override { return system_rng().is_seeded(); }

      bool accepts_input() const override { return system_rng().accepts_input(); }

      void clear() override { system_rng().clear(); }
   };

}

namespace Botan {

/*
* Get information describing the version
*/

/**
* Get a human-readable string identifying the version of Botan.
* No particular format should be assumed.
* @return version string
*/
BOTAN_PUBLIC_API(2,0) std::string version_string();

/**
* Same as version_string() except returning a pointer to a statically
* allocated string.
* @return version string
*/
BOTAN_PUBLIC_API(2,0) const char* version_cstr();

/**
* Return a version string of the form "MAJOR.MINOR.PATCH" where
* each of the values is an integer.
*/
BOTAN_PUBLIC_API(2,4) std::string short_version_string();

/**
* Same as version_short_string except returning a pointer to the string.
*/
BOTAN_PUBLIC_API(2,4) const char* short_version_cstr();

/**
* Return the date this version of botan was released, in an integer of
* the form YYYYMMDD. For instance a version released on May 21, 2013
* would return the integer 20130521. If the currently running version
* is not an official release, this function will return 0 instead.
*
* @return release date, or zero if unreleased
*/
BOTAN_PUBLIC_API(2,0) uint32_t version_datestamp();

/**
* Get the major version number.
* @return major version number
*/
BOTAN_PUBLIC_API(2,0) uint32_t version_major();

/**
* Get the minor version number.
* @return minor version number
*/
BOTAN_PUBLIC_API(2,0) uint32_t version_minor();

/**
* Get the patch number.
* @return patch number
*/
BOTAN_PUBLIC_API(2,0) uint32_t version_patch();

/**
* Usable for checking that the DLL version loaded at runtime exactly
* matches the compile-time version. Call using BOTAN_VERSION_* macro
* values. Returns the empty string if an exact match, otherwise an
* appropriate message. Added with 1.11.26.
*/
BOTAN_PUBLIC_API(2,0) std::string
runtime_version_check(uint32_t major,
                      uint32_t minor,
                      uint32_t patch);

/*
* Macros for compile-time version checks
*/
#define BOTAN_VERSION_CODE_FOR(a,b,c) ((a << 16) | (b << 8) | (c))

/**
* Compare using BOTAN_VERSION_CODE_FOR, as in
*  # if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,8,0)
*  #    error "Botan version too old"
*  # endif
*/
#define BOTAN_VERSION_CODE BOTAN_VERSION_CODE_FOR(BOTAN_VERSION_MAJOR, \
                                                  BOTAN_VERSION_MINOR, \
                                                  BOTAN_VERSION_PATCH)

}

namespace Botan {

class RandomNumberGenerator;
class BigInt;
class Private_Key;
class PKCS10_Request;
class PK_Signer;

/**
* This class represents X.509 Certificate Authorities (CAs).
*/
class BOTAN_PUBLIC_API(2,0) X509_CA final
   {
   public:
      /**
      * Sign a PKCS#10 Request.
      * @param req the request to sign
      * @param rng the rng to use
      * @param not_before the starting time for the certificate
      * @param not_after the expiration time for the certificate
      * @return resulting certificate
      */
      X509_Certificate sign_request(const PKCS10_Request& req,
                                    RandomNumberGenerator& rng,
                                    const X509_Time& not_before,
                                    const X509_Time& not_after) const;

      /**
      * Sign a PKCS#10 Request.
      * @param req the request to sign
      * @param rng the rng to use
      * @param serial_number the serial number the cert will be assigned.
      * @param not_before the starting time for the certificate
      * @param not_after the expiration time for the certificate
      * @return resulting certificate
      */
      X509_Certificate sign_request(const PKCS10_Request& req,
                                    RandomNumberGenerator& rng,
                                    const BigInt& serial_number,
                                    const X509_Time& not_before,
                                    const X509_Time& not_after) const;

      /**
      * Get the certificate of this CA.
      * @return CA certificate
      */
      X509_Certificate ca_certificate() const;

      /**
      * Create a new and empty CRL for this CA.
      * @param rng the random number generator to use
      * @param issue_time the issue time (typically system_clock::now)
      * @param next_update the time interval after issue_data within which
      *        a new CRL will be produced.
      * @return new CRL
      */
      X509_CRL new_crl(RandomNumberGenerator& rng,
                       std::chrono::system_clock::time_point issue_time,
                       std::chrono::seconds next_update) const;

      /**
      * Create a new CRL by with additional entries.
      * @param last_crl the last CRL of this CA to add the new entries to
      * @param new_entries contains the new CRL entries to be added to the CRL
      * @param rng the random number generator to use
      * @param issue_time the issue time (typically system_clock::now)
      * @param next_update the time interval after issue_data within which
      *        a new CRL will be produced.
      */
      X509_CRL update_crl(const X509_CRL& last_crl,
                          const std::vector<CRL_Entry>& new_entries,
                          RandomNumberGenerator& rng,
                          std::chrono::system_clock::time_point issue_time,
                          std::chrono::seconds next_update) const;

      /**
      * Create a new and empty CRL for this CA.
      * @param rng the random number generator to use
      * @param next_update the time to set in next update in seconds
      * as the offset from the current time
      * @return new CRL
      */
      X509_CRL new_crl(RandomNumberGenerator& rng,
                       uint32_t next_update = 604800) const;

      /**
      * Create a new CRL by with additional entries.
      * @param last_crl the last CRL of this CA to add the new entries to
      * @param new_entries contains the new CRL entries to be added to the CRL
      * @param rng the random number generator to use
      * @param next_update the time to set in next update in seconds
      * as the offset from the current time
      */
      X509_CRL update_crl(const X509_CRL& last_crl,
                          const std::vector<CRL_Entry>& new_entries,
                          RandomNumberGenerator& rng,
                          uint32_t next_update = 604800) const;

      /**
      * Interface for creating new certificates
      * @param signer a signing object
      * @param rng a random number generator
      * @param sig_algo the signature algorithm identifier
      * @param pub_key the serialized public key
      * @param not_before the start time of the certificate
      * @param not_after the end time of the certificate
      * @param issuer_dn the DN of the issuer
      * @param subject_dn the DN of the subject
      * @param extensions an optional list of certificate extensions
      * @returns newly minted certificate
      */
      static X509_Certificate make_cert(PK_Signer* signer,
                                        RandomNumberGenerator& rng,
                                        const AlgorithmIdentifier& sig_algo,
                                        const std::vector<uint8_t>& pub_key,
                                        const X509_Time& not_before,
                                        const X509_Time& not_after,
                                        const X509_DN& issuer_dn,
                                        const X509_DN& subject_dn,
                                        const Extensions& extensions);

      /**
      * Interface for creating new certificates
      * @param signer a signing object
      * @param rng a random number generator
      * @param serial_number the serial number the cert will be assigned
      * @param sig_algo the signature algorithm identifier
      * @param pub_key the serialized public key
      * @param not_before the start time of the certificate
      * @param not_after the end time of the certificate
      * @param issuer_dn the DN of the issuer
      * @param subject_dn the DN of the subject
      * @param extensions an optional list of certificate extensions
      * @returns newly minted certificate
      */
      static X509_Certificate make_cert(PK_Signer* signer,
                                        RandomNumberGenerator& rng,
                                        const BigInt& serial_number,
                                        const AlgorithmIdentifier& sig_algo,
                                        const std::vector<uint8_t>& pub_key,
                                        const X509_Time& not_before,
                                        const X509_Time& not_after,
                                        const X509_DN& issuer_dn,
                                        const X509_DN& subject_dn,
                                        const Extensions& extensions);

      /**
      * Create a new CA object.
      * @param ca_certificate the certificate of the CA
      * @param key the private key of the CA
      * @param hash_fn name of a hash function to use for signing
      * @param rng the random generator to use
      */
      X509_CA(const X509_Certificate& ca_certificate,
              const Private_Key& key,
              const std::string& hash_fn,
              RandomNumberGenerator& rng);

      /**
      * Create a new CA object.
      * @param ca_certificate the certificate of the CA
      * @param key the private key of the CA
      * @param opts additional options, e.g. padding, as key value pairs
      * @param hash_fn name of a hash function to use for signing
      * @param rng the random generator to use
      */
      X509_CA(const X509_Certificate& ca_certificate,
              const Private_Key& key,
              const std::map<std::string,std::string>& opts,
              const std::string& hash_fn,
              RandomNumberGenerator& rng);

      X509_CA(const X509_CA&) = delete;
      X509_CA& operator=(const X509_CA&) = delete;

      X509_CA(X509_CA&&) = default;
      X509_CA& operator=(X509_CA&&) = default;

      ~X509_CA();

   private:
      X509_CRL make_crl(const std::vector<CRL_Entry>& entries,
                        uint32_t crl_number,
                        RandomNumberGenerator& rng,
                        std::chrono::system_clock::time_point issue_time,
                        std::chrono::seconds next_update) const;

      AlgorithmIdentifier m_ca_sig_algo;
      X509_Certificate m_ca_cert;
      std::string m_hash_fn;
      std::unique_ptr<PK_Signer> m_signer;
   };

/**
* Choose the default signature format for a certain public key signature
* scheme.
* @param key will be the key to choose a padding scheme for
* @param rng the random generator to use
* @param hash_fn is the desired hash function
* @param alg_id will be set to the chosen scheme
* @return A PK_Signer object for generating signatures
*/
BOTAN_PUBLIC_API(2,0) PK_Signer* choose_sig_format(const Private_Key& key,
                                       RandomNumberGenerator& rng,
                                       const std::string& hash_fn,
                                       AlgorithmIdentifier& alg_id);

/**
* @verbatim
* Choose the default signature format for a certain public key signature
* scheme.
*
* The only option recognized by opts at this moment is "padding"
* Find an entry from src/build-data/oids.txt under [signature] of the form
* <sig_algo>/<padding>[(<hash_algo>)] and add {"padding",<padding>}
* to opts.
* @endverbatim
*
* @param key will be the key to choose a padding scheme for
* @param opts contains additional options for building the certificate
* @param rng the random generator to use
* @param hash_fn is the desired hash function
* @param alg_id will be set to the chosen scheme
* @return A PK_Signer object for generating signatures
*/
PK_Signer* choose_sig_format(const Private_Key& key,
                             const std::map<std::string,std::string>& opts,
                             RandomNumberGenerator& rng,
                             const std::string& hash_fn,
                             AlgorithmIdentifier& alg_id);

}

namespace Botan {

class X509_Certificate;

namespace Cert_Extension {

static const size_t NO_CERT_PATH_LIMIT = 0xFFFFFFF0;

/**
* Basic Constraints Extension
*/
class BOTAN_PUBLIC_API(2,0) Basic_Constraints final : public Certificate_Extension
   {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<Basic_Constraints>(m_is_ca, m_path_limit); }

      Basic_Constraints(bool ca = false, size_t limit = 0) :
         m_is_ca(ca), m_path_limit(limit) {}

      bool get_is_ca() const { return m_is_ca; }
      size_t get_path_limit() const;

      static OID static_oid() { return OID("2.5.29.19"); }
      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override
         { return "X509v3.BasicConstraints"; }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      bool m_is_ca;
      size_t m_path_limit;
   };

/**
* Key Usage Constraints Extension
*/
class BOTAN_PUBLIC_API(2,0) Key_Usage final : public Certificate_Extension
   {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override
         {
         return std::make_unique<Key_Usage>(m_constraints);
         }

      explicit Key_Usage(Key_Constraints c = NO_CONSTRAINTS) : m_constraints(c) {}

      Key_Constraints get_constraints() const { return m_constraints; }

      static OID static_oid() { return OID("2.5.29.15"); }
      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.KeyUsage"; }

      bool should_encode() const override
         { return (m_constraints != NO_CONSTRAINTS); }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      Key_Constraints m_constraints;
   };

/**
* Subject Key Identifier Extension
*/
class BOTAN_PUBLIC_API(2,0) Subject_Key_ID final : public Certificate_Extension
   {
   public:
      Subject_Key_ID() = default;

      explicit Subject_Key_ID(const std::vector<uint8_t>& k) : m_key_id(k) {}

      Subject_Key_ID(const std::vector<uint8_t>& public_key,
                     const std::string& hash_fn);

      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<Subject_Key_ID>(m_key_id); }

      const std::vector<uint8_t>& get_key_id() const { return m_key_id; }

      static OID static_oid() { return OID("2.5.29.14"); }
      OID oid_of() const override { return static_oid(); }

   private:

      std::string oid_name() const override
         { return "X509v3.SubjectKeyIdentifier"; }

      bool should_encode() const override { return (m_key_id.size() > 0); }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      std::vector<uint8_t> m_key_id;
   };

/**
* Authority Key Identifier Extension
*/
class BOTAN_PUBLIC_API(2,0) Authority_Key_ID final : public Certificate_Extension
   {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<Authority_Key_ID>(m_key_id); }

      Authority_Key_ID() = default;
      explicit Authority_Key_ID(const std::vector<uint8_t>& k) : m_key_id(k) {}

      const std::vector<uint8_t>& get_key_id() const { return m_key_id; }

      static OID static_oid() { return OID("2.5.29.35"); }
      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override
         { return "X509v3.AuthorityKeyIdentifier"; }

      bool should_encode() const override { return (m_key_id.size() > 0); }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      std::vector<uint8_t> m_key_id;
   };

/**
* Subject Alternative Name Extension
*/
class BOTAN_PUBLIC_API(2,4) Subject_Alternative_Name final : public Certificate_Extension
   {
   public:
      const AlternativeName& get_alt_name() const { return m_alt_name; }

      static OID static_oid() { return OID("2.5.29.17"); }
      OID oid_of() const override { return static_oid(); }

      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<Subject_Alternative_Name>(get_alt_name()); }

      explicit Subject_Alternative_Name(const AlternativeName& name = AlternativeName()) :
         m_alt_name(name) {}

   private:
      std::string oid_name() const override { return "X509v3.SubjectAlternativeName"; }

      bool should_encode() const override { return m_alt_name.has_items(); }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      AlternativeName m_alt_name;
   };

/**
* Issuer Alternative Name Extension
*/
class BOTAN_PUBLIC_API(2,0) Issuer_Alternative_Name final : public Certificate_Extension
   {
   public:
      const AlternativeName& get_alt_name() const { return m_alt_name; }

      static OID static_oid() { return OID("2.5.29.18"); }
      OID oid_of() const override { return static_oid(); }

      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<Issuer_Alternative_Name>(get_alt_name()); }

      explicit Issuer_Alternative_Name(const AlternativeName& name = AlternativeName()) :
         m_alt_name(name) {}

   private:
      std::string oid_name() const override { return "X509v3.IssuerAlternativeName"; }

      bool should_encode() const override { return m_alt_name.has_items(); }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      AlternativeName m_alt_name;
   };

/**
* Extended Key Usage Extension
*/
class BOTAN_PUBLIC_API(2,0) Extended_Key_Usage final : public Certificate_Extension
   {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<Extended_Key_Usage>(m_oids); }

      Extended_Key_Usage() = default;
      explicit Extended_Key_Usage(const std::vector<OID>& o) : m_oids(o) {}

      const std::vector<OID>& get_oids() const { return m_oids; }

      static OID static_oid() { return OID("2.5.29.37"); }
      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.ExtendedKeyUsage"; }

      bool should_encode() const override { return (m_oids.size() > 0); }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      std::vector<OID> m_oids;
   };

/**
* Name Constraints
*/
class BOTAN_PUBLIC_API(2,0) Name_Constraints final : public Certificate_Extension
   {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<Name_Constraints>(m_name_constraints); }

      Name_Constraints() = default;
      Name_Constraints(const NameConstraints &nc) : m_name_constraints(nc) {}

      void validate(const X509_Certificate& subject, const X509_Certificate& issuer,
            const std::vector<X509_Certificate>& cert_path,
            std::vector<std::set<Certificate_Status_Code>>& cert_status,
            size_t pos) override;

      const NameConstraints& get_name_constraints() const { return m_name_constraints; }

      static OID static_oid() { return OID("2.5.29.30"); }
      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override
         { return "X509v3.NameConstraints"; }

      bool should_encode() const override { return true; }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      NameConstraints m_name_constraints;
   };

/**
* Certificate Policies Extension
*/
class BOTAN_PUBLIC_API(2,0) Certificate_Policies final : public Certificate_Extension
   {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<Certificate_Policies>(m_oids); }

      Certificate_Policies() = default;
      explicit Certificate_Policies(const std::vector<OID>& o) : m_oids(o) {}

      const std::vector<OID>& get_policy_oids() const { return m_oids; }

      static OID static_oid() { return OID("2.5.29.32"); }
      OID oid_of() const override { return static_oid(); }

      void validate(const X509_Certificate& subject, const X509_Certificate& issuer,
            const std::vector<X509_Certificate>& cert_path,
            std::vector<std::set<Certificate_Status_Code>>& cert_status,
            size_t pos) override;
   private:
      std::string oid_name() const override
         { return "X509v3.CertificatePolicies"; }

      bool should_encode() const override { return (m_oids.size() > 0); }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      std::vector<OID> m_oids;
   };

/**
* Authority Information Access Extension
*/
class BOTAN_PUBLIC_API(2,0) Authority_Information_Access final : public Certificate_Extension
   {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<Authority_Information_Access>(m_ocsp_responder, m_ca_issuers); }

      Authority_Information_Access() = default;

      explicit Authority_Information_Access(const std::string& ocsp, const std::vector<std::string>& ca_issuers = std::vector<std::string>()) :
         m_ocsp_responder(ocsp), m_ca_issuers(ca_issuers) {}

      std::string ocsp_responder() const { return m_ocsp_responder; }

      static OID static_oid() { return OID("1.3.6.1.5.5.7.1.1"); }
      OID oid_of() const override { return static_oid(); }
      const std::vector<std::string> ca_issuers() const { return m_ca_issuers; }

   private:
      std::string oid_name() const override
         { return "PKIX.AuthorityInformationAccess"; }

      bool should_encode() const override { return (!m_ocsp_responder.empty()); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;


      std::string m_ocsp_responder;
      std::vector<std::string> m_ca_issuers;
   };

/**
* CRL Number Extension
*/
class BOTAN_PUBLIC_API(2,0) CRL_Number final : public Certificate_Extension
   {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override;

      CRL_Number() : m_has_value(false), m_crl_number(0) {}
      CRL_Number(size_t n) : m_has_value(true), m_crl_number(n) {}

      size_t get_crl_number() const;

      static OID static_oid() { return OID("2.5.29.20"); }
      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.CRLNumber"; }

      bool should_encode() const override { return m_has_value; }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      bool m_has_value;
      size_t m_crl_number;
   };

/**
* CRL Entry Reason Code Extension
*/
class BOTAN_PUBLIC_API(2,0) CRL_ReasonCode final : public Certificate_Extension
   {
   public:
      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<CRL_ReasonCode>(m_reason); }

      explicit CRL_ReasonCode(CRL_Code r = CRL_Code::UNSPECIFIED) : m_reason(r) {}

      CRL_Code get_reason() const { return m_reason; }

      static OID static_oid() { return OID("2.5.29.21"); }
      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override { return "X509v3.ReasonCode"; }

      bool should_encode() const override { return (m_reason != CRL_Code::UNSPECIFIED); }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      CRL_Code m_reason;
   };

/**
* CRL Distribution Points Extension
* todo enforce restrictions from RFC 5280 4.2.1.13
*/
class BOTAN_PUBLIC_API(2,0) CRL_Distribution_Points final : public Certificate_Extension
   {
   public:
      class BOTAN_PUBLIC_API(2,0) Distribution_Point final : public ASN1_Object
         {
         public:
            void encode_into(DER_Encoder&) const override;
            void decode_from(BER_Decoder&) override;

            const AlternativeName& point() const { return m_point; }
         private:
            AlternativeName m_point;
         };

      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<CRL_Distribution_Points>(m_distribution_points); }

      CRL_Distribution_Points() = default;

      explicit CRL_Distribution_Points(const std::vector<Distribution_Point>& points) :
         m_distribution_points(points) {}

      const std::vector<Distribution_Point>& distribution_points() const
         { return m_distribution_points; }

      const std::vector<std::string>& crl_distribution_urls() const
         { return m_crl_distribution_urls; }

      static OID static_oid() { return OID("2.5.29.31"); }
      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override
         { return "X509v3.CRLDistributionPoints"; }

      bool should_encode() const override
         { return !m_distribution_points.empty(); }

      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      std::vector<Distribution_Point> m_distribution_points;
      std::vector<std::string> m_crl_distribution_urls;
   };

/**
* CRL Issuing Distribution Point Extension
* todo enforce restrictions from RFC 5280 5.2.5
*/
class CRL_Issuing_Distribution_Point final : public Certificate_Extension
   {
   public:
      CRL_Issuing_Distribution_Point() = default;

      explicit CRL_Issuing_Distribution_Point(const CRL_Distribution_Points::Distribution_Point& distribution_point) :
         m_distribution_point(distribution_point) {}

      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<CRL_Issuing_Distribution_Point>(m_distribution_point); }

      const AlternativeName& get_point() const
         { return m_distribution_point.point(); }

      static OID static_oid() { return OID("2.5.29.28"); }
      OID oid_of() const override { return static_oid(); }

   private:
      std::string oid_name() const override
         { return "X509v3.CRLIssuingDistributionPoint"; }

      bool should_encode() const override { return true; }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      CRL_Distribution_Points::Distribution_Point m_distribution_point;
   };

/**
* An unknown X.509 extension
* Will add a failure to the path validation result, if critical
*/
class BOTAN_PUBLIC_API(2,4) Unknown_Extension final : public Certificate_Extension
   {
   public:
      Unknown_Extension(const OID& oid, bool critical) :
         m_oid(oid), m_critical(critical) {}

      std::unique_ptr<Certificate_Extension> copy() const override
         { return std::make_unique<Unknown_Extension>(m_oid, m_critical); }

      /**
      * Return the OID of this unknown extension
      */
      OID oid_of() const override
         { return m_oid; }

      //static_oid not defined for Unknown_Extension

      /**
      * Return the extension contents
      */
      const std::vector<uint8_t>& extension_contents() const { return m_bytes; }

      /**
      * Return if this extension was marked critical
      */
      bool is_critical_extension() const { return m_critical; }

      void validate(const X509_Certificate&, const X509_Certificate&,
            const std::vector<X509_Certificate>&,
            std::vector<std::set<Certificate_Status_Code>>& cert_status,
            size_t pos) override
         {
         if(m_critical)
            {
            cert_status.at(pos).insert(Certificate_Status_Code::UNKNOWN_CRITICAL_EXTENSION);
            }
         }

   private:
      std::string oid_name() const override { return ""; }

      bool should_encode() const override { return true; }
      std::vector<uint8_t> encode_inner() const override;
      void decode_inner(const std::vector<uint8_t>&) override;

      OID m_oid;
      bool m_critical;
      std::vector<uint8_t> m_bytes;
   };

}

}

namespace Botan {

/**
* This namespace contains functions for handling X.509 public keys
*/
namespace X509 {

/**
* BER encode a key
* @param key the public key to encode
* @return BER encoding of this key
*/
inline std::vector<uint8_t> BER_encode(const Public_Key& key)
   {
   return key.subject_public_key();
   }

/**
* PEM encode a public key into a string.
* @param key the key to encode
* @return PEM encoded key
*/
BOTAN_PUBLIC_API(2,0) std::string PEM_encode(const Public_Key& key);

/**
* Create a public key from a data source.
* @param source the source providing the DER or PEM encoded key
* @return new public key object
*/
BOTAN_PUBLIC_API(2,0) Public_Key* load_key(DataSource& source);

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
/**
* Create a public key from a file
* @param filename pathname to the file to load
* @return new public key object
*/
inline Public_Key* load_key(const std::string& filename)
   {
   DataSource_Stream source(filename, true);
   return X509::load_key(source);
   }
#endif

/**
* Create a public key from a memory region.
* @param enc the memory region containing the DER or PEM encoded key
* @return new public key object
*/
inline Public_Key* load_key(const std::vector<uint8_t>& enc)
   {
   DataSource_Memory source(enc);
   return X509::load_key(source);
   }

/**
* Copy a key.
* @param key the public key to copy
* @return new public key object
*/
inline Public_Key* copy_key(const Public_Key& key)
   {
   DataSource_Memory source(PEM_encode(key));
   return X509::load_key(source);
   }

}

}

#if defined(BOTAN_TARGET_OS_HAS_THREADS) && defined(BOTAN_HAS_HTTP_UTIL)
  #define BOTAN_HAS_ONLINE_REVOCATION_CHECKS
#endif

namespace Botan {

/**
* This type represents the validation status of an entire certificate path.
* There is one set of status codes for each certificate in the path.
*/
typedef std::vector<std::set<Certificate_Status_Code>> CertificatePathStatusCodes;

/**
* Specifies restrictions on the PKIX path validation
*/
class BOTAN_PUBLIC_API(2,0) Path_Validation_Restrictions final
   {
   public:
      /**
      * @param require_rev if true, revocation information is required

      * @param minimum_key_strength is the minimum strength (in terms of
      *    operations, eg 80 means 2^80) of a signature. Signatures weaker than
      *    this are rejected. If more than 80, SHA-1 signatures are also
      *    rejected. If possible use at least setting 110.
      *
      *        80 bit strength requires 1024 bit RSA
      *        110 bit strength requires 2k bit RSA
      *        128 bit strength requires ~3k bit RSA or P-256
      * @param ocsp_all_intermediates Make OCSP requests for all CAs as
      * well as end entity (if OCSP enabled in path validation request)
      * @param max_ocsp_age maximum age of OCSP responses w/o next_update.
      *        If zero, there is no maximum age
      */
      Path_Validation_Restrictions(bool require_rev = false,
                                   size_t minimum_key_strength = 110,
                                   bool ocsp_all_intermediates = false,
                                   std::chrono::seconds max_ocsp_age = std::chrono::seconds::zero());

      /**
      * @param require_rev if true, revocation information is required
      * @param minimum_key_strength is the minimum strength (in terms of
      *        operations, eg 80 means 2^80) of a signature. Signatures
      *        weaker than this are rejected.
      * @param ocsp_all_intermediates Make OCSP requests for all CAs as
      * well as end entity (if OCSP enabled in path validation request)
      * @param trusted_hashes a set of trusted hashes. Any signatures
      *        created using a hash other than one of these will be
      *        rejected.
      * @param max_ocsp_age maximum age of OCSP responses w/o next_update.
      *        If zero, there is no maximum age
      */
      Path_Validation_Restrictions(bool require_rev,
                                   size_t minimum_key_strength,
                                   bool ocsp_all_intermediates,
                                   const std::set<std::string>& trusted_hashes,
                                   std::chrono::seconds max_ocsp_age = std::chrono::seconds::zero()) :
         m_require_revocation_information(require_rev),
         m_ocsp_all_intermediates(ocsp_all_intermediates),
         m_trusted_hashes(trusted_hashes),
         m_minimum_key_strength(minimum_key_strength),
         m_max_ocsp_age(max_ocsp_age) {}

      /**
      * @return whether revocation information is required
      */
      bool require_revocation_information() const
         { return m_require_revocation_information; }

      /**
      * @return whether all intermediate CAs should also be OCSPed. If false
      * then only end entity OCSP is required/requested.
      */
      bool ocsp_all_intermediates() const
         { return m_ocsp_all_intermediates; }

      /**
      * @return trusted signature hash functions
      */
      const std::set<std::string>& trusted_hashes() const
         { return m_trusted_hashes; }

      /**
      * @return minimum required key strength
      */
      size_t minimum_key_strength() const
         { return m_minimum_key_strength; }

      /**
      * @return maximum age of OCSP responses w/o next_update.
      * If zero, there is no maximum age
      */
      std::chrono::seconds max_ocsp_age() const
         { return m_max_ocsp_age; }

   private:
      bool m_require_revocation_information;
      bool m_ocsp_all_intermediates;
      std::set<std::string> m_trusted_hashes;
      size_t m_minimum_key_strength;
      std::chrono::seconds m_max_ocsp_age;
   };

/**
* Represents the result of a PKIX path validation
*/
class BOTAN_PUBLIC_API(2,0) Path_Validation_Result final
   {
   public:
      typedef Certificate_Status_Code Code;

      /**
      * @return the set of hash functions you are implicitly
      * trusting by trusting this result.
      */
      std::set<std::string> trusted_hashes() const;

      /**
      * @return the trust root of the validation if successful
      * throws an exception if the validation failed
      */
      const X509_Certificate& trust_root() const;

      /**
      * @return the full path from subject to trust root
      * This path may be empty
      */
      const std::vector<X509_Certificate>& cert_path() const { return m_cert_path; }

      /**
      * @return true iff the validation was successful
      */
      bool successful_validation() const;

      /**
      * @return true iff no warnings occured during validation
      */
      bool no_warnings() const;

      /**
      * @return overall validation result code
      */
      Certificate_Status_Code result() const { return m_overall; }

      /**
      * @return a set of status codes for each certificate in the chain
      */
      const CertificatePathStatusCodes& all_statuses() const
         { return m_all_status; }

      /**
      * @return the subset of status codes that are warnings
      */
      CertificatePathStatusCodes warnings() const;

      /**
      * @return string representation of the validation result
      */
      std::string result_string() const;

      /**
      * @return string representation of the warnings
      */
      std::string warnings_string() const;

      /**
      * @param code validation status code
      * @return corresponding validation status message
      */
      static const char* status_string(Certificate_Status_Code code);

      /**
      * Create a Path_Validation_Result
      * @param status list of validation status codes
      * @param cert_chain the certificate chain that was validated
      */
      Path_Validation_Result(CertificatePathStatusCodes status,
                             std::vector<X509_Certificate>&& cert_chain);

      /**
      * Create a Path_Validation_Result
      * @param status validation status code
      */
      explicit Path_Validation_Result(Certificate_Status_Code status) : m_overall(status) {}

   private:
      CertificatePathStatusCodes m_all_status;
      CertificatePathStatusCodes m_warnings;
      std::vector<X509_Certificate> m_cert_path;
      Certificate_Status_Code m_overall;
   };

/**
* PKIX Path Validation
* @param end_certs certificate chain to validate (with end entity certificate in end_certs[0])
* @param restrictions path validation restrictions
* @param trusted_roots list of certificate stores that contain trusted certificates
* @param hostname if not empty, compared against the DNS name in end_certs[0]
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_certs[0]
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeout for OCSP operations, 0 disables OCSP check
* @param ocsp_resp additional OCSP responses to consider (eg from peer)
* @return result of the path validation
*   note: when enabled, OCSP check is softfail by default: if the OCSP server is not
*   reachable, Path_Validation_Result::successful_validation() will return true.
*   Hardfail OCSP check can be achieve by also calling Path_Validation_Result::no_warnings().
*/
Path_Validation_Result BOTAN_PUBLIC_API(2,0) x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& trusted_roots,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
   std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0),
   const std::vector<std::optional<OCSP::Response>>& ocsp_resp = {});

/**
* PKIX Path Validation
* @param end_cert certificate to validate
* @param restrictions path validation restrictions
* @param trusted_roots list of stores that contain trusted certificates
* @param hostname if not empty, compared against the DNS name in end_cert
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_cert
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeout for OCSP operations, 0 disables OCSP check
* @param ocsp_resp additional OCSP responses to consider (eg from peer)
* @return result of the path validation
*/
Path_Validation_Result BOTAN_PUBLIC_API(2,0) x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& trusted_roots,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
   std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0),
   const std::vector<std::optional<OCSP::Response>>& ocsp_resp = {});

/**
* PKIX Path Validation
* @param end_cert certificate to validate
* @param restrictions path validation restrictions
* @param store store that contains trusted certificates
* @param hostname if not empty, compared against the DNS name in end_cert
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_cert
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeout for OCSP operations, 0 disables OCSP check
* @param ocsp_resp additional OCSP responses to consider (eg from peer)
* @return result of the path validation
*/
Path_Validation_Result BOTAN_PUBLIC_API(2,0) x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
   std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0),
   const std::vector<std::optional<OCSP::Response>>& ocsp_resp = {});

/**
* PKIX Path Validation
* @param end_certs certificate chain to validate
* @param restrictions path validation restrictions
* @param store store that contains trusted certificates
* @param hostname if not empty, compared against the DNS name in end_certs[0]
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_certs[0]
* @param validation_time what reference time to use for validation
* @param ocsp_timeout timeout for OCSP operations, 0 disables OCSP check
* @param ocsp_resp additional OCSP responses to consider (eg from peer)
* @return result of the path validation
*/
Path_Validation_Result BOTAN_PUBLIC_API(2,0) x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
   std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0),
   const std::vector<std::optional<OCSP::Response>>& ocsp_resp = {});


/**
* namespace PKIX holds the building blocks that are called by x509_path_validate.
* This allows custom validation logic to be written by applications and makes
* for easier testing, but unless you're positive you know what you're doing you
* probably want to just call x509_path_validate instead.
*/
namespace PKIX {

Certificate_Status_Code
build_all_certificate_paths(std::vector<std::vector<X509_Certificate>>& cert_paths,
                            const std::vector<Certificate_Store*>& trusted_certstores,
                            const std::optional<X509_Certificate>& end_entity,
                            const std::vector<X509_Certificate>& end_entity_extra);


/**
* Build certificate path
* @param cert_path_out output parameter, cert_path will be appended to this vector
* @param trusted_certstores list of certificate stores that contain trusted certificates
* @param end_entity the cert to be validated
* @param end_entity_extra optional list of additional untrusted certs for path building
* @return result of the path building operation (OK or error)
*/
Certificate_Status_Code
BOTAN_PUBLIC_API(2,0) build_certificate_path(std::vector<X509_Certificate>& cert_path_out,
                                 const std::vector<Certificate_Store*>& trusted_certstores,
                                 const X509_Certificate& end_entity,
                                 const std::vector<X509_Certificate>& end_entity_extra);

/**
* Check the certificate chain, but not any revocation data
*
* @param cert_path path built by build_certificate_path with OK result
* @param ref_time whatever time you want to perform the validation
* against (normally current system clock)
* @param hostname the hostname
* @param usage end entity usage checks
* @param min_signature_algo_strength 80 or 110 typically
* Note 80 allows 1024 bit RSA and SHA-1. 110 allows 2048 bit RSA and SHA-2.
* Using 128 requires ECC (P-256) or ~3000 bit RSA keys.
* @param trusted_hashes set of trusted hash functions, empty means accept any
* hash we have an OID for
* @return vector of results on per certificate in the path, each containing a set of
* results. If all codes in the set are < Certificate_Status_Code::FIRST_ERROR_STATUS,
* then the result for that certificate is successful. If all results are
*/
CertificatePathStatusCodes
BOTAN_PUBLIC_API(2,0) check_chain(const std::vector<X509_Certificate>& cert_path,
                      std::chrono::system_clock::time_point ref_time,
                      const std::string& hostname,
                      Usage_Type usage,
                      size_t min_signature_algo_strength,
                      const std::set<std::string>& trusted_hashes);

/**
* Check OCSP responses for revocation information
* @param cert_path path already validated by check_chain
* @param ocsp_responses the OCSP responses to consider
* @param certstores trusted roots
* @param ref_time whatever time you want to perform the validation against
* (normally current system clock)
* @param max_ocsp_age maximum age of OCSP responses w/o next_update. If zero,
* there is no maximum age
* @return revocation status
*/
CertificatePathStatusCodes
BOTAN_PUBLIC_API(2, 0) check_ocsp(const std::vector<X509_Certificate>& cert_path,
                                  const std::vector<std::optional<OCSP::Response>>& ocsp_responses,
                                  const std::vector<Certificate_Store*>& certstores,
                                  std::chrono::system_clock::time_point ref_time,
                                  std::chrono::seconds max_ocsp_age = std::chrono::seconds::zero());

/**
* Check CRLs for revocation information
* @param cert_path path already validated by check_chain
* @param crls the list of CRLs to check, it is assumed that crls[i] (if not null)
* is the associated CRL for the subject in cert_path[i].
* @param ref_time whatever time you want to perform the validation against
* (normally current system clock)
* @return revocation status
*/
CertificatePathStatusCodes
BOTAN_PUBLIC_API(2,0) check_crl(const std::vector<X509_Certificate>& cert_path,
                                const std::vector<std::optional<X509_CRL>>& crls,
                                std::chrono::system_clock::time_point ref_time);

/**
* Check CRLs for revocation information
* @param cert_path path already validated by check_chain
* @param certstores a list of certificate stores to query for the CRL
* @param ref_time whatever time you want to perform the validation against
* (normally current system clock)
* @return revocation status
*/
CertificatePathStatusCodes
BOTAN_PUBLIC_API(2,0) check_crl(const std::vector<X509_Certificate>& cert_path,
                    const std::vector<Certificate_Store*>& certstores,
                    std::chrono::system_clock::time_point ref_time);

#if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)

/**
* Check OCSP using online (HTTP) access. Current version creates a thread and
* network connection per OCSP request made.
*
* @param cert_path path already validated by check_chain
* @param trusted_certstores a list of certstores with trusted certs
* @param ref_time whatever time you want to perform the validation against
* (normally current system clock)
* @param timeout for timing out the responses, though actually this function
* may block for up to timeout*cert_path.size()*C for some small C.
* @param ocsp_check_intermediate_CAs if true also performs OCSP on any intermediate
* CA certificates. If false, only does OCSP on the end entity cert.
* @param max_ocsp_age maximum age of OCSP responses w/o next_update. If zero,
* there is no maximum age
* @return revocation status
*/
CertificatePathStatusCodes
BOTAN_PUBLIC_API(2, 0) check_ocsp_online(const std::vector<X509_Certificate>& cert_path,
      const std::vector<Certificate_Store*>& trusted_certstores,
      std::chrono::system_clock::time_point ref_time,
      std::chrono::milliseconds timeout,
      bool ocsp_check_intermediate_CAs,
      std::chrono::seconds max_ocsp_age = std::chrono::seconds::zero());

/**
* Check CRL using online (HTTP) access. Current version creates a thread and
* network connection per CRL access.

* @param cert_path path already validated by check_chain
* @param trusted_certstores a list of certstores with trusted certs
* @param certstore_to_recv_crls optional (nullptr to disable), all CRLs
* retreived will be saved to this cert store.
* @param ref_time whatever time you want to perform the validation against
* (normally current system clock)
* @param timeout for timing out the responses, though actually this function
* may block for up to timeout*cert_path.size()*C for some small C.
* @return revocation status
*/
CertificatePathStatusCodes
BOTAN_PUBLIC_API(2,0) check_crl_online(const std::vector<X509_Certificate>& cert_path,
                           const std::vector<Certificate_Store*>& trusted_certstores,
                           Certificate_Store_In_Memory* certstore_to_recv_crls,
                           std::chrono::system_clock::time_point ref_time,
                           std::chrono::milliseconds timeout);

#endif

/**
* Find overall status (OK, error) of a validation
* @param cert_status result of merge_revocation_status or check_chain
*/
Certificate_Status_Code BOTAN_PUBLIC_API(2,0) overall_status(const CertificatePathStatusCodes& cert_status);

/**
* Merge the results from CRL and/or OCSP checks into chain_status
* @param chain_status the certificate status
* @param crl_status results from check_crl
* @param ocsp_status results from check_ocsp
* @param require_rev_on_end_entity require valid CRL or OCSP on end-entity cert
* @param require_rev_on_intermediates require valid CRL or OCSP on all intermediate certificates
*/
void BOTAN_PUBLIC_API(2,0) merge_revocation_status(CertificatePathStatusCodes& chain_status,
                                       const CertificatePathStatusCodes& crl_status,
                                       const CertificatePathStatusCodes& ocsp_status,
                                       bool require_rev_on_end_entity,
                                       bool require_rev_on_intermediates);

}

}

namespace Botan {

class RandomNumberGenerator;
class Private_Key;

/**
* Options for X.509 certificates.
*/
class BOTAN_PUBLIC_API(2,0) X509_Cert_Options final
   {
   public:
      /**
      * the subject common name
      */
      std::string common_name;

      /**
      * the subject counry
      */
      std::string country;

      /**
      * the subject organization
      */
      std::string organization;

      /**
      * the subject organizational unit
      */
      std::string org_unit;

      /**
       * additional subject organizational units.
       */
      std::vector<std::string> more_org_units;

      /**
      * the subject locality
      */
      std::string locality;

      /**
      * the subject state
      */
      std::string state;

      /**
      * the subject serial number
      */
      std::string serial_number;

      /**
      * the subject email adress
      */
      std::string email;

      /**
      * the subject URI
      */
      std::string uri;

      /**
      * the subject IPv4 address
      */
      std::string ip;

      /**
      * the subject DNS
      */
      std::string dns;

      /**
       * additional subject DNS entries.
       */
      std::vector<std::string> more_dns;

      /**
      * the subject XMPP
      */
      std::string xmpp;

      /**
      * the subject challenge password
      */
      std::string challenge;

      /**
      * the subject notBefore
      */
      X509_Time start;
      /**
      * the subject notAfter
      */
      X509_Time end;

      /**
      * Indicates whether the certificate request
      */
      bool is_CA;

      /**
      * Indicates the BasicConstraints path limit
      */
      size_t path_limit;

      std::string padding_scheme;

      /**
      * The key constraints for the subject public key
      */
      Key_Constraints constraints;

      /**
      * The key extended constraints for the subject public key
      */
      std::vector<OID> ex_constraints;

      /**
      * Additional X.509 extensions
      */
      Extensions extensions;

      /**
      * Mark the certificate as a CA certificate and set the path limit.
      * @param limit the path limit to be set in the BasicConstraints extension.
      */
      void CA_key(size_t limit = 1);

      /**
      * Choose a padding scheme different from the default for the key used.
      */
      void set_padding_scheme(const std::string& scheme);

      /**
      * Set the notBefore of the certificate.
      * @param time the notBefore value of the certificate
      */
      void not_before(const std::string& time);

      /**
      * Set the notAfter of the certificate.
      * @param time the notAfter value of the certificate
      */
      void not_after(const std::string& time);

      /**
      * Add the key constraints of the KeyUsage extension.
      * @param constr the constraints to set
      */
      void add_constraints(Key_Constraints constr);

      /**
      * Add constraints to the ExtendedKeyUsage extension.
      * @param oid the oid to add
      */
      void add_ex_constraint(const OID& oid);

      /**
      * Add constraints to the ExtendedKeyUsage extension.
      * @param name the name to look up the oid to add
      */
      void add_ex_constraint(const std::string& name);

      /**
      * Construct a new options object
      * @param opts define the common name of this object. An example for this
      * parameter would be "common_name/country/organization/organizational_unit".
      * @param expire_time the expiration time (from the current clock in seconds)
      */
      X509_Cert_Options(const std::string& opts = "",
                        uint32_t expire_time = 365 * 24 * 60 * 60);
   };

namespace X509 {

/**
* Create a self-signed X.509 certificate.
* @param opts the options defining the certificate to create
* @param key the private key used for signing, i.e. the key
* associated with this self-signed certificate
* @param hash_fn the hash function to use
* @param rng the rng to use
* @return newly created self-signed certificate
*/
BOTAN_PUBLIC_API(2,0) X509_Certificate
create_self_signed_cert(const X509_Cert_Options& opts,
                        const Private_Key& key,
                        const std::string& hash_fn,
                        RandomNumberGenerator& rng);

/**
* Create a PKCS#10 certificate request.
* @param opts the options defining the request to create
* @param key the key used to sign this request
* @param rng the rng to use
* @param hash_fn the hash function to use
* @return newly created PKCS#10 request
*/
BOTAN_PUBLIC_API(2,0) PKCS10_Request create_cert_req(const X509_Cert_Options& opts,
                                         const Private_Key& key,
                                         const std::string& hash_fn,
                                         RandomNumberGenerator& rng);

}

}

#endif // BOTAN_AMALGAMATION_H_
