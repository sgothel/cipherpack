/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2021 Gothel Software e.K.
 * Copyright (c) 2021 ZAFENA AB
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <fstream>

#include <cipherpack/cipherpack.hpp>

#include <curl/curl.h>

#include <jau/cpuid.hpp>

#include <jau/debug.hpp>

namespace Botan {
    class CPUID final   {
        public:
            static bool has_simd_32();

            /**
             * Return a possibly empty string containing list of known CPU
             * extensions. Each name will be seperated by a space, and the ordering
             * will be arbitrary. This list only contains values that are useful to
             * Botan (for example FMA instructions are not checked).
             *
             * Example outputs "sse2 ssse3 rdtsc", "neon arm_aes", "altivec"
             */
            static std::string to_string();
    };
}

using namespace cipherpack;

static std::string cp_query_hash_provider(const std::string& algo) noexcept {
    std::unique_ptr<Botan::HashFunction> hash_func = Botan::HashFunction::create(algo);
    if( nullptr == hash_func ) {
        return "";
    }
    return hash_func->provider();
}

static void cp_print_hash_provider(const std::string& algo) noexcept {
    std::string p = cp_query_hash_provider(algo);
    if( p.empty() ) {
        jau::fprintf_td(stderr, "hash '%s': Not available, provider {", algo.c_str());
    } else {
        jau::fprintf_td(stderr, "hash '%s': provider '%s' of {", algo.c_str(), p.c_str());
    }
    std::vector<std::string> hash_provider = Botan::HashFunction::providers(algo);
    for(const std::string& pi : hash_provider) {
        ::fprintf(stderr, "'%s', ", pi.c_str());
    }
    ::fprintf(stderr, "}\n");
}

environment::environment() noexcept {
    jau::environment::get("cipherpack");

    curl_global_init(CURL_GLOBAL_ALL);
}


void environment::print_info() noexcept {
    jau::cpu::print_cpu_info(stderr);

    jau::fprintf_td(stderr, "Botan cpuid: '%s'\n", Botan::CPUID::to_string().c_str());
    jau::fprintf_td(stderr, "Botan cpuid: has_simd32 %d\n", (int)Botan::CPUID::has_simd_32());

    cp_print_hash_provider("SHA-256");
    cp_print_hash_provider("SHA-512");
    cp_print_hash_provider("BLAKE2b(512)");
}

const std::string Constants::package_magic              = "CIPHERPACK_0003";

static const std::string default_pk_type                = "RSA";
static const std::string default_pk_fingerprt_hash_algo = "SHA-256";
static const std::string default_pk_enc_padding_algo    = "OAEP"; // or "EME1"
static const std::string default_pk_enc_hash_algo       = "SHA-256";
static const std::string default_pk_sign_algo           = "EMSA1(SHA-256)";

static const std::string default_sym_enc_mac_algo       = "ChaCha20Poly1305"; // or "AES-256/GCM"

static const std::string default_hash_algo_             = "BLAKE2b(512)";

std::string_view cipherpack::default_hash_algo() noexcept {
    return default_hash_algo_;
}

/**
 * Symmetric Encryption nonce size in bytes.
 *
 * We only process one message per 'encrypted_key', hence medium nonce size of 96 bit.
 *
 * ChaCha Nonce Sizes are usually: 64-bit classic, 96-bit IETF, 192-bit big
 */
static constexpr const size_t ChaCha_Nonce_BitSize      = 96;

CryptoConfig CryptoConfig::getDefault() noexcept {
    return CryptoConfig (
        default_pk_type, default_pk_fingerprt_hash_algo,
        default_pk_enc_padding_algo, default_pk_enc_hash_algo,
        default_pk_sign_algo, default_sym_enc_mac_algo, ChaCha_Nonce_BitSize/8
    );
}

bool CryptoConfig::valid() const noexcept {
    return !pk_type.empty() &&
           !pk_fingerprt_hash_algo.empty() &&
           !pk_enc_padding_algo.empty() &&
           !pk_enc_hash_algo.empty() &&
           !pk_sign_algo.empty() &&
           !sym_enc_algo.empty() &&
           sym_enc_nonce_bytes > 0;
}

std::string CryptoConfig::to_string() const noexcept {
    return "CCfg[pk[type '"+pk_type+"', fingerprt_hash '"+pk_fingerprt_hash_algo+"', enc_padding '"+pk_enc_padding_algo+
            "', enc_hash '"+pk_enc_hash_algo+"', sign '"+pk_sign_algo+
            "'], sym['"+sym_enc_algo+"', nonce "+std::to_string(sym_enc_nonce_bytes)+" bytes]]";
}

std::string PackHeader::toString(const bool show_crypto_algos, const bool force_all_fingerprints) const noexcept {
    const std::string crypto_str = show_crypto_algos ? crypto_cfg.to_string() : "";

    std::string recevr_fingerprint_str;
    {
        if( 0 <= used_recevr_key_idx ) {
            recevr_fingerprint_str += "dec '"+recevr_fingerprints.at(used_recevr_key_idx)+"', ";
        }
        if( force_all_fingerprints || 0 > used_recevr_key_idx ) {
            recevr_fingerprint_str += "enc[";
            int i = 0;
            for(const std::string& tkf : recevr_fingerprints) {
                if( 0 < i ) {
                    recevr_fingerprint_str += ", ";
                }
                recevr_fingerprint_str += "'"+tkf+"'";
                ++i;
            }
            recevr_fingerprint_str += "]";
        }
    }

    std::string res = "Header[";
    res += "valid "+std::to_string( isValid() )+
           ", file[target_path "+target_path+", content_size "+jau::to_decstring(content_size).c_str()+
           "], creation "+ts_creation.to_iso8601_string()+" UTC, subject '"+subject+"', "+
           " version["+payload_version+
           ", parent "+payload_version_parent+crypto_str+
           "], fingerprints[sender '"+sender_fingerprint+
           "', recevr["+recevr_fingerprint_str+
           "]], phash['"+payload_hash_algo+"', sz "+std::to_string(payload_hash.size())+"]]";
    return res;
}

std::shared_ptr<Botan::Public_Key> cipherpack::load_public_key(const std::string& pubkey_fname) {
    jau::io::ByteInStream_File key_data(pubkey_fname, false /* use_binary */);
    std::shared_ptr<Botan::Public_Key> key(Botan::X509::load_key(key_data));
    if( !key ) {
        ERR_PRINT("Couldn't load Key %s", pubkey_fname.c_str());
        return std::shared_ptr<Botan::Public_Key>();
    }
    if( key->algo_name() != "RSA" ) {
        ERR_PRINT("Key doesn't support RSA %s", pubkey_fname.c_str());
        return std::shared_ptr<Botan::Public_Key>();
    }
    return key;
}

/**
 * Get info from an EncryptedPrivateKeyInfo
 *
 * Copied from Botan, allowing to only pass passphrase by const reference
 * for later secure erasure not leaving a copy in memory.
 */
static jau::io::secure_vector<uint8_t> jau_PKCS8_extract(Botan::DataSource& source,
                                                         Botan::AlgorithmIdentifier& pbe_alg_id)
{
    jau::io::secure_vector<uint8_t> key_data;

    Botan::BER_Decoder(source)
        .start_sequence()
        .decode(pbe_alg_id)
        .decode(key_data, Botan::ASN1_Type::OctetString)
        .verify_end();

    return key_data;
}

#if defined(BOTAN_HAS_PKCS5_PBES2)
namespace Botan {
    /**
    * Decrypt a PKCS #5 v2.0 encrypted stream
    * @param key_bits the input
    * @param passphrase the passphrase to use for decryption
    * @param params the PBES2 parameters
    */
    secure_vector<uint8_t>
    pbes2_decrypt(const secure_vector<uint8_t>& key_bits,
                  const std::string& passphrase,
                  const std::vector<uint8_t>& params);
}
#endif

/**
 * PEM decode and/or decrypt a private key
 *
 * Copied from Botan, allowing to only pass passphrase by const reference
 * for later secure erasure not leaving a copy in memory.
 */
static jau::io::secure_vector<uint8_t> jau_PKCS8_decode(Botan::DataSource& source,
                                                        const std::string& passphrase,
                                                        Botan::AlgorithmIdentifier& pk_alg_id,
                                                        bool is_encrypted)
{
    Botan::AlgorithmIdentifier pbe_alg_id;
    jau::io::secure_vector<uint8_t> key_data, key;

    try {
        if(Botan::ASN1::maybe_BER(source) && !Botan::PEM_Code::matches(source)) {
            if(is_encrypted) {
                key_data = jau_PKCS8_extract(source, pbe_alg_id);
            } else {
                // todo read more efficiently
                while(!source.end_of_data()) {
                    uint8_t b;
                    size_t read = source.read_byte(b);
                    if(read) {
                        key_data.push_back(b);
                    }
                }
            }
        } else {
            std::string label;
            key_data = Botan::PEM_Code::decode(source, label);

            // todo remove autodetect for pem as well?
            if(label == "PRIVATE KEY") {
                is_encrypted = false;
            } else if(label == "ENCRYPTED PRIVATE KEY") {
                Botan::DataSource_Memory key_source(key_data);
                key_data = jau_PKCS8_extract(key_source, pbe_alg_id);
            } else {
                throw Botan::PKCS8_Exception("Unknown PEM label " + label);
            }
        }

        if(key_data.empty()) {
            throw Botan::PKCS8_Exception("No key data found");
        }
    } catch(Botan::Decoding_Error& e) {
        throw Botan::Decoding_Error("PKCS #8 private key decoding", e);
    }

    try {
        if(is_encrypted) {
            if(Botan::OIDS::oid2str_or_throw(pbe_alg_id.get_oid()) != "PBE-PKCS5v20") {
                throw Botan::PKCS8_Exception("Unknown PBE type " + pbe_alg_id.get_oid().to_string());
            }
#if defined(BOTAN_HAS_PKCS5_PBES2)
            key = Botan::pbes2_decrypt(key_data, passphrase, pbe_alg_id.get_parameters()); // pass passphrase by const reference, OK
#else
            #error Private key is encrypted but PBES2 was disabled in build
            BOTAN_UNUSED(passphrase);
            throw Botan::Decoding_Error("Private key is encrypted but PBES2 was disabled in build");
#endif
        } else {
            key = key_data;
        }

        Botan::BER_Decoder(key)
            .start_sequence()
            .decode_and_check<size_t>(0, "Unknown PKCS #8 version number")
            .decode(pk_alg_id)
            .decode(key, Botan::ASN1_Type::OctetString)
            .discard_remaining()
            .end_cons();
    } catch(std::exception& e) {
        throw Botan::Decoding_Error("PKCS #8 private key decoding", e);
    }
    return key;
}

std::shared_ptr<Botan::Private_Key> cipherpack::load_private_key(const std::string& privatekey_fname, const jau::io::secure_string& passphrase) {
    jau::io::ByteInStream_File key_data(privatekey_fname, false /* use_binary */);
    std::shared_ptr<Botan::Private_Key> key;
    if( passphrase.empty() ) {
        key = Botan::PKCS8::load_key(key_data);
    } else {
        /**
         * We drop Botan::PKCS8::load_key(), since it copies the std::string passphrase via
         * `const std::function<std::string ()>& get_pass`
         * and hence leaves an intact copy of the passphrase in memory.
         *
         * Hence we replace it by our own 'jau_PKCS8_decode()' handing down only a const reference w/o copy.
         *
         * `key = Botan::PKCS8::load_key(key_data, passphrase);`
         */
        std::string insec_passphrase_copy(passphrase);
        Botan::AlgorithmIdentifier alg_id;
        jau::io::secure_vector<uint8_t> pkcs8_key = jau_PKCS8_decode(key_data, insec_passphrase_copy, alg_id, true /* is_encrypted */);

        const std::string alg_name = Botan::OIDS::oid2str_or_empty(alg_id.get_oid());
        if( alg_name.empty() ) {
            throw Botan::PKCS8_Exception("Unknown algorithm OID: " + alg_id.get_oid().to_string());
        }
        key = load_private_key(alg_id, pkcs8_key);
        ::explicit_bzero(insec_passphrase_copy.data(), insec_passphrase_copy.size());
    }
    if( !key ) {
        ERR_PRINT("Couldn't load Key %s", privatekey_fname.c_str());
        return std::shared_ptr<Botan::Private_Key>();
    }
    if( key->algo_name() != "RSA" ) {
        ERR_PRINT("Key doesn't support RSA %s", privatekey_fname.c_str());
        return std::shared_ptr<Botan::Private_Key>();
    }
    return key;
}

std::string cipherpack::hash_util::file_suffix(const std::string& algo) noexcept {
    std::string s = algo;
    // lower-case
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    // remove '-'
    auto it = std::remove( s.begin(), s.end(), '-');
    s.erase(it, s.end());
    return s;
}

bool cipherpack::hash_util::append_to_file(const std::string& out_file, const std::string& hashed_file, const std::vector<uint8_t>& hash) noexcept {
    const std::string hash_str = jau::bytesHexString(hash.data(), 0, hash.size(), true /* lsbFirst */, true /* lowerCase */);

    std::ofstream out(out_file, std::ios::out | std::ios::binary | std::ios::app);
    if( !out.good() || !out.is_open() ) {
        return false;
    }
    out.write(hash_str.data(), hash_str.size());
    out.write(" *", 2);
    out.write(hashed_file.data(), hashed_file.size());
    out.write("\n", 1);
    if( !out.good() || !out.is_open() ) {
        return false;
    }
    return true;
}

std::unique_ptr<std::vector<uint8_t>> cipherpack::hash_util::calc(const std::string_view& algo, jau::io::ByteInStream& source) noexcept {
    const std::string algo_s(algo);
    std::unique_ptr<Botan::HashFunction> hash_func = Botan::HashFunction::create(algo_s);
    if( nullptr == hash_func ) {
        ERR_PRINT2("Hash failed: Algo %s not available", algo_s.c_str());
        return nullptr;
    }
    jau::io::StreamConsumerFunc consume_data = [&](jau::io::secure_vector<uint8_t>& data, bool is_final) -> bool {
        (void) is_final;
        hash_func->update(data);
        return true;
    };
    jau::io::secure_vector<uint8_t> io_buffer;
    io_buffer.reserve(Constants::buffer_size);
    const uint64_t in_bytes_total = jau::io::read_stream(source, io_buffer, consume_data);
    source.close();
    if( source.has_content_size() && in_bytes_total != source.content_size() ) {
        ERR_PRINT2("Hash failed: Only read %" PRIu64 " bytes of %s", in_bytes_total, source.to_string().c_str());
        return nullptr;
    }
    std::unique_ptr<std::vector<uint8_t>> res = std::make_unique<std::vector<uint8_t>>(hash_func->output_length());
    hash_func->final(res->data());
    return res;
}

std::unique_ptr<std::vector<uint8_t>> cipherpack::hash_util::calc(const std::string_view& algo, const std::string& path, uint64_t& bytes_hashed) noexcept {
    bytes_hashed = 0;
    jau::fs::file_stats source_stats(path);
    if( source_stats.is_file() ) {
        jau::io::ByteInStream_File in(path);
        if( in.error() ) {
            return nullptr;
        }
        return calc(algo, in);
    }
    if( !source_stats.is_dir() ) {
        ERR_PRINT("path is neither file nor dir: %s", source_stats.to_string());
        return nullptr;
    }

    //
    // directory handling
    //
    struct context_t {
        std::vector<int> dirfds;
        std::unique_ptr<Botan::HashFunction> hash_func;
        jau::io::secure_vector<uint8_t> io_buffer;
        jau::io::StreamConsumerFunc consume_data;
        uint64_t bytes_hashed;
    };
    context_t ctx { std::vector<int>(), nullptr, jau::io::secure_vector<uint8_t>(), nullptr, 0 };
    {
        const std::string algo_s(algo);
        ctx.hash_func = Botan::HashFunction::create(algo_s);
        if( nullptr == ctx.hash_func ) {
            ERR_PRINT2("Hash failed: Algo %s not available", algo_s.c_str());
            return nullptr;
        }
    }
    ctx.consume_data = [&](jau::io::secure_vector<uint8_t>& data, bool is_final) -> bool {
        (void) is_final;
        ctx.hash_func->update(data);
        return true;
    };
    ctx.io_buffer.reserve(Constants::buffer_size);

    const jau::fs::path_visitor pv = jau::bindCaptureRefFunc<bool, context_t, jau::fs::traverse_event, const jau::fs::file_stats&>(&ctx,
            ( bool(*)(context_t*, jau::fs::traverse_event, const jau::fs::file_stats&) ) /* help template type deduction of function-ptr */
                ( [](context_t* ctx_ptr, jau::fs::traverse_event tevt, const jau::fs::file_stats& element_stats) -> bool {
                    if( is_set(tevt, jau::fs::traverse_event::file) && !is_set(tevt, jau::fs::traverse_event::symlink) ) {
                        // FIXME: It would be desirable to have ByteInStream_File handle dirfd,
                        // i.e. implementation based on OS level I/O.
                        //
                        // const int dirfd = ctx_ptr->dirfds.back();
                        // const std::string& basename_ = element_stats.item().basename();
                        jau::io::ByteInStream_File in(element_stats.path());
                        if( in.error() ) {
                            return false;
                        }
                        const uint64_t in_bytes_total = jau::io::read_stream(in, ctx_ptr->io_buffer, ctx_ptr->consume_data);
                        in.close();
                        if( in.has_content_size() && in_bytes_total != in.content_size() ) {
                            ERR_PRINT2("Hash failed: Only read %" PRIu64 " bytes of %s", in_bytes_total, in.to_string().c_str());
                            return false;
                        }
                        ctx_ptr->bytes_hashed += in_bytes_total;
                    }
                    return true;
                  } ) );
    if( jau::fs::visit(source_stats, jau::fs::traverse_options::recursive, pv, &ctx.dirfds) ) {
        std::unique_ptr<std::vector<uint8_t>> res = std::make_unique<std::vector<uint8_t>>(ctx.hash_func->output_length());
        ctx.hash_func->final(res->data());
        bytes_hashed = ctx.bytes_hashed;
        return res;
    }
    return nullptr;
}
