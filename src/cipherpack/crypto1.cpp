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
#include <iostream>

#include <cipherpack/cipherpack.hpp>

#include <jau/debug.hpp>
#include <jau/file_util.hpp>

using namespace cipherpack;

// static uint32_t to_uint32_t(const Botan::BigInt& v) const { return v.to_u32bit(); }

static Botan::BigInt to_BigInt(const uint64_t & v) {
    return Botan::BigInt::from_u64(v);
}

static uint64_t to_uint64_t(const Botan::BigInt& v) {
    if( v.is_negative() ) {
        throw Botan::Encoding_Error("BigInt::to_u64bit: Number is negative");
    }
    if( v.bits() > 64 ) {
        throw Botan::Encoding_Error("BigInt::to_u64bit: Number is too big to convert");
    }
    uint64_t out = 0;
    for(size_t i = 0; i < 8; ++i) {
        out = (out << 8) | v.byte_at(7-i);
    }
    return out;
}

static std::vector<uint8_t> to_OctetString(const std::string& s) {
    return std::vector<uint8_t>( s.begin(), s.end() );
}

static std::string to_string(const std::vector<uint8_t>& v) {
    return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}

class WrappingCipherpackListener : public CipherpackListener{
    public:
        CipherpackListenerRef parent;

        WrappingCipherpackListener(CipherpackListenerRef parent_)
        : parent(parent_) {}

        void notifyError(const bool decrypt_mode, const std::string& msg) noexcept override {
            parent->notifyError(decrypt_mode, msg);
        }

        void notifyHeader(const bool decrypt_mode, const PackHeader& header, const bool verified) noexcept override {
            parent->notifyHeader(decrypt_mode, header, verified);
        }

        void notifyProgress(const bool decrypt_mode, const uint64_t content_size, const uint64_t bytes_processed) noexcept override {
            parent->notifyProgress(decrypt_mode, content_size, bytes_processed);
        }

        void notifyEnd(const bool decrypt_mode, const PackHeader& header, const bool success) noexcept override {
            parent->notifyEnd(decrypt_mode, header, success);
        }

        bool getSendContent(const bool decrypt_mode) const noexcept override {
            return parent->getSendContent(decrypt_mode);
        }

        bool contentProcessed(const bool decrypt_mode, const content_type ctype, jau::io::secure_vector<uint8_t>& data, const bool is_final) noexcept override {
            return parent->contentProcessed(decrypt_mode, ctype, data, is_final);
        }

        ~WrappingCipherpackListener() noexcept override {}

        std::string toString() const noexcept override { return "WrappingCipherpackListener["+jau::to_hexstring(this)+"]"; }
};

static PackHeader encryptThenSign_Impl(const CryptoConfig& crypto_cfg,
                                       const std::vector<std::string>& enc_pub_keys,
                                       const std::string& sign_sec_key_fname, const jau::io::secure_string& passphrase,
                                       jau::io::ByteInStream& source,
                                       const std::string& target_path, const std::string& subject,
                                       const std::string& payload_version,
                                       const std::string& payload_version_parent,
                                       CipherpackListenerRef listener,
                                       const std::string_view& payload_hash_algo) {
    const bool decrypt_mode = false;
    environment::get();
    const jau::fraction_timespec ts_creation = jau::getWallClockTime();

    PackHeader header(target_path,
                      source.content_size(),
                      ts_creation,
                      subject,
                      payload_version, payload_version_parent,
                      crypto_cfg,
                      std::string(),
                      std::vector<std::string>(),
                      -1 /* term_key_fingerprint_used_idx */,
                      false /* valid */);

    if( nullptr == listener ) {
        ERR_PRINT2("Encrypt failed: Listener is nullptr for source %s", source.to_string().c_str());
        return header;
    }

    if( source.end_of_data() || source.error() ) {
        ERR_PRINT2("Encrypt failed: Source is EOS or has an error %s", source.to_string().c_str());
        return header;
    }
    if( !source.has_content_size() ) {
        ERR_PRINT2("Encrypt failed: Source doesn't provide content_size %s", source.to_string().c_str());
        return header;
    }
    const uint64_t content_size = source.content_size();

    if( !crypto_cfg.valid() ) {
        ERR_PRINT2("Encrypt failed: CryptoConfig incomplete %s", crypto_cfg.to_string().c_str());
        return header;
    }

    const jau::fraction_timespec _t0 = jau::getMonotonicTime();

    if( target_path.empty() ) {
        ERR_PRINT2("Encrypt failed: Target path is empty for %s", source.to_string().c_str());
        return header;
    }
    uint64_t out_bytes_header = 0;

    try {
        std::unique_ptr<Botan::HashFunction> hash_func = nullptr;
        if( !payload_hash_algo.empty() ) {
            const std::string payload_hash_algo_s(payload_hash_algo);
            hash_func = Botan::HashFunction::create(payload_hash_algo_s);
            if( nullptr == hash_func ) {
                ERR_PRINT2("Encrypt failed: Payload hash algo %s not available", payload_hash_algo_s.c_str());
                return header;
            }
        }
        Botan::RandomNumberGenerator& rng = Botan::system_rng();

        std::shared_ptr<Botan::Private_Key> sign_sec_key = load_private_key(sign_sec_key_fname, passphrase);
        if( !sign_sec_key ) {
            return header;
        }

        const Botan::OID sym_enc_algo_oid = Botan::OID::from_string(crypto_cfg.sym_enc_algo);
        if( sym_enc_algo_oid.empty() ) {
            ERR_PRINT2("Encrypt failed: No OID defined for cypher algo %s", crypto_cfg.sym_enc_algo.c_str());
            return header;
        }
        std::shared_ptr<Botan::AEAD_Mode> aead = Botan::AEAD_Mode::create(crypto_cfg.sym_enc_algo, Botan::ENCRYPTION);
        if(!aead) {
           ERR_PRINT2("Encrypt failed: AEAD algo %s not available", crypto_cfg.sym_enc_algo.c_str());
           return header;
        }
        jau::io::secure_vector<uint8_t> plain_sym_key = rng.random_vec(aead->key_spec().maximum_keylength());
        jau::io::secure_vector<uint8_t> nonce = rng.random_vec(crypto_cfg.sym_enc_nonce_bytes);
        const std::string sender_fingerprint = sign_sec_key->fingerprint_public(crypto_cfg.pk_fingerprt_hash_algo);

        struct recevr_data_t {
            std::shared_ptr<Botan::Public_Key> pub_key;
            std::vector<uint8_t> encrypted_sym_key;
            std::vector<uint8_t> encrypted_nonce;
        };
        std::vector<recevr_data_t> recevr_data_list;
        std::vector<std::string> recevr_fingerprints;

        for( const std::string& pub_key_fname : enc_pub_keys ) {
            recevr_data_t recevr_data;

            recevr_data.pub_key = load_public_key(pub_key_fname);
            if( !recevr_data.pub_key ) {
                return header;
            }
            Botan::PK_Encryptor_EME enc(*recevr_data.pub_key, rng, crypto_cfg.pk_enc_padding_algo+"(" + crypto_cfg.pk_enc_hash_algo + ")");

            recevr_data.encrypted_sym_key = enc.encrypt(plain_sym_key, rng);
            recevr_data.encrypted_nonce = enc.encrypt(nonce, rng);
            recevr_data_list.push_back(recevr_data);
        }

        std::vector<uint8_t> sender_signature;
        {
            jau::io::secure_vector<uint8_t> header_buffer;
            header_buffer.reserve(Constants::buffer_size);

            // DER-Header-1
            header_buffer.clear();
            {
                Botan::DER_Encoder der(header_buffer);
                der.start_sequence()
                   .encode( to_OctetString( Constants::package_magic ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( target_path ), Botan::ASN1_Type::OctetString )
                   .encode( to_BigInt( static_cast<uint64_t>( content_size ) ), Botan::ASN1_Type::Integer )
                   .encode( to_BigInt( static_cast<uint64_t>( ts_creation.tv_sec ) ), Botan::ASN1_Type::Integer )
                   .encode( to_BigInt( static_cast<uint64_t>( ts_creation.tv_nsec ) ), Botan::ASN1_Type::Integer )
                   .encode( to_OctetString( subject ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( payload_version ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( payload_version_parent ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( crypto_cfg.pk_type ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( crypto_cfg.pk_fingerprt_hash_algo ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( crypto_cfg.pk_enc_padding_algo ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( crypto_cfg.pk_enc_hash_algo ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( crypto_cfg.pk_sign_algo ), Botan::ASN1_Type::OctetString )
                   .encode( sym_enc_algo_oid )
                   .encode( to_OctetString( sender_fingerprint ), Botan::ASN1_Type::OctetString )
                   .encode( recevr_data_list.size(), Botan::ASN1_Type::Integer )
                   .end_cons(); // data push
            }

            Botan::PK_Signer signer(*sign_sec_key, rng, crypto_cfg.pk_sign_algo);
            signer.update(header_buffer);
            out_bytes_header += header_buffer.size();
            if( listener->getSendContent( decrypt_mode ) ) {
                listener->contentProcessed(decrypt_mode, CipherpackListener::content_type::header, header_buffer, false /* final */);
            }
            DBG_PRINT("Encrypt: DER Header1 written + %zu bytes / %" PRIu64 " bytes", header_buffer.size(), out_bytes_header);

            for(const recevr_data_t& recevr_data : recevr_data_list) {
                const std::string recevr_fingerprt = recevr_data.pub_key->fingerprint_public(crypto_cfg.pk_fingerprt_hash_algo);
                recevr_fingerprints.push_back(recevr_fingerprt);

                // DER Header recevr_n
                header_buffer.clear();
                {
                    Botan::DER_Encoder der(header_buffer);
                    der.start_sequence()
                       .encode( to_OctetString( recevr_fingerprt ), Botan::ASN1_Type::OctetString )
                       .encode( recevr_data.encrypted_sym_key, Botan::ASN1_Type::OctetString )
                       .encode( recevr_data.encrypted_nonce, Botan::ASN1_Type::OctetString )
                       .end_cons();
                }
                signer.update(header_buffer);
                out_bytes_header += header_buffer.size();
                if( listener->getSendContent( decrypt_mode ) ) {
                    listener->contentProcessed(decrypt_mode, CipherpackListener::content_type::header, header_buffer, false /* final */);
                }
                DBG_PRINT("Encrypt: DER Header-recevr written + %zu bytes / %" PRIu64 " bytes", header_buffer.size(), out_bytes_header);
            }

            // DER-Header-2 (signature)
            sender_signature = signer.signature(rng);
            DBG_PRINT("Encrypt: Signature for %" PRIu64 " bytes: %s", out_bytes_header,
                    jau::bytesHexString(sender_signature.data(), 0, sender_signature.size(), true /* lsbFirst */).c_str());
            header_buffer.clear();
            {
                Botan::DER_Encoder der(header_buffer);
                der.start_sequence()
                   .encode( sender_signature, Botan::ASN1_Type::OctetString )
                   .end_cons();
            }
            out_bytes_header += header_buffer.size();
            if( listener->getSendContent( decrypt_mode ) ) {
                listener->contentProcessed(decrypt_mode, CipherpackListener::content_type::header, header_buffer, false /* final */);
            }
            DBG_PRINT("Encrypt: DER Header2 written + %zu bytes / %" PRIu64 " bytes for %zu keys", header_buffer.size(), out_bytes_header, recevr_data_list.size());
        }

        header = PackHeader(target_path,
                            content_size,
                            ts_creation,
                            subject,
                            payload_version, payload_version_parent,
                            crypto_cfg,
                            sender_fingerprint,
                            recevr_fingerprints,
                            -1 /* term_key_fingerprint_used_idx */,
                            false /* valid */);

        DBG_PRINT("Encrypt: DER Header done, %" PRIu64 " header: %s",
                out_bytes_header, header.toString(true /* show_crypto_algos */, true /* force_all_fingerprints */).c_str());

        listener->notifyHeader(decrypt_mode, header, true /* verified */);

        //
        // Symmetric Encryption incl. hash
        //

        aead->set_key(plain_sym_key);
        aead->set_associated_data_vec(sender_signature);
        aead->start(nonce);

        const bool sent_content_to_user = listener->getSendContent( decrypt_mode );
        uint64_t out_bytes_payload = 0;
        jau::io::StreamConsumerFunc consume_data = [&](jau::io::secure_vector<uint8_t>& data, bool is_final) -> bool {
            bool res = true;
            if( !is_final ) {
                if( nullptr != hash_func ) {
                    hash_func->update(data);
                }
                aead->update(data);
                if( sent_content_to_user ) {
                    res = listener->contentProcessed(decrypt_mode, CipherpackListener::content_type::payload, data, false /* is_final */);
                }
                out_bytes_payload += data.size();
                DBG_PRINT("Encrypt: EncPayload written0 + %zu bytes -> %" PRIu64 " bytes / %zu bytes, user[sent %d, res %d]",
                        data.size(), out_bytes_payload, content_size, sent_content_to_user, res);
                listener->notifyProgress(decrypt_mode, content_size, source.bytes_read());
            } else {
                if( nullptr != hash_func ) {
                    hash_func->update(data);
                }
                aead->finish(data);
                if( sent_content_to_user ) {
                    res = listener->contentProcessed(decrypt_mode, CipherpackListener::content_type::payload, data, true /* is_final */);
                }
                out_bytes_payload += data.size();
                DBG_PRINT("Encrypt: EncPayload writtenF + %zu bytes -> %" PRIu64 " bytes / %zu bytes, user[sent %d, res %d]",
                        data.size(), out_bytes_payload, content_size, sent_content_to_user, res);
                listener->notifyProgress(decrypt_mode, content_size, source.bytes_read());
            }
            return res;
        };
        jau::io::secure_vector<uint8_t> io_buffer;
        io_buffer.reserve(Constants::buffer_size);
        const uint64_t in_bytes_total = jau::io::read_stream(source, io_buffer, consume_data);
        source.close();

        if( nullptr != hash_func ) {
            std::vector<uint8_t> hash_value( hash_func->output_length() );
            hash_func->final(hash_value.data());
            header.setPayloadHash(hash_func->name(), hash_value);
        }

        if ( 0==in_bytes_total || source.error() ) {
            ERR_PRINT2("Encrypt failed: Source read failed %s", source.to_string().c_str());
            return header;
        }

        if( source.bytes_read() != in_bytes_total ) {
            ERR_PRINT2("Encrypt: Writing done, %s bytes read != %s",
                    jau::to_decstring(in_bytes_total).c_str(),
                    source.to_string().c_str());
            return header;
        } else if( jau::environment::get().verbose ) {
            WORDY_PRINT("Encrypt: Reading done from %s", source.to_string().c_str());
            WORDY_PRINT("Encrypt: Writing done, %s header + %s payload for %s bytes written, ratio %lf out/in",
                    jau::to_decstring(out_bytes_header).c_str(),
                    jau::to_decstring(out_bytes_payload).c_str(),
                    jau::to_decstring(in_bytes_total).c_str(), (double)(out_bytes_header+out_bytes_payload)/(double)in_bytes_total);
            WORDY_PRINT("Encrypt: Writing done: source: %s", source.to_string().c_str());
        }

        if( jau::environment::get().verbose ) {
            const jau::fraction_i64 _td = ( jau::getMonotonicTime() - _t0 ).to_fraction_i64();
            jau::io::print_stats("Encrypt", (out_bytes_header+out_bytes_payload), _td);
        }
        header.setValid(true);
        return header;
    } catch (std::exception &e) {
        ERR_PRINT("Encrypt failed: Caught exception: %s on %s", e.what(), source.to_string().c_str());
        return header;
    }
}

PackHeader cipherpack::encryptThenSign(const CryptoConfig& crypto_cfg,
                                       const std::vector<std::string>& enc_pub_keys,
                                       const std::string& sign_sec_key_fname, const jau::io::secure_string& passphrase,
                                       jau::io::ByteInStream& source,
                                       const std::string& target_path, const std::string& subject,
                                       const std::string& payload_version,
                                       const std::string& payload_version_parent,
                                       CipherpackListenerRef listener,
                                       const std::string_view& payload_hash_algo,
                                       const std::string destination_fname) {
    environment::get();
    const bool decrypt_mode = false;

    if( destination_fname.empty() ) {
        PackHeader ph = encryptThenSign_Impl(crypto_cfg,
                                             enc_pub_keys,
                                             sign_sec_key_fname, passphrase,
                                             source,
                                             target_path, subject,
                                             payload_version,
                                             payload_version_parent,
                                             listener, payload_hash_algo);
        listener->notifyEnd(decrypt_mode, ph, ph.isValid());
        return ph;
    }

    const jau::fraction_timespec ts_creation = jau::getWallClockTime();

    PackHeader header(target_path,
                      source.content_size(),
                      ts_creation,
                      subject,
                      payload_version, payload_version_parent,
                      crypto_cfg,
                      std::string(),
                      std::vector<std::string>(),
                      -1 /* term_key_fingerprint_used_idx */,
                      false /* valid */);

    if( nullptr == listener ) {
        ERR_PRINT2("Encrypt failed: Listener is nullptr for source %s", source.to_string().c_str());
        return header;
    }

    class MyListener : public WrappingCipherpackListener {
        private:
            std::ofstream* outfile_;
            uint64_t& out_bytes_header_;
            uint64_t& out_bytes_payload_;
        public:
            MyListener(CipherpackListenerRef parent_, uint64_t& bytes_header, uint64_t& bytes_payload)
            : WrappingCipherpackListener(parent_), outfile_(nullptr),
              out_bytes_header_(bytes_header), out_bytes_payload_(bytes_payload)
            {}

            void set_outfile(std::ofstream* of) noexcept { outfile_ = of; }

            bool getSendContent(const bool decrypt_mode) const noexcept override {
                return true;
            }

            bool contentProcessed(const bool decrypt_mode, const content_type ctype, jau::io::secure_vector<uint8_t>& data, const bool is_final) noexcept override {
                if( nullptr != outfile_ ) {
                    outfile_->write(reinterpret_cast<char*>(data.data()), data.size());
                    if( outfile_->fail() ) {
                        return false;
                    }
                    switch( ctype ) {
                        case content_type::header:
                            out_bytes_header_ += data.size();
                            break;
                        case content_type::payload:
                            [[fallthrough]];
                        default:
                            out_bytes_payload_ += data.size();
                            break;
                    }
                }
                if( parent->getSendContent(decrypt_mode) ) {
                    return parent->contentProcessed(decrypt_mode, ctype, data, is_final);
                } else {
                    return true;
                }
            }
    };
    uint64_t out_bytes_header=0, out_bytes_payload=0;
    std::shared_ptr<MyListener> my_listener = std::make_shared<MyListener>(listener, out_bytes_header, out_bytes_payload);
    {
        const jau::fs::file_stats output_stats(destination_fname);
        if( output_stats.exists() ) {
            if( output_stats.is_file() ) {
                if( !jau::fs::remove(destination_fname) ) {
                    ERR_PRINT2("Encrypt failed: Failed deletion of existing output file %s", output_stats.to_string().c_str());
                    my_listener->notifyEnd(decrypt_mode, header, false);
                    return header;
                }
            } else {
                ERR_PRINT2("Encrypt failed: Not overwriting existing %s", output_stats.to_string().c_str());
                my_listener->notifyEnd(decrypt_mode, header, false);
                return header;
            }
        }
    }
    std::ofstream outfile(destination_fname, std::ios::out | std::ios::binary);
    if ( !outfile.good() || !outfile.is_open() ) {
        ERR_PRINT2("Encrypt failed: Output file not open %s", destination_fname.c_str());
        my_listener->notifyEnd(decrypt_mode, header, false);
        return header;
    }
    my_listener->set_outfile(&outfile);

    PackHeader ph = encryptThenSign_Impl(crypto_cfg,
                                         enc_pub_keys,
                                         sign_sec_key_fname, passphrase,
                                         source,
                                         target_path, subject,
                                         payload_version,
                                         payload_version_parent,
                                         my_listener, payload_hash_algo);
    if ( outfile.fail() ) {
        ERR_PRINT2("Encrypt failed: Output file write failed %s", destination_fname.c_str());
        jau::fs::remove(destination_fname);
        ph.setValid(false);
        my_listener->notifyEnd(decrypt_mode, ph, false);
        return header;
    }
    outfile.close();

    if( !ph.isValid() ) {
        jau::fs::remove(destination_fname);
        my_listener->notifyEnd(decrypt_mode, ph, false);
        return header;
    }

    const jau::fs::file_stats output_stats(destination_fname);
    if( out_bytes_header + out_bytes_payload != output_stats.size() ) {
        ERR_PRINT2("Encrypt: Writing done, %s header + %s payload != %s total bytes",
                jau::to_decstring(out_bytes_header).c_str(),
                jau::to_decstring(out_bytes_payload).c_str(),
                jau::to_decstring(output_stats.size()).c_str());
        jau::fs::remove(destination_fname);
        ph.setValid(false);
        my_listener->notifyEnd(decrypt_mode, ph, false);
        return header;
    }

    WORDY_PRINT("Encrypt: Writing done: output: %s", output_stats.to_string().c_str());
    my_listener->notifyEnd(decrypt_mode, ph, true);
    return ph;
}


static PackHeader checkSignThenDecrypt_Impl(const std::vector<std::string>& sign_pub_keys,
                                            const std::string& dec_sec_key_fname, const jau::io::secure_string& passphrase,
                                            jau::io::ByteInStream& source,
                                            CipherpackListenerRef listener,
                                            const std::string_view& payload_hash_algo) {
    const bool decrypt_mode = true;
    environment::get();
    jau::fraction_timespec ts_creation;
    PackHeader header(ts_creation);

    if( nullptr == listener ) {
        ERR_PRINT2("Decrypt failed: Listener is nullptr for source %s", source.to_string().c_str());
        return header;
    }

    const jau::fraction_timespec _t0 = jau::getMonotonicTime();

    if( source.end_of_data() || source.error() ) {
        ERR_PRINT2("Decrypt failed: Source is EOS or has an error %s", source.to_string().c_str());
        return header;
    }
    try {
        Botan::RandomNumberGenerator& rng = Botan::system_rng();

        struct sender_data_t {
            std::shared_ptr<Botan::Public_Key> pub_key;
            std::string fingerprint;
        };
        std::vector<sender_data_t> sender_data_list;
        for( const std::string& pub_key_fname : sign_pub_keys ) {
            sender_data_t sender_data;
            sender_data.pub_key = load_public_key(pub_key_fname);
            if( !sender_data.pub_key ) {
                return header;
            }
            sender_data_list.push_back(sender_data);
        }
        std::shared_ptr<Botan::Public_Key> sender_pub_key = nullptr; // not found

        std::vector<std::string> recevr_fingerprints;
        std::shared_ptr<Botan::Private_Key> dec_sec_key = load_private_key(dec_sec_key_fname, passphrase);
        if( !dec_sec_key ) {
            return header;
        }

        std::string package_magic_in;
        std::string target_path;
        std::string subject;
        uint64_t content_size;
        std::string payload_version;
        std::string payload_version_parent;

        CryptoConfig crypto_cfg;
        Botan::OID sym_enc_algo_oid;

        std::string fingerprt_sender;
        size_t recevr_count;
        ssize_t used_recevr_key_idx = -1;
        std::vector<uint8_t> encrypted_sym_key;
        std::vector<uint8_t> encrypted_nonce;

        std::vector<uint8_t> sender_signature;

        std::unique_ptr<Botan::HashFunction> hash_func = nullptr;
        if( !payload_hash_algo.empty() ) {
            const std::string payload_hash_algo_s(payload_hash_algo);
            hash_func = Botan::HashFunction::create(payload_hash_algo_s);
            if( nullptr == hash_func ) {
                ERR_PRINT2("Decrypt failed: Payload hash algo %s not available", payload_hash_algo_s.c_str());
                return header;
            }
        }

        jau::io::secure_vector<uint8_t> input_buffer;
        jau::io::ByteInStream_Recorder input(source, input_buffer);
        uint64_t in_bytes_header = 0;

        try {
            // DER-Header-1
            input.start_recording();
            {
                std::vector<uint8_t> package_magic_charvec;

                Botan::BER_Decoder ber0(input);

                Botan::BER_Decoder ber = ber0.start_sequence();
                ber.decode(package_magic_charvec, Botan::ASN1_Type::OctetString);
                package_magic_in = to_string(package_magic_charvec);

                if( Constants::package_magic != package_magic_in ) {
                    ERR_PRINT2("Decrypt failed: Expected Magic %s, but got %s in %s", Constants::package_magic.c_str(), package_magic_in.c_str(), source.to_string().c_str());
                    return header;
                }
                DBG_PRINT("Decrypt: Magic is %s", package_magic_in.c_str());

                std::vector<uint8_t> target_path_charvec;
                Botan::BigInt bi_content_size;
                Botan::BigInt bi_ts_creation_sec;
                Botan::BigInt bi_ts_creation_nsec;
                std::vector<uint8_t> subject_charvec;
                std::vector<uint8_t> payload_version_charvec;
                std::vector<uint8_t> payload_version_parent_charvec;

                std::vector<uint8_t> pk_type_cv;
                std::vector<uint8_t> pk_fingerprt_hash_algo_cv;
                std::vector<uint8_t> pk_enc_padding_algo_cv;
                std::vector<uint8_t> pk_enc_hash_algo_cv;
                std::vector<uint8_t> pk_sign_algo_cv;

                std::vector<uint8_t> fingerprt_sender_charvec;
                Botan::BigInt bi_recevr_count;

                ber.decode( target_path_charvec, Botan::ASN1_Type::OctetString )
                   .decode( bi_content_size, Botan::ASN1_Type::Integer )
                   .decode( bi_ts_creation_sec, Botan::ASN1_Type::Integer )
                   .decode( bi_ts_creation_nsec, Botan::ASN1_Type::Integer )
                   .decode( subject_charvec, Botan::ASN1_Type::OctetString )
                   .decode( payload_version_charvec, Botan::ASN1_Type::OctetString )
                   .decode( payload_version_parent_charvec, Botan::ASN1_Type::OctetString )
                   .decode( pk_type_cv, Botan::ASN1_Type::OctetString )
                   .decode( pk_fingerprt_hash_algo_cv, Botan::ASN1_Type::OctetString )
                   .decode( pk_enc_padding_algo_cv, Botan::ASN1_Type::OctetString )
                   .decode( pk_enc_hash_algo_cv, Botan::ASN1_Type::OctetString )
                   .decode( pk_sign_algo_cv, Botan::ASN1_Type::OctetString )
                   .decode( sym_enc_algo_oid )
                   .decode( fingerprt_sender_charvec, Botan::ASN1_Type::OctetString )
                   .decode( bi_recevr_count, Botan::ASN1_Type::Integer )
                   .end_cons()
                   ;

                target_path = to_string(target_path_charvec);
                subject = to_string(subject_charvec);
                content_size = to_uint64_t(bi_content_size);
                ts_creation.tv_sec = static_cast<int64_t>( to_uint64_t(bi_ts_creation_sec) );
                ts_creation.tv_nsec = static_cast<int64_t>( to_uint64_t(bi_ts_creation_nsec) );
                payload_version = to_string(payload_version_charvec);
                payload_version_parent = to_string(payload_version_parent_charvec);
                crypto_cfg.pk_type = to_string( pk_type_cv );
                crypto_cfg.pk_fingerprt_hash_algo = to_string( pk_fingerprt_hash_algo_cv );
                crypto_cfg.pk_enc_padding_algo = to_string( pk_enc_padding_algo_cv );
                crypto_cfg.pk_enc_hash_algo = to_string( pk_enc_hash_algo_cv );
                crypto_cfg.pk_sign_algo = to_string( pk_sign_algo_cv );
                crypto_cfg.sym_enc_algo = Botan::OIDS::oid2str_or_empty( sym_enc_algo_oid );
                fingerprt_sender = to_string(fingerprt_sender_charvec);
                recevr_count = to_uint64_t(bi_recevr_count);
            }

            header = PackHeader(target_path,
                                content_size,
                                ts_creation,
                                subject,
                                payload_version, payload_version_parent,
                                crypto_cfg,
                                fingerprt_sender,
                                recevr_fingerprints,
                                used_recevr_key_idx,
                                false /* valid */);

            if( target_path.empty() ) {
               ERR_PRINT2("Decrypt failed: Unknown target_path in %s", source.to_string().c_str());
               listener->notifyHeader(decrypt_mode, header, false);
               return header;
            }
            if( 0 == content_size ) {
               ERR_PRINT2("Decrypt failed: Zero file-size in %s", source.to_string().c_str());
               listener->notifyHeader(decrypt_mode, header, false);
               return header;
            }

            for( sender_data_t& sign_key_data : sender_data_list ) {
                if( sign_key_data.pub_key->algo_name() == crypto_cfg.pk_type ) {
                    sign_key_data.fingerprint = sign_key_data.pub_key->fingerprint_public( crypto_cfg.pk_fingerprt_hash_algo );
                }
            }
            if( !fingerprt_sender.empty() ) {
                for( const sender_data_t& sender_data : sender_data_list ) {
                    if( sender_data.pub_key->algo_name() == crypto_cfg.pk_type &&
                        fingerprt_sender == sender_data.fingerprint )
                    {
                            sender_pub_key = sender_data.pub_key;
                            break;
                    }
                }
            }
            if( nullptr == sender_pub_key ) {
                jau::INFO_PRINT("Decrypt failed: No matching sender fingerprint, received `%s` in %s",
                        fingerprt_sender.c_str(), source.to_string().c_str());
                listener->notifyHeader(decrypt_mode, header, false);
                return header;
            }

            Botan::PK_Verifier verifier(*sender_pub_key, crypto_cfg.pk_sign_algo);
            verifier.update( input.get_recording() );
            in_bytes_header += input.get_recording().size();
            input.start_recording(); // start over ..

            const std::string dec_key_fingerprint = dec_sec_key->fingerprint_public(crypto_cfg.pk_fingerprt_hash_algo);
            std::vector<uint8_t> fingerprint_charvec;
            std::vector<uint8_t> encrypted_sym_key_temp;
            std::vector<uint8_t> encrypted_nonce_temp;

            // DER-Header per receiver
            for(size_t idx=0; idx < recevr_count; idx++) {
                Botan::BER_Decoder ber(input);
                ber.start_sequence()
                   .decode(fingerprint_charvec, Botan::ASN1_Type::OctetString)
                   .decode(encrypted_sym_key_temp, Botan::ASN1_Type::OctetString)
                   .decode(encrypted_nonce_temp, Botan::ASN1_Type::OctetString)
                   .end_cons()
                   ;
                verifier.update( input.get_recording() );
                in_bytes_header += input.get_recording().size();
                input.start_recording(); // start over ..

                const std::string fingerprint = to_string(fingerprint_charvec);
                recevr_fingerprints.push_back(fingerprint);

                if( 0 > used_recevr_key_idx  ) {
                    if( !fingerprint.empty() && fingerprint == dec_key_fingerprint ) {
                        // match, we found our entry
                        used_recevr_key_idx = idx;
                        encrypted_sym_key = encrypted_sym_key_temp; // pick the encrypted key
                        encrypted_nonce = encrypted_nonce_temp;     // and encrypted nonce
                    }
                }
            }
            if( 0 > used_recevr_key_idx || 0 == recevr_count ) {
                jau::INFO_PRINT("Decrypt failed: No matching receiver key found %zd/%zu in %s", used_recevr_key_idx, recevr_count, source.to_string().c_str());
                header = PackHeader(target_path,
                                    content_size,
                                    ts_creation,
                                    subject,
                                    payload_version, payload_version_parent,
                                    crypto_cfg,
                                    fingerprt_sender,
                                    recevr_fingerprints,
                                    used_recevr_key_idx,
                                    false /* valid */);
                listener->notifyHeader(decrypt_mode, header, false);
                return header;
            }

            header = PackHeader(target_path,
                                content_size,
                                ts_creation,
                                subject,
                                payload_version, payload_version_parent,
                                crypto_cfg,
                                fingerprt_sender,
                                recevr_fingerprints,
                                used_recevr_key_idx,
                                false /* valid */);

            const uint64_t in_bytes_signature = in_bytes_header;
            {
                Botan::BER_Decoder ber(input);
                ber.start_sequence()
                   .decode(sender_signature, Botan::ASN1_Type::OctetString)
                   .end_cons() // encrypted data follows ..
                   ;
                in_bytes_header += input.get_recording().size();
                input.clear_recording(); // implies stop
            }
            if( !verifier.check_signature(sender_signature) ) {
                ERR_PRINT2("Decrypt failed: Signature mismatch on %" PRIu64 " header bytes / % " PRIu64 " bytes, received signature %s in %s",
                        in_bytes_signature, in_bytes_header,
                        jau::bytesHexString(sender_signature.data(), 0, sender_signature.size(), true /* lsbFirst */).c_str(),
                        source.to_string().c_str());
                listener->notifyHeader(decrypt_mode, header, false);
                return header;
            }

            DBG_PRINT("Decrypt: Signature OK for %" PRIu64 " header bytes / %" PRIu64 ": %s from %s",
                    in_bytes_signature, in_bytes_header,
                    jau::bytesHexString(sender_signature.data(), 0, sender_signature.size(), true /* lsbFirst */).c_str(),
                    source.to_string().c_str());

            DBG_PRINT("Decrypt: DER Header*: enc_key %zu/%zu (size %zd): %s",
                    used_recevr_key_idx, recevr_count, encrypted_sym_key.size(),
                    header.toString(true /* show_crypto_algos */, true /* force_all_fingerprints */).c_str());
        } catch (Botan::Decoding_Error &e) {
            ERR_PRINT("Decrypt failed: Caught exception: %s on %s", e.what(), source.to_string().c_str());
            return header;
        }
        DBG_PRINT("Decrypt: target_path '%s', net_file_size %s, version %s (parent %s), intention %s",
                target_path.c_str(), jau::to_decstring(content_size).c_str(),
                payload_version.c_str(),
                payload_version_parent.c_str(),
                subject.c_str());
        DBG_PRINT("Decrypt: creation time %s UTC", ts_creation.to_iso8601_string().c_str());

        listener->notifyHeader(decrypt_mode, header, true);

        //
        // Symmetric Encryption
        //

        std::shared_ptr<Botan::AEAD_Mode> aead = Botan::AEAD_Mode::create_or_throw(crypto_cfg.sym_enc_algo, Botan::DECRYPTION);
        if(!aead) {
           ERR_PRINT2("Decrypt failed: sym_enc_algo %s not available from %s", crypto_cfg.sym_enc_algo.c_str(), source.to_string().c_str());
           return header;
        }
        const size_t expected_keylen = aead->key_spec().maximum_keylength();

        Botan::PK_Decryptor_EME dec(*dec_sec_key, rng, crypto_cfg.pk_enc_padding_algo+"(" + crypto_cfg.pk_enc_hash_algo + ")");

        const jau::io::secure_vector<uint8_t> plain_file_key =
                dec.decrypt_or_random(encrypted_sym_key.data(), encrypted_sym_key.size(), expected_keylen, rng);
        const jau::io::secure_vector<uint8_t> nonce = dec.decrypt(encrypted_nonce);
        crypto_cfg.sym_enc_nonce_bytes = nonce.size();
        header = PackHeader(target_path,
                            content_size,
                            ts_creation,
                            subject,
                            payload_version, payload_version_parent,
                            crypto_cfg,
                            fingerprt_sender,
                            recevr_fingerprints,
                            used_recevr_key_idx,
                            false /* valid */);
        DBG_PRINT("Decrypt sym_key[sz %zd], %s", plain_file_key.size(), crypto_cfg.to_string().c_str());

        if( !crypto_cfg.valid() ) {
            ERR_PRINT2("Decrypt failed: CryptoConfig incomplete %s from %s", crypto_cfg.to_string().c_str(), source.to_string().c_str());
            listener->notifyHeader(decrypt_mode, header, false);
            return header;
        }

        aead->set_key(plain_file_key);
        aead->set_associated_data_vec(sender_signature);
        aead->start(nonce);

        const bool sent_content_to_user = listener->getSendContent( decrypt_mode );
        uint64_t out_bytes_payload = 0;
        jau::io::StreamConsumerFunc consume_data = [&](jau::io::secure_vector<uint8_t>& data, bool is_final) -> bool {
            bool res = true;
            if( !is_final && out_bytes_payload + data.size() < content_size ) {
                aead->update(data);
                if( nullptr != hash_func ) {
                    hash_func->update(data);
                }
                if( sent_content_to_user ) {
                    res = listener->contentProcessed(decrypt_mode, CipherpackListener::content_type::payload, data, false /* is_final */);
                }
                out_bytes_payload += data.size();
                DBG_PRINT("Decrypt: DecPayload written0 + %zu bytes -> %" PRIu64 " bytes / %zu bytes, user[sent %d, res %d]",
                        data.size(), out_bytes_payload, content_size, sent_content_to_user, res);
                listener->notifyProgress(decrypt_mode, content_size, out_bytes_payload);
                return res; // continue if user so desires
            } else {
                aead->finish(data);
                if( nullptr != hash_func ) {
                    hash_func->update(data);
                }
                if( sent_content_to_user ) {
                    res = listener->contentProcessed(decrypt_mode, CipherpackListener::content_type::payload, data, true /* is_final */);
                }
                out_bytes_payload += data.size();
                DBG_PRINT("Decrypt: DecPayload writtenF + %zu bytes -> %" PRIu64 " bytes / %zu bytes, user[sent %d, res %d]",
                        data.size(), out_bytes_payload, content_size, sent_content_to_user, res);
                listener->notifyProgress(decrypt_mode, content_size, out_bytes_payload);
                return false; // EOS
            }
        };
        jau::io::secure_vector<uint8_t> io_buffer;
        io_buffer.reserve(Constants::buffer_size);
        const uint64_t in_bytes_total = jau::io::read_stream(input, io_buffer, consume_data);
        input.close();

        if( nullptr != hash_func ) {
            std::vector<uint8_t> hash_value( hash_func->output_length() );
            hash_func->final(hash_value.data());
            header.setPayloadHash(hash_func->name(), hash_value);
        }

        if ( 0==in_bytes_total || source.error() ) {
            ERR_PRINT2("Decrypt failed: Input file read failed %s", source.to_string().c_str());
            return header;
        }
        if( out_bytes_payload != content_size ) {
            ERR_PRINT2("Decrypt: Writing done, %s output payload != %s header files size from %s",
                    jau::to_decstring(out_bytes_payload).c_str(),
                    jau::to_decstring(content_size).c_str(), source.to_string().c_str());
            return header;
        } else {
            WORDY_PRINT("Decrypt: Reading done from %s", source.to_string().c_str());
            WORDY_PRINT("Decrypt: Writing done, %s total bytes from %s bytes input, ratio %lf in/out",
                    jau::to_decstring(out_bytes_payload).c_str(),
                    jau::to_decstring(in_bytes_total).c_str(),
                    (double)out_bytes_payload/(double)in_bytes_total);
        }

        const jau::fraction_i64 _td = ( jau::getMonotonicTime() - _t0 ).to_fraction_i64();
        if( jau::environment::get().verbose ) {
            jau::io::print_stats("Decrypt", out_bytes_payload, _td);
        }

        header.setValid(true);
        return header;
    } catch (std::exception &e) {
        ERR_PRINT("Decrypt failed: Caught exception: %s on %s", e.what(), source.to_string().c_str());
        return header;
    }
}

PackHeader cipherpack::checkSignThenDecrypt(const std::vector<std::string>& sign_pub_keys,
                                            const std::string& dec_sec_key_fname, const jau::io::secure_string& passphrase,
                                            jau::io::ByteInStream& source,
                                            CipherpackListenerRef listener,
                                            const std::string_view& payload_hash_algo,
                                            const std::string destination_fname) {
    environment::get();
    const bool decrypt_mode = true;

    if( destination_fname.empty() ) {
        PackHeader ph = checkSignThenDecrypt_Impl(sign_pub_keys,
                                                  dec_sec_key_fname, passphrase,
                                                  source, listener, payload_hash_algo);
        listener->notifyEnd(decrypt_mode, ph, ph.isValid());
        return ph;
    }

    jau::fraction_timespec ts_creation;
    PackHeader header(ts_creation);

    if( nullptr == listener ) {
        ERR_PRINT2("Decrypt failed: Listener is nullptr for source %s", source.to_string().c_str());
        return header;
    }

    class MyListener : public WrappingCipherpackListener {
        private:
            std::ofstream* outfile_;
            uint64_t& out_bytes_payload_;
        public:
            MyListener(CipherpackListenerRef parent_, uint64_t& bytes_payload)
            : WrappingCipherpackListener(parent_), outfile_(nullptr),
              out_bytes_payload_(bytes_payload)
            {}

            void set_outfile(std::ofstream* of) noexcept { outfile_ = of; }

            bool getSendContent(const bool decrypt_mode) const noexcept override {
                return true;
            }

            bool contentProcessed(const bool decrypt_mode, const content_type ctype, jau::io::secure_vector<uint8_t>& data, const bool is_final) noexcept override {
                if( nullptr != outfile_ && content_type::payload == ctype ) {
                    outfile_->write(reinterpret_cast<char*>(data.data()), data.size());
                    if( outfile_->fail() ) {
                        return false;
                    }
                    out_bytes_payload_ += data.size();
                }
                if( parent->getSendContent(decrypt_mode) ) {
                    return parent->contentProcessed(decrypt_mode, ctype, data, is_final);
                } else {
                    return true;
                }
            }
    };
    uint64_t out_bytes_payload=0;
    std::shared_ptr<MyListener> my_listener = std::make_shared<MyListener>(listener, out_bytes_payload);
    {
        const jau::fs::file_stats output_stats(destination_fname);
        if( output_stats.exists() ) {
            if( output_stats.is_file() ) {
                if( !jau::fs::remove(destination_fname) ) {
                    ERR_PRINT2("Decrypt failed: Failed deletion of existing output file %s", output_stats.to_string().c_str());
                    my_listener->notifyEnd(decrypt_mode, header, false);
                    return header;
                }
            } else {
                ERR_PRINT2("Decrypt failed: Not overwriting existing %s", output_stats.to_string().c_str());
                my_listener->notifyEnd(decrypt_mode, header, false);
                return header;
            }
        }
    }
    std::ofstream outfile(destination_fname, std::ios::out | std::ios::binary);
    if ( !outfile.good() || !outfile.is_open() ) {
        ERR_PRINT2("Decrypt failed: Output file not open %s", destination_fname.c_str());
        my_listener->notifyEnd(decrypt_mode, header, false);
        return header;
    }
    my_listener->set_outfile(&outfile);

    PackHeader ph = checkSignThenDecrypt_Impl(sign_pub_keys,
                                              dec_sec_key_fname, passphrase,
                                              source, my_listener, payload_hash_algo);
    if ( outfile.fail() ) {
        ERR_PRINT2("Decrypt failed: Output file write failed %s", destination_fname.c_str());
        jau::fs::remove(destination_fname);
        ph.setValid(false);
        my_listener->notifyEnd(decrypt_mode, ph, false);
        return ph;
    }
    outfile.close();

    if( !ph.isValid() ) {
        jau::fs::remove(destination_fname);
        my_listener->notifyEnd(decrypt_mode, ph, false);
        return ph;
    }

    const jau::fs::file_stats output_stats(destination_fname);
    if( ph.getContentSize() != output_stats.size() ) {
        ERR_PRINT2("Decrypt: Writing done, %s content_size != %s total bytes",
                jau::to_decstring(ph.getContentSize()).c_str(),
                jau::to_decstring(output_stats.size()).c_str());
        jau::fs::remove(destination_fname);
        ph.setValid(false);
        my_listener->notifyEnd(decrypt_mode, ph, false);
        return ph;
    }

    WORDY_PRINT("Decrypt: Writing done: output: %s", output_stats.to_string().c_str());
    my_listener->notifyEnd(decrypt_mode, ph, true);
    return ph;
}

