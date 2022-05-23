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

#include <elevator/elevator.hpp>

#include <jau/debug.hpp>
#include <jau/file_util.hpp>

#include <botan_all.h>

using namespace elevator;
using namespace elevator::cipherpack;

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

PackInfo elevator::cipherpack::encryptThenSign_RSA1(const CryptoConfig& crypto_cfg,
                                                    const std::vector<std::string> &enc_pub_keys,
                                                    const std::string &sign_sec_key_fname, const std::string &passphrase,
                                                    const std::string &input_fname,
                                                    const std::string &target_path, const std::string &intention,
                                                    const uint64_t payload_version,
                                                    const uint64_t payload_version_parent,
                                                    const std::string &output_fname, const bool overwrite) {
    Elevator::env_init();

    const jau::fraction_timespec ts_creation = jau::getWallClockTime();

    if( !crypto_cfg.valid() ) {
        ERR_PRINT2("Encrypt failed: CryptoConfig incomplete %s", crypto_cfg.toString().c_str());
        return PackInfo(PackHeader(ts_creation), input_fname, false);
    }

    const jau::fraction_timespec _t0 = jau::getMonotonicTime();

    const jau::fs::file_stats input_stats(input_fname);
    if( !input_stats.exists() || !input_stats.has_access() || !input_stats.is_file() ) {
        ERR_PRINT2("Encrypt failed: Input file not accessible %s", input_stats.to_string(true).c_str());
        return PackInfo(PackHeader(ts_creation), input_fname, false);
    }
    if( 0 == input_stats.size() ) {
        ERR_PRINT2("Encrypt failed: Input file has zero size %s", input_stats.to_string(true).c_str());
        return PackInfo(PackHeader(ts_creation), input_fname, false);
    }
    if( target_path.empty() ) {
        ERR_PRINT2("Encrypt failed: Target path is empty for %s", input_stats.to_string(true).c_str());
        return PackInfo(PackHeader(ts_creation), input_fname, false);
    }
    {
        const jau::fs::file_stats output_stats(output_fname);
        if( output_stats.exists() ) {
            if( overwrite && output_stats.is_file() ) {
                if( !io::remove(output_fname) ) {
                    ERR_PRINT2("Encrypt failed: Failed deletion of existing output file %s", output_stats.to_string(true).c_str());
                    return PackInfo(PackHeader(ts_creation), input_fname, false);
                }
            } else {
                ERR_PRINT2("Encrypt failed: Not overwriting existing output file %s", output_stats.to_string(true).c_str());
                return PackInfo(PackHeader(ts_creation), input_fname, false);
            }
        }
    }
    std::ofstream outfile(output_fname, std::ios::out | std::ios::binary);
    if ( !outfile.good() || !outfile.is_open() ) {
        ERR_PRINT2("Encrypt failed: Output file not open %s", output_fname.c_str());
        return PackInfo(PackHeader(ts_creation), input_fname, false);
    }
    uint64_t out_bytes_header;

    try {
        Botan::RandomNumberGenerator& rng = Botan::system_rng();

        std::shared_ptr<Botan::Private_Key> sign_sec_key = load_private_key(sign_sec_key_fname, passphrase);
        if( !sign_sec_key ) {
            return PackInfo(PackHeader(ts_creation), input_fname, false);
        }

        const Botan::OID sym_enc_algo_oid = Botan::OID::from_string(crypto_cfg.sym_enc_algo);
        if( sym_enc_algo_oid.empty() ) {
            ERR_PRINT2("Encrypt failed: No OID defined for cypher algo %s", crypto_cfg.sym_enc_algo.c_str());
            return PackInfo(PackHeader(ts_creation), input_fname, false);
        }
        std::shared_ptr<Botan::AEAD_Mode> aead = Botan::AEAD_Mode::create(crypto_cfg.sym_enc_algo, Botan::ENCRYPTION);
        if(!aead) {
           ERR_PRINT2("Encrypt failed: AEAD algo %s not available", crypto_cfg.sym_enc_algo.c_str());
           return PackInfo(PackHeader(ts_creation), input_fname, false);
        }
        Botan::secure_vector<uint8_t> plain_file_key = rng.random_vec(aead->key_spec().maximum_keylength());
        Botan::secure_vector<uint8_t> nonce = rng.random_vec(crypto_cfg.sym_enc_nonce_bytes);
        const std::string host_key_fingerprint = sign_sec_key->fingerprint_public(crypto_cfg.pk_fingerprt_hash_algo);

        struct enc_key_data_t {
            std::shared_ptr<Botan::Public_Key> pub_key;
            std::vector<uint8_t> encrypted_file_key;
        };
        std::vector<enc_key_data_t> enc_key_data_list;
        std::vector<std::string> enc_pub_keys_fingerprint;

        for( const std::string& pub_key_fname : enc_pub_keys ) {
            enc_key_data_t enc_key_data;

            enc_key_data.pub_key = load_public_key(pub_key_fname);
            if( !enc_key_data.pub_key ) {
                return PackInfo(PackHeader(ts_creation), input_fname, false);
            }
            Botan::PK_Encryptor_EME enc(*enc_key_data.pub_key, rng, crypto_cfg.pk_enc_padding_algo+"(" + crypto_cfg.pk_enc_hash_algo + ")");

            enc_key_data.encrypted_file_key = enc.encrypt(plain_file_key, rng);
            enc_key_data_list.push_back(enc_key_data);
        }

        std::vector<uint8_t> signature;
        {
            Botan::secure_vector<uint8_t> header_buffer;
            header_buffer.reserve(Constants::buffer_size);

            // DER-Header-1
            header_buffer.clear();
            {
                Botan::DER_Encoder der(header_buffer);
                der.start_sequence()
                   .encode( to_OctetString( Constants::package_magic ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( target_path ), Botan::ASN1_Type::OctetString )
                   .encode( to_BigInt( static_cast<uint64_t>( input_stats.size() ) ), Botan::ASN1_Type::Integer )
                   .encode( to_BigInt( static_cast<uint64_t>( ts_creation.tv_sec ) ), Botan::ASN1_Type::Integer )
                   .encode( to_OctetString( intention ), Botan::ASN1_Type::OctetString )
                   .encode( to_BigInt(payload_version), Botan::ASN1_Type::Integer )
                   .encode( to_BigInt(payload_version_parent), Botan::ASN1_Type::Integer )
                   .encode( to_OctetString( crypto_cfg.pk_type ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( crypto_cfg.pk_fingerprt_hash_algo ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( crypto_cfg.pk_enc_padding_algo ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( crypto_cfg.pk_enc_hash_algo ), Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( crypto_cfg.pk_sign_algo ), Botan::ASN1_Type::OctetString )
                   .encode( sym_enc_algo_oid )
                   .encode( nonce, Botan::ASN1_Type::OctetString )
                   .encode( to_OctetString( host_key_fingerprint ), Botan::ASN1_Type::OctetString )
                   .encode( enc_key_data_list.size(), Botan::ASN1_Type::Integer );

                for(const enc_key_data_t& enc_key_data : enc_key_data_list) {
                    const std::string fingerprt_term = enc_key_data.pub_key->fingerprint_public(crypto_cfg.pk_fingerprt_hash_algo);
                    enc_pub_keys_fingerprint.push_back(fingerprt_term);
                    der.encode( to_OctetString( fingerprt_term ), Botan::ASN1_Type::OctetString )
                       .encode( enc_key_data.encrypted_file_key, Botan::ASN1_Type::OctetString );
                }

                der.end_cons(); // data push
            }
            outfile.write((char*)header_buffer.data(), header_buffer.size());
            out_bytes_header = header_buffer.size();
            DBG_PRINT("Encrypt: DER Header1 written + %zu bytes -> %" PRIu64 " bytes, enc_keys %zu",
                    header_buffer.size(), out_bytes_header, enc_key_data_list.size());

            // DER-Header-2 (signature)
            Botan::PK_Signer signer(*sign_sec_key, rng, crypto_cfg.pk_sign_algo);
            signature = signer.sign_message(header_buffer, rng);
            DBG_PRINT("Encrypt: Signature for %zu bytes: %s",
                    header_buffer.size(),
                    jau::bytesHexString(signature.data(), 0, signature.size(), true /* lsbFirst */).c_str());
            header_buffer.clear();
            {
                Botan::DER_Encoder der(header_buffer);
                der.start_sequence()
                   .encode( signature, Botan::ASN1_Type::OctetString )
                   .end_cons();
            }
            outfile.write((char*)header_buffer.data(), header_buffer.size());
            out_bytes_header += header_buffer.size();
            DBG_PRINT("Encrypt: DER Header2 written + %zu bytes -> %" PRIu64 " bytes", header_buffer.size(), out_bytes_header);
        }

        uint64_t out_bytes_total = outfile.tellp();
        if( out_bytes_header != out_bytes_total ) {
            ERR_PRINT2("Encrypt: DER Header done, %" PRIu64 " header != %" PRIu64 " total bytes", out_bytes_header, out_bytes_total);
            io::remove(output_fname);
            return PackInfo(PackHeader(ts_creation), input_fname, false);
        } else {
            DBG_PRINT("Encrypt: DER Header done, %" PRIu64 " header == %" PRIu64 " total bytes", out_bytes_header, out_bytes_total);
        }

        aead->set_key(plain_file_key);
        aead->set_associated_data_vec(signature);
        aead->start(nonce);

        uint64_t out_bytes_payload = 0;
        io::StreamConsumerFunc consume_data = [&](Botan::secure_vector<uint8_t>& data, bool is_final) -> bool {
            if( !is_final ) {
                aead->update(data);
                outfile.write(reinterpret_cast<char*>(data.data()), data.size());
                out_bytes_payload += data.size();
                DBG_PRINT("Encrypt: EncPayload written0 + %zu bytes -> %" PRIu64 " bytes / %zu bytes", data.size(), out_bytes_payload, input_stats.size());
            } else {
                aead->finish(data);
                outfile.write(reinterpret_cast<char*>(data.data()), data.size());
                out_bytes_payload += data.size();
                DBG_PRINT("Encrypt: EncPayload writtenF + %zu bytes -> %" PRIu64 " bytes / %zu bytes", data.size(), out_bytes_payload, input_stats.size());
            }
            return true;
        };
        Botan::secure_vector<uint8_t> io_buffer;
        io_buffer.reserve(Constants::buffer_size);
        const uint64_t in_bytes_total = io::read_file(input_fname, input_stats.size(), io_buffer, consume_data);

        if ( 0==in_bytes_total || outfile.fail() ) {
            ERR_PRINT2("Encrypt failed: Output file write failed %s", output_fname.c_str());
            io::remove(output_fname);
            return PackInfo(PackHeader(ts_creation), input_fname, false);
        }

        out_bytes_total = outfile.tellp();
        outfile.close();
        const jau::fs::file_stats output_stats(output_fname);
        if( out_bytes_header + out_bytes_payload != out_bytes_total ) {
            ERR_PRINT2("Encrypt: Writing done, %s header + %s payload != %s total bytes for %s bytes input",
                    jau::to_decstring(out_bytes_header).c_str(),
                    jau::to_decstring(out_bytes_payload).c_str(),
                    jau::to_decstring(out_bytes_total).c_str(),
                    jau::to_decstring(in_bytes_total).c_str());
            io::remove(output_fname);
            return PackInfo(PackHeader(ts_creation), input_fname, false);
        } else if( output_stats.size() != out_bytes_total ) {
            ERR_PRINT2("Encrypt: Writing done, %s total bytes != %s",
                    jau::to_decstring(out_bytes_payload).c_str(),
                    output_stats.to_string(true).c_str() );
            io::remove(output_fname);
            return PackInfo(PackHeader(ts_creation), input_fname, false);
        } else if( input_stats.size() != in_bytes_total ) {
            ERR_PRINT2("Encrypt: Writing done, %s != %s bytes input",
                    input_stats.to_string(true).c_str(),
                    jau::to_decstring(in_bytes_total).c_str());
            io::remove(output_fname);
            return PackInfo(PackHeader(ts_creation), input_fname, false);
        } else if( jau::environment::get().verbose ) {
            jau::PLAIN_PRINT(true, "Encrypt: Writing done, %s header + %s payload == %s total bytes for %s bytes input, ratio %lf out/in",
                    jau::to_decstring(out_bytes_header).c_str(),
                    jau::to_decstring(out_bytes_payload).c_str(),
                    jau::to_decstring(out_bytes_total).c_str(),
                    jau::to_decstring(in_bytes_total).c_str(), (double)out_bytes_total/(double)in_bytes_total);
            jau::PLAIN_PRINT(true, "Encrypt: Writing done: input : %s", input_stats.to_string(true).c_str());
            jau::PLAIN_PRINT(true, "Encrypt: Writing done: output: %s", output_stats.to_string(true).c_str());
        }

        const jau::fraction_i64 _td = ( jau::getMonotonicTime() - _t0 ).to_fraction_i64();
        io::print_stats("Encrypt", out_bytes_total, _td);

        return PackInfo( PackHeader(target_path,
                                    input_stats.size(),
                                    ts_creation,
                                    intention,
                                    payload_version, payload_version_parent,
                                    crypto_cfg,
                                    host_key_fingerprint,
                                    enc_pub_keys_fingerprint,
                                    -1 /* term_key_fingerprint_used_idx */,
                                    true /* valid */),
                         input_fname, false, output_stats, true);
    } catch (std::exception &e) {
        ERR_PRINT2("Encrypt failed: Caught exception: %s", e.what());
        io::remove(output_fname);
        return PackInfo(ts_creation, input_fname, false);
    }
}

PackInfo elevator::cipherpack::checkSignThenDecrypt_RSA1(const std::vector<std::string>& sign_pub_keys,
                                                         const std::string &dec_sec_key_fname, const std::string &passphrase,
                                                         io::DataSource_Closeable &source,
                                                         const std::string &output_fname, const bool overwrite) {
    Elevator::env_init();

    jau::fraction_timespec ts_creation;

    const jau::fraction_timespec _t0 = jau::getMonotonicTime();
    {
        const jau::fs::file_stats output_stats(output_fname);
        if( output_stats.exists() ) {
            if( overwrite && output_stats.is_file() ) {
                if( !io::remove(output_fname) ) {
                    ERR_PRINT2("Decrypt failed: Failed deletion of existing output file %s", output_fname.c_str());
                    return PackInfo(ts_creation, source.id(), true);
                }
            } else {
                ERR_PRINT2("Decrypt failed: Not overwriting existing output file %s", output_fname.c_str());
                return PackInfo(ts_creation, source.id(), true);
            }
        }
    }
    std::ofstream outfile(output_fname, std::ios::out | std::ios::binary);
    if ( !outfile.good() || !outfile.is_open() ) {
        ERR_PRINT2("Decrypt failed: Couldn't open output file %s", output_fname.c_str());
        return PackInfo(ts_creation, source.id(), true);
    }

    try {
        Botan::RandomNumberGenerator& rng = Botan::system_rng();

        struct sign_key_data_t {
            std::shared_ptr<Botan::Public_Key> pub_key;
            std::string fingerprint;
        };
        std::vector<sign_key_data_t> sign_key_data_list;
        for( const std::string& pub_key_fname : sign_pub_keys ) {
            sign_key_data_t sign_key_data;
            sign_key_data.pub_key = load_public_key(pub_key_fname);
            if( !sign_key_data.pub_key ) {
                return PackInfo(ts_creation, source.id(), false);
            }
            sign_key_data_list.push_back(sign_key_data);
        }
        std::shared_ptr<Botan::Public_Key> sign_pub_key = nullptr; // not found

        std::vector<std::string> term_keys_fingerprint;
        std::shared_ptr<Botan::Private_Key> dec_sec_key = load_private_key(dec_sec_key_fname, passphrase);
        if( !dec_sec_key ) {
            return PackInfo(ts_creation, source.id(), true);
        }

        std::string package_magic_in;
        std::string target_path;
        std::string intention;
        uint64_t file_size;
        uint64_t payload_version;
        uint64_t payload_version_parent;

        CryptoConfig crypto_cfg;
        Botan::OID sym_enc_algo_oid;

        std::string host_key_fingerprt;
        size_t encrypted_key_count;
        ssize_t encrypted_key_idx = -1;
        std::vector<uint8_t> encrypted_file_key;
        std::vector<uint8_t> nonce;

        std::vector<uint8_t> signature;

        Botan::secure_vector<uint8_t> input_buffer;
        io::DataSource_Recorder input(source, input_buffer);

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
                    ERR_PRINT2("Decrypt failed: Expected Magic %s, but got %s in %s", Constants::package_magic.c_str(), package_magic_in.c_str(), source.id().c_str());
                    io::remove(output_fname);
                    return PackInfo(ts_creation, source.id(), true);
                }
                DBG_PRINT("Decrypt: Magic is %s", package_magic_in.c_str());

                std::vector<uint8_t> target_path_charvec;
                std::vector<uint8_t> intention_charvec;
                Botan::BigInt bi_file_size;
                Botan::BigInt bi_ts_creation_sec;
                Botan::BigInt bi_payload_version;
                Botan::BigInt bi_payload_version_parent;

                std::vector<uint8_t> pk_type_cv;
                std::vector<uint8_t> pk_fingerprt_hash_algo_cv;
                std::vector<uint8_t> pk_enc_padding_algo_cv;
                std::vector<uint8_t> pk_enc_hash_algo_cv;
                std::vector<uint8_t> pk_sign_algo_cv;

                std::vector<uint8_t> fingerprt_host_charvec;
                Botan::BigInt bi_encrypted_key_count;

                ber.decode( target_path_charvec, Botan::ASN1_Type::OctetString )
                   .decode( bi_file_size, Botan::ASN1_Type::Integer )
                   .decode( bi_ts_creation_sec, Botan::ASN1_Type::Integer )
                   .decode( intention_charvec, Botan::ASN1_Type::OctetString )
                   .decode( bi_payload_version, Botan::ASN1_Type::Integer )
                   .decode( bi_payload_version_parent, Botan::ASN1_Type::Integer )
                   .decode( pk_type_cv, Botan::ASN1_Type::OctetString )
                   .decode( pk_fingerprt_hash_algo_cv, Botan::ASN1_Type::OctetString )
                   .decode( pk_enc_padding_algo_cv, Botan::ASN1_Type::OctetString )
                   .decode( pk_enc_hash_algo_cv, Botan::ASN1_Type::OctetString )
                   .decode( pk_sign_algo_cv, Botan::ASN1_Type::OctetString )
                   .decode( sym_enc_algo_oid )
                   .decode( nonce, Botan::ASN1_Type::OctetString)
                   .decode( fingerprt_host_charvec, Botan::ASN1_Type::OctetString )
                   .decode( bi_encrypted_key_count, Botan::ASN1_Type::Integer );

                target_path = to_string(target_path_charvec);
                intention = to_string(intention_charvec);
                file_size = to_uint64_t(bi_file_size);
                ts_creation.tv_sec = static_cast<int64_t>( to_uint64_t(bi_ts_creation_sec) );
                payload_version = to_uint64_t(bi_payload_version);
                payload_version_parent = to_uint64_t(bi_payload_version_parent);
                crypto_cfg.pk_type = to_string( pk_type_cv );
                crypto_cfg.pk_fingerprt_hash_algo = to_string( pk_fingerprt_hash_algo_cv );
                crypto_cfg.pk_enc_padding_algo = to_string( pk_enc_padding_algo_cv );
                crypto_cfg.pk_enc_hash_algo = to_string( pk_enc_hash_algo_cv );
                crypto_cfg.pk_sign_algo = to_string( pk_sign_algo_cv );
                crypto_cfg.sym_enc_algo = Botan::OIDS::oid2str_or_empty( sym_enc_algo_oid );
                crypto_cfg.sym_enc_nonce_bytes = nonce.size();
                host_key_fingerprt = to_string(fingerprt_host_charvec);
                encrypted_key_count = to_uint64_t(bi_encrypted_key_count);

                DBG_PRINT("Decrypt: %s", crypto_cfg.toString().c_str());

                if( target_path.empty() ) {
                   ERR_PRINT2("Decrypt failed: Unknown target_path in %s", source.id().c_str());
                   io::remove(output_fname);
                   return PackInfo(ts_creation, source.id(), true);
                }
                if( 0 == file_size ) {
                   ERR_PRINT2("Decrypt failed: Zero file-size in %s", source.id().c_str());
                   io::remove(output_fname);
                   return PackInfo(ts_creation, source.id(), true);
                }
                if( !crypto_cfg.valid() ) {
                    ERR_PRINT2("Decrypt failed: CryptoConfig transmission incomplete %s from %s", crypto_cfg.toString().c_str(), source.id().c_str());
                    io::remove(output_fname);
                    return PackInfo(ts_creation, source.id(), true);
                }

                for( sign_key_data_t& sign_key_data : sign_key_data_list ) {
                    if( sign_key_data.pub_key->algo_name() == crypto_cfg.pk_type ) {
                        sign_key_data.fingerprint = sign_key_data.pub_key->fingerprint_public( crypto_cfg.pk_fingerprt_hash_algo );
                    }
                }
                if( !host_key_fingerprt.empty() ) {
                    for( const sign_key_data_t& sign_key_data : sign_key_data_list ) {
                        if( sign_key_data.pub_key->algo_name() == crypto_cfg.pk_type &&
                            host_key_fingerprt == sign_key_data.fingerprint )
                        {
                                sign_pub_key = sign_key_data.pub_key;
                                break;
                        }
                    }
                }
                if( nullptr == sign_pub_key ) {
                    jau::INFO_PRINT("Decrypt failed: No matching host fingerprint, received `%s` in %s",
                            host_key_fingerprt.c_str(), source.id().c_str());
                    io::remove(output_fname);
                    return PackInfo(ts_creation, source.id(), true);
                }

                const std::string dec_key_fingerprint = dec_sec_key->fingerprint_public(crypto_cfg.pk_fingerprt_hash_algo);
                std::vector<uint8_t> fingerprint_charvec;
                std::vector<uint8_t> encrypted_file_key_temp;

                for(size_t idx=0; idx < encrypted_key_count; idx++) {
                    ber.decode(fingerprint_charvec, Botan::ASN1_Type::OctetString)
                       .decode(encrypted_file_key_temp, Botan::ASN1_Type::OctetString);

                    const std::string fingerprint = to_string(fingerprint_charvec);
                    term_keys_fingerprint.push_back(fingerprint);

                    if( 0 > encrypted_key_idx  ) {
                        if( !fingerprint.empty() && fingerprint == dec_key_fingerprint ) {
                            // match, we found our entry
                            encrypted_key_idx = idx;
                            encrypted_file_key = encrypted_file_key_temp; // pick the encrypted key
                        }
                    }
                }
                if( 0 > encrypted_key_idx || 0 == encrypted_key_count ) {
                    jau::INFO_PRINT("Decrypt failed: No matching enc_key found %zd/%zu in %s", encrypted_key_idx, encrypted_key_count, source.id().c_str());
                    io::remove(output_fname);
                    return PackInfo(ts_creation, source.id(), true);
                }

                // ber.end_cons(); // header2 + encrypted data follows ...

                crypto_cfg.sym_enc_nonce_bytes = nonce.size();
            }
            Botan::secure_vector<uint8_t> header1_buffer( input.get_recording() ); // copy
            input.clear_recording(); // implies stop_recording()
            DBG_PRINT("Decrypt: DER Header1 Size %zu bytes, enc_key %zu/%zu (size %zd)",
                    header1_buffer.size(), encrypted_key_idx, encrypted_key_count, encrypted_file_key.size());

            {
                Botan::BER_Decoder ber(input);
                ber.start_sequence()
                   .decode(signature, Botan::ASN1_Type::OctetString)
                   // .end_cons() // encrypted data follows ..
                   ;
            }
            DBG_PRINT("Decrypt: Signature for %zu bytes: %s",
                    header1_buffer.size(),
                    jau::bytesHexString(signature.data(), 0, signature.size(), true /* lsbFirst */).c_str());

            Botan::PK_Verifier verifier(*sign_pub_key, crypto_cfg.pk_sign_algo);
            verifier.update(header1_buffer);
            if( !verifier.check_signature(signature) ) {
                ERR_PRINT2("Decrypt failed: Signature mismatch on %zu bytes, received signature %s in %s",
                        header1_buffer.size(),
                        jau::bytesHexString(signature.data(), 0, signature.size(), true /* lsbFirst */).c_str(),
                        source.id().c_str());
                io::remove(output_fname);
                return PackInfo(ts_creation, source.id(), true);
            } else {
                DBG_PRINT("Decrypt: Signature OK");
            }
        } catch (Botan::Decoding_Error &e) {
            ERR_PRINT2("Decrypt failed: Invalid input file format: source %s, %s", source.id().c_str(), e.what());
            io::remove(output_fname);
            return PackInfo(ts_creation, source.id(), true);
        }

        DBG_PRINT("Decrypt: target_path '%s', net_file_size %s, version %s (parent %s), intention %s",
                target_path.c_str(), jau::to_decstring(file_size).c_str(),
                jau::to_decstring(payload_version).c_str(),
                jau::to_decstring(payload_version_parent).c_str(),
                intention.c_str());
        DBG_PRINT("Decrypt: creation time %s UTC", ts_creation.to_iso8601_string(true).c_str());

        std::shared_ptr<Botan::AEAD_Mode> aead = Botan::AEAD_Mode::create_or_throw(crypto_cfg.sym_enc_algo, Botan::DECRYPTION);
        if(!aead) {
           ERR_PRINT2("Decrypt failed: sym_enc_algo %s not available", crypto_cfg.sym_enc_algo.c_str());
           return PackInfo(ts_creation, source.id(), true);
        }
        const size_t expected_keylen = aead->key_spec().maximum_keylength();

        Botan::PK_Decryptor_EME dec(*dec_sec_key, rng, crypto_cfg.pk_enc_padding_algo+"(" + crypto_cfg.pk_enc_hash_algo + ")");

        const Botan::secure_vector<uint8_t> plain_file_key =
                dec.decrypt_or_random(encrypted_file_key.data(), encrypted_file_key.size(), expected_keylen, rng);

        DBG_PRINT("Decrypt file_key[sz %zd]", plain_file_key.size());

        aead->set_key(plain_file_key);
        aead->set_associated_data_vec(signature);
        aead->start(nonce);

        uint64_t out_bytes_payload = 0;
        io::StreamConsumerFunc consume_data = [&](Botan::secure_vector<uint8_t>& data, bool is_final) -> bool {
            if( !is_final ) {
                aead->update(data);
                outfile.write(reinterpret_cast<char*>(data.data()), data.size());
                out_bytes_payload += data.size();
                DBG_PRINT("Decrypt: DecPayload written0 + %zu bytes -> %" PRIu64 " bytes / %zu bytes", data.size(), out_bytes_payload, file_size);
                return out_bytes_payload < file_size; // end streaming if done
            } else {
                // DBG_PRINT("Decrypt: p111a size %zu, capacity %zu", data.size(), data.capacity());
                // DBG_PRINT("Decrypt: p111a data %s",
                //           jau::bytesHexString(data.data(), 0, data.size(), true /* lsbFirst */).c_str());
                aead->finish(data);
                // DBG_PRINT("Decrypt: p111b size %zu, capacity %zu", data.size(), data.capacity());
                // DBG_PRINT("Decrypt: p111b data %s",
                //           jau::bytesHexString(data.data(), 0, data.size(), true /* lsbFirst */).c_str());
                outfile.write(reinterpret_cast<char*>(data.data()), data.size());
                out_bytes_payload += data.size();
                DBG_PRINT("Decrypt: DecPayload writtenF + %zu bytes -> %" PRIu64 " bytes / %zu bytes", data.size(), out_bytes_payload, file_size);
                return true;
            }
        };
        Botan::secure_vector<uint8_t> io_buffer;
        io_buffer.reserve(Constants::buffer_size);
        const uint64_t in_bytes_total = io::read_stream(input, 0, io_buffer, consume_data);
        input.close();

        if ( 0==in_bytes_total || outfile.fail() ) {
            ERR_PRINT2("Decrypt failed: Output file write failed %s", output_fname.c_str());
            io::remove(output_fname);
            return PackInfo(ts_creation, source.id(), true);
        }

        const uint64_t out_bytes_total = outfile.tellp();
        outfile.close();
        const jau::fs::file_stats output_stats(output_fname);
        if( out_bytes_payload != out_bytes_total ) {
            ERR_PRINT2("Decrypt: Writing done, %s payload != %s total bytes for %s bytes input",
                    jau::to_decstring(out_bytes_payload).c_str(), jau::to_decstring(out_bytes_total).c_str(),
                    jau::to_decstring(in_bytes_total).c_str());
            io::remove(output_fname);
            return PackInfo(ts_creation, source.id(), true);
        } else if( output_stats.size() != out_bytes_payload ) {
            ERR_PRINT2("Descrypt: Writing done, %s payload bytes != %s",
                    jau::to_decstring(out_bytes_payload).c_str(),
                    output_stats.to_string(true).c_str() );
            io::remove(output_fname);
            return PackInfo(ts_creation, source.id(), true);
        } else if( output_stats.size() != file_size ) {
            ERR_PRINT2("Descrypt: Writing done, %s payload bytes != %s header file_size",
                    jau::to_decstring(out_bytes_payload).c_str(),
                    jau::to_decstring(file_size).c_str() );
            io::remove(output_fname);
            return PackInfo(ts_creation, source.id(), true);
        } else {
            WORDY_PRINT("Decrypt: Writing done, %s total bytes from %s bytes input, ratio %lf in/out",
                    jau::to_decstring(out_bytes_total).c_str(),
                    jau::to_decstring(in_bytes_total).c_str(), (double)out_bytes_total/(double)in_bytes_total);
        }

        const jau::fraction_i64 _td = ( jau::getMonotonicTime() - _t0 ).to_fraction_i64();
        io::print_stats("Decrypt", out_bytes_total, _td);

        return PackInfo( PackHeader(target_path,
                                    file_size,
                                    ts_creation,
                                    intention,
                                    payload_version, payload_version_parent,
                                    crypto_cfg,
                                    host_key_fingerprt,
                                    term_keys_fingerprint,
                                    encrypted_key_idx,
                                    true /* valid */),
                         source.id(), true, output_stats, false);
    } catch (std::exception &e) {
        ERR_PRINT2("Decrypt failed: Caught exception: %s", e.what());
        io::remove(output_fname);
        return PackInfo(ts_creation, source.id(), true);
    }
}
