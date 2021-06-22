/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
 */

#include <fstream>
#include <iostream>

#include <elevator/elevator.hpp>

#include <jau/debug.hpp>

#include <botan_all.h>

using namespace elevator;

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

Cipherpack::PackInfo Cipherpack::encryptThenSign_RSA1(const std::string &enc_pub_key_fname,
                                                      const std::string &sign_sec_key_fname, const std::string &passphrase,
                                                      const std::string &input_fname,
                                                      const std::string &designated_fname,
                                                      const uint64_t payload_version,
                                                      const uint64_t payload_version_parent,
                                                      const std::string &output_fname, const bool overwrite) {
    Elevator::env_init();

    const uint64_t ts_creation_sec = jau::getWallClockSeconds();

    const uint64_t _t0 = jau::getCurrentMilliseconds();

    if( IOUtil::file_exists(output_fname) ) {
        if( overwrite ) {
            if( !IOUtil::remove(output_fname) ) {
                ERR_PRINT("Encrypt failed: Failed deletion of existing output file %s", output_fname.c_str());
                return PackInfo(ts_creation_sec, input_fname, false);
            }
        } else {
            ERR_PRINT("Encrypt failed: Not overwriting existing output file %s", output_fname.c_str());
            return PackInfo(ts_creation_sec, input_fname, false);
        }
    }
    std::ofstream outfile(output_fname, std::ios::out | std::ios::binary);
    if ( !outfile.good() || !outfile.is_open() ) {
        ERR_PRINT("Encrypt failed: Output file not open %s", output_fname.c_str());
        return PackInfo(ts_creation_sec, input_fname, false);
    }
    uint64_t out_bytes_header;

    try {
        Botan::RandomNumberGenerator& rng = Botan::system_rng();

        std::unique_ptr<Botan::Public_Key> enc_pub_key = load_public_key(enc_pub_key_fname);
        if( !enc_pub_key ) {
            return PackInfo(ts_creation_sec, input_fname, false);
        }
        std::unique_ptr<Botan::Private_Key> sign_sec_key = load_private_key(sign_sec_key_fname, passphrase);
        if( !sign_sec_key ) {
            return PackInfo(ts_creation_sec, input_fname, false);
        }

        std::unique_ptr<Botan::AEAD_Mode> aead = Botan::AEAD_Mode::create(aead_cipher_algo, Botan::ENCRYPTION);
        if(!aead) {
           ERR_PRINT("Encrypt failed: AEAD algo %s not available", aead_cipher_algo.c_str());
           return PackInfo(ts_creation_sec, input_fname, false);
        }
        const Botan::OID cipher_algo_oid = Botan::OID::from_string(aead_cipher_algo);
        if( cipher_algo_oid.empty() ) {
            ERR_PRINT("Encrypt failed: No OID defined for cypher algo %s", aead_cipher_algo.c_str());
            return PackInfo(ts_creation_sec, input_fname, false);
        }

        const Botan::AlgorithmIdentifier hash_id(rsa_hash_algo, Botan::AlgorithmIdentifier::USE_EMPTY_PARAM);
        const Botan::AlgorithmIdentifier pk_alg_id("RSA/"+rsa_padding_algo, hash_id.BER_encode());

        Botan::PK_Encryptor_EME enc(*enc_pub_key, rng, rsa_padding_algo+"(" + rsa_hash_algo + ")");

        const Botan::secure_vector<uint8_t> file_key = rng.random_vec(aead->key_spec().maximum_keylength());

        const std::vector<uint8_t> encrypted_key = enc.encrypt(file_key, rng);

        const Botan::secure_vector<uint8_t> nonce = rng.random_vec(ChaCha_Nonce_Size);
        aead->set_key(file_key);
        aead->set_associated_data_vec(encrypted_key);
        aead->start(nonce);

        {
            Botan::secure_vector<uint8_t> header_buffer;
            header_buffer.reserve(buffer_size);

            // DER-Header-1
            header_buffer.clear();
            {
                Botan::DER_Encoder der(header_buffer);
                der.start_sequence()
                   .encode(std::vector<uint8_t>(package_magic.begin(), package_magic.end()), Botan::ASN1_Type::OctetString)
                   .encode(std::vector<uint8_t>(designated_fname.begin(), designated_fname.end()), Botan::ASN1_Type::OctetString)
                   .encode(to_BigInt(ts_creation_sec), Botan::ASN1_Type::Integer)
                   .encode(to_BigInt(payload_version), Botan::ASN1_Type::Integer)
                   .encode(to_BigInt(payload_version_parent), Botan::ASN1_Type::Integer)
                   .encode(std::vector<uint8_t>(rsa_sign_algo.begin(), rsa_sign_algo.end()), Botan::ASN1_Type::OctetString)
                   .encode(pk_alg_id)
                   .encode(cipher_algo_oid)
                   .encode(encrypted_key, Botan::ASN1_Type::OctetString)
                   .encode(nonce, Botan::ASN1_Type::OctetString)
                   .end_cons(); // data push
            }
            outfile.write((char*)header_buffer.data(), header_buffer.size());
            out_bytes_header = header_buffer.size();
            DBG_PRINT("Encrypt: DER Header1 written + %zu bytes -> %" PRIu64 " bytes", header_buffer.size(), out_bytes_header);

            // DER-Header-2 (signature)
            Botan::PK_Signer signer(*sign_sec_key, rng, rsa_sign_algo);
            std::vector<uint8_t> signature = signer.sign_message(header_buffer, rng);
            DBG_PRINT("Encrypt: Signature for %zu bytes: %s",
                    header_buffer.size(),
                    jau::bytesHexString(signature.data(), 0, signature.size(), true /* lsbFirst */).c_str());
            header_buffer.clear();
            {
                Botan::DER_Encoder der(header_buffer);
                der.start_sequence()
                   .encode(signature, Botan::ASN1_Type::OctetString)
                   .end_cons();
            }
            outfile.write((char*)header_buffer.data(), header_buffer.size());
            out_bytes_header += header_buffer.size();
            DBG_PRINT("Encrypt: DER Header2 written + %zu bytes -> %" PRIu64 " bytes", header_buffer.size(), out_bytes_header);
        }

        uint64_t out_bytes_total = outfile.tellp();
        if( out_bytes_header != out_bytes_total ) {
            ERR_PRINT("Encrypt: DER Header done, %" PRIu64 " header != %" PRIu64 " total bytes", out_bytes_header, out_bytes_total);
            IOUtil::remove(output_fname);
            return PackInfo(ts_creation_sec, input_fname, false);
        } else {
            DBG_PRINT("Encrypt: DER Header done, %" PRIu64 " header == %" PRIu64 " total bytes", out_bytes_header, out_bytes_total);
        }

        uint64_t out_bytes_payload = 0;
        IOUtil::StreamConsumerFunc consume_data = [&](Botan::secure_vector<uint8_t>& data, bool is_final) -> void {
            if( !is_final ) {
                aead->update(data);
                outfile.write(reinterpret_cast<char*>(data.data()), data.size());
                out_bytes_payload += data.size();
                DBG_PRINT("Encrypt: EncPayload written0 + %zu bytes -> %" PRIu64 " bytes", data.size(), out_bytes_payload);
            } else {
                aead->finish(data);
                outfile.write(reinterpret_cast<char*>(data.data()), data.size());
                out_bytes_payload += data.size();
                DBG_PRINT("Encrypt: EncPayload writtenF + %zu bytes -> %" PRIu64 " bytes", data.size(), out_bytes_payload);
            }
        };
        Botan::secure_vector<uint8_t> io_buffer;
        io_buffer.reserve(buffer_size);
        const uint64_t in_bytes_total = IOUtil::read_file(input_fname, io_buffer, consume_data);

        if ( 0==in_bytes_total || outfile.fail() ) {
            ERR_PRINT("Encrypt failed: Output file write failed %s", output_fname.c_str());
            IOUtil::remove(output_fname);
            return PackInfo(ts_creation_sec, input_fname, false);
        }

        out_bytes_total = outfile.tellp();
        if( out_bytes_header + out_bytes_payload != out_bytes_total ) {
            ERR_PRINT("Encrypt: Writing done, %s header + %s payload != %s total bytes for %s bytes input",
                    jau::to_decstring(out_bytes_header).c_str(),
                    jau::to_decstring(out_bytes_payload).c_str(),
                    jau::to_decstring(out_bytes_total).c_str(),
                    jau::to_decstring(in_bytes_total).c_str());
            IOUtil::remove(output_fname);
            return PackInfo(ts_creation_sec, input_fname, false);
        } else if( jau::environment::get().verbose ) {
            jau::PLAIN_PRINT(true, "Encrypt: Writing done, %s header + %s payload == %s total bytes for %s bytes input, ratio %lf out/in",
                    jau::to_decstring(out_bytes_header).c_str(),
                    jau::to_decstring(out_bytes_payload).c_str(),
                    jau::to_decstring(out_bytes_total).c_str(),
                    jau::to_decstring(in_bytes_total).c_str(), (double)out_bytes_total/(double)in_bytes_total);
        }

        const uint64_t _td_ms = jau::getCurrentMilliseconds() - _t0; // in milliseconds
        IOUtil::print_stats("Encrypt", out_bytes_total, _td_ms);
    } catch (std::exception &e) {
        ERR_PRINT("Encrypt failed: Caught exception: %s", e.what());
        IOUtil::remove(output_fname);
        return PackInfo(ts_creation_sec, input_fname, false);
    }
    return PackInfo(ts_creation_sec, input_fname, false, output_fname, true, designated_fname, payload_version, payload_version_parent);
}

Cipherpack::PackInfo Cipherpack::checkSignThenDecrypt_RSA1(const std::string &sign_pub_key_fname,
                                                           const std::string &dec_sec_key_fname, const std::string &passphrase,
                                                           Botan::DataSource &source,
                                                           const std::string &output_fname, const bool overwrite) {
    Elevator::env_init();

    uint64_t ts_creation_sec = 0;
    const uint64_t _t0 = jau::getCurrentMilliseconds();

    if( IOUtil::file_exists(output_fname) ) {
        if( overwrite ) {
            if( !IOUtil::remove(output_fname) ) {
                ERR_PRINT("Decrypt failed: Failed deletion of existing output file %s", output_fname.c_str());
                return PackInfo(ts_creation_sec, source.id(), true);
            }
        } else {
            ERR_PRINT("Decrypt failed: Not overwriting existing output file %s", output_fname.c_str());
            return PackInfo(ts_creation_sec, source.id(), true);
        }
    }
    std::ofstream outfile(output_fname, std::ios::out | std::ios::binary);
    if ( !outfile.good() || !outfile.is_open() ) {
        ERR_PRINT("Decrypt failed: Output file not open %s", output_fname.c_str());
        return PackInfo(ts_creation_sec, source.id(), true);
    }

    try {
        Botan::RandomNumberGenerator& rng = Botan::system_rng();

        std::unique_ptr<Botan::Public_Key> sign_pub_key = load_public_key(sign_pub_key_fname);
        if( !sign_pub_key ) {
            return PackInfo(ts_creation_sec, source.id(), true);
        }
        std::unique_ptr<Botan::Private_Key> dec_sec_key = load_private_key(dec_sec_key_fname, passphrase);
        if( !dec_sec_key ) {
            return PackInfo(ts_creation_sec, source.id(), true);
        }

        std::vector<uint8_t> package_magic_charvec;
        std::vector<uint8_t> designated_fame_charvec;
        uint64_t payload_version;
        uint64_t payload_version_parent;
        std::vector<uint8_t> sign_algo_charvec;
        Botan::AlgorithmIdentifier pk_alg_id;
        Botan::OID cipher_algo_oid;
        std::vector<uint8_t> encrypted_key;
        std::vector<uint8_t> nonce;

        Botan::secure_vector<uint8_t> input_buffer;
        DataSource_Recorder input(source, input_buffer);

        try {
            // DER-Header-1
            input.start_recording();
            {
                Botan::BER_Decoder ber0(input);

                Botan::BER_Decoder ber = ber0.start_sequence();
                ber.decode(package_magic_charvec, Botan::ASN1_Type::OctetString);

                const std::string package_magic_in(package_magic_charvec.begin(), package_magic_charvec.end());
                if( package_magic != package_magic_in ) {
                    ERR_PRINT("Decrypt failed: Expected Magic %s, but got %s", package_magic.c_str(), package_magic_in.c_str());
                    IOUtil::remove(output_fname);
                    return PackInfo(ts_creation_sec, source.id(), true);
                }
                DBG_PRINT("Decrypt: Magic is %s", package_magic_in.c_str());

                Botan::BigInt bi_ts_creation_sec;
                Botan::BigInt bi_payload_version;
                Botan::BigInt bi_payload_version_parent;

                ber.decode(designated_fame_charvec, Botan::ASN1_Type::OctetString)
                   .decode(bi_ts_creation_sec, Botan::ASN1_Type::Integer)
                   .decode(bi_payload_version, Botan::ASN1_Type::Integer)
                   .decode(bi_payload_version_parent, Botan::ASN1_Type::Integer)
                   .decode(sign_algo_charvec, Botan::ASN1_Type::OctetString)
                   .decode(pk_alg_id)
                   .decode(cipher_algo_oid)
                   .decode(encrypted_key, Botan::ASN1_Type::OctetString)
                   .decode(nonce, Botan::ASN1_Type::OctetString)
                   // .end_cons() // header2 + encrypted data follows ...
                   ;

                ts_creation_sec = to_uint64_t(bi_ts_creation_sec);
                payload_version = to_uint64_t(bi_payload_version);
                payload_version_parent = to_uint64_t(bi_payload_version_parent);
            }
            Botan::secure_vector<uint8_t> header1_buffer( input.get_recording() ); // copy
            input.clear_recording(); // implies stop_recording()
            DBG_PRINT("Decrypt: DER Header1 Size %zu bytes", header1_buffer.size());

            std::vector<uint8_t> signature;
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

            Botan::PK_Verifier verifier(*sign_pub_key, rsa_sign_algo);
            verifier.update(header1_buffer);
            if( !verifier.check_signature(signature) ) {
                ERR_PRINT("Decrypt failed: Signature mismatch on %zu bytes, received signature %s in %s",
                        header1_buffer.size(),
                        jau::bytesHexString(signature.data(), 0, signature.size(), true /* lsbFirst */).c_str(),
                        source.id().c_str());
                IOUtil::remove(output_fname);
                return PackInfo(ts_creation_sec, source.id(), true);
            } else {
                DBG_PRINT("Decrypt: Signature OK");
            }
        } catch (Botan::Decoding_Error &e) {
            ERR_PRINT("Decrypt failed: Invalid input file format: source %s, %s", source.id().c_str(), e.what());
            IOUtil::remove(output_fname);
            return PackInfo(ts_creation_sec, source.id(), true);
        }

        const std::string designated_fname(reinterpret_cast<char*>(designated_fame_charvec.data()), designated_fame_charvec.size());
        {
            if( designated_fname.empty() ) {
               ERR_PRINT("Decrypt failed: Unknown filename in %s", output_fname.c_str());
               IOUtil::remove(output_fname);
               return PackInfo(ts_creation_sec, source.id(), true);
            }
        }
        DBG_PRINT("Decrypt: designated filename %s, version %s (parent %s)",
                designated_fname.c_str(),
                jau::to_decstring(payload_version).c_str(),
                jau::to_decstring(payload_version_parent).c_str());
        DBG_PRINT("Decrypt: creation time %s UTC", IOUtil::getTimestampString(ts_creation_sec, false).c_str());

        const std::string sign_algo(reinterpret_cast<char*>(sign_algo_charvec.data()), sign_algo_charvec.size());
        {
            if( sign_algo.empty() ) {
               ERR_PRINT("Decrypt failed: Unknown signing algo in %s", output_fname.c_str());
               IOUtil::remove(output_fname);
               return PackInfo(ts_creation_sec, source.id(), true);
            }
            DBG_PRINT("Decrypt: sign algo is %s", sign_algo.c_str());
            if( sign_algo != rsa_sign_algo) {
               ERR_PRINT("Decrypt failed: Expected signing algo %s, but got %s in %s",
                       rsa_sign_algo.c_str(), sign_algo.c_str(), output_fname.c_str());
               IOUtil::remove(output_fname);
               return PackInfo(ts_creation_sec, source.id(), true);
            }
        }
        {
            const std::string padding_combo = "RSA/"+rsa_padding_algo;
            const Botan::OID pk_alg_oid = pk_alg_id.get_oid();
            const std::string pk_algo_str = Botan::OIDS::oid2str_or_empty(pk_alg_oid);
            DBG_PRINT("Decrypt: ciphertext encryption/padding algo is %s -> %s", pk_alg_oid.to_string().c_str(), pk_algo_str.c_str());
            if( pk_algo_str != padding_combo ) {
                ERR_PRINT("Decrypt failed: Expected ciphertext encryption/padding algo %s, but got %s in %s",
                        padding_combo.c_str(), pk_algo_str.c_str(), output_fname.c_str());
                IOUtil::remove(output_fname);
                return PackInfo(ts_creation_sec, source.id(), true);
            }
        }
        {
            Botan::AlgorithmIdentifier hash_algo_id;
            Botan::BER_Decoder( pk_alg_id.get_parameters() ).decode(hash_algo_id);
            const std::string hash_algo = Botan::OIDS::oid2str_or_empty(hash_algo_id.get_oid());
            if( hash_algo.empty() ) {
                ERR_PRINT("Decrypt failed: Unknown hash function used with %s padding, OID is %s in %s",
                        rsa_padding_algo.c_str(), hash_algo_id.get_oid().to_string().c_str(), output_fname.c_str());
                IOUtil::remove(output_fname);
                return PackInfo(ts_creation_sec, source.id(), true);
            }
            DBG_PRINT("Decrypt: hash function for %s padding is %s", rsa_padding_algo.c_str(), hash_algo.c_str());
            if( hash_algo != rsa_hash_algo ) {
               ERR_PRINT("Decrypt failed: Expected hash function for % padding is %s, but got %s in %s",
                       rsa_padding_algo.c_str(), rsa_hash_algo.c_str(), hash_algo.c_str(), output_fname.c_str());
               IOUtil::remove(output_fname);
               return PackInfo(ts_creation_sec, source.id(), true);
            }
            if( !hash_algo_id.get_parameters().empty() ) {
                ERR_PRINT("Decrypt failed: Unknown %s padding - %s hash function parameter used in %s",
                        rsa_padding_algo.c_str(), hash_algo.c_str(), output_fname.c_str());
                IOUtil::remove(output_fname);
                return PackInfo(ts_creation_sec, source.id(), true);
            }
        }


        const std::string cipher_algo = Botan::OIDS::oid2str_or_empty(cipher_algo_oid);
        {
            if( cipher_algo.empty() ) {
               ERR_PRINT("Decrypt failed: Unknown ciphertext encryption algo in %s", output_fname.c_str());
               IOUtil::remove(output_fname);
               return PackInfo(ts_creation_sec, source.id(), true);
            }
            DBG_PRINT("Decrypt: ciphertext encryption algo is %s", cipher_algo.c_str());
            if( cipher_algo != aead_cipher_algo) {
               ERR_PRINT("Decrypt failed: Expected ciphertext encryption algo %s, but got %s in %s",
                       aead_cipher_algo.c_str(), cipher_algo.c_str(), output_fname.c_str());
               IOUtil::remove(output_fname);
               return PackInfo(ts_creation_sec, source.id(), true);
            }
        }

        std::unique_ptr<Botan::AEAD_Mode> aead = Botan::AEAD_Mode::create_or_throw(cipher_algo, Botan::DECRYPTION);
        if(!aead) {
           ERR_PRINT("Decrypt failed: Cipher algo %s not available", cipher_algo.c_str());
           return PackInfo(ts_creation_sec, source.id(), true);
        }

        const size_t expected_keylen = aead->key_spec().maximum_keylength();

        Botan::PK_Decryptor_EME dec(*dec_sec_key, rng, rsa_padding_algo+"(" + rsa_hash_algo + ")");

        const Botan::secure_vector<uint8_t> file_key =
                dec.decrypt_or_random(encrypted_key.data(), encrypted_key.size(), expected_keylen, rng);

        aead->set_key(file_key);
        aead->set_associated_data_vec(encrypted_key);
        aead->start(nonce);

        uint64_t out_bytes_payload = 0;
        auto consume_data = [&](Botan::secure_vector<uint8_t>& data, bool is_final) {
            if( !is_final ) {
                aead->update(data);
                outfile.write(reinterpret_cast<char*>(data.data()), data.size());
                out_bytes_payload += data.size();
                DBG_PRINT("Decrypt: DecPayload written0 + %zu bytes -> %" PRIu64 " bytes", data.size(), out_bytes_payload);
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
                DBG_PRINT("Decrypt: DecPayload writtenF + %zu bytes -> %" PRIu64 " bytes", data.size(), out_bytes_payload);
            }
        };
        Botan::secure_vector<uint8_t> io_buffer;
        io_buffer.reserve(buffer_size);
        const uint64_t in_bytes_total = IOUtil::read_stream(input, io_buffer, consume_data);

        if ( 0==in_bytes_total || outfile.fail() ) {
            ERR_PRINT("Decrypt failed: Output file write failed %s", output_fname.c_str());
            IOUtil::remove(output_fname);
            return PackInfo(ts_creation_sec, source.id(), true);
        }

        const uint64_t out_bytes_total = outfile.tellp();

        if( out_bytes_payload != out_bytes_total ) {
            ERR_PRINT("Decrypt: Writing done, %s payload != %s total bytes for %s bytes input",
                    jau::to_decstring(out_bytes_payload).c_str(), jau::to_decstring(out_bytes_total).c_str(),
                    jau::to_decstring(in_bytes_total).c_str());
        } else {
            WORDY_PRINT("Decrypt: Writing done, %s total bytes from %s bytes input, ratio %lf in/out",
                    jau::to_decstring(out_bytes_total).c_str(),
                    jau::to_decstring(in_bytes_total).c_str(), (double)out_bytes_total/(double)in_bytes_total);
        }

        const uint64_t _td_ms = jau::getCurrentMilliseconds() - _t0; // in milliseconds
        IOUtil::print_stats("Decrypt", out_bytes_total, _td_ms);

        return PackInfo(ts_creation_sec, source.id(), true, output_fname, false, designated_fname, payload_version, payload_version_parent);
    } catch (std::exception &e) {
        ERR_PRINT("Decrypt failed: Caught exception: %s", e.what());
        IOUtil::remove(output_fname);
        return PackInfo(ts_creation_sec, source.id(), true);
    }
}
