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

#define NO_CIPHER_ALGO_OID 1

bool Cipherpack::encryptThenSign_RSA2(const std::string &enc_pub_key_fname,
                                  const std::string &sign_sec_key_fname, const std::string &passphrase,
                                  const std::string &data_fname,
                                  const std::string &outfilename, const bool overwrite) {
    Elevator::env_init();

    const uint64_t _t0 = jau::getCurrentMilliseconds();

    if( IOUtil::file_exists(outfilename) ) {
        if( overwrite ) {
            if( !IOUtil::remove(outfilename) ) {
                ERR_PRINT("Encrypt failed: Failed deletion of existing output file %s", outfilename.c_str());
                return false;
            }
        } else {
            ERR_PRINT("Encrypt failed: Not overwriting existing output file %s", outfilename.c_str());
            return false;
        }
    }
    std::ofstream outfile(outfilename, std::ios::out | std::ios::binary);
    if ( !outfile.good() || !outfile.is_open() ) {
        ERR_PRINT("Encrypt failed: Output file not open %s", outfilename.c_str());
        return false;
    }
    uint64_t out_bytes_header = 0;

    try {
        Botan::RandomNumberGenerator& rng = Botan::system_rng();

        std::unique_ptr<Botan::Public_Key> enc_pub_key = load_public_key(enc_pub_key_fname);
        if( !enc_pub_key ) {
            return false;
        }
        std::unique_ptr<Botan::Private_Key> sign_sec_key = load_private_key(sign_sec_key_fname, passphrase);
        if( !sign_sec_key ) {
            return false;
        }
        Botan::PK_Signer signer(*sign_sec_key, rng, rsa_sign_algo);

        std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create(simple_cipher_algo));
        if(!cipher) {
           ERR_PRINT("Encrypt failed: Cipher algo %s not available", simple_cipher_algo.c_str());
           return false;
        }
#if !NO_CIPHER_ALGO_OID
        const Botan::OID cipher_algo_oid = Botan::OID::from_string(simple_cipher_algo);
        if( cipher_algo_oid.empty() ) {
            ERR_PRINT("Encrypt failed: No OID defined for cipher algo %s", simple_cipher_algo.c_str());
            return false;
        }
#endif

        const Botan::AlgorithmIdentifier hash_id(rsa_hash_algo, Botan::AlgorithmIdentifier::USE_EMPTY_PARAM);
        const Botan::AlgorithmIdentifier pk_alg_id("RSA/"+rsa_padding_algo, hash_id.BER_encode());

        Botan::PK_Encryptor_EME enc(*enc_pub_key, rng, rsa_padding_algo+"(" + rsa_hash_algo + ")");

        const Botan::secure_vector<uint8_t> file_key = rng.random_vec(cipher->key_spec().maximum_keylength());

        const std::vector<uint8_t> encrypted_key = enc.encrypt(file_key, rng);

        const Botan::secure_vector<uint8_t> nonce = rng.random_vec(ChaCha_Nonce_Size);
        cipher->set_key(file_key);
        cipher->set_iv(nonce.data(), nonce.size());

        Botan::DER_Encoder::append_fn der_append = [&](const uint8_t b[], size_t l) {
            outfile.write((char*)b, l);
            out_bytes_header += l;
            signer.update(b, l);
            DBG_PRINT("Encrypt: DER Header written + %" PRIu64 " bytes -> %" PRIu64 " bytes", l, out_bytes_header);
        };
        Botan::DER_Encoder der(der_append);

        uint64_t payload_version = 1;
        uint64_t payload_version_parent = 0;

        der.start_sequence()
           .encode(std::vector<uint8_t>(package_magic.begin(), package_magic.end()), Botan::ASN1_Type::OctetString)
           .encode(std::vector<uint8_t>(data_fname.begin(), data_fname.end()), Botan::ASN1_Type::OctetString)
           .encode(payload_version, Botan::ASN1_Type::Integer)
           .encode(payload_version_parent, Botan::ASN1_Type::Integer)
           .encode(std::vector<uint8_t>(rsa_sign_algo.begin(), rsa_sign_algo.end()), Botan::ASN1_Type::OctetString)
           .encode(pk_alg_id)
#if NO_CIPHER_ALGO_OID
           .encode(std::vector<uint8_t>(simple_cipher_algo.begin(), simple_cipher_algo.end()), Botan::ASN1_Type::OctetString)
#else
           .encode(cipher_algo_oid)
#endif
           .encode(encrypted_key, Botan::ASN1_Type::OctetString)
           .encode(nonce, Botan::ASN1_Type::OctetString)
           .end_cons();

        uint64_t out_bytes_total = outfile.tellp();
        if( out_bytes_header != out_bytes_total ) {
            ERR_PRINT("Encrypt: DER Header done, %" PRIu64 " header != %" PRIu64 " total bytes", out_bytes_header, out_bytes_total);
        } else {
            DBG_PRINT("Encrypt: DER Header done, %" PRIu64 " header == %" PRIu64 " total bytes", out_bytes_header, out_bytes_total);
        }

        uint64_t out_bytes_payload = 0;
        uint64_t out_bytes_signature = 0;
        auto consume_data = [&](Botan::secure_vector<uint8_t>& data, bool is_final) {
            if( !is_final ) {
                cipher->encipher(data);
                outfile.write(reinterpret_cast<char*>(data.data()), data.size());
                out_bytes_payload += data.size();
                signer.update(data);
                DBG_PRINT("Encrypt: EncPayload written0 + %" PRIu64 " bytes -> %" PRIu64 " bytes", data.size(), out_bytes_payload);
            } else {
                cipher->encipher(data);
                outfile.write(reinterpret_cast<char*>(data.data()), data.size());
                out_bytes_payload += data.size();
                signer.update(data);
                std::vector<uint8_t> signature = signer.signature(rng);
                outfile.write(reinterpret_cast<char*>(signature.data()), signature.size());
                out_bytes_signature += signature.size();
                DBG_PRINT("Encrypt: EncPayload writtenF + %" PRIu64 " bytes -> %" PRIu64 " bytes", data.size(), out_bytes_payload);
                DBG_PRINT("Encrypt: Signature  written  + %" PRIu64 " bytes", out_bytes_signature);
            }
        };
        Botan::secure_vector<uint8_t> io_buffer;
        io_buffer.reserve(buffer_size);
        const ssize_t in_bytes_total = IOUtil::read_file(data_fname, io_buffer, consume_data);

        if ( 0>in_bytes_total || outfile.fail() ) {
            ERR_PRINT("Encrypt failed: Output file write failed %s", outfilename.c_str());
            IOUtil::remove(outfilename);
            return false;
        }

        out_bytes_total = outfile.tellp();
        if( out_bytes_header + out_bytes_payload + out_bytes_signature != out_bytes_total ) {
            ERR_PRINT("Encrypt: Writing done, %" PRIu64 " header + %s payload + %s signature != %s total bytes for %s bytes input",
                    out_bytes_header,
                    jau::to_decstring(out_bytes_payload).c_str(),
                    jau::to_decstring(out_bytes_signature).c_str(),
                    jau::to_decstring(out_bytes_total).c_str(),
                    jau::to_decstring(in_bytes_total).c_str());
        } else if( jau::environment::get().verbose ) {
            jau::PLAIN_PRINT(true, "Encrypt: Writing done, %s header + %s payload + %s signature == %s total bytes for %s bytes input, ratio %lf out/in",
                    jau::to_decstring(out_bytes_header).c_str(),
                    jau::to_decstring(out_bytes_payload).c_str(),
                    jau::to_decstring(out_bytes_total).c_str(),
                    jau::to_decstring(in_bytes_total).c_str(), (double)out_bytes_total/(double)in_bytes_total);
        }

        const uint64_t _td_ms = jau::getCurrentMilliseconds() - _t0; // in milliseconds
        IOUtil::print_stats("Encrypt", out_bytes_total, _td_ms);
    } catch (std::exception &e) {
        ERR_PRINT("Encrypt failed: Caught exception: %s", e.what());
        IOUtil::remove(outfilename);
        return false;
    }

    return true;
}

bool Cipherpack::checkSignThenDecrypt_RSA2(const std::string &sign_pub_key_fname,
                                       const std::string &dec_sec_key_fname, const std::string &passphrase,
                                       const std::string &data_fname,
                                       const std::string &outfilename, const bool overwrite) {
    Elevator::env_init();

    const uint64_t _t0 = jau::getCurrentMilliseconds();

    if( IOUtil::file_exists(outfilename) ) {
        if( overwrite ) {
            if( !IOUtil::remove(outfilename) ) {
                ERR_PRINT("Decrypt failed: Failed deletion of existing output file %s", outfilename.c_str());
                return false;
            }
        } else {
            ERR_PRINT("Decrypt failed: Not overwriting existing output file %s", outfilename.c_str());
            return false;
        }
    }
    std::ofstream outfile(outfilename, std::ios::out | std::ios::binary);
    if ( !outfile.good() || !outfile.is_open() ) {
        ERR_PRINT("Decrypt failed: Output file not open %s", outfilename.c_str());
        return false;
    }

    try {
        Botan::RandomNumberGenerator& rng = Botan::system_rng();

        std::unique_ptr<Botan::Public_Key> sign_pub_key = load_public_key(sign_pub_key_fname);
        if( !sign_pub_key ) {
            return false;
        }
        std::unique_ptr<Botan::Private_Key> dec_sec_key = load_private_key(dec_sec_key_fname, passphrase);
        if( !dec_sec_key ) {
            return false;
        }

        // Botan::PK_Verifier verifier(*sign_pub_key, rsa_sign_algo);

        std::vector<uint8_t> package_magic_charvec;
        std::vector<uint8_t> filename_charvec;
        uint64_t payload_version;
        uint64_t payload_version_parent;
        std::vector<uint8_t> sign_algo_charvec;
        Botan::AlgorithmIdentifier pk_alg_id;
#if NO_CIPHER_ALGO_OID
        std::vector<uint8_t> cipher_algo_charvec;
#else
        Botan::OID cipher_algo_oid;
#endif
        std::vector<uint8_t> encrypted_key;
        std::vector<uint8_t> nonce;

        Botan::DataSource_Stream input(data_fname, true /* use_binary */);

        try {
            Botan::BER_Decoder ber(input);
            ber.start_sequence()
               .decode(package_magic_charvec, Botan::ASN1_Type::OctetString)
               .decode(filename_charvec, Botan::ASN1_Type::OctetString)
               .decode(payload_version, Botan::ASN1_Type::Integer)
               .decode(payload_version_parent, Botan::ASN1_Type::Integer)
               .decode(sign_algo_charvec, Botan::ASN1_Type::OctetString)
               .decode(pk_alg_id)
#if NO_CIPHER_ALGO_OID
               .decode(cipher_algo_charvec, Botan::ASN1_Type::OctetString)
#else
               .decode(cipher_algo_oid)
#endif
               .decode(encrypted_key, Botan::ASN1_Type::OctetString)
               .decode(nonce, Botan::ASN1_Type::OctetString)
               // .end_cons() // we have data left, i.e. the encrypted payload, non-DER encoded
               ;
        } catch (Botan::Decoding_Error &e) {
            ERR_PRINT("Decrypt failed: Invalid input file format: file %s, %s", data_fname, e.what());
            IOUtil::remove(outfilename);
            return false;
        }

        {
            const std::string s(reinterpret_cast<char*>(package_magic_charvec.data()), package_magic_charvec.size());
            if( s.empty() ) {
               ERR_PRINT("Decrypt failed: Unknown package_magic in %s", outfilename.c_str());
               IOUtil::remove(outfilename);
               return false;
            }
            DBG_PRINT("Decrypt: package_magic is %s", s.c_str());
            if( s != package_magic ) {
               ERR_PRINT("Decrypt failed: Expected package magic %s, but got %s in %s",
                       package_magic.c_str(), s.c_str(), outfilename.c_str());
               IOUtil::remove(outfilename);
               return false;
            }
        }
        {
            const std::string s(reinterpret_cast<char*>(filename_charvec.data()), filename_charvec.size());
            if( s.empty() ) {
               ERR_PRINT("Decrypt failed: Unknown filename in %s", outfilename.c_str());
               IOUtil::remove(outfilename);
               return false;
            }
            DBG_PRINT("Decrypt: filename is %s", s.c_str());
        }
        DBG_PRINT("Decrypt: payload version %s (parent %s)",
                jau::to_decstring(payload_version).c_str(),
                jau::to_decstring(payload_version_parent).c_str());

        const std::string sign_algo(reinterpret_cast<char*>(sign_algo_charvec.data()), sign_algo_charvec.size());
        {
            if( sign_algo.empty() ) {
               ERR_PRINT("Decrypt failed: Unknown signing algo in %s", outfilename.c_str());
               IOUtil::remove(outfilename);
               return false;
            }
            DBG_PRINT("Decrypt: sign algo is %s", sign_algo.c_str());
            if( sign_algo != rsa_sign_algo) {
               ERR_PRINT("Decrypt failed: Expected signing algo %s, but got %s in %s",
                       rsa_sign_algo.c_str(), sign_algo.c_str(), outfilename.c_str());
               IOUtil::remove(outfilename);
               return false;
            }
        }
        {
            const std::string padding_combo = "RSA/"+rsa_padding_algo;
            const Botan::OID pk_alg_oid = pk_alg_id.get_oid();
            const std::string pk_algo_str = Botan::OIDS::oid2str_or_empty(pk_alg_oid);
            DBG_PRINT("Decrypt: ciphertext encryption/padding algo is %s -> %s", pk_alg_oid.to_string().c_str(), pk_algo_str.c_str());
            if( pk_algo_str != padding_combo ) {
                ERR_PRINT("Decrypt failed: Expected ciphertext encryption/padding algo %s, but got %s in %s",
                        padding_combo.c_str(), pk_algo_str.c_str(), outfilename.c_str());
                IOUtil::remove(outfilename);
                return false;
            }
        }
        {
            Botan::AlgorithmIdentifier hash_algo_id;
            Botan::BER_Decoder( pk_alg_id.get_parameters() ).decode(hash_algo_id);
            const std::string hash_algo = Botan::OIDS::oid2str_or_empty(hash_algo_id.get_oid());
            if( hash_algo.empty() ) {
                ERR_PRINT("Decrypt failed: Unknown hash function used with %s padding, OID is %s in %s",
                        rsa_padding_algo.c_str(), hash_algo_id.get_oid().to_string().c_str(), outfilename.c_str());
                IOUtil::remove(outfilename);
                return false;
            }
            DBG_PRINT("Decrypt: hash function for %s padding is %s", rsa_padding_algo.c_str(), hash_algo.c_str());
            if( hash_algo != rsa_hash_algo ) {
               ERR_PRINT("Decrypt failed: Expected hash function for % padding is %s, but got %s in %s",
                       rsa_padding_algo.c_str(), rsa_hash_algo.c_str(), hash_algo.c_str(), outfilename.c_str());
               IOUtil::remove(outfilename);
               return false;
            }
            if( !hash_algo_id.get_parameters().empty() ) {
                ERR_PRINT("Decrypt failed: Unknown %s padding - %s hash function parameter used in %s",
                        rsa_padding_algo.c_str(), hash_algo.c_str(), outfilename.c_str());
                IOUtil::remove(outfilename);
                return false;
            }
        }


#if NO_CIPHER_ALGO_OID
        const std::string cipher_algo(reinterpret_cast<char*>(cipher_algo_charvec.data()), cipher_algo_charvec.size());
#else
        const std::string cipher_algo = Botan::OIDS::oid2str_or_empty(cipher_algo_oid);
#endif
        {
            if( cipher_algo.empty() ) {
               ERR_PRINT("Decrypt failed: Unknown ciphertext encryption algo in %s", outfilename.c_str());
               IOUtil::remove(outfilename);
               return false;
            }
            DBG_PRINT("Decrypt: ciphertext encryption algo is %s", cipher_algo.c_str());
            if( cipher_algo != simple_cipher_algo) {
               ERR_PRINT("Decrypt failed: Expected ciphertext encryption algo %s, but got %s in %s",
                       simple_cipher_algo.c_str(), cipher_algo.c_str(), outfilename.c_str());
               IOUtil::remove(outfilename);
               return false;
            }
        }

        std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create(cipher_algo));
        if(!cipher) {
           ERR_PRINT("Decrypt failed: Cipher algo %s not available", cipher_algo.c_str());
           return false;
        }

        const size_t expected_keylen = cipher->key_spec().maximum_keylength();

        Botan::PK_Decryptor_EME dec(*dec_sec_key, rng, rsa_padding_algo+"(" + rsa_hash_algo + ")");

        const Botan::secure_vector<uint8_t> file_key =
                dec.decrypt_or_random(encrypted_key.data(), encrypted_key.size(), expected_keylen, rng);

        cipher->set_key(file_key);
        cipher->set_iv(nonce.data(), nonce.size());

        uint64_t out_bytes_payload = 0;
        auto consume_data = [&](Botan::secure_vector<uint8_t>& data, bool is_final) {
            if( !is_final ) {
                cipher->encipher(data);
                outfile.write(reinterpret_cast<char*>(data.data()), data.size());
                out_bytes_payload += data.size();
                DBG_PRINT("Decrypt: EncPayload written0 + %" PRIu64 " bytes -> %" PRIu64 " bytes", data.size(), out_bytes_payload);
            } else {
                // DBG_PRINT("Decrypt: p111a size %" PRIu64 ", capacity %" PRIu64 "", data.size(), data.capacity());
                // DBG_PRINT("Decrypt: p111a data %s",
                //           jau::bytesHexString(data.data(), 0, data.size(), true /* lsbFirst */).c_str());
                cipher->encipher(data);
                // DBG_PRINT("Decrypt: p111b size %" PRIu64 ", capacity %" PRIu64 "", data.size(), data.capacity());
                // DBG_PRINT("Decrypt: p111b data %s",
                //           jau::bytesHexString(data.data(), 0, data.size(), true /* lsbFirst */).c_str());
                outfile.write(reinterpret_cast<char*>(data.data()), data.size());
                out_bytes_payload += data.size();
                DBG_PRINT("Decrypt: EncPayload writtenF + %" PRIu64 " bytes -> %" PRIu64 " bytes", data.size(), out_bytes_payload);
            }
        };
        Botan::secure_vector<uint8_t> io_buffer;
        io_buffer.reserve(buffer_size);
        const ssize_t in_bytes_total = IOUtil::read_stream(input, io_buffer, consume_data);

        if ( 0>in_bytes_total || outfile.fail() ) {
            ERR_PRINT("Decrypt failed: Output file write failed %s", outfilename.c_str());
            IOUtil::remove(outfilename);
            return false;
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
    } catch (std::exception &e) {
        ERR_PRINT("Decrypt failed: Caught exception: %s", e.what());
        IOUtil::remove(outfilename);
        return false;
    }

    return true;
}

