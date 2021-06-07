/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
 */

#include <fstream>
#include <iostream>

#include <elevator/elevator.hpp>

#include <jau/debug.hpp>

#include <botan_all.h>

#include <curl/curl.h>

// #define USE_CXX17lib_FS 1
#if USE_CXX17lib_FS
    #include <filesystem>
    namespace fs = std::filesystem;
#endif

using namespace elevator;

bool IOUtil::file_exists(const std::string& name) {
    std::ifstream f(name);
    return f.good() && f.is_open();
}

bool IOUtil::remove(const std::string& fname) {
#if USE_CXX17lib_FS
    const fs::path fname2 = fname;
    return fs::remove(fname);
#else
    return 0 == std::remove( fname.c_str() );
#endif
}

ssize_t IOUtil::read_file(const std::string& input_file, Botan::secure_vector<uint8_t>& buffer,
                          StreamConsumerFunc consumer_fn)
{
    if(input_file == "-") {
        return read_stream(std::cin, buffer, consumer_fn);
    } else {
        std::ifstream in(input_file, std::ios::binary);
        if( !in ) {
            ERR_PRINT("Error reading file %s", input_file.c_str());
            return -1;
        }
        return read_stream(in, buffer, consumer_fn);
    }
}

ssize_t IOUtil::read_stream(std::istream& in, Botan::secure_vector<uint8_t>& buffer,
                            StreamConsumerFunc consumer_fn)
{
    size_t total = 0;
    bool has_more = in.good();
    while( has_more ) {
        buffer.resize(buffer.capacity());

        in.read(reinterpret_cast<char*>(buffer.data()), buffer.capacity());
        const size_t got = static_cast<size_t>(in.gcount());

        buffer.resize(got);
        total += got;
        has_more = in.good();
        consumer_fn(buffer, !has_more);
   }
   return total;
}

ssize_t IOUtil::read_stream(Botan::DataSource& in, Botan::secure_vector<uint8_t>& buffer,
                            StreamConsumerFunc consumer_fn) {
    size_t total = 0;
    bool has_more = !in.end_of_data();
    while( has_more ) {
        buffer.resize(buffer.capacity());

        const size_t got = in.read(buffer.data(), buffer.capacity());

        buffer.resize(got);
        total += got;
        has_more = !in.end_of_data();
        consumer_fn(buffer, !has_more);
    }
    return total;
}

struct curl_glue_t {
    CURL *curl_handle;
    ssize_t content_length;
    ssize_t total_read;
    Botan::secure_vector<uint8_t>& buffer;
    IOUtil::StreamConsumerFunc consumer_fn;
};

static size_t consume_curl0(void *ptr, size_t size, size_t nmemb, void *stream) {
    curl_glue_t * cg = (curl_glue_t*)stream;

    if( 0 > cg->content_length ) {
        curl_off_t v = 0;
        CURLcode r = curl_easy_getinfo(cg->curl_handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &v);
        if( !r ) {
            cg->content_length = v;
        }
    }
    const size_t realsize = size * nmemb;
    cg->buffer.resize(realsize);
    memcpy(cg->buffer.data(), ptr, realsize);

    cg->total_read += realsize;
    bool is_final = 0 < cg->content_length ? cg->total_read >= cg->content_length : false;
    cg->consumer_fn(cg->buffer, is_final);

    return realsize;
}

ssize_t IOUtil::read_http_get(const std::string& url, Botan::secure_vector<uint8_t>& buffer,
                              StreamConsumerFunc consumer_fn) {
     /* init the curl session */
     CURL *curl_handle = curl_easy_init();

     curl_glue_t cg = { curl_handle, -1, 0, buffer, consumer_fn };

     /* set URL to get here */
     curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());

     /* Switch on full protocol/debug output while testing */
     curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0L);

     /* disable progress meter, set to 0L to enable it */
     curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);

     /* send all data to this function  */
     curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, consume_curl0);

     /* write the page body to this file handle */
     curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void*)&cg);

     /* performs the tast, blocking! */
     curl_easy_perform(curl_handle);

     /* cleanup curl stuff */
     curl_easy_cleanup(curl_handle);

     return cg.total_read;
}

void IOUtil::print_stats(const std::string &prefix, const uint64_t out_bytes_total, uint64_t td_ms) {
    if( jau::environment::get().verbose ) {

        jau::PLAIN_PRINT(true, "%s: Duration %s s, %s ms", prefix.c_str(),
                jau::to_decstring(std::llround(td_ms/1'000.0)).c_str(), jau::to_decstring(td_ms).c_str());

        if( out_bytes_total >= 100'000'000 ) {
            jau::PLAIN_PRINT(true, "%s: Size %s MB", prefix.c_str(),
                    jau::to_decstring(std::llround(out_bytes_total/1'000'000.0)).c_str());
        } else if( out_bytes_total >= 100'000 ) {
            jau::PLAIN_PRINT(true, "%s: Size %s KB", prefix.c_str(),
                    jau::to_decstring(std::llround(out_bytes_total/1'000.0)).c_str());
        } else {
            jau::PLAIN_PRINT(true, "%s: Size %s B", prefix.c_str(),
                    jau::to_decstring(out_bytes_total).c_str());
        }

        const uint64_t _rate_bps = std::llround( ( out_bytes_total / (double)td_ms ) * 1'000.0 ); // bytes per second
        const uint64_t _rate_bitps = std::llround( ( ( out_bytes_total * 8.0 ) / (double)td_ms ) * 1'000.0 ); // bytes per second

        if( _rate_bitps >= 100'000'000 ) {
            jau::PLAIN_PRINT(true, "%s: Bitrate %s Mbit/s, %s MB/s", prefix.c_str(),
                    jau::to_decstring(std::llround(_rate_bitps/1'000'000.0)).c_str(),
                    jau::to_decstring(std::llround(_rate_bps/1'000'000.0)).c_str());
        } else if( _rate_bitps >= 100'000 ) {
            jau::PLAIN_PRINT(true, "%s: Bitrate %s kbit/s, %s kB/s", prefix.c_str(),
                    jau::to_decstring(std::llround(_rate_bitps/1'000.0)).c_str(),
                    jau::to_decstring(std::llround(_rate_bps/1'000.0)).c_str());
        } else {
            jau::PLAIN_PRINT(true, "%s: Bitrate %s bit/s, %s B/s", prefix.c_str(),
                    jau::to_decstring(_rate_bitps).c_str(),
                    jau::to_decstring(_rate_bps).c_str());
        }
    }
}


