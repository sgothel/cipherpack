/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
 */

#include <fstream>
#include <iostream>
#include <chrono>

#include <elevator/elevator.hpp>

#include <jau/debug.hpp>

#include <botan_all.h>

#include <curl/curl.h>

#include <thread>
#include <pthread.h>

// #define USE_CXX17lib_FS 1
#if USE_CXX17lib_FS
    #include <filesystem>
    namespace fs = std::filesystem;
#endif

using namespace elevator;

bool IOUtil::file_exists(const std::string& name) noexcept {
    std::ifstream f(name);
    return f.good() && f.is_open();
}

bool IOUtil::remove(const std::string& fname) noexcept {
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

struct curl_glue1_t {
    CURL *curl_handle;
    ssize_t content_length;
    ssize_t total_read;
    Botan::secure_vector<uint8_t>& buffer;
    IOUtil::StreamConsumerFunc consumer_fn;
};

static size_t consume_curl1(void *ptr, size_t size, size_t nmemb, void *stream) noexcept {
    curl_glue1_t * cg = (curl_glue1_t*)stream;

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
    const bool is_final = 0 == realsize ||
                          ( 0 < cg->content_length ) ? cg->total_read >= cg->content_length : false;
    cg->consumer_fn(cg->buffer, is_final);

    return realsize;
}

ssize_t IOUtil::read_http_get(const std::string& url, Botan::secure_vector<uint8_t>& buffer,
                              StreamConsumerFunc consumer_fn) {
    std::vector<char> errorbuffer;
    errorbuffer.reserve(CURL_ERROR_SIZE);
    CURLcode res;

    /* init the curl session */
    CURL *curl_handle = curl_easy_init();
    if( nullptr == curl_handle ) {
        ERR_PRINT("Error setting up http url %s, null curl handle", url.c_str());
        return -1;
    }

    curl_glue1_t cg = { curl_handle, -1, 0, buffer, consumer_fn };

    res = curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errorbuffer.data());
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url.c_str(), (int)res, curl_easy_strerror(res));
        goto errout;
    }

    /* set URL to get here */
    res = curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* Switch on full protocol/debug output while testing */
    res = curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0L);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* disable progress meter, set to 0L to enable it */
    res = curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* send all data to this function  */
    res = curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, consume_curl1);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* write the page body to this file handle */
    res = curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void*)&cg);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* performs the tast, blocking! */
    res = curl_easy_perform(curl_handle);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error processing http url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* cleanup curl stuff */
    curl_easy_cleanup(curl_handle);
    return cg.total_read;

errout:
    curl_easy_cleanup(curl_handle);
    return -1;
}

struct curl_glue2_t {
    curl_glue2_t(CURL *_curl_handle,
            jau::relaxed_atomic_ssize_t* _content_length,
            bool _content_length_mine,
            jau::relaxed_atomic_ssize_t* _total_read,
            bool _total_read_mine,
            IOUtil::ByteRingbuffer& _buffer,
            IOUtil::relaxed_atomic_result_t& _result)
    : curl_handle(_curl_handle),
      content_length(_content_length),
      content_length_mine(_content_length_mine),
      total_read(_total_read),
      total_read_mine(_total_read_mine),
      buffer(_buffer),
      result(_result)
    {}

    CURL *curl_handle;
    jau::relaxed_atomic_ssize_t* content_length;
    bool content_length_mine;
    jau::relaxed_atomic_ssize_t* total_read;
    bool total_read_mine;
    IOUtil::ByteRingbuffer& buffer;
    IOUtil::relaxed_atomic_result_t& result;
};

static size_t consume_curl2(void *ptr, size_t size, size_t nmemb, void *stream) noexcept {
    curl_glue2_t * cg = (curl_glue2_t*)stream;

    if( 0 > *cg->content_length ) {
        curl_off_t v = 0;
        const CURLcode r = curl_easy_getinfo(cg->curl_handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &v);
        if( CURLE_OK == r ) {
            *cg->content_length = v;
        }
    }
    ssize_t total_read = *cg->total_read;
    const size_t realsize = size * nmemb;
    DBG_PRINT("consume_curl2.0 realsize % " PRIu64 ", rb %s", realsize, cg->buffer.toString().c_str() );
    cg->buffer.putBlocking(reinterpret_cast<uint8_t*>(ptr),
                           reinterpret_cast<uint8_t*>(ptr)+realsize, 0 /* timeoutMS */);

    total_read += realsize;
    *cg->total_read = total_read;
    const bool is_final = 0 == realsize ||
                          ( 0 < *cg->content_length ) ? total_read >= *cg->content_length : false;
    if( is_final ) {
        cg->result = IOUtil::result_t::SUCCESS;
    }

    DBG_PRINT("consume_curl2.X realsize % " PRIu64 ", total %" PRIi64 ", result %d, rb %s",
           realsize, total_read, cg->result.load(), cg->buffer.toString().c_str() );

    return realsize;
}

static void read_http_get_thread(const char *url, std::unique_ptr<curl_glue2_t> && cg) noexcept {
    std::vector<char> errorbuffer;
    errorbuffer.reserve(CURL_ERROR_SIZE);
    CURLcode res;

    /* init the curl session */
    CURL *curl_handle = curl_easy_init();
    if( nullptr == curl_handle ) {
        ERR_PRINT("Error setting up http url %s, null curl handle", url);
        goto errout;
    }
    cg->curl_handle = curl_handle;

    res = curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errorbuffer.data());
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url, (int)res, curl_easy_strerror(res));
        goto errout;
    }

    /* set URL to get here */
    res = curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url, (int)res, errorbuffer.data());
        goto errout;
    }

    /* Switch on full protocol/debug output while testing */
    res = curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0L);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url, (int)res, errorbuffer.data());
        goto errout;
    }

    /* disable progress meter, set to 0L to enable it */
    res = curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url, (int)res, errorbuffer.data());
        goto errout;
    }

    /* send all data to this function  */
    res = curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, consume_curl2);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url, (int)res, errorbuffer.data());
        goto errout;
    }

    /* write the page body to this file handle */
    res = curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void*)cg.get());
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up http url %s, error %d %d",
                  url, (int)res, errorbuffer.data());
        goto errout;
    }

    /* performs the tast, blocking! */
    res = curl_easy_perform(curl_handle);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error processing http url %s, error %d %d",
                  url, (int)res, errorbuffer.data());
        goto errout;
    }

    /* cleanup curl stuff */
    cg->result = IOUtil::result_t::SUCCESS;
    goto cleanup;

errout:
    cg->result = IOUtil::result_t::FAILED;

cleanup:
    if( nullptr != curl_handle ) {
        curl_easy_cleanup(curl_handle);
    }

    if( cg->content_length_mine ) {
        delete cg->content_length;
        cg->content_length = nullptr;
    }
    if( cg->total_read_mine ) {
        delete cg->total_read;
        cg->total_read = nullptr;
    }
    return;
}

const size_t IOUtil::BEST_HTTP_RINGBUFFER_SIZE = 2*CURL_MAX_WRITE_SIZE;

void IOUtil::read_http_get(const std::string& url, ByteRingbuffer& buffer,
                           jau::relaxed_atomic_ssize_t& content_length,
                           jau::relaxed_atomic_ssize_t& total_read,
                           relaxed_atomic_result_t& result) noexcept {
    /* init user referenced values */
    content_length = -1;
    total_read = 0;
    result = IOUtil::result_t::NONE;

    if( buffer.capacity() < BEST_HTTP_RINGBUFFER_SIZE ) {
        buffer.recapacity( BEST_HTTP_RINGBUFFER_SIZE );
    }

    std::unique_ptr<curl_glue2_t> cg ( std::make_unique<curl_glue2_t>(nullptr, &content_length, false, &total_read, false, buffer, result ) );

    std::thread http_thread00(&::read_http_get_thread, url.c_str(), std::move(cg)); // @suppress("Invalid arguments")
    http_thread00.detach();
}

void IOUtil::read_http_get(const std::string& url, ByteRingbuffer& buffer,
                           relaxed_atomic_result_t& result) noexcept {

    /* init user referenced values */
    result = IOUtil::result_t::NONE;

    if( buffer.capacity() < BEST_HTTP_RINGBUFFER_SIZE ) {
        buffer.recapacity( BEST_HTTP_RINGBUFFER_SIZE );
    }

    jau::relaxed_atomic_ssize_t* content_length = new jau::relaxed_atomic_ssize_t(-1);
    jau::relaxed_atomic_ssize_t* total_read = new jau::relaxed_atomic_ssize_t(0);
    std::unique_ptr<curl_glue2_t> cg ( std::make_unique<curl_glue2_t>(nullptr, content_length, true, total_read, true, buffer, result ) );

    std::thread http_thread00(&::read_http_get_thread, url.c_str(), std::move(cg)); // @suppress("Invalid arguments")
    http_thread00.detach();
}

void IOUtil::print_stats(const std::string &prefix, const uint64_t out_bytes_total, uint64_t td_ms) noexcept {
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


