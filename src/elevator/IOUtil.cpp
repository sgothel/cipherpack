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
#include <chrono>

#include <elevator/elevator.hpp>

#include <jau/debug.hpp>

#include <botan_all.h>

#include <curl/curl.h>

#include <thread>
#include <pthread.h>

using namespace elevator;
using namespace jau::fractions_i64_literals;

bool IOUtil::remove(const std::string& fname) noexcept {
    return 0 == std::remove( fname.c_str() );
}

uint64_t IOUtil::read_file(const std::string& input_file, Botan::secure_vector<uint8_t>& buffer,
                           StreamConsumerFunc consumer_fn)
{
    if(input_file == "-") {
        return read_stream(std::cin, buffer, consumer_fn);
    } else {
        std::ifstream in(input_file, std::ios::binary);
        if( !in ) {
            ERR_PRINT("Error reading file %s", input_file.c_str());
            return 0;
        }
        return read_stream(in, buffer, consumer_fn);
    }
}

uint64_t IOUtil::read_stream(std::istream& in, Botan::secure_vector<uint8_t>& buffer,
                            StreamConsumerFunc consumer_fn)
{
    uint64_t total = 0;
    bool has_more = in.good();
    while( has_more ) {
        buffer.resize(buffer.capacity());

        in.read(reinterpret_cast<char*>(buffer.data()), buffer.capacity());
        const uint64_t got = static_cast<size_t>(in.gcount());

        buffer.resize(got);
        total += got;
        has_more = in.good();
        consumer_fn(buffer, !has_more);
   }
   return total;
}

uint64_t IOUtil::read_stream(Botan::DataSource& in, Botan::secure_vector<uint8_t>& buffer,
                             StreamConsumerFunc consumer_fn) {
    uint64_t total = 0;
    bool has_more = !in.end_of_data();
    while( has_more ) {
        buffer.resize(buffer.capacity());

        const uint64_t got = in.read(buffer.data(), buffer.capacity());

        buffer.resize(got);
        total += got;
        has_more = !in.end_of_data();
        consumer_fn(buffer, !has_more);
    }
    return total;
}

struct curl_glue1_t {
    CURL *curl_handle;
    bool has_content_length;
    uint64_t content_length;
    uint64_t total_read;
    Botan::secure_vector<uint8_t>& buffer;
    IOUtil::StreamConsumerFunc consumer_fn;
};

static size_t consume_curl1(void *ptr, size_t size, size_t nmemb, void *stream) noexcept {
    curl_glue1_t * cg = (curl_glue1_t*)stream;

    if( !cg->has_content_length ) {
        curl_off_t v = 0;
        CURLcode r = curl_easy_getinfo(cg->curl_handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &v);
        if( !r ) {
            cg->content_length = v;
            cg->has_content_length = true;
        }
    }
    const size_t realsize = size * nmemb;
    DBG_PRINT("consume_curl1.0 realsize %zu", realsize);
    cg->buffer.resize(realsize);
    memcpy(cg->buffer.data(), ptr, realsize);

    cg->total_read += realsize;
    const bool is_final = 0 == realsize ||
                          cg->has_content_length ? cg->total_read >= cg->content_length : false;

    DBG_PRINT("consume_curl1.X realsize %zu, total %" PRIu64 ", is_final %d",
           realsize, cg->total_read, is_final );

    cg->consumer_fn(cg->buffer, is_final);

    return realsize;
}

uint64_t IOUtil::read_url_stream(const std::string& url, Botan::secure_vector<uint8_t>& buffer,
                                 StreamConsumerFunc consumer_fn) {
    std::vector<char> errorbuffer;
    errorbuffer.reserve(CURL_ERROR_SIZE);
    CURLcode res;

    /* init the curl session */
    CURL *curl_handle = curl_easy_init();
    if( nullptr == curl_handle ) {
        ERR_PRINT("Error setting up url %s, null curl handle", url.c_str());
        return 0;
    }

    curl_glue1_t cg = { curl_handle, false, 0, 0, buffer, consumer_fn };

    res = curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errorbuffer.data());
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url.c_str(), (int)res, curl_easy_strerror(res));
        goto errout;
    }

    /* set URL to get here */
    res = curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* Switch on full protocol/debug output while testing */
    res = curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0L);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* disable progress meter, set to 0L to enable it */
    res = curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* send all data to this function  */
    res = curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, consume_curl1);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* write the page body to this file handle */
    res = curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void*)&cg);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* performs the tast, blocking! */
    res = curl_easy_perform(curl_handle);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error processing url %s, error %d %d",
                  url.c_str(), (int)res, errorbuffer.data());
        goto errout;
    }

    /* cleanup curl stuff */
    curl_easy_cleanup(curl_handle);
    return cg.total_read;

errout:
    curl_easy_cleanup(curl_handle);
    return 0;
}

struct curl_glue2_t {
    curl_glue2_t(CURL *_curl_handle,
                 jau::relaxed_atomic_bool& _has_content_length,
                 jau::relaxed_atomic_uint64& _content_length,
                 jau::relaxed_atomic_uint64& _total_read,
                 IOUtil::ByteRingbuffer& _buffer,
                 IOUtil::relaxed_atomic_result_t& _result)
    : curl_handle(_curl_handle),
      has_content_length(_has_content_length),
      content_length(_content_length),
      total_read(_total_read),
      buffer(_buffer),
      result(_result)
    {}

    CURL *curl_handle;
    jau::relaxed_atomic_bool& has_content_length;
    jau::relaxed_atomic_uint64& content_length;
    jau::relaxed_atomic_uint64& total_read;
    IOUtil::ByteRingbuffer& buffer;
    IOUtil::relaxed_atomic_result_t& result;
};

static size_t consume_curl2(void *ptr, size_t size, size_t nmemb, void *stream) noexcept {
    curl_glue2_t * cg = (curl_glue2_t*)stream;

    if( IOUtil::result_t::NONE!= cg->result ) {
        // user abort!
        DBG_PRINT("consume_curl2 ABORT by User: total %" PRIi64 ", result %d, rb %s",
                cg->total_read.load(), cg->result.load(), cg->buffer.toString().c_str() );
        return 0;
    }

    if( !cg->has_content_length ) {
        curl_off_t v = 0;
        const CURLcode r = curl_easy_getinfo(cg->curl_handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &v);
        if( CURLE_OK == r ) {
            cg->content_length = v;
            cg->has_content_length = true;
        }
    }
    const size_t realsize = size * nmemb;
    DBG_PRINT("consume_curl2.0 realsize %zu, rb %s", realsize, cg->buffer.toString().c_str() );
    cg->buffer.putBlocking(reinterpret_cast<uint8_t*>(ptr),
                           reinterpret_cast<uint8_t*>(ptr)+realsize, 0_s);

    cg->total_read = cg->total_read + realsize;
    const bool is_final = 0 == realsize ||
                          cg->has_content_length ? cg->total_read >= cg->content_length : false;
    if( is_final ) {
        cg->result = IOUtil::result_t::SUCCESS;
    }

    DBG_PRINT("consume_curl2.X realsize %zu, total %" PRIu64 ", result %d, rb %s",
           realsize, cg->total_read.load(), cg->result.load(), cg->buffer.toString().c_str() );

    return realsize;
}

static void read_url_stream_thread(const char *url, std::unique_ptr<curl_glue2_t> && cg) noexcept {
    std::vector<char> errorbuffer;
    errorbuffer.reserve(CURL_ERROR_SIZE);
    CURLcode res;

    /* init the curl session */
    CURL *curl_handle = curl_easy_init();
    if( nullptr == curl_handle ) {
        ERR_PRINT("Error setting up url %s, null curl handle", url);
        goto errout;
    }
    cg->curl_handle = curl_handle;

    res = curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errorbuffer.data());
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url, (int)res, curl_easy_strerror(res));
        goto errout;
    }

    /* set URL to get here */
    res = curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url, (int)res, errorbuffer.data());
        goto errout;
    }

    /* Switch on full protocol/debug output while testing */
    res = curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0L);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url, (int)res, errorbuffer.data());
        goto errout;
    }

    /* disable progress meter, set to 0L to enable it */
    res = curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url, (int)res, errorbuffer.data());
        goto errout;
    }

    /* send all data to this function  */
    res = curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, consume_curl2);
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url, (int)res, errorbuffer.data());
        goto errout;
    }

    /* write the page body to this file handle */
    res = curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void*)cg.get());
    if( CURLE_OK != res ) {
        ERR_PRINT("Error setting up url %s, error %d %d",
                  url, (int)res, errorbuffer.data());
        goto errout;
    }

    /* performs the tast, blocking! */
    res = curl_easy_perform(curl_handle);
    if( CURLE_OK != res ) {
        if( IOUtil::result_t::NONE == cg->result ) {
            // Error during normal processing
            ERR_PRINT("Error processing url %s, error %d %d",
                      url, (int)res, errorbuffer.data());
        } else {
            // User aborted
            DBG_PRINT("Processing aborted url %s, error %d %d",
                      url, (int)res, errorbuffer.data());
        }
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
    return;
}

const size_t IOUtil::BEST_URLSTREAM_RINGBUFFER_SIZE = 2*CURL_MAX_WRITE_SIZE;

std::thread IOUtil::read_url_stream(const std::string& url, ByteRingbuffer& buffer,
                                    jau::relaxed_atomic_bool& has_content_length,
                                    jau::relaxed_atomic_uint64& content_length,
                                    jau::relaxed_atomic_uint64& total_read,
                                    relaxed_atomic_result_t& result) noexcept {
    /* init user referenced values */
    has_content_length = false;
    content_length = 0;
    total_read = 0;
    result = IOUtil::result_t::NONE;

    if( buffer.capacity() < BEST_URLSTREAM_RINGBUFFER_SIZE ) {
        buffer.recapacity( BEST_URLSTREAM_RINGBUFFER_SIZE );
    }

    std::unique_ptr<curl_glue2_t> cg ( std::make_unique<curl_glue2_t>(nullptr, has_content_length, content_length, total_read, buffer, result ) );

    return std::thread(&::read_url_stream_thread, url.c_str(), std::move(cg)); // @suppress("Invalid arguments")
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



DataSource_URL::DataSource_URL(const std::string& url)
: m_url(url), m_buffer(0x00, IOUtil::BEST_URLSTREAM_RINGBUFFER_SIZE), m_bytes_consumed(0)
{
    m_http_thread = IOUtil::read_url_stream(m_url, m_buffer, m_url_has_content_length, m_url_content_length, m_url_total_read, m_http_result);
}

DataSource_URL::~DataSource_URL() {
    DBG_PRINT("DataSource_Http: dtor.0 %s, %s", id().c_str(), m_buffer.toString().c_str());

    m_http_result = IOUtil::result_t::FAILED; // signal end of curl thread!

    m_buffer.drop(m_buffer.size()); // unblock putBlocking(..)
    if( m_http_thread.joinable() ) {
        DBG_PRINT("DataSource_Http: dtor.1 %s, %s", id().c_str(), m_buffer.toString().c_str());
        m_http_thread.join();
    }
    DBG_PRINT("DataSource_Http: dtor.X %s, %s", id().c_str(), m_buffer.toString().c_str());
}

size_t DataSource_URL::read(uint8_t out[], size_t length) {
    if( !check_available( 1 ) ) {
        DBG_PRINT("DataSource_Http::read(.., length %zu): !avail, abort: %s", length, to_string().c_str());
        return 0;
    }
    const size_t consumed_bytes = m_buffer.getBlocking(out, length, 1, 0_s);
    m_bytes_consumed += consumed_bytes;
    return consumed_bytes;
}

size_t DataSource_URL::peek(uint8_t out[], size_t length, size_t peek_offset) const {
    (void)out;
    (void)length;
    (void)peek_offset;
    throw Botan::Not_Implemented("DataSource_Http::peek not implemented");
    return 0;
}

std::string DataSource_URL::to_string() const {
    return "DataSource_Http["+m_url+", http[content_length "+std::to_string(m_url_has_content_length.load())+
                                                   " "+std::to_string(m_url_content_length.load())+
                                                   ", read "+std::to_string(m_url_total_read.load())+
                                                   ", result "+std::to_string((int8_t)m_http_result.load())+
                            "], consumed "+std::to_string(m_bytes_consumed)+
                            ", available "+std::to_string(get_available())+
                            ", eod "+std::to_string(end_of_data())+", "+m_buffer.toString()+"]";
}



DataSource_Recorder::~DataSource_Recorder() {
    DBG_PRINT("DataSource_Recorder: dtor.X %s", id().c_str());
}

void DataSource_Recorder::start_recording() noexcept {
    if( is_recording() ) {
        m_buffer.resize(0);
    }
    m_rec_offset = m_bytes_consumed;
    m_is_recording = true;
}

void DataSource_Recorder::stop_recording() noexcept {
    m_is_recording = false;
}

void DataSource_Recorder::clear_recording() noexcept {
    m_is_recording = false;
    m_buffer.clear();
    m_rec_offset = 0;
}

size_t DataSource_Recorder::read(uint8_t out[], size_t length) {
    const size_t consumed_bytes = m_parent.read(out, length);
    m_bytes_consumed += consumed_bytes;
    if( is_recording() ) {
        m_buffer.insert(m_buffer.end(), out, out+consumed_bytes);
    }
    return consumed_bytes;
}
