/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2021 Gothel Software e.K.
 * Copyright (c) 1999-2007 Jack Lloyd (Botan)
 * Copyright (c) 2005 Matthew Gregan (Botan)
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

#include <elevator/data_source.hpp>
#include <elevator/io_util.hpp>

#include <jau/debug.hpp>

#include <curl/curl.h>

#include <thread>
#include <pthread.h>

using namespace elevator::io;
using namespace jau::fractions_i64_literals;

const size_t elevator::io::BEST_URLSTREAM_RINGBUFFER_SIZE = 2*CURL_MAX_WRITE_SIZE;

size_t DataSource_SecMemory::read(uint8_t out[], size_t length) {
   const size_t got = std::min<size_t>(m_source.size() - m_offset, length);
   Botan::copy_mem(out, m_source.data() + m_offset, got);
   m_offset += got;
   return got;
}

bool DataSource_SecMemory::check_available(size_t n) {
   return (n <= (m_source.size() - m_offset));
}

size_t DataSource_SecMemory::peek(uint8_t out[], size_t length, size_t peek_offset) const {
   const size_t bytes_left = m_source.size() - m_offset;
   if(peek_offset >= bytes_left) return 0;

   const size_t got = std::min(bytes_left - peek_offset, length);
   Botan::copy_mem(out, &m_source[m_offset + peek_offset], got);
   return got;
}

bool DataSource_SecMemory::end_of_data() const {
   return (m_offset == m_source.size());
}

DataSource_SecMemory::DataSource_SecMemory(const std::string& in)
: m_source(Botan::cast_char_ptr_to_uint8(in.data()),
           Botan::cast_char_ptr_to_uint8(in.data()) + in.length()),
  m_offset(0)
{ }

void DataSource_SecMemory::close() noexcept {
    m_source.clear();
    m_offset = 0;
}

size_t DataSource_File::read(uint8_t out[], size_t length) {
   m_source.read(Botan::cast_uint8_ptr_to_char(out), length);
   if( m_source.bad() ) {
      throw Botan::Stream_IO_Error("DataSource_Stream::read: Source failure");
   }

   const size_t got = static_cast<size_t>(m_source.gcount());
   m_total_read += got;
   return got;
}

bool DataSource_File::check_available(size_t n) {
   const std::streampos orig_pos = m_source.tellg();
   m_source.seekg(0, std::ios::end);
   const size_t avail = static_cast<size_t>(m_source.tellg() - orig_pos);
   m_source.seekg(orig_pos);
   return avail >= n;
}

size_t DataSource_File::peek(uint8_t out[], size_t length, size_t offset) const {
   if(end_of_data()) {
      throw Botan::Invalid_State("DataSource_Stream: Cannot peek when out of data");
   }

   size_t got = 0;

   if(offset) {
      Botan::secure_vector<uint8_t> buf(offset);
      m_source.read(Botan::cast_uint8_ptr_to_char(buf.data()), buf.size());
      if(m_source.bad()) {
         throw Botan::Stream_IO_Error("DataSource_Stream::peek: Source failure");
      }
      got = static_cast<size_t>(m_source.gcount());
   }

   if(got == offset) {
      m_source.read(Botan::cast_uint8_ptr_to_char(out), length);
      if(m_source.bad()) {
         throw Botan::Stream_IO_Error("DataSource_Stream::peek: Source failure");
      }
      got = static_cast<size_t>(m_source.gcount());
   }

   if(m_source.eof()) {
      m_source.clear();
   }
   m_source.seekg(m_total_read, std::ios::beg);

   return got;
}

bool DataSource_File::end_of_data() const {
   return !m_source.good();
}

std::string DataSource_File::id() const {
   return m_identifier;
}

DataSource_File::DataSource_File(const std::string& path, bool use_binary)
: m_identifier(path),
  m_source_memory(new std::ifstream(path, use_binary ? std::ios::binary : std::ios::in)),
  m_source(*m_source_memory),
  m_total_read(0)
{
   if(!m_source.good()) {
      throw Botan::Stream_IO_Error("DataSource: Failure opening file " + path);
   }
}

DataSource_File::DataSource_File(std::istream& in, const std::string& name)
: m_identifier(name),
  m_source(in),
  m_total_read(0)
{ }

void DataSource_File::close() noexcept {
    m_source_memory->close();
}

DataSource_URL::DataSource_URL(const std::string& url, const uint64_t exp_size)
: m_url(url), m_exp_size(exp_size), m_buffer(0x00, BEST_URLSTREAM_RINGBUFFER_SIZE), m_bytes_consumed(0)
{
    m_url_thread = read_url_stream(m_url, m_exp_size, m_buffer, m_url_has_content_length, m_url_content_length, m_url_total_read, m_url_result);
}

void DataSource_URL::close() noexcept {
    DBG_PRINT("DataSource_Url: close.0 %s, %s", id().c_str(), m_buffer.toString().c_str());

    m_url_result = result_t::FAILED; // signal end of curl thread!

    m_buffer.drop(m_buffer.size()); // unblock putBlocking(..)
    if( m_url_thread.joinable() ) {
        DBG_PRINT("DataSource_Url: close.1 %s, %s", id().c_str(), m_buffer.toString().c_str());
        m_url_thread.join();
    }
    DBG_PRINT("DataSource_Url: close.X %s, %s", id().c_str(), m_buffer.toString().c_str());
}

size_t DataSource_URL::read(uint8_t out[], size_t length) {
    if( !check_available( 1 ) ) {
        DBG_PRINT("DataSource_Url::read(.., length %zu): !avail, abort: %s", length, to_string().c_str());
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
    throw Botan::Not_Implemented("DataSource_Url::peek not implemented");
    return 0;
}

std::string DataSource_URL::to_string() const {
    return "DataSource_Url["+m_url+", Url[content_length "+std::to_string(m_url_has_content_length.load())+
                                                   " "+std::to_string(m_url_content_length.load())+
                                                   ", read "+std::to_string(m_url_total_read.load())+
                                                   ", result "+std::to_string((int8_t)m_url_result.load())+
                            "], consumed "+std::to_string(m_bytes_consumed)+
                            ", available "+std::to_string(get_available())+
                            ", eod "+std::to_string(end_of_data())+", "+m_buffer.toString()+"]";
}



void DataSource_Recorder::close() noexcept {
    clear_recording();
    m_parent.close();
    DBG_PRINT("DataSource_Recorder: close.X %s", id().c_str());
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
