#ifndef CRYPTO_HPP
#define CRYPTO_HPP
#include <cstring>
#include <string>
#include <iostream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/blowfish.h>
#include <boost/cstdint.hpp>
#include <boost/format.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/hex.hpp>

using namespace std;
using namespace boost::archive::iterators;

namespace xcrypto {
enum
{
    BF_ECB,
    BF_CBC,
    BF_CFB,
    BF_OFB
};

class crypto
{
public:
    crypto();
public:
    static void blowfish_encrypt(const unsigned char* inbuf, unsigned char* outbuf, int blklen,
                                 unsigned char* key, int keylen,
                                 int mode, int enc);

    static bool base64_encrypt(const string& inbuf, string* outbuf);

    static bool base64_decrypt(const string& inbuf, string* outbuf);

    static void base64_encrypt(const char* inbuf, char* outbuf,
                               size_t length, bool with_new_line);

    static void base64_decrypt(const char* inbuf, char* outbuf,
                               size_t length, bool with_new_line);

    static void xencrypt(unsigned char* inbuf, size_t length, string* outbuf,
                         unsigned char* key, int keylen, int mode);

    static void xdecrypt(string& inbuf, unsigned char* outbuf,
                         unsigned char* key, int keylen, int mode);

    static std::string char2hexstring(const unsigned char* str, size_t n);

    static size_t hexstring2char(const std::string& str, unsigned char* out);
};
}

#endif // CRYPTO_HPP
