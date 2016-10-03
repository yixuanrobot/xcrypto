#include "crypto.hpp"

namespace xcrypto {

crypto::crypto()
{

}

void crypto::blowfish_encrypt(const unsigned char* inbuf, unsigned char* outbuf, int blklen,
                              unsigned char* key, int keylen,
                              int mode, int enc)
{
    int num = 0;
    unsigned char ivec[8];
    BF_KEY bfkey;

    memset(ivec, 0, 8);
    BF_set_key(&bfkey, keylen, key);

    __try
    {
        switch(mode)
        {
        case    xcrypto::BF_CFB:
            BF_cfb64_encrypt(inbuf, outbuf, blklen, &bfkey,
                             ivec, &num, enc);
            break;
        case    xcrypto::BF_ECB:
            BF_ecb_encrypt(inbuf, outbuf, &bfkey, enc);
            break;
        case    xcrypto::BF_CBC:
            BF_cbc_encrypt(inbuf, outbuf, blklen, &bfkey,
                             ivec, enc);
            break;
        case    xcrypto::BF_OFB:
            BF_ofb64_encrypt(inbuf, outbuf, blklen, &bfkey,
                             ivec, &num);
            break;
        default:
            break;
        }
    }
    __catch(...)
    {
       throw;
    }
}

bool crypto::base64_encrypt(const string& inbuf, string* outbuf)
{
  typedef base64_from_binary<transform_width<string::const_iterator, 6, 8> > Base64EncodeIterator;
  stringstream result;
  copy(Base64EncodeIterator(inbuf.begin()) , Base64EncodeIterator(inbuf.end()), ostream_iterator<char>(result));
  size_t equal_count = (3 - inbuf.length() % 3) % 3;
  for (size_t i = 0; i < equal_count; i++)
  {
    result.put('=');
  }
  *outbuf = result.str();
  return outbuf->empty() == false;
}

bool crypto::base64_decrypt(const string& inbuf, string* outbuf)
{
  typedef transform_width<binary_from_base64<string::const_iterator>, 8, 6> Base64DecodeIterator;
  stringstream result;
  try {
    copy(Base64DecodeIterator(inbuf.begin()) , Base64DecodeIterator(inbuf.end()), ostream_iterator<char>(result));
  } catch(...) {
    return false;
  }
  *outbuf = result.str();
  return outbuf->empty() == false;
}

void crypto::base64_encrypt(const char* inbuf, char* outbuf,
                            size_t length, bool with_new_line)
{
    BIO * bmem = NULL;
    BIO * b64 = NULL;
    BUF_MEM * bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    if(!with_new_line) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, inbuf, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    memcpy(outbuf, bptr->data, bptr->length);
    outbuf[bptr->length] = 0;

    BIO_free_all(b64);
}

void crypto::base64_decrypt(const char* inbuf, char* outbuf,
                            size_t length, bool with_new_line)
{
    BIO * b64 = NULL;
    BIO * bmem = NULL;
    char * buffer = (char *)malloc(length);
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    if(!with_new_line) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new_mem_buf(inbuf, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, outbuf, length);

    BIO_free_all(bmem);
}

}
