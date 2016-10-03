#include <iostream>
#include <cstring>
#include <openssl/blowfish.h>
#include <boost/cstdint.hpp>
#include <boost/format.hpp>
#include <stdio.h>

using namespace std;

enum
{
    BF_ECB,
    BF_CBC,
    BF_CFB,
    BF_OFB
};

void bf_encrypt(boost::uint8_t *inbuf, boost::uint8_t *outbuf, boost::int32_t blklen,
                boost::uint8_t *key, boost::int32_t keylen,
                boost::int8_t mode, boost::int32_t enc)
{
    boost::int32_t num = 0;
    boost::uint8_t ivec[8];
    BF_KEY bfkey;

    memset(ivec, 0, 8);
    BF_set_key(&bfkey, keylen, key);
    switch(mode)
    {
    case    BF_CFB:
        BF_cfb64_encrypt(inbuf, outbuf, blklen, &bfkey,
                         ivec, &num, enc);
        break;
    case    BF_ECB:
        BF_ecb_encrypt(inbuf, outbuf, &bfkey, enc);
        break;
    case    BF_CBC:
        BF_cbc_encrypt(inbuf, outbuf, blklen, &bfkey,
                         ivec, enc);
        break;
    case    BF_OFB:
        BF_ofb64_encrypt(inbuf, outbuf, blklen, &bfkey,
                         ivec, &num);
        break;
    default:
        break;
    }
}


int main(int argc, char *argv[])
{
    boost::uint8_t key[8] = {1,2,3,4,5,6,7,8};
    boost::uint8_t intbuf[10] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39};
    boost::uint8_t outbuf[10];
    boost::uint8_t reintbuf[10];

    bf_encrypt(intbuf, outbuf, 10, key, 8, BF_CFB, BF_ENCRYPT);
    for (boost::int8_t i=0;i<10;i++)
    {
        printf("%02X ", outbuf[i]);
    }
    printf("\n");

    bf_encrypt(outbuf, reintbuf, 10, key, 8, BF_CFB, BF_DECRYPT);
    for (boost::int8_t i=0;i<10;i++)
    {
        printf("%02X ", reintbuf[i]);
    }
    printf("\n");

    return 0;
}
