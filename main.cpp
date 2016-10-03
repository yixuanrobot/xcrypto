#include <iostream>
#include <stdio.h>
#include "crypto.hpp"

using namespace std;

int main(int argc, char *argv[])
{
//    if(argc < 3)
//    {
//        printf("Usage: ./xcrypto test 1\n");
//        printf("1 openssl->blowfish\n");
//        printf("2 boost->base64\n");
//        printf("3 openssl->base64\n");
//        return 0;
//    }

    /*
     test blowfish
    */
    unsigned char key[8] = {1,2,3,4,5,6,7,8};
    unsigned char intbuf[10] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39};
    unsigned char outbuf[10];
    unsigned char reintbuf[10];

    printf("origin: \n");
    for (size_t i=0;i<10;i++)
    {
        printf("%02X ", intbuf[i]);
    }
    printf("\n");

    printf("encrypt: \n");
    xcrypto::crypto::blowfish_encrypt(intbuf, outbuf, 10, key, 8, xcrypto::BF_CFB, BF_ENCRYPT);
    for (size_t i=0;i<10;i++)
    {
        printf("%02X ", outbuf[i]);
    }
    printf("\n");

    printf("decrypt: \n");
    xcrypto::crypto::blowfish_encrypt(outbuf, reintbuf, 10, key, 8, xcrypto::BF_CFB, BF_DECRYPT);
    for (size_t i=0;i<10;i++)
    {
        printf("%02X ", reintbuf[i]);
    }
    printf("\n");

    /*
     test boost::base64
    */
    string input_str("https://github.com/yixuanrobot/xcrypto.git ~!@#$%\r\n\t0123456789");
    string base64_str, output_str;

    cout<<"origin text: \n"<<input_str<<endl;

    xcrypto::crypto::base64_encrypt(input_str, &base64_str);
    cout<<"encode: \n"<<base64_str<<endl;

    xcrypto::crypto::base64_decrypt(base64_str, &output_str);
    cout<<"decode: \n"<<output_str<<endl;

    /*
     test openssl->base64
    */
    string enc_input = "Henry Alfred Kissinger is a German-born American writer, political scientist, " \
            "diplomat, and businessman. A recipient of the Nobel Peace Prize, he served as National " \
            "Security Advisor and later concurrently as Secretary of State in the administrations of " \
            "Presidents Richard Nixon and Gerald Ford.";

    char enc_output[1024];
    char dec_output[1024];
    cout << endl << "To be encoded:" << endl << "~" << enc_input << "~" << endl << endl;

    xcrypto::crypto::base64_encrypt(enc_input.c_str(), (char*)enc_output, enc_input.length(), false);
    cout << "Base64 Encoded:" << endl << "~" << enc_output << "~" << endl << endl;

    string dec_input = (char*)enc_output;
    xcrypto::crypto::base64_decrypt(dec_input.c_str(), (char*)dec_output, dec_input.length(), false);
    cout << "Base64 Decoded:" << endl << "~" << dec_output << "~" << endl << endl;

    return 0;
}
