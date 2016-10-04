#include <iostream>
#include "crypto.hpp"

using namespace std;

int main(int argc, char *argv[])
{
    /*
     test blowfish
    */
    unsigned char key[8] = {1,2,3,4,5,6,7,8};
    unsigned char inbuf[20] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39};
    unsigned char outbuf[20] = {0};
    unsigned char reinbuf[20];

    cout << "origin:" << endl;
    cout << xcrypto::crypto::char2hexstring(inbuf, 10) << endl;

    xcrypto::crypto::blowfish_encrypt(inbuf, outbuf, 10, key, 8, xcrypto::BF_CFB, BF_ENCRYPT);

    cout<< "encrypt:" << endl;
    cout<<xcrypto::crypto::char2hexstring(outbuf, 10) << endl;

    xcrypto::crypto::blowfish_encrypt(outbuf, reinbuf, 10, key, 8, xcrypto::BF_CFB, BF_DECRYPT);

    cout<< "decrypt:" << endl;
    cout<<xcrypto::crypto::char2hexstring(reinbuf, 10) << endl;

    /*
     test boost::base64
    */
    string input_str("https://github.com/yixuanrobot/xcrypto.git ~!@#$%\r\n\t0123456789");
    string base64_str, output_str;

    cout<<"origin text:"<< endl << input_str << endl;

    xcrypto::crypto::base64_encrypt(input_str, &base64_str);
    cout<<"encode:"<< endl << base64_str << endl;

    xcrypto::crypto::base64_decrypt(base64_str, &output_str);
    cout<<"decode:"<< endl << output_str << endl;

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

    /*
      test xcrypt
    */
    unsigned char xkey[8] = {1,2,3,4,5,6,7,8};
    unsigned char xinbuf[18] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x38,0x38,0x38,0x38,0x38,0x38,0x38,0x38};
    string xoutbuf;
    unsigned char xreinbuf[18] = {0};

    cout << "origin: " << xcrypto::crypto::char2hexstring(xinbuf, 18) << endl;
    xcrypto::crypto::xencrypt(xinbuf, 18, &xoutbuf, xkey, 8, xcrypto::BF_CFB);
    cout<< "xencrypt:" << xoutbuf << endl;
    xcrypto::crypto::xdecrypt(xoutbuf, xreinbuf, xkey, 8, xcrypto::BF_CFB);
    cout<< "xdecrypt:" << xcrypto::crypto::char2hexstring(xreinbuf,18) << endl;

    return 0;
}
