//rsa_crypt.cpp
//Generate private key(length 1024): openssl genrsa -out priv_key.pem 1024
//Generate public key: openssl rsa -in priv_key.pem -pubout -out pub_key.pem
//g++ rsa_crypt.cpp -o rsa_crypt -lcrypto
//author: kevinjs
//email: dysj4099@gmail.com
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

RSA* createRSA(unsigned char* key, bool isPublic)
{
    RSA* rsa = NULL;
    BIO* bio;

    bio = BIO_new_mem_buf(key, -1);
    if (NULL == bio)
    {
        printf("error: create key BIO failed");
        return NULL;
    }

    if(isPublic)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(bio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
    }
    return rsa;
}

RSA* createRSAWithFile(const char* filename, bool isPublic)
{
    FILE* fp = fopen(filename, "rb");

    if (NULL == fp)
    {
        printf("error: open keyfile %s failed", filename);
        return NULL;
    }

    RSA* rsa = RSA_new();

    if(isPublic)
    {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    }
    fclose(fp);
    return rsa;
}

int base64_encode(const unsigned char* data, int length, bool with_nl, char* encodedData)
{
    BIO* bio = NULL;
    BIO* b64 = NULL;
    BUF_MEM* bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    if(!with_nl)
    {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    memcpy(encodedData, bptr->data, bptr->length);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    return bptr->length > 0 ? bptr->length : -1;
}

int base64_decode(char* encodedData, int length, bool with_nl, unsigned char* decodedData)
{
    BIO* bio = NULL;
    BIO* b64 = NULL;

    int padding = 0;
    int decLen = 0;
    if (encodedData[length-1] == '=' && encodedData[length-2] == '=')
    {
        padding = 2;
    }
    else if(encodedData[length-1] == '=')
    {
        padding = 1;
    }
    decLen = (length * 3)/4 - padding;

    bio = BIO_new_mem_buf(encodedData, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    if(!with_nl)
    {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }

    int readLen = BIO_read(bio, decodedData, length);
    printf("decLen: %d, readLen: %d", decLen, readLen);
    BIO_free_all(bio);

    return decLen == readLen ? readLen : -1;
}

int public_encrypt(const char* publicKeyFile, unsigned char* data, int length, unsigned char* encryptdData)
{
    RSA* rsa = createRSAWithFile(publicKeyFile, true);
    int ret = RSA_public_encrypt(length,
                                 data,
                                 encryptdData,
                                 rsa,
                                 RSA_PKCS1_PADDING);
    RSA_free(rsa);
    CRYPTO_cleanup_all_ex_data();
    return ret;
}

int private_decrypt(const char* privateKeyFile, unsigned char* encryptdData, int length, unsigned char* decryptData)
{
    RSA* rsa = createRSAWithFile(privateKeyFile, false);
    int ret = RSA_private_decrypt(length,
                                  encryptdData,
                                  decryptData,
                                  rsa,
                                  RSA_PKCS1_PADDING);
    RSA_free(rsa);
    CRYPTO_cleanup_all_ex_data();
    return ret;
}

int private_encrypt(const char* privateKeyFile, unsigned char* data, int length, unsigned char* encryptdData)
{
    RSA* rsa = createRSAWithFile(privateKeyFile, false);
    int ret = RSA_private_encrypt(length,
                                  data,
                                  encryptdData,
                                  rsa,
                                  RSA_PKCS1_PADDING);
    RSA_free(rsa);
    CRYPTO_cleanup_all_ex_data();
    return ret;
}

int public_decrypt(const char* publicKeyFile, unsigned char* encryptdData, int length, unsigned char* decryptData)
{
    RSA* rsa = createRSAWithFile(publicKeyFile, true);
    int ret = RSA_public_decrypt(length,
                                 encryptdData,
                                 decryptData,
                                 rsa,
                                 RSA_PKCS1_PADDING);
    RSA_free(rsa);
    CRYPTO_cleanup_all_ex_data();
    return ret;
}

int main()
{
    unsigned char orignText[1024/8] = "Hello, I'm kevinjs, this is a RSA example by openssl."; //key length 1024

    unsigned char encrypted1[256] = {};
    unsigned char decrypted1[256] = {};

    char encoded1[1024] = {};
    unsigned char decoded1[1024] = {};

    int encrypted_length_1 = public_encrypt("pub_key.pem", orignText, strlen((char*)orignText), encrypted1);
    printf("PUB_EN:Ori:%s, EncLen:%d\n", orignText, encrypted_length_1);

    int encoded_length_1 = base64_encode(encrypted1, encrypted_length_1, false, encoded1);
    printf("B64DE:%s, DeLen:%d\n", encoded1, encoded_length_1);

    int decoded_length_1 = base64_decode(encoded1, encoded_length_1, false, decoded1);

    int decrypted_length_1 = private_decrypt("priv_key.pem", decoded1, decoded_length_1, decrypted1);
    printf("PRI_DE:Dec:%s, DecLen:%d\n", decrypted1, decrypted_length_1);

    printf("----------------------------------------------\n");

    unsigned char encrypted2[256]={};
    unsigned char decrypted2[256]={};

    char encoded2[1024] = {};
    unsigned char decoded2[1024] = {};

    int encrypted_length_2 = private_encrypt("priv_key.pem", orignText, strlen((char*)orignText), encrypted2);
    printf("PRI_EN:Ori:%s, EncLen:%d\n", orignText, encrypted_length_2);

    int encoded_length_2 = base64_encode(encrypted2, encrypted_length_2, false, encoded2);
    printf("B64DE:%s, DeLen:%d\n", encoded2, encoded_length_2);
    int decoded_length_2 = base64_decode(encoded2, encoded_length_2, false, decoded2);
    int decrypted_length_2 = public_decrypt("pub_key.pem", decoded2, decoded_length_2, decrypted2);
    printf("PUB_DE:Dec:%s, DecLen:%d\n", decrypted2, decrypted_length_2);

    return 0;
}

