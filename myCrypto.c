/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By:  1- Hannah Ripley
             2- Adrian Brazil

Submitted on: 9/18/2019
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}

//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

// For the following Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             uint8_t *key, uint8_t *iv, uint8_t *pCipherText )
{
    int status ;
    unsigned len=0 , encryptedLen=0 ;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;

    if( ! ctx )
        handleErrors("encrypt: failed to creat CTX");

    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ;

    if( status != 1 )
        handleErrors("encrypt: failed to EncryptInit_ex");

    // Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
    status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len) ;
    if( status != 1 )
        handleErrors("encrypt: failed to EncryptUpdate");
    encryptedLen += len;

    // If additional ciphertext may still be generated,
    // the pCipherText pointer must be first advanced forward
    pCipherText += len ;

    // Finalize the encryption.
    status = EVP_EncryptFinal_ex( ctx, pCipherText , &len ) ;

    if( status != 1 )
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len;

    // len could be 0 if no additional cipher text was generated
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return encryptedLen ;

}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  uint8_t *key, uint8_t *iv, uint8_t *pDecryptedText)
{
    int status ;
    unsigned len=0 , decryptedLen=0 ;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;
    if( ! ctx )
        handleErrors("decrypt: failed to creat CTX");
    // Initialise the decryption operation.
    status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ;
    if( status != 1 )
        handleErrors("decrypt: failed to DecryptInit_ex");

    // Call DecryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular decryption
    status = EVP_DecryptUpdate( ctx, pDecryptedText, &len, pCipherText, cipherText_len) ;
    if( status != 1 )
        handleErrors("decrypt: failed to DecryptUpdate");
    decryptedLen += len;

    // If additionl decrypted text may still be generated,
    // the pDecryptedText pointer must be first advanced forward
    pDecryptedText += len ;

    // Finalize the decryption.
    status = EVP_DecryptFinal_ex( ctx, pDecryptedText , &len ) ;
    if( status != 1 )
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return decryptedLen;

}

//***********************************************************************
// PA-01
//***********************************************************************

int encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{

    uint8_t plaintext[PLAINTEXT_LEN_MAX]; 
    uint8_t ciphertext[CIPHER_LEN_MAX];
    int plain_bytes = 0; // number of plaintext bytes read
    int cipher_bytes = 0; // number of cipher bytes encrypted

    while ((plain_bytes = read(fd_in, plaintext, PLAINTEXT_LEN_MAX)) != 0){
        cipher_bytes = encrypt(plaintext, plain_bytes, key, iv, ciphertext); 
        write(fd_out, ciphertext, cipher_bytes);
    }

}

//-----------------------------------------------------------------------------
int decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{

    uint8_t plaintext[CIPHER_LEN_MAX]; // max = 1024
    uint8_t ciphertext[CIPHER_LEN_MAX]; // max = 1024
    int cipher_bytes = 0; // number of ciphertext bytes read
    int plain_bytes = 0; // number of plaintext bytes decrypted

    while ((cipher_bytes = read(fd_in, ciphertext, CIPHER_LEN_MAX)) != 0){
        plain_bytes = decrypt(ciphertext, cipher_bytes, key, iv, plaintext); 
        write(fd_out, plaintext, plain_bytes);
    }

}

//***********************************************************************
// pLAB-02
//***********************************************************************

RSA *getRSAfromFile(char * filename, int public)
{
    RSA * rsa;
    FILE * file; 
    // open the binary file whose name if 'filename' for reading
    file = fopen(filename , "r" );
    if( ! file )
    {
        fprintf( stderr , "Could not open %s to get RSA.\n", filename);
        exit(-1) ;
    }

    // Create a new RSA object using RSA_new() ;
    rsa = RSA_new(); 

    // To read a public RSA key, use PEM_read_RSA_PUBKEY()
    if (public)
        PEM_read_PUBKEY(file, rsa, null, null);

    // To read a public RSA key, use PEM_read_RSAPrivateKey()
    else
        PEM_read_RSAPrivateKey(); 

    // close the binary file 'filename'
    fclose(file); 

    return rsa;
}

//-----------------------------------------------------------------------------
