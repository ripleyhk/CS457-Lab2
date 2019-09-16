/*----------------------------------------------------------------------------
pLAB-02   Key Exchange using Public-Key Encryption

Written By:  1- Your Name
             2- Your Name

             Submitted on: 
----------------------------------------------------------------------------*/
/*
    I am Amal. I will encrypt a large file to Basim.
    I will exchange the session key with Basim encrypted using his RSA public key.

    Adapted from:
        http://hayageek.com/rsa-encryption-decryption-openssl-c/
*/

#include "../myCrypto.h"

// Always check for possible failures AND Free any dynamic memory you allocated 
// to avoid losing points

void main( int argc , char * argv[] ) 
{
    RSA  *rsa_pubK = NULL  ;
    // key & IV for symmetric encryption of data
    uint8_t  sessionKey[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ;    
    char     *plaintextFile  = "bunny.mp4" ;
    int      fd_plain , fd_ctrl , fd_data ;
    
    // Initialize the crypto library
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();

    // Get AtoB Control and Data file descriptor from the argv[]
    // Open Log File
    // Open Plaintext File
    // Get Basim's RSA Public key generated outside this program by the opessl tool 
    rsa_pubK  =  getRSAfromFile( .... ) ;

    // Generate a random session key , and an IV then dump them to Log file

    // Encrypt the session key using Basim's Public Key
    uint8_t *encryptedKey = malloc( RSA_size( rsa_pubK ) ) ;  

    // Using RSA_PKCS1_PADDING padding, which is the currently recommended mode.
    int encrKey_len  
        = RSA_public_encrypt( SYMMETRIC_KEY_LEN, sessionKey, encryptedKey, rsa_pubK 
                              , RSA_PKCS1_PADDING );

    // Send the encrypted session key, and  the IV to the AtoB Control Pipe 
   
    /* Finally, encrypt the plaintext file using the symmetric session key */
    encryptFile(  ..... );

    // Close any open files / descriptors
    // Clean up the crypto library
    RSA_free( rsa_pubK  ) ;
    ERR_free_strings ();
    RAND_cleanup ();
    EVP_cleanup ();
    CONF_modules_free ();
}

