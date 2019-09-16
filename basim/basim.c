/*----------------------------------------------------------------------------
pLAB-02   Key Exchange using Public-Key Encryption

Written By:  1- Your Name
             2- Your Name

Submitted on: 
----------------------------------------------------------------------------*/
/*
    I am Basim. I will decncrypt a file from Amal.
    She exchanged the session key with me encrypted using my public key.

    Adapted from:
        http://hayageek.com/rsa-encryption-decryption-openssl-c/
*/

#include "../myCrypto.h"

// Always check for possible failures AND Free any dynamic memory you allocated 
// to avoid losing points

void main( int argc , char * argv[] ) 
{
    RSA      *rsa_privK = NULL ;
    // key & IV for symmetric encryption of data
    uint8_t  sessionKey[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ;    
    char     *decryptedFile  = "bunny.decr" ;
    int      fd_decr , fd_ctrl , fd_data ;
     
    // Initialize the crypto library
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();

    // Get AtoB Control and Data file descriptor from the argv[]
    // Open Log File
    // Open Decrypted Output File
    // Get my RSA Private key generated outside this program using the openssl tool 
    rsa_privK = getRSAfromFile( .... ) ;

    // Allocate memory to receive the encrypted session key
    int encrKey_len = RSA_size( rsa_privK ) ;
    uint8_t *encryptedKey = malloc( encrKey_len ) ;  

    // Now read the encrypted session key and the IV from the Control Pipe
    read ( fd_ctrl , .... ) ;
    read ( fd_ctrl , .... ) ;

    // Now, decrypt the session key using Basim's private key
    // Using RSA_PKCS1_PADDING padding, which is the currently recommended mode.
    int sessionKey_len = 
        RSA_private_decrypt( encrKey_len , encryptedKey, sessionKey , rsa_privK 
                             , RSA_PKCS1_PADDING );

    // Dump the session key and IV to the Log

    /* Finally, decrypt the ciphertext file using the symmetric session key */
    decryptFile( ..... );
    
    // Close any open files / descriptors
    // Clean up the crypto library    
    RSA_free( rsa_privK ) ;
    ERR_free_strings ();
    RAND_cleanup ();
    EVP_cleanup ();
    CONF_modules_free ();   
}

