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
    FILE     *log ;
     
    // Initialize the crypto library
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();

    // Get AtoB Control and Data file descriptor from the argv[]
    fd_ctrl    = atoi( argv[1] ) ;
    fd_data    = atoi( argv[2] ) ;

    // Open Log File
    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Basim. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Basim. Will read encrypted data from FD %d\n" , fd_data);

    // Open Decrypted Output File
    fd_decr = open("basim/bunny.decr" , O_WRONLY | O_CREAT , S_IRUSR | S_IWUSR);
    if( fd_decr == -1 )
    {
        fprintf( stderr , "\nBasim: Could not open bunny.decr\n");
        fclose( log ) ; exit(-1) ;
    }

    // Get my RSA Private key generated outside this program using the openssl tool 
    rsa_privK = getRSAfromFile("basim_priv_key.pem", 1) ;

    // Allocate memory to receive the encrypted session key
    int encrKey_len = RSA_size( rsa_privK ) ;
    uint8_t *encryptedKey = malloc( encrKey_len ) ;  

    // Now read the encrypted session key and the IV from the Control Pipe
    // read ( fd_ctrl , .... ) ;
    // read ( fd_ctrl , .... ) ;

    // Now, decrypt the session key using Basim's private key
    // Using RSA_PKCS1_PADDING padding, which is the currently recommended mode.
    //int sessionKey_len = 
    //    RSA_private_decrypt( encrKey_len , encryptedKey, sessionKey , rsa_privK 
    //                         , RSA_PKCS1_PADDING );

    // Dump the session key and IV to the Log

    /* Finally, decrypt the ciphertext file using the symmetric session key */
    // decryptFile( ..... );
    
    // Close any open files / descriptors
    // Clean up the crypto library    
    RSA_free( rsa_privK ) ;
    ERR_free_strings ();
    RAND_cleanup ();
    EVP_cleanup ();
    CONF_modules_free ();   
}

