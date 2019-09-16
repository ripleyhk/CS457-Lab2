#!/bin/bash

# "Script to run pLab-02"
# "Written by: YOUR NAMES here"

echo
echo

# Generate public/private key-pair for Basim
cd basim
rm -f *.pem 
openssl  genpkey -algorithm RSA -out basim_priv_key.pem -pkeyopt rsa_keygen_bits:2048
openssl  rsa     -pubout        -in  basim_priv_key.pem -out     basim_pub_key.pem
#openssl rsa     -text          -in  amal_priv_key.pem

cd ../amal

# Now, share Basim's public key with Amal
rm -f *.pem
ln -s  ../basim/basim_pub_key.pem  basim_pub_key.pem
cd ../

echo "=============================="
echo "Compiling all source code"
rm -f dispatcher amal/amal amal/logAmal.txt basim/basim basim/logBasim.txt bunny.decr 

#
#  Add the necessary commands to build th three executables: 
#       ./dispatcher      ,      amal/amal      ,      and  basim/basim
#
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto
	gcc wrappers.c     dispatcher.c -o dispatcher

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo
echo "======  Amal's  LOG  ========="
cat  amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat  basim/logBasim.txt
echo
echo

echo "=============================="
echo "Verifying File Encryption / Decryption"
echo
diff -s bunny.mp4    bunny.decr
echo
