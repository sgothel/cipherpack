#! /bin/bash

key_base_name=$1
shift 1

ssh-keygen -b 4096 -t rsa -m PKCS8 -f $key_base_name
ssh-keygen -f $key_base_name.pub -e -m pkcs8 > $key_base_name.pub.pem

#openssl pkcs8 -topk8 -inform PEM -outform DER -in $key_base_name -out $key_base_name.der -nocrypt

