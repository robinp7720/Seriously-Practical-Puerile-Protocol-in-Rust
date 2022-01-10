# The certificate folder

## How to genereate a cetrificate?

Create private key by running: `openssl genrsa -out [NANE].key 4096`.

Create a Certificate Signing Request (CSR): `openssl req -new -sha256 -key [NAME].key -out [NAME].csr`.

Create a Certificate (This step is done by your CA): ` openssl x509 -req -in [NAME].csr -CA [CA].crt -CAkey [CA].key -CAcreateserial -out [NAME].crt -days 365 -extfile [NAME].ext -sha256`.

The .ext file is necessary to force openssl to use the correct protocol version. It can be an empty file.

## Become a CA

Create private key by running: `openssl genrsa -out [CA].key 4096`.

Create CSR: `openssl req -new -sha256 -key [CA].key -out [CA].csr`

Self sign the certificate: `openssl x509 -req -sha256 -days 365 -in [CA].csr -signkey [CA].key -extfile [CA].ext -out [CA].crt`

The .ext file is necessary to force openssl to use the correct protocol version. It can be an empty file.

## Install CAs

You can install CAs for this transport protocol by putting the .crt file in the `./CA` folder (relative to this README). You can have as many CAs as you want to have. But make sure you add the CA of all of your communication partners.

## Install Keys

You can install your own key by placing the .key file and the .crt file in this directory. The files have to be names as follows: `server.{key, cet}`.

## Hint

1. Make sure to keep all of your .key files private. There is no situation where someone, but you should be in possession of this file!

2. Do NOT use the .crt files provided by this repository for any real world application. The public keys associated with the certificate is not kept secret (for simplification of development).

3. The DO_NOT_USE key can be used for testing. Due to the fact that the private key of the certificate is published, it is not recommended using it in any other case! 