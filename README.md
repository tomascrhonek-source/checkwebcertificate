# ChechWebCertificate

Tool for checking webserver certificates. It test quality of TLS connection using Golang standard TLS 1.3 library, check for names in certificate
and for most important, it check for expiration date. It can export data for Prometheus with cli option -prometheus

## Usage

checkwebcertificate [-prometheus] domain[:port]

## Exit codes
    0 - certificate is valid
    1 - error - see error message for more information

