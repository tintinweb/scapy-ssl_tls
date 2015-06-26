#!/bin/bash

# Silly OSX readlink doesn't have -f
if [[ $(uname -s) == "Darwin" ]]; then
    readlink=$(which greadlink)
else
    readlink=$(which readlink)
fi

# Change to the script directory to find our keys
script_dir="$(dirname "$(${readlink} -f "${0}")")"
cd "${script_dir}"

# possible values tls1, tls1_1, tls1_2
openssl s_server -accept 8443 -www -debug -msg -key keys/key.pem -cert keys/cert.pem -${1} -no_ssl3
