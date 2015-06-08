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

[[ ! -e JSSEDebuggingServer.class ]] && javac JSSEDebuggingServer.java

java -cp . -Djavax.net.ssl.trustStore="keys/scapy-ssl_tls.jks" -Djavax.net.debug=ssl JSSEDebuggingServer
