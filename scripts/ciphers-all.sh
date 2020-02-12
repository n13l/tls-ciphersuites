#!/bin/bash
./opt/bin/openssl ciphers ALL | sed 's/\:/\n/g'
