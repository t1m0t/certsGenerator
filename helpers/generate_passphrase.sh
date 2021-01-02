#!/bin/bash

PASS_PATH="passphrase"
PASS_FILE="$PASS_PATH/$1"
if [ ! -f $PASS_FILE ]
then
    echo $(openssl rand -hex 32) > $PASS_FILE
    chmod go-rwx $PASS_FILE
else
    echo "$PASS_FILE aleady exists"
fi
