#!/bin/bash

# install tool container-structure-test

install-container-structure-test() {
    os_name=$(uname 2> /dev/null | tr '[:upper:]' '[:lower:]')

    file_name="container-structure-test-${os_name}-amd64"
    release="v1.7.0"

    curl -LO https://storage.googleapis.com/container-structure-test/${release}/${file_name} &&
    mkdir -p ${HOME}/bin &&
    mv ${file_name} ${HOME}/bin/container-structure-test &&
    chmod +x $HOME/bin/container-structure-test
}

if [ -z "$(which container-structure-test)" ]; then
    install-container-structure-test
else
    echo "container-structure-test is installed already. skipping."
fi
