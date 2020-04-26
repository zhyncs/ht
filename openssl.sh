#!/bin/bash

set -e

install_dependency() {
  sudo apt update
  sudo apt install -y build-essential
}

download_openssl() {
  ver=$(wget --no-check-certificate -qO- https://www.openssl.org/source/ | grep openssl-1.1.1 | cut -d '"' -f2 | sed 's/.tar.gz//g')
  if [[ ! -d ${ver} ]]; then
    if [[ ! -f ${ver}.tar.gz ]]; then
      wget --no-check-certificate https://www.openssl.org/source/"${ver}".tar.gz
    fi
    tar xf "${ver}".tar.gz
  fi
  pushd "${ver}"
}

install_openssl() {
  ./config
  make -j
  sudo make install -j
  export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
  sudo ldconfig
  popd
}

install_dependency
download_openssl
install_openssl
