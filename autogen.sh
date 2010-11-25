#! /bin/sh

# check in submodules

git submodule init
git submodule update

# run autotools
autoreconf -i
