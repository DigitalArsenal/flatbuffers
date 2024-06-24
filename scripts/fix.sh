#!/bin/sh

sed -i "s/#ifdef FLATBUFFERS_NO_ABSOLUTE_PATH_RESOLUTION/#if 1/" src/util.cpp
#sed -i "s/if.*kKeep)//" src/util.cpp
cp ./scripts/replacements/util.cpp src/util.cpp
sed -i "s/\"read_/\"read/" src/idl_gen_ts.cpp
sed -i "s/kDasher/kKeep/" src/idl_gen_ts.cpp
sed -i "s/mkdir.*;/return;/" src/util.cpp
sed -i "s/if (binary) {/if (false) {/" src/util.cpp
sed -i "s/if (DirExists(name)) return false;//" src/util.cpp
#sed -i "s/\.js//" src/idl_gen_ts.cpp
sed -i "s/!IsLowerSnakeCase(name)/false/" src/idl_parser.cpp