#!/bin/bash
# Copyright (C) 2021 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -e
PARAMS=$*
echo $PARAMS
echo "begin to check input"
target_os='linux'
target_dir='linux'
gn_path='linux'
is_debug='false'
is_clean='false'
target='trace_streamer'
gn='gn'
ninja='ninja'
case "$OSTYPE" in
  solaris*) echo "SOLARIS" ;;
  darwin*)  gn_path='macx' target_os='macx' ;;
  linux*)   gn_path='linux' target_os='linux'  ;;
  bsd*)     echo "is bsd os" ;;
  msys*)    gn_path='windows' target_os='windows' gn='gn.exe' ninja='ninja.exe'  ;;
  *)        echo "unknown: $OSTYPE" ;;
esac
usage="Usage: $basename $0 wasm/test/fuzz/protoc debug/release/clean"


if [ "$1" == 'windows' ];then
    echo "gn only support linux and wasm build currently"
    if [ ! -d "out/windows" ];then
        mkdir out/windows
    fi
    touch out/windows/trace_streamer.exe
    exit
fi

if [ "$#" -ne "0" ];then
    if [ "$1" == "wasm" ];then
        if [ ! -d "prebuilts/emsdk" ];then
            echo "you need emsdk to compile wasm"
            #mv emsdk.tar.gz prebuilts/
            #mv ../emsdk.tar.gz prebuilts/
            if [ ! -f "prebuilts/emsdk.tar.gz" ];then
                # consider <compile_trace_streamer.md>
                # you need to get emsdk.tar.gz some where
                mv emsdk.tar.gz prebuilts/
                tar -zxvf prebuilts/emsdk.tar.gz -C prebuilts/
            else
                tar -zxvf prebuilts/emsdk.tar.gz -C prebuilts/
            fi
        fi
        target='wasm'
    fi
    if [ "$1" == "test" ];then
        target='test'
    fi
    if [ "$1" == "fuzz" ];then
        target='fuzz'
    fi
    if [ "$1" == "protoc" ];then
        target='protoc'
    fi
    if [ "$1" == "sdkdemo" ];then
        target='sdkdemo'
    fi
    if [ "$1" == "sdkdemotest" ];then
        target='sdkdemotest'
    fi
fi
if [ "$#" -eq "2" ];then
    if [ "$1" != 'trace' ] && [ "$1" != "linux" ] && [ "$1" != "windows" ] && [ "$1" != "macx" ] && [ "$1" != "trace_streamer" ] && [ "$1" != "wasm" ] && [ "$1" != "test" ] && [ "$1" != "fuzz" ] && [ "$1" != "protoc" ];then
	echo "failed"
    echo "$usage"
	exit
    fi
    if [ "$2" != "debug" -a "$2" != "release" -a "$2" != "clean" ];then
    if [ "$2" == "protoc" ];then
    target="$2"
    else
	echo "failed"
    	echo "$usage"
	exit
    fi
    fi
    if [ "$2" == "debug" ];then
	is_debug='true'
    elif [ "$2" == "clean" ];then
	is_clean='true'
    else
	is_debug='false'
    fi
    echo "platform is $target_os"
    echo "isdebug: $is_debug"
    echo "isclean: $is_clean"
else
    echo "$usage"
    echo "You provided $# parameters,but 2 are required."
    echo "use default input paramter"
    echo "platform is $target_os"
    echo "target is $target"
    echo "is_debug:$is_debug"
fi
echo "gen ..."
ext=""
if [ "$is_debug" != 'false' ];then
       	ext="_debug"
fi
#exec "protogen.sh"
echo "the output file will be at ""$prefix""$target_os"
echo ""
echo ""
echo "-------------tips-------------"
echo ""
echo "if you are compiling first time, or your proto has changed, you need to run ./src/protos/protogen.sh"
echo ""
echo ""
echo
#./src/protos/protogen.sh
if [ ! -d "prebuilts/$gn_path" ];then
    mkdir prebuilts/$gn_path
fi
if [ ! -f "prebuilts/$gn_path/gn" ];then
	echo "you may get gn for $target_os and place it in prebuilts/$target_os"
	echo "the file can be get at https://gitee.com/su_fu/public_tools/raw/master/gn/$target_os/gn, you need to download it manually"
    #wget https://gitee.com/su_fu/public_tools/raw/master/gn/$target_os/gn
    #mv gn prebuilts/$target_os/
    #chmod +x prebuilts/$target_os/gn
	exit
fi
if [ ! -f "prebuilts/$gn_path/ninja" ];then
	echo "you may get ninja for $target_os and place it in prebuilts/$target_os"
	ehco "the file can be get at https://gitee.com/su_fu/public_tools/raw/master/gn/$target_os/ninja, you need to download it manually"
    #wget "https://gitee.com/su_fu/public_tools/raw/master/gn/$target_os/ninja"
	#wget https://gitee.com/su_fu/public_tools/raw/master/gn/$target_os/ninja
    #mv ninja prebuilts/$target_os/
    #chmod +x prebuilts/$target_os/*
	exit
fi
echo "$is_clean"
if [ $target == 'test' ] || [ $target == 'fuzz' ] || [ $target='wasm' ] || [ $target='sdkdemo' ] || [ $target='sdkdemotest' ];then
    target_dir=$target
else
    target_dir=$target_os
fi
if [ $target == 'trace_streamer' ] || [ $target == 'trace' ];then
    target_dir=$target_os
fi
echo "target_dir:" $target_dir
# exit
if [ "$is_clean" == 'true'  ];then
    prebuilts/$gn_path/$gn gen out/"$target_dir""$ext" --clean
    prebuilts/$gn_path/$ninja -C out/"$target_dir""$ext" -t clean
else
    prebuilts/$gn_path/$gn gen out/"$target_dir""$ext" --args='is_debug='"$is_debug"' target="'"$target"'" target_os="'"$target_os"'"'
    echo "begin to build ..."
    mkdir -p out/windows
    touch out/windows/trace_streamer.exe
    prebuilts/$gn_path/$ninja -C out/"$target_dir""$ext"
   # prebuilts/$gn_path/ninja -C out/"$target_os""$ext"
fi
