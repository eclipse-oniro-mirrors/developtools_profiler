# 如何独立编译TraceStreamer
尽管TraceStreamer是在ohos工具箱中的一员，但你依然可以独立编译此工具。

TraceStreamer可以编译为linux, mac, windows, WebAssembly版本。

本工具默认编译方式是使用gn。  
## 编译步骤  
### 处理第三方库
因为需要同时支持pc和WebAssembly环境，TraceStreamer构造了一个独立编译编译的环境，需对第三方库的gn脚本做适当的修改，可按下面的步骤进行。    
third_party相关控件下载链接：https://gitee.com/organizations/openharmony/projects  
在TraceStreamer的src同级目录下创建third_party目录。
#### sqlite
1.在第三方库中，找到并下载sqlite组件；  
2.把下载的文件解压后，文件夹命名为sqlite放入到third_party目录中；  
3.使用下面的命令，把sqlite的BUILD.gn修改为TraceStreamer适用的风格。  
```
patch -p0 third_party/sqlite/BUILD.gn prebuilts/buildsqlite/sqlite3build.gn.patch
```
#### protobuf
1.在第三方库中，找到并下载protobuf组件；  
2.把下载的文件解压后，文件夹命名为protobuf，放入到third_party目录中； 
3.使用下面的命令，把protobuf的BUILD.gn修改为TraceStreamer适用的风格。  
```
patch -p0 third_party/protobuf/BUILD.gn prebuilts/protobuf/protobufbuild.gn.patch
```
#### googletest
1.在第三方库中，找到并下载googletest组件；  
2.把googletest文件夹放入third_party目录中；  
3.使用下面的命令，把googletest的BUILD.gn修改为TraceStreamer适用的风格。  
```
patch -p0 third_party/googletest/BUILD.gn prebuilts/buildgoogletest/googletestbuild.gn.patch
```
4.找到文件\googletest\include\gtest\internal\ gtest-port.h 把286行 #include <sstream>  // NOLINT修改为  
#undef private
#define private private
#include <sstream>  // NOLINT
#undef private
#define private public
### nlohmann_json
1.在第三方库中，找到并下载third_party_json库；  
2.把下载的文件解压后，文件夹命名为json-master，放入到third_party目录中。  

### 开始编译
#### 预置条件
1.您需要先获取一个可用的protoc可执行文件，或者在linux平台上执行：
```
./build.sh protoc
```
来生成可用的protoc可执行的程序。  
2.生成proto相关文件对应的pb.h或pb.cc文件  
可执行如下脚本来完成：  
```
./src/protos/protogen.sh
```
#### 编译linux、mac、windows平台的TraceStreamer
编译不同平台的程序，你需要在各自的PC环境编译，编译脚本会自行识别平台并编译程序。  
目前wasm版本仅支持在linux或mac平台编译。  
编译不同版本：linux, windows, mac：
```
./build.sh
```
特别地，如果你需要编译debug版本的应用，只需要输入debug标识即可，否则，默认是release版本的应用。
```
./build.sh linux debug
```
生成的可执行文件分别位于如下路径：
```
out/linux
out/windows
out/macx
out/linux_debug
```
___在不同的平台上，均需要gn和ninja的可执行文件来执行gn工程相关的操作，比如，windows上是gn.exe和ninja.exe。  
在https://gitee.com/su_fu/public_tools/tree/master/gn目录下，您可以获取不同平台下可用的gn和ninja可执行文件，同时，为linux平台下提供了protoc可执行文件。你可以下载并部署在本地的prebuilts目录下。您也可以在linux平台下执行：___
```
./build.sh protoc
```
___来生成out/linux/protoc可执行文件。___
#### 编译WebAssembly版本
如果需要编译WebAssembly版本，您需要在prebuilts/目录下安装emsdk。
```
git clone https://github.com/juj/emsdk.git --depth=1
cd emsdk
git pull
./emsdk update # this may not work, ignore it
./emsdk install latest
./emsdk activate latest
```
安装之后，您需要将upstream目录复制到prebuilts/emsdk/emsdk，node复制到prebuilts/emsdk/node。  
安装之后，目录结构当如下：  
```
prebuilts/emsdk
├── prebuilts/emsdk/emsdk
│   ├── prebuilts/emsdk/emsdk/bin
│   ├── prebuilts/emsdk/emsdk/emscripten
│   │   ├── prebuilts/emsdk/emsdk/emscripten/cache
│   │   ├── prebuilts/emsdk/emsdk/emscripten/cmake
│   │   ├── prebuilts/emsdk/emsdk/emscripten/docs
│   │   ├── prebuilts/emsdk/emsdk/emscripten/media
│   │   ├── prebuilts/emsdk/emsdk/emscripten/node_modules
│   │   ├── prebuilts/emsdk/emsdk/emscripten/__pycache__
│   │   ├── prebuilts/emsdk/emsdk/emscripten/src
│   │   ├── prebuilts/emsdk/emsdk/emscripten/system
│   │   ├── prebuilts/emsdk/emsdk/emscripten/tests
│   │   ├── prebuilts/emsdk/emsdk/emscripten/third_party
│   │   └── prebuilts/emsdk/emsdk/emscripten/tools
│   ├── prebuilts/emsdk/emsdk/include
│   │   └── prebuilts/emsdk/emsdk/include/c++
│   └── prebuilts/emsdk/emsdk/lib
│       └── prebuilts/emsdk/emsdk/lib/clang
└── prebuilts/emsdk/node
    └── prebuilts/emsdk/node/14.18.2_64bit
        ├── prebuilts/emsdk/node/14.18.2_64bit/bin
        ├── prebuilts/emsdk/node/14.18.2_64bit/include
        ├── prebuilts/emsdk/node/14.18.2_64bit/lib
        └── prebuilts/emsdk/node/14.18.2_64bit/share
```
之后，在TraceStream代码根目录，也就是这个文档的上级目录下执行：
```
./build.sh wasm
```
您需要将sh脚本进行部分修改，因为这个脚本内置了一些库的下载和解析方式，你可可以在你的编译环境对此脚本做定制修改。