# 1.如何独立编译Trace_streamer
尽管本工具(trace_streamer)是在ohos工具箱中的一员，但你依然可以独立编译此工具。

本工具可以编译linux, mac, windows, WebAssembly版本。

本工具默认编译方式是使用gn
+ 编译方式
```
./build.sh linux/wasm
```
如果需要编译WebAssembly版本，您需要在prebuilts/目录下安装emsdk
```
git clone https://github.com/juj/emsdk.git --depth=1
cd emsdk
git pull
./emsdk update # this may not work, ignore it
./emsdk install latest
./emsdk activate latest
安装之后，您需要将upstream目录复制到prebuilts/emsdk/emsdk，node复制到prebuilts/emsdk/node
```
安装之后，目录结构当如：
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
之后调用
```
./build.sh wasm进行编译，您需要将sh脚本进行部分修改，因为这个脚本内置了一些库的下载和解析方式
```
本工具还支持使用QtCreator来编译。

src/trace_streamer.pro 是工程文件，编译本工具需要依赖Sqlite库和一些基于proto的pb.h文件
## 2 准备工程
### 2.1 基于proto文件生成pb文件
您需要自行下载并编译一个当前系统（linux)可用的proobuf/protoc程序，此全路径为位于out/linux/protoc
src/protos目录下有一个protogen.sh文件，运行该文件可以在third_party/protogen目录下生成项目需要的pb相关文件
序列化二进制的解析依赖于基于proto生成的.pb.cc文件。
在执行protogen.sh脚本之后
你的目录结构当类似如下结构：
```
third_party/protogen/types/plugins/ftrace_data/*.pb.cc
third_party/sqlite/*.
third_party/protobuf/*
```
### 2.2 获取第三方依赖库
从
https://gitee.com/openharmony/third_party_sqlite
获取sqlite3目录到代码根目录的third_party目录 
从
https://gitee.com/openharmony/third_party_protobuf
获取protobuf目录到代码根目录的third_party目录 
之后，你的目录当如下所示  
trace_streamer/third_party/protobuf  
trace_streamer/third_party/sqlite 
# 3.（linux和ohos平台）使用gn编译TraceStreamer 
在编译WebAssembly目标时，需要将sqlite3和protobuf里面相关的ohos_xxx_library统一修改为source_set 
## 3.1 准备gn
在自己的项目中使用gn，必须遵循以下要求：  
在根目录创建.gn文件，该文件用于指定CONFIG.gn文件的位置；  
在BUILDCONFIG.gn中指定编译时使用的编译工具链；  
在独立的gn文件中定义编译使用的工具链；  
在项目根目录下创建BUILD.gn文件，指定编译的目标。  
```
cp prebuilts/gn ./
```
不同的操作系统下，你需要获取不同的gn
## 3.2 执行编译
./build.sh linux debug  
或./build.sh linux debug  
./build.sh将直接编译linux的release版本  
build.sh wasm 命令将可以编译WebAssembly版本  
特别说明：编译WebAssembly版本需要emSDK支持，你需要将build.sh里面的相关路径做更改，以保证编译时必须的文件是存在的
# 4 编译Windows版本或Mac版本
## 4.1 编译依赖文件
### 4.1.1 编译SqliteLib
使用QtCreator打开prebuiltsprebuilts/buildprotobuf/sqlite.pro
### 4.1.2 编译ProtobufLib
使用QtCreator打开prebuilts/buildprotobuf/protobuf.pro
编译之后，文件结构当如下所示：
```
lib
├── linux
│   ├── libdl.so
│   └── libsqlite.a
├── linux_debug
│   ├── libprotobuf.a
│   └── libsqlite.a
├── macx
│   ├── libprotobuf.a
│   └── libsqlite.a
├── macx_debug
│   ├── libprotobuf.a
│   └── libsqlite.a
├── windows
│   ├── libprotobuf.a
│   └── libsqlite.a
└── windows_debug
    ├── libprotobuf.a
    └── libsqlite.a
```
## 4.2 编译TraceStreamer
之后，使用QtCreator打开src/trace_streamer.pro，选择合适的构建工具，执行 Ctrl + b 即可编译

编译之后的可执行文件位于out目录
```
- out
---- linux (Linux平台下QtCreator或gn生成)
---- macx (mac平台下QtCreator或gn生成)
---- windows (windows平台下QtCreator或gn生成)
```