# 编译UT
直接运行./build.sh test 即可编译ut代码，编译ut时，可能会遇到一些问题，需要将部分代码做如下处理：  
v412.pb.h 大约第36行，添加如下内容
```
#ifdef major
#undef major
#endif
#ifdef minor
#undef minor
#endif
```
gtest-port.h 第286行，在
```
#include <sstream>
```
修改为
```
#undef private
#define private private
#include <sstream>
#undef private
#define private public
```

在ut代码编译完成之后，直接运行./test.sh，可以执行所有ut，显示正确与否。  
在ut执行之后，直接运行./lcov.sh，可以生成覆盖率报告。  
覆盖率报告位于out/test/html目录。  