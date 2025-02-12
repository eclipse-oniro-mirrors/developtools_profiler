# SmartPerf

-   [简介](#简介)
-   [目录](#目录)
-   [约束](#约束)
-   [相关文档](#相关文档)

## 简介
在OpenHarmony中，研发工具链子系统主要为开发人员提供了开发时用于调试的命令行以及追踪性能轨迹、查看性能的工具。SmartPerf 旨在为开发者提供一套性能调优组件，可以用来分析系统内存、性能等问题。


其主要的结构如下图所示：

![系统架构图](./figures/smartperf_framework.png)


## 目录
```
/developtools/profiler/host/smartperf
├── doc                      # SmartPerf 相关使用文档
├── ide                      # SmartPerf IDE 模块目录
│   └── src                  # 主机测调优模块代码
│   │   ├── base-ui          # 基础组件目录
│   │   └── Trace            # 业务逻辑目录 
├── trace_streame            # 解析模块代码目录
│   ├── base                 # 基础功能  
│   ├── cfg                  # 配置目录
│   ├── filter               # Filter功能
│   ├── include              # Include头文件
│   ├── multi_platform       # 平台适配
│   ├── parser               # 解析业务逻辑
│   │   ├── bytrace_parser   # byTrace解析业务逻辑
│   │   └── htrace_parser    # hTrace 解析业务逻辑
│   ├── table                # 表结构
│   ├── trace_data           # trace 结构
│   ├── trace_streamer       # traceStreamer 结构
│   │   └── kits             # js/napi接口存放目录
```



## 约束
- 语言版本
    - C++11或以上
    - TypeScript 4.2.3


## 相关文档
- [quickstart_trace_streamer](https://gitee.com/openharmony/developtools_profiler/blob/master/host/smartperf/doc/quickstart_trace_streamer.md)
- [quickstart_smartperf](https://gitee.com/openharmony/developtools_profiler/blob/master/host/smartperf/doc/quickstart_smartperf.md) 
- [quickstart_hiprofiler_cmd](https://gitee.com/openharmony/developtools_profiler/blob/master/host/smartperf/doc/quickstart_hiprofiler_cmd.md) 
- [compile_smartperf](https://gitee.com/openharmony/developtools_profiler/blob/master/host/smartperf/doc/compile_smartperf.md) 
- [compile_trace_streamer](https://gitee.com/openharmony/developtools_profiler/blob/master/host/smartperf/doc/compile_trace_streamer.md)
- [des_stat](https://gitee.com/openharmony/developtools_profiler/blob/master/host/smartperf/doc/des_stat.md)  
- [des_support_event](https://gitee.com/openharmony/developtools_profiler/blob/master/host/smartperf/doc/des_support_event.md) 
- [des_tables](https://gitee.com/openharmony/developtools_profiler/blob/master/host/smartperf/doc/des_tables.md) 