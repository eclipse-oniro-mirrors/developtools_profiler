tools 目录代码说明
==================

| 目录条目                      | 说明        |
|-------------------------------|------------|
| allowlist.txt                 | 事件允许列表 |
| refresh_device_kernel_code.py | ftrace内核相关代码生成器，传入内核版本自动调用脚本生成proto、parsers cpp、formatters cpp代码 |
| ftrace_cpp_generator.py       | C++代码生成器，用于生成ftrace具体事件原始数据解析和格式化代码 |
| ftrace_format_parser.py       | format文件解析器，用于解析从设备上拉出来的format文件 |
| ftrace_proto_generator.py     | proto代码生成器，用于生成ftrace具体事件的proto定义代码 |
| pack_ftrace_formats.sh        | 打包format文件的脚本，用于将设备上的format文件打包为tar.gz文件 |
| snapshot/                     | 从设备上拉去的format文件及目录结构 |
| trace_converter/              | trace数据转换器，用于将ftrace插件数据文件转为内核trace文本格式 |

