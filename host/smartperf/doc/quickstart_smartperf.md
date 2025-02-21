# 网页加载trace 使用说明

## 1.打开版本包里面的main.exe可执行文件，启动web页面
![GitHub Logo](../figures/main.jpg)

## 2.Web页面展开
![GitHub Logo](../figures/opentrace.jpg)

说明：
+ Open trace file：导入离线trace文件入口
+ Record new trace：抓取新的trace文件入口

## 3.导入文件后显示页面
![GitHub Logo](../figures/trace.jpg)
说明：
+ 操作说明：在当前页面可以通过键盘上的wasd四个键位操纵当前的时间轴进行缩放，w放大，s为缩小，a为左移，d为右移。
## 功能介绍
模块从上往下主要展示时间轴和cpu使用率、cpu使用情况、进程间通讯数据的方法调用情况、进程、线程和方法调用情况
### 1. 时间轴和cpu使用率
![GitHub Logo](../figures/figures/time.jpg)
最上方带刻度的为时间轴，主要展示当前抓取数据的总时长和时间刻度的分布情况，如上图所示，左下角展示总时长，
中间区域展示的是抓取数据时间段内的cpu使用率，颜色越深代表cpu使用率越高，颜色越浅代表cpu使用率越低。
![GitHub Logo](../figures/highlit.jpg)
在白色背景时间轴区域内可以点击后拖拽鼠标，可以对从鼠标按下到拖拽完成鼠标松开的区域内的数据进行筛选，高亮显示的部分为当前所选区域，如上图所示
### 2.cpu使用情况
![GitHub Logo](../figures/cpu.jpg)
 
如上图所示，当前抓取数据有4个cpu工作，前四组数据对应的是当前调用cpu的线程和对应的进程情况，以颜色作为区分。后四组数据则为cpu的使用频率信息。鼠标移动到相应的线程上还会将当前选中的进程信息全部置为高亮，其他的进程会置灰，如下图所示
![GitHub Logo](../figures/gray.jpg)
#### 2.1.cpu使用情况的框选功能
可以对cpu的数据进行框选，框选后在最下方的弹出层中会展示框选数据的统计表格,总共有三个tab页
CPU by thread的Tab页，主要显示了在框选时间区间内的进程名，进程号，线程名，线程号，总运行时长，平均运行时长和调度次数信息
![GitHub Logo](../figures/cpubythread.jpg)
CPU by process的Tab页，主要显示了在框选时间区间内的进程名，进程号，总运行时长，平均运行时长和调度次数信息
![GitHub Logo](../figures/cpubyprocess.jpg)
CPUUsage的Tab页，主要显示了在框选时间区间内，该频率时间占比前三的信息
![GitHub Logo](../figures/cpusage.jpg)
#### 2.2.cpu使用情况的单选功能
单选CPU使用情况数据，单击方法会在选中的方法外层加上深色边框，能够突出当前选中色块，弹出层中会展示当前CPU上的进程名，线程名，开始时间和运行时长，线程运行状态等信息
![GitHub Logo](../figures/cpuclick.jpg)
### 3.FPS数据
FPS是帧率的显示，每秒产生画面的个数
![GitHub Logo](../figures/fps.jpg)
#### 3.1FPS的框选功能
可以对fps的数据进行框选，框选后在最下方的弹出层中会展示框选时间区间内的统计表格,主要显示了time(时间)，FPS(帧率)
![GitHub Logo](../figures/fpsselect.jpg)
### 4.进程,线程和方法数据
下图是进程数据，左边部分展示进程名称和id
![GitHub Logo](../figures/process.jpg)
点击进程名前面向下箭头可以展开对应的线程进行查看，展开后的线程如下图，如果存在堆内存占用情况，就会显示在第一行，如果出现两个名字和id一样的线程，则第一个为线程的使用情况，第二为线程内的方法栈调用情况
![GitHub Logo](../figures/threadinfo.jpg)

#### 4.1进程,线程和方法数据的框选功能
可以对线程的数据进行框选，框选后在最下方的弹出层中会展示框选数据的统计表格，包含线程运行状态，线程调用栈的统计情况。当框选的数据中同时存在线程运行状态和线程调用栈数据，下方的弹出层中就会出现多个tab选项，可以进行切换

下图是线程运行状态框选统计信息,包括进程名，进程号，线程名，线程号，线程状态，状态持续时间，平均持续时间，该线程状态发生的次数
![GitHub Logo](../figures/threadselect.jpg)

下图是线程调用栈框选统计信息,包括方法名，持续时间，平均持续时间，调用的次数
![GitHub Logo](../figures/callstackselect.jpg)
#### 4.2进程,线程和方法数据的单选功能
单选线程的state数据时，会展示当前选中线程的状态数据，开始时间和持续时长，线程状态，所在进程名称、
![GitHub Logo](../figures/threadclick.jpg)
单选调用栈数据，单击方法会在选中的方法外层加上黑色边框，能够突出当前选中的方法，弹出层中会展示当前方法的名称、开始时间和运行时长信息。
![GitHub Logo](../figures/callstackclick.jpg)

