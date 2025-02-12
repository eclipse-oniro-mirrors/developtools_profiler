# trace_streamer工具说明
trace_streamer工具可以2种方式使用  
1. 可以将系统离线trace文件解析并转为db，此工具支持基于文本的trace和基于proto的trace。  
2. trace_streamer工具还可以WebAssembly的方式在浏览器中运行，需暴露相关接口给js文件。  
  
## 关于trace解析工具的使用说明：
### 导出db模式
在导出db模式下，trace_streamer.exe trace文件路径名 -e 导出db路径名.db
此命令可以将trace文件转为db
本应用支持在ohos, linux, windows, mac使用。
关于db文件的说明：
使用db查看工具查看stat表，可以浏览当前数据一共有多少类数据，各类数据都收到多少条，数据是否正常等情况。在meta表会记录数据库导出时的一些系统信息，比如导入和导出的文件全路径，解析时间等信息。
meta表可以选择不导出（有些情况下会暴露系统敏感信息），在导出时添加 -nm选项即可。
在数据导出之后，会在本地目录下生成一个trace_streamer.log文件，在导出db的目录下生成一个数据库文件同名，.db.ohos.ts后缀的文件
文件内容如下：
时间戳:执行结果（数字）
应用运行时间

执行结果解释如下：0 代表执行成功 1 表示输入文件不匹配， 2 表示解析错误， 3其他错误
### 内置浏览器方式
trace_streamer可以WebAssembly方式在浏览器中运行，暴露如下接口给js
```
extern "C" {
/* 上传trace数据
 * 
 * @data: 数据的缓冲区 
 * @dataLen: 数据长度
 * 
 * return: 0：成功； -1：失败
*/
EMSCRIPTEN_KEEPALIVE int TraceStreamerParseData(const uint8_t* data, int dataLen);

/* 通知TS上传trace数据结束
 *  
 * return: 0：成功； -1：失败
*/
EMSCRIPTEN_KEEPALIVE int TraceStreamerParseDataOver();

/* 通过sql语句操作数据库
 * 
 * @sql: sql语句 
 * @sqlLen: sql语句长度
 * 
 * return: 0：成功； -1：失败
*/
EMSCRIPTEN_KEEPALIVE int TraceStreamerSqlOperate(const uint8_t* sql, int sqlLen);

/* 通过sql语句查询数据库
 * 
 * @sql: sql语句 
 * @sqlLen: sql语句长度
 * @out: 查询结果的缓冲区，查询结果为json
 * @outLen: 缓冲区长度
 * 
 * return: >0：查询成功，返回查询结果数据长度； -1：失败
*/
EMSCRIPTEN_KEEPALIVE int TraceStreamerSqlQuery(const uint8_t* sql, int sqlLen, uint8_t* out, int outLen);

} // extern "C"
```

### 你也可以执行如下命令查看应用帮助
./trace_streamer --help
-i 选项可查看应用支持的事件源和具体的事件名列表  

#### trace_streamer支持的事件解析
本工具支持基于文本的trace（# TRACE)和基于proto的二进制日志文件的解析，支持的事件列表如下：
##### ftrace事件
```
binder_transaction
binder_transaction_received
binder_transaction_alloc_buf
binder_transaction_lock
binder_transaction_locked
binder_transaction_unlock
sched_switch
task_rename
task_newtask
tracing_mark_write
print
sched_wakeup
sched_waking
cpu_idle
cpu_frequency
suspend_resume
workqueue_execute_start
workqueue_execute_end
clock_set_rate
clock_enable
clock_disable
clk_set_rate
clk_enable
clk_disable
sys_enter
sys_exit
regulator_set_voltage
regulator_set_voltage_complete
regulator_disable
regulator_disable_complete
ipi_entry
ipi_exit
irq_handler_entry
irq_handler_exit
softirq_raise
softirq_entry
softirq_exit
sched_wakeup_new
sched_process_exit
trace_event_clock_sync
```
##### 内存事件
```
mem.vm.size
mem.rss
mem.rss.anon
mem.rss.file
mem.rss.schem
mem.swap
mem.locked
mem.hwm
mem.oom_score_adj
```
##### 系统内存事件
```
sys.mem.unspecified
sys.mem.total
sys.mem.free
sys.mem.avaiable
sys.mem.buffers
sys.mem.cached
sys.mem.swap.chard
sys.mem.active
sys.mem.inactive
sys.mem.active.anon
sys.mem.inactive.anon
sys.mem.active_file
sys.mem.inactive_file
sys.mem.unevictable
sys.mem.mlocked
sys.mem.swap.total
sys.mem.swap.free
sys.mem.dirty
sys.mem.writeback
sys.mem.anon.pages
sys.mem.mapped
sys.mem.shmem
sys.mem.slab
sys.mem.slab.reclaimable
sys.mem.slab.unreclaimable
sys.mem.kernel.stack
sys.mem.page.tables
sys.mem.commit.limit
sys.mem.commited.as
sys.mem.vmalloc.total
sys.mem.vmalloc.used
sys.mem.vmalloc.chunk
sys.mem.cma.total
sys.mem.cma.free
```
##### 系统虚拟内存事件
```
sys.virtual.mem.unspecified
sys.virtual.mem.nr.free.pages
sys.virtual.mem.nr.alloc.batch
sys.virtual.mem.nr.inactive.anon
sys.virtual.mem.nr.active_anon
sys.virtual.mem.nr.inactive.file
sys.virtual.mem.nr.active_file
sys.virtual.mem.nr.unevictable
sys.virtual.mem.nr.mlock
sys.virtual.mem.anon.pages
sys.virtual.mem.nr.mapped
sys.virtual.mem.nr.file.pages
sys.virtual.mem.nr.dirty
sys.virtual.mem.nr.writeback
sys.virtual.mem.nr.slab.reclaimable
sys.virtual.mem.nr.slab.unreclaimable
sys.virtual.mem.nr.page_table.pages
sys.virtual.mem.nr_kernel.stack
sys.virtual.mem.nr.overhead
sys.virtual.mem.nr.unstable
sys.virtual.mem.nr.bounce
sys.virtual.mem.nr.vmscan.write
sys.virtual.mem.nr.vmscan.immediate.reclaim
sys.virtual.mem.nr.writeback_temp
sys.virtual.mem.nr.isolated_anon
sys.virtual.mem.nr.isolated_file
sys.virtual.mem.nr.shmem
sys.virtual.mem.nr.dirtied
sys.virtual.mem.nr.written
sys.virtual.mem.nr.pages.scanned
sys.virtual.mem.workingset.refault
sys.virtual.mem.workingset.activate
sys.virtual.mem.workingset_nodereclaim
sys.virtual.mem.nr_anon.transparent.hugepages
sys.virtual.mem.nr.free_cma
sys.virtual.mem.nr.swapcache
sys.virtual.mem.nr.dirty.threshold
sys.virtual.mem.nr.dirty.background.threshold
sys.virtual.mem.vmeminfo.pgpgin
sys.virtual.mem.pgpgout
sys.virtual.mem.pgpgoutclean
sys.virtual.mem.pswpin
sys.virtual.mem.pswpout
sys.virtual.mem.pgalloc.dma
sys.virtual.mem.pgalloc.normal
sys.virtual.mem.pgalloc.movable
sys.virtual.mem.pgfree
sys.virtual.mem.pgactivate
sys.virtual.mem.pgdeactivate
sys.virtual.mem.pgfault
sys.virtual.mem.pgmajfault
sys.virtual.mem.pgrefill.dma
sys.virtual.mem.pgrefill.normal
sys.virtual.mem.pgrefill.movable
sys.virtual.mem.pgsteal.kswapd.dma
sys.virtual.mem.pgsteal.kswapd.normal
sys.virtual.mem.pgsteal.kswapd.movable
sys.virtual.mem.pgsteal.direct.dma
sys.virtual.mem.pgsteal.direct.normal
sys.virtual.mem.pgsteal_direct.movable
sys.virtual.mem.pgscan.kswapd.dma
sys.virtual.mem.pgscan_kswapd.normal
sys.virtual.mem.pgscan.kswapd.movable
sys.virtual.mem.pgscan.direct.dma
sys.virtual.mem.pgscan.direct.normal
sys.virtual.mem.pgscan.direct.movable
sys.virtual.mem.pgscan.direct.throttle
sys.virtual.mem.pginodesteal
sys.virtual.mem.slabs_scanned
sys.virtual.mem.kswapd.inodesteal
sys.virtual.mem.kswapd.low.wmark.hit.quickly
sys.virtual.mem.high.wmark.hit.quickly
sys.virtual.mem.pageoutrun
sys.virtual.mem.allocstall
sys.virtual.mem.pgrotated
sys.virtual.mem.drop.pagecache
sys.virtual.mem.drop.slab
sys.virtual.mem.pgmigrate.success
sys.virtual.mem.pgmigrate.fail
sys.virtual.mem.compact.migrate.scanned
sys.virtual.mem.compact.free.scanned
sys.virtual.mem.compact.isolated
sys.virtual.mem.compact.stall
sys.virtual.mem.compact.fail
sys.virtual.mem.compact.success
sys.virtual.mem.compact.daemon.wake
sys.virtual.mem.unevictable.pgs.culled
sys.virtual.mem.unevictable.pgs.scanned
sys.virtual.mem.unevictable.pgs.rescued
sys.virtual.mem.unevictable.pgs.mlocked
sys.virtual.mem.unevictable.pgs.munlocked
sys.virtual.mem.unevictable.pgs.cleared
sys.virtual.mem.unevictable.pgs.stranded
sys.virtual.mem.nr.zspages
sys.virtual.mem.nr.ion.heap
sys.virtual.mem.nr.gpu.heap
sys.virtual.mem.allocstall.dma
sys.virtual.mem.allocstall.movable
sys.virtual.mem.allocstall.normal
sys.virtual.mem.compact_daemon.free.scanned
sys.virtual.mem.compact.daemon.migrate.scanned
sys.virtual.mem.nr.fastrpc
sys.virtual.mem.nr.indirectly.reclaimable
sys.virtual.mem.nr_ion_heap_pool
sys.virtual.mem.nr.kernel_misc.reclaimable
sys.virtual.mem.nr.shadow_call.stack_bytes
sys.virtual.mem.nr.shmem.hugepages
sys.virtual.mem.nr.shmem.pmdmapped
sys.virtual.mem.nr.unreclaimable.pages
sys.virtual.mem.nr.zone.active.anon
sys.virtual.mem.nr.zone.active.file
ys.virtual.mem.nr.zone.inactive_anon
sys.virtual.mem.nr.zone.inactive_file
sys.virtual.mem.nr.zone.unevictable
sys.virtual.mem.nr.zone.write_pending
sys.virtual.mem.oom.kill
sys.virtual.mem.pglazyfree
sys.virtual.mem.pglazyfreed
sys.virtual.mem.pgrefill
sys.virtual.mem.pgscan.direct
sys.virtual.mem.pgscan.kswapd
sys.virtual.mem.pgskip.dma
sys.virtual.mem.pgskip.movable
sys.virtual.mem.pgskip.normal
sys.virtual.mem.pgsteal.direct
sys.virtual.mem.pgsteal.kswapd
sys.virtual.mem.swap.ra
sys.virtual.mem.swap.ra.hit
```

## trace_streamer开发环境搭建和编译运行指引

本应用使用gn作为构建工具，支持在linux环境同时编译linux，windows和mac使用QtCreator作为开发IDE
### 1、开发环境
ubuntu使用vscode，windows和mac使用QtCreator
# 对外部的依赖
本应用依赖与sqlite，protobuf(htrace解析部分依赖) 

本应用同时依赖于src/protos目录下文件来生成相关pb.h，pb.cc文件 

### 2.1、 编译linux版应用
在根目录下执行相关命令进行编译

### 2.2、编译Windows版和Mac应用
在项目目录下有pro文件，为QtCreator的工程文件，但部分内容赖在于上面所添加的外部依赖，如果要编译相关平台应用，开发者需自行补充相关工程文件，或者在论坛留言

### 2.3、开始编译
具体方法可参考《compile_trace_streamer.md》