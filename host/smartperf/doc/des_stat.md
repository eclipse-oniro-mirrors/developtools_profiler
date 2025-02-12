# TraceStreamer 解析数据状态表
TraceStreamer使用stat表统计解析trace数据源过程遇到的重要事件状态。通过stat表可以对trace数据源中各个类型事件的数据有一个基本了解。
## stat表支持统计的事件列表如下：
|event_name                     |
| ----                          |
|binder_transaction             |
|binder_transaction_alloc_buf   |
|binder_transaction_lock        |
|binder_transaction_locked      |
|binder_transaction_received    |
|binder_transaction_unlock      |
|clk_disable                    |
|clk_enable                     |
|clk_set_rate                   |
|clock_disable                  |
|clock_enable                   |
|clock_set_rate                 |
|cpu_frequency                  |
|cpu_idle                       |
|hidump_fps                     |
|hilog                          |
|ipi_entry                      |
|ipi_exit                       |
|irq_handler_entry              |
|irq_handler_exit               |
|memory                         |
|native_hook_free               |
|native_hook_malloc             |
|oom_score_adj_update           |
|other                          |
|print                          |
|regulator_disable              |
|regulator_disable_complete     |
|regulator_set_voltage          |
|regulator_set_voltage_complete |
|sched_process_exit             |
|sched_process_free             |
|sched_switch                   |
|sched_wakeup                   |
|sched_wakeup_new               |
|sched_waking                   |
|signal_deliver                 |
|signal_generate                |
|softirq_entry                  |
|softirq_exit                   |
|softirq_raise                  |
|suspend_resume                 |
|sys_enter                      |
|sys_exit                       |
|sys_memory                     |
|sys_virtual_memory             |
|task_newtask                   |
|task_rename                    |
|trace_bblock_bio_queue         |
|trace_block_bio_backmerge      |
|trace_block_bio_bounce         |
|trace_block_bio_complete       |
|trace_block_bio_frontmerge     |
|trace_block_bio_remap          |
|trace_block_dirty_buffer       |
|trace_block_getrq              |
|trace_block_plug               |
|trace_block_rq_complete        |
|trace_block_rq_insert          |
|trace_block_rq_issue           |
|trace_block_rq_remap           |
|trace_event_clock_sync         |
|tracing_mark_write             |
|workqueue_execute_end          |
|workqueue_execute_start        |

## 事件对应解析状态： 
每种事件解析数据都有5种状态，描述如下表：
|stat_type|description|
|----     |----       |
|received  | 统计trace数据源中总共有多少该事件。|
|data_lost | 统计TraceStreamer解析过程中发现丢失数据条数。 |
|not_match | 统计有多少数据与上下文其他数据不匹配。 |
|not_supported | 统计有多少暂不支持解析该事件（一个事件可能包含多种类型的子事件， TraceStreamer可能支持该事件的一部分子事件）。| 
|invalid_data | 统计收到多少条该事件的非法数据。|

## 数据状态级别
数据状态级别总共有4种，分别是：info, warn, error,fatal。由于数据的重要性不同，不同事件的同一种状态可能对应不同的级别。
例如binder_transaction_received的 not_supported状态的数据为info级别，而binder_transaction_alloc_buf的not_supported状态数据为warn级别。 

## 事件，状态与级别对应关系
|	event_name	|	stat_type	|	serverity	|
|----           |----           |----           |
|	binder_transaction	|	received	|	info	|
|	binder_transaction	|	data_lost	|	error	|
|	binder_transaction	|	not_match	|	info	|
|	binder_transaction	|	not_supported	|	info	|
|	binder_transaction	|	invalid_data	|	error	|
|	binder_transaction_received	|	received	|	info	|
|	binder_transaction_received	|	data_lost	|	error	|
|	binder_transaction_received	|	not_match	|	info	|
|	binder_transaction_received	|	not_supported	|	info	|
|	binder_transaction_received	|	invalid_data	|	error	|
|	binder_transaction_alloc_buf	|	received	|	info	|
|	binder_transaction_alloc_buf	|	data_lost	|	error	|
|	binder_transaction_alloc_buf	|	not_match	|	info	|
|	binder_transaction_alloc_buf	|	not_supported	|	warn	|
|	binder_transaction_alloc_buf	|	invalid_data	|	error	|
|	binder_transaction_lock	|	received	|	info	|
|	binder_transaction_lock	|	data_lost	|	error	|
|	binder_transaction_lock	|	not_match	|	info	|
|	binder_transaction_lock	|	not_supported	|	warn	|
|	binder_transaction_lock	|	invalid_data	|	error	|
|	binder_transaction_locked	|	received	|	info	|
|	binder_transaction_locked	|	data_lost	|	error	|
|	binder_transaction_locked	|	not_match	|	info	|
|	binder_transaction_locked	|	not_supported	|	warn	|
|	binder_transaction_locked	|	invalid_data	|	error	|
|	binder_transaction_unlock	|	received	|	info	|
|	binder_transaction_unlock	|	data_lost	|	error	|
|	binder_transaction_unlock	|	not_match	|	info	|
|	binder_transaction_unlock	|	not_supported	|	warn	|
|	binder_transaction_unlock	|	invalid_data	|	error	|
|	sched_switch	|	received	|	info	|
|	sched_switch	|	data_lost	|	error	|
|	sched_switch	|	not_match	|	info	|
|	sched_switch	|	not_supported	|	info	|
|	sched_switch	|	invalid_data	|	error	|
|	task_rename	|	received	|	info	|
|	task_rename	|	data_lost	|	error	|
|	task_rename	|	not_match	|	info	|
|	task_rename	|	not_supported	|	info	|
|	task_rename	|	invalid_data	|	error	|
|	task_newtask	|	received	|	info	|
|	task_newtask	|	data_lost	|	error	|
|	task_newtask	|	not_match	|	info	|
|	task_newtask	|	not_supported	|	info	|
|	task_newtask	|	invalid_data	|	error	|
|	tracing_mark_write	|	received	|	info	|
|	tracing_mark_write	|	data_lost	|	error	|
|	tracing_mark_write	|	not_match	|	info	|
|	tracing_mark_write	|	not_supported	|	info	|
|	tracing_mark_write	|	invalid_data	|	error	|
|	print	|	received	|	info	|
|	print	|	data_lost	|	error	|
|	print	|	not_match	|	info	|
|	print	|	not_supported	|	info	|
|	print	|	invalid_data	|	error	|
|	sched_wakeup	|	received	|	info	|
|	sched_wakeup	|	data_lost	|	error	|
|	sched_wakeup	|	not_match	|	info	|
|	sched_wakeup	|	not_supported	|	info	|
|	sched_wakeup	|	invalid_data	|	error	|
|	sched_waking	|	received	|	info	|
|	sched_waking	|	data_lost	|	error	|
|	sched_waking	|	not_match	|	info	|
|	sched_waking	|	not_supported	|	info	|
|	sched_waking	|	invalid_data	|	error	|
|	cpu_idle	|	received	|	info	|
|	cpu_idle	|	data_lost	|	error	|
|	cpu_idle	|	not_match	|	info	|
|	cpu_idle	|	not_supported	|	info	|
|	cpu_idle	|	invalid_data	|	error	|
|	cpu_frequency	|	received	|	info	|
|	cpu_frequency	|	data_lost	|	error	|
|	cpu_frequency	|	not_match	|	info	|
|	cpu_frequency	|	not_supported	|	info	|
|	cpu_frequency	|	invalid_data	|	error	|
|	suspend_resume	|	received	|	info	|
|	suspend_resume	|	data_lost	|	error	|
|	suspend_resume	|	not_match	|	info	|
|	suspend_resume	|	not_supported	|	info	|
|	suspend_resume	|	invalid_data	|	error	|
|	workqueue_execute_start	|	received	|	info	|
|	workqueue_execute_start	|	data_lost	|	error	|
|	workqueue_execute_start	|	not_match	|	info	|
|	workqueue_execute_start	|	not_supported	|	info	|
|	workqueue_execute_start	|	invalid_data	|	error	|
|	workqueue_execute_end	|	received	|	info	|
|	workqueue_execute_end	|	data_lost	|	error	|
|	workqueue_execute_end	|	not_match	|	info	|
|	workqueue_execute_end	|	not_supported	|	warn	|
|	workqueue_execute_end	|	invalid_data	|	error	|
|	clock_set_rate	|	received	|	info	|
|	clock_set_rate	|	data_lost	|	error	|
|	clock_set_rate	|	not_match	|	info	|
|	clock_set_rate	|	not_supported	|	warn	|
|	clock_set_rate	|	invalid_data	|	error	|
|	clock_enable	|	received	|	info	|
|	clock_enable	|	data_lost	|	error	|
|	clock_enable	|	not_match	|	info	|
|	clock_enable	|	not_supported	|	warn	|
|	clock_enable	|	invalid_data	|	error	|
|	clock_disable	|	received	|	info	|
|	clock_disable	|	data_lost	|	error	|
|	clock_disable	|	not_match	|	info	|
|	clock_disable	|	not_supported	|	warn	|
|	clock_disable	|	invalid_data	|	error	|
|	clk_set_rate	|	received	|	info	|
|	clk_set_rate	|	data_lost	|	error	|
|	clk_set_rate	|	not_match	|	info	|
|	clk_set_rate	|	not_supported	|	warn	|
|	clk_set_rate	|	invalid_data	|	error	|
|	clk_enable	|	received	|	info	|
|	clk_enable	|	data_lost	|	error	|
|	clk_enable	|	not_match	|	info	|
|	clk_enable	|	not_supported	|	warn	|
|	clk_enable	|	invalid_data	|	error	|
|	clk_disable	|	received	|	info	|
|	clk_disable	|	data_lost	|	error	|
|	clk_disable	|	not_match	|	info	|
|	clk_disable	|	not_supported	|	warn	|
|	clk_disable	|	invalid_data	|	error	|
|	sys_enter	|	received	|	info	|
|	sys_enter	|	data_lost	|	error	|
|	sys_enter	|	not_match	|	info	|
|	sys_enter	|	not_supported	|	warn	|
|	sys_enter	|	invalid_data	|	error	|
|	sys_exit	|	received	|	info	|
|	sys_exit	|	data_lost	|	error	|
|	sys_exit	|	not_match	|	info	|
|	sys_exit	|	not_supported	|	warn	|
|	sys_exit	|	invalid_data	|	error	|
|	regulator_set_voltage	|	received	|	info	|
|	regulator_set_voltage	|	data_lost	|	error	|
|	regulator_set_voltage	|	not_match	|	info	|
|	regulator_set_voltage	|	not_supported	|	warn	|
|	regulator_set_voltage	|	invalid_data	|	error	|
|	regulator_set_voltage_complete	|	received	|	info	|
|	regulator_set_voltage_complete	|	data_lost	|	error	|
|	regulator_set_voltage_complete	|	not_match	|	info	|
|	regulator_set_voltage_complete	|	not_supported	|	warn	|
|	regulator_set_voltage_complete	|	invalid_data	|	error	|
|	regulator_disable	|	received	|	info	|
|	regulator_disable	|	data_lost	|	error	|
|	regulator_disable	|	not_match	|	info	|
|	regulator_disable	|	not_supported	|	warn	|
|	regulator_disable	|	invalid_data	|	error	|
|	regulator_disable_complete	|	received	|	info	|
|	regulator_disable_complete	|	data_lost	|	error	|
|	regulator_disable_complete	|	not_match	|	info	|
|	regulator_disable_complete	|	not_supported	|	warn	|
|	regulator_disable_complete	|	invalid_data	|	error	|
|	ipi_entry	|	received	|	info	|
|	ipi_entry	|	data_lost	|	error	|
|	ipi_entry	|	not_match	|	info	|
|	ipi_entry	|	not_supported	|	warn	|
|	ipi_entry	|	invalid_data	|	error	|
|	ipi_exit	|	received	|	info	|
|	ipi_exit	|	data_lost	|	error	|
|	ipi_exit	|	not_match	|	info	|
|	ipi_exit	|	not_supported	|	warn	|
|	ipi_exit	|	invalid_data	|	error	|
|	irq_handler_entry	|	received	|	info	|
|	irq_handler_entry	|	data_lost	|	error	|
|	irq_handler_entry	|	not_match	|	info	|
|	irq_handler_entry	|	not_supported	|	warn	|
|	irq_handler_entry	|	invalid_data	|	error	|
|	irq_handler_exit	|	received	|	info	|
|	irq_handler_exit	|	data_lost	|	error	|
|	irq_handler_exit	|	not_match	|	info	|
|	irq_handler_exit	|	not_supported	|	warn	|
|	irq_handler_exit	|	invalid_data	|	error	|
|	softirq_raise	|	received	|	info	|
|	softirq_raise	|	data_lost	|	error	|
|	softirq_raise	|	not_match	|	info	|
|	softirq_raise	|	not_supported	|	warn	|
|	softirq_raise	|	invalid_data	|	error	|
|	softirq_entry	|	received	|	info	|
|	softirq_entry	|	data_lost	|	error	|
|	softirq_entry	|	not_match	|	info	|
|	softirq_entry	|	not_supported	|	warn	|
|	softirq_entry	|	invalid_data	|	error	|
|	softirq_exit	|	received	|	info	|
|	softirq_exit	|	data_lost	|	error	|
|	softirq_exit	|	not_match	|	info	|
|	softirq_exit	|	not_supported	|	warn	|
|	softirq_exit	|	invalid_data	|	error	|
|	oom_score_adj_update	|	received	|	info	|
|	oom_score_adj_update	|	data_lost	|	error	|
|	oom_score_adj_update	|	not_match	|	info	|
|	oom_score_adj_update	|	not_supported	|	warn	|
|	oom_score_adj_update	|	invalid_data	|	error	|
|	sched_wakeup_new	|	received	|	info	|
|	sched_wakeup_new	|	data_lost	|	error	|
|	sched_wakeup_new	|	not_match	|	info	|
|	sched_wakeup_new	|	not_supported	|	warn	|
|	sched_wakeup_new	|	invalid_data	|	error	|
|	sched_process_exit	|	received	|	info	|
|	sched_process_exit	|	data_lost	|	error	|
|	sched_process_exit	|	not_match	|	info	|
|	sched_process_exit	|	not_supported	|	warn	|
|	sched_process_exit	|	invalid_data	|	error	|
|	sched_process_free	|	received	|	info	|
|	sched_process_free	|	data_lost	|	error	|
|	sched_process_free	|	not_match	|	info	|
|	sched_process_free	|	not_supported	|	warn	|
|	sched_process_free	|	invalid_data	|	error	|
|	trace_event_clock_sync	|	received	|	info	|
|	trace_event_clock_sync	|	data_lost	|	error	|
|	trace_event_clock_sync	|	not_match	|	info	|
|	trace_event_clock_sync	|	not_supported	|	warn	|
|	trace_event_clock_sync	|	invalid_data	|	error	|
|	memory	|	received	|	info	|
|	memory	|	data_lost	|	error	|
|	memory	|	not_match	|	info	|
|	memory	|	not_supported	|	warn	|
|	memory	|	invalid_data	|	error	|
|	hilog	|	received	|	info	|
|	hilog	|	data_lost	|	error	|
|	hilog	|	not_match	|	info	|
|	hilog	|	not_supported	|	warn	|
|	hilog	|	invalid_data	|	error	|
|	hidump_fps	|	received	|	info	|
|	hidump_fps	|	data_lost	|	error	|
|	hidump_fps	|	not_match	|	info	|
|	hidump_fps	|	not_supported	|	warn	|
|	hidump_fps	|	invalid_data	|	error	|
|	native_hook_malloc	|	received	|	info	|
|	native_hook_malloc	|	data_lost	|	error	|
|	native_hook_malloc	|	not_match	|	info	|
|	native_hook_malloc	|	not_supported	|	warn	|
|	native_hook_malloc	|	invalid_data	|	error	|
|	native_hook_free	|	received	|	info	|
|	native_hook_free	|	data_lost	|	error	|
|	native_hook_free	|	not_match	|	info	|
|	native_hook_free	|	not_supported	|	warn	|
|	native_hook_free	|	invalid_data	|	error	|
|	sys_memory	|	received	|	info	|
|	sys_memory	|	data_lost	|	error	|
|	sys_memory	|	not_match	|	info	|
|	sys_memory	|	not_supported	|	warn	|
|	sys_memory	|	invalid_data	|	error	|
|	sys_virtual_memory	|	received	|	info	|
|	sys_virtual_memory	|	data_lost	|	error	|
|	sys_virtual_memory	|	not_match	|	info	|
|	sys_virtual_memory	|	not_supported	|	warn	|
|	sys_virtual_memory	|	invalid_data	|	error	|
|	signal_generate	|	received	|	info	|
|	signal_generate	|	data_lost	|	error	|
|	signal_generate	|	not_match	|	info	|
|	signal_generate	|	not_supported	|	warn	|
|	signal_generate	|	invalid_data	|	error	|
|	signal_deliver	|	received	|	info	|
|	signal_deliver	|	data_lost	|	error	|
|	signal_deliver	|	not_match	|	info	|
|	signal_deliver	|	not_supported	|	warn	|
|	signal_deliver	|	invalid_data	|	error	|
|	trace_block_bio_backmerge	|	received	|	info	|
|	trace_block_bio_backmerge	|	data_lost	|	error	|
|	trace_block_bio_backmerge	|	not_match	|	info	|
|	trace_block_bio_backmerge	|	not_supported	|	warn	|
|	trace_block_bio_backmerge	|	invalid_data	|	error	|
|	trace_block_bio_bounce	|	received	|	info	|
|	trace_block_bio_bounce	|	data_lost	|	error	|
|	trace_block_bio_bounce	|	not_match	|	info	|
|	trace_block_bio_bounce	|	not_supported	|	warn	|
|	trace_block_bio_bounce	|	invalid_data	|	error	|
|	trace_block_bio_complete	|	received	|	info	|
|	trace_block_bio_complete	|	data_lost	|	error	|
|	trace_block_bio_complete	|	not_match	|	info	|
|	trace_block_bio_complete	|	not_supported	|	warn	|
|	trace_block_bio_complete	|	invalid_data	|	error	|
|	trace_block_bio_frontmerge	|	received	|	info	|
|	trace_block_bio_frontmerge	|	data_lost	|	error	|
|	trace_block_bio_frontmerge	|	not_match	|	info	|
|	trace_block_bio_frontmerge	|	not_supported	|	warn	|
|	trace_block_bio_frontmerge	|	invalid_data	|	error	|
|	trace_bblock_bio_queue	|	received	|	info	|
|	trace_bblock_bio_queue	|	data_lost	|	error	|
|	trace_bblock_bio_queue	|	not_match	|	info	|
|	trace_bblock_bio_queue	|	not_supported	|	warn	|
|	trace_bblock_bio_queue	|	invalid_data	|	error	|
|	trace_block_bio_remap	|	received	|	info	|
|	trace_block_bio_remap	|	data_lost	|	error	|
|	trace_block_bio_remap	|	not_match	|	info	|
|	trace_block_bio_remap	|	not_supported	|	warn	|
|	trace_block_bio_remap	|	invalid_data	|	error	|
|	trace_block_dirty_buffer	|	received	|	info	|
|	trace_block_dirty_buffer	|	data_lost	|	error	|
|	trace_block_dirty_buffer	|	not_match	|	info	|
|	trace_block_dirty_buffer	|	not_supported	|	warn	|
|	trace_block_dirty_buffer	|	invalid_data	|	error	|
|	trace_block_getrq	|	received	|	info	|
|	trace_block_getrq	|	data_lost	|	error	|
|	trace_block_getrq	|	not_match	|	info	|
|	trace_block_getrq	|	not_supported	|	warn	|
|	trace_block_getrq	|	invalid_data	|	error	|
|	trace_block_plug	|	received	|	info	|
|	trace_block_plug	|	data_lost	|	error	|
|	trace_block_plug	|	not_match	|	info	|
|	trace_block_plug	|	not_supported	|	warn	|
|	trace_block_plug	|	invalid_data	|	error	|
|	trace_block_rq_complete	|	received	|	info	|
|	trace_block_rq_complete	|	data_lost	|	error	|
|	trace_block_rq_complete	|	not_match	|	info	|
|	trace_block_rq_complete	|	not_supported	|	warn	|
|	trace_block_rq_complete	|	invalid_data	|	error	|
|	trace_block_rq_insert	|	received	|	info	|
|	trace_block_rq_insert	|	data_lost	|	error	|
|	trace_block_rq_insert	|	not_match	|	info	|
|	trace_block_rq_insert	|	not_supported	|	warn	|
|	trace_block_rq_insert	|	invalid_data	|	error	|
|	trace_block_rq_remap	|	received	|	info	|
|	trace_block_rq_remap	|	data_lost	|	error	|
|	trace_block_rq_remap	|	not_match	|	info	|
|	trace_block_rq_remap	|	not_supported	|	warn	|
|	trace_block_rq_remap	|	invalid_data	|	error	|
|	trace_block_rq_issue	|	received	|	info	|
|	trace_block_rq_issue	|	data_lost	|	error	|
|	trace_block_rq_issue	|	not_match	|	info	|
|	trace_block_rq_issue	|	not_supported	|	warn	|
|	trace_block_rq_issue	|	invalid_data	|	error	|
|	other	|	received	|	info	|
|	other	|	data_lost	|	error	|
|	other	|	not_match	|	info	|
|	other	|	not_supported	|	warn	|
|	other	|	invalid_data	|	error	|
