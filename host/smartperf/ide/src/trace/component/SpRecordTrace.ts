/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {BaseElement, element} from "../../base-ui/BaseElement.js";
import "../../base-ui/popover/LitPopover.js"
import "../../base-ui/button/LitButton.js";
import {LitMainMenuGroup} from "../../base-ui/menu/LitMainMenuGroup.js";
import {LitMainMenuItem} from "../../base-ui/menu/LitMainMenuItem.js";
import {SpRecordSetting} from "./setting/SpRecordSetting.js";
import {LitMainMenu, MenuGroup, MenuItem} from "../../base-ui/menu/LitMainMenu.js";
import {SpProbesConfig} from "./setting/SpProbesConfig.js";
import {SpTraceCommand} from "./setting/SpTraceCommand.js";

import {
    CpuConfig,
    CreateSessionRequest,
    DiskioConfig, FileSystemConfig,
    FpsConfig,
    HilogConfig,
    HiperfPluginConfig, HiSystemEventConfig,
    levelFromJSON,
    MemoryConfig,
    NativeHookConfig,
    NetworkConfig,
    ProcessConfig,
    ProfilerPluginConfig,
    ProfilerSessionConfig,
    ProfilerSessionConfigBufferConfig,
    ProfilerSessionConfigBufferConfigPolicy,
    ProfilerSessionConfigMode,
    sysMeminfoTypeFromJSON,
    sysVMeminfoTypeFromJSON,
    TracePluginConfig,
    Type
} from "./setting/bean/ProfilerServiceTypes.js";
import {PluginConvertUtils} from "./setting/utils/PluginConvertUtils.js";
import {SpAllocations} from "./setting/SpAllocations.js";
import {SpRecordPerf} from "./setting/SpRecordPerf.js";
import {HdcDeviceManager} from "../../hdc/HdcDeviceManager.js";
import {LitButton} from "../../base-ui/button/LitButton.js";
import {SpApplication} from "../SpApplication.js";
import {LitSearch} from "./trace/search/Search.js";
import {LitProgressBar} from "../../base-ui/progress-bar/LitProgressBar.js";
import {info, log} from "../../log/Log.js";
import {CmdConstant} from "../../command/CmdConstant.js";
import {Cmd} from "../../command/Cmd.js";
import {SpFileSystem} from "./setting/SpFileSystem.js";
import {SpSdkConfig} from "./setting/SpSdkConfig.js";
import {SpVmTracker} from "./setting/SpVmTracker.js";

@element('sp-record-trace')
export class SpRecordTrace extends BaseElement {
    public static serialNumber: string = '';
    // 1GB
    public static MaxFileSize: number = 1024 * 1024 * 1024;
    public static isVscode = false;

    set vs(vs: boolean) {
        if (vs) {
            SpRecordTrace.isVscode = true;
            this.setAttribute("vs", '')
        } else {
            SpRecordTrace.isVscode = false;
            this.removeAttribute("vs");
        }
    }

    get vs(): boolean {
        return this.hasAttribute("vs");
    }

    static MEM_INFO = ["MEMINFO_ACTIVE", "MEMINFO_ACTIVE_ANON", "MEMINFO_ACTIVE_FILE", "MEMINFO_ANON_PAGES", "MEMINFO_BUFFERS",
        "MEMINFO_CACHED", "MEMINFO_CMA_FREE", "MEMINFO_CMA_TOTAL", "MEMINFO_COMMIT_LIMIT", "MEMINFO_COMMITED_AS",
        "MEMINFO_DIRTY", "MEMINFO_INACTIVE", "MEMINFO_INACTIVE_ANON", "MEMINFO_INACTIVE_FILE",
        "MEMINFO_KERNEL_STACK", "MEMINFO_MAPPED", "MEMINFO_MEM_AVAILABLE", "MEMINFO_MEM_FREE", "MEMINFO_MEM_TOTAL",
        "MEMINFO_MLOCKED", "MEMINFO_PAGE_TABLES", "MEMINFO_SHMEM", "MEMINFO_SLAB", "MEMINFO_SLAB_RECLAIMABLE",
        "MEMINFO_SLAB_UNRECLAIMABLE", "MEMINFO_SWAP_CACHED", "MEMINFO_SWAP_FREE", "MEMINFO_SWAP_TOTAL",
        "MEMINFO_UNEVICTABLE", "MEMINFO_VMALLOC_CHUNK", "MEMINFO_VMALLOC_TOTAL", "MEMINFO_VMALLOC_USED",
        "MEMINFO_WRITEBACK", "MEMINFO_KERNEL_RECLAIMABLE"]
    static VMEM_INFO = ["VMEMINFO_UNSPECIFIED", "VMEMINFO_NR_FREE_PAGES", "VMEMINFO_NR_ALLOC_BATCH",
        "VMEMINFO_NR_INACTIVE_ANON", "VMEMINFO_NR_ACTIVE_ANON", "VMEMINFO_NR_INACTIVE_FILE",
        "VMEMINFO_NR_ACTIVE_FILE", "VMEMINFO_NR_UNEVICTABLE", "VMEMINFO_NR_MLOCK", "VMEMINFO_NR_ANON_PAGES",
        "VMEMINFO_NR_MAPPED", "VMEMINFO_NR_FILE_PAGES", "VMEMINFO_NR_DIRTY", "VMEMINFO_NR_WRITEBACK",
        "VMEMINFO_NR_SLAB_RECLAIMABLE", "VMEMINFO_NR_SLAB_UNRECLAIMABLE", "VMEMINFO_NR_PAGE_TABLE_PAGES",
        "VMEMINFO_NR_KERNEL_STACK", "VMEMINFO_NR_OVERHEAD", "VMEMINFO_NR_UNSTABLE", "VMEMINFO_NR_BOUNCE",
        "VMEMINFO_NR_VMSCAN_WRITE", "VMEMINFO_NR_VMSCAN_IMMEDIATE_RECLAIM", "VMEMINFO_NR_WRITEBACK_TEMP",
        "VMEMINFO_NR_ISOLATED_ANON", "VMEMINFO_NR_ISOLATED_FILE", "VMEMINFO_NR_SHMEM", "VMEMINFO_NR_DIRTIED",
        "VMEMINFO_NR_WRITTEN", "VMEMINFO_NR_PAGES_SCANNED", "VMEMINFO_WORKINGSET_REFAULT",
        "VMEMINFO_WORKINGSET_ACTIVATE", "VMEMINFO_WORKINGSET_NODERECLAIM", "VMEMINFO_NR_ANON_TRANSPARENT_HUGEPAGES",
        "VMEMINFO_NR_FREE_CMA", "VMEMINFO_NR_SWAPCACHE", "VMEMINFO_NR_DIRTY_THRESHOLD",
        "VMEMINFO_NR_DIRTY_BACKGROUND_THRESHOLD", "VMEMINFO_PGPGIN", "VMEMINFO_PGPGOUT", "VMEMINFO_PGPGOUTCLEAN",
        "VMEMINFO_PSWPIN", "VMEMINFO_PSWPOUT", "VMEMINFO_PGALLOC_DMA"]
    static VMEM_INFO_SECOND = ["VMEMINFO_PGALLOC_NORMAL", "VMEMINFO_PGALLOC_MOVABLE", "VMEMINFO_PGFREE", "VMEMINFO_PGACTIVATE",
        "VMEMINFO_PGDEACTIVATE", "VMEMINFO_PGFAULT", "VMEMINFO_PGMAJFAULT", "VMEMINFO_PGREFILL_DMA",
        "VMEMINFO_PGREFILL_NORMAL", "VMEMINFO_PGREFILL_MOVABLE", "VMEMINFO_PGSTEAL_KSWAPD_DMA",
        "VMEMINFO_PGSTEAL_KSWAPD_NORMAL", "VMEMINFO_PGSTEAL_KSWAPD_MOVABLE", "VMEMINFO_PGSTEAL_DIRECT_DMA",
        "VMEMINFO_PGSTEAL_DIRECT_NORMAL", "VMEMINFO_PGSTEAL_DIRECT_MOVABLE", "VMEMINFO_PGSCAN_KSWAPD_DMA",
        "VMEMINFO_PGSCAN_KSWAPD_NORMAL", "VMEMINFO_PGSCAN_KSWAPD_MOVABLE", "VMEMINFO_PGSCAN_DIRECT_DMA",
        "VMEMINFO_PGSCAN_DIRECT_NORMAL", "VMEMINFO_PGSCAN_DIRECT_MOVABLE", "VMEMINFO_PGSCAN_DIRECT_THROTTLE",
        "VMEMINFO_PGINODESTEAL", "VMEMINFO_SLABS_SCANNED", "VMEMINFO_KSWAPD_INODESTEAL",
        "VMEMINFO_KSWAPD_LOW_WMARK_HIT_QUICKLY", "VMEMINFO_KSWAPD_HIGH_WMARK_HIT_QUICKLY", "VMEMINFO_PAGEOUTRUN",
        "VMEMINFO_ALLOCSTALL", "VMEMINFO_PGROTATED", "VMEMINFO_DROP_PAGECACHE", "VMEMINFO_DROP_SLAB",
        "VMEMINFO_PGMIGRATE_SUCCESS", "VMEMINFO_PGMIGRATE_FAIL", "VMEMINFO_COMPACT_MIGRATE_SCANNED",
        "VMEMINFO_COMPACT_FREE_SCANNED", "VMEMINFO_COMPACT_ISOLATED", "VMEMINFO_COMPACT_STALL",
        "VMEMINFO_COMPACT_FAIL", "VMEMINFO_COMPACT_SUCCESS", "VMEMINFO_COMPACT_DAEMON_WAKE",
        "VMEMINFO_UNEVICTABLE_PGS_CULLED", "VMEMINFO_UNEVICTABLE_PGS_SCANNED", "VMEMINFO_UNEVICTABLE_PGS_RESCUED",
        "VMEMINFO_UNEVICTABLE_PGS_MLOCKED", "VMEMINFO_UNEVICTABLE_PGS_MUNLOCKED"]
    static VMEM_INFO_THIRD = [
        "VMEMINFO_UNEVICTABLE_PGS_CLEARED", "VMEMINFO_UNEVICTABLE_PGS_STRANDED", "VMEMINFO_NR_ZSPAGES",
        "VMEMINFO_NR_ION_HEAP", "VMEMINFO_NR_GPU_HEAP", "VMEMINFO_ALLOCSTALL_DMA", "VMEMINFO_ALLOCSTALL_MOVABLE",
        "VMEMINFO_ALLOCSTALL_NORMAL", "VMEMINFO_COMPACT_DAEMON_FREE_SCANNED",
        "VMEMINFO_COMPACT_DAEMON_MIGRATE_SCANNED", "VMEMINFO_NR_FASTRPC", "VMEMINFO_NR_INDIRECTLY_RECLAIMABLE",
        "VMEMINFO_NR_ION_HEAP_POOL", "VMEMINFO_NR_KERNEL_MISC_RECLAIMABLE", "VMEMINFO_NR_SHADOW_CALL_STACK_BYTES",
        "VMEMINFO_NR_SHMEM_HUGEPAGES", "VMEMINFO_NR_SHMEM_PMDMAPPED", "VMEMINFO_NR_UNRECLAIMABLE_PAGES",
        "VMEMINFO_NR_ZONE_ACTIVE_ANON", "VMEMINFO_NR_ZONE_ACTIVE_FILE", "VMEMINFO_NR_ZONE_INACTIVE_ANON",
        "VMEMINFO_NR_ZONE_INACTIVE_FILE", "VMEMINFO_NR_ZONE_UNEVICTABLE", "VMEMINFO_NR_ZONE_WRITE_PENDING",
        "VMEMINFO_OOM_KILL", "VMEMINFO_PGLAZYFREE", "VMEMINFO_PGLAZYFREED", "VMEMINFO_PGREFILL",
        "VMEMINFO_PGSCAN_DIRECT", "VMEMINFO_PGSCAN_KSWAPD", "VMEMINFO_PGSKIP_DMA", "VMEMINFO_PGSKIP_MOVABLE",
        "VMEMINFO_PGSKIP_NORMAL", "VMEMINFO_PGSTEAL_DIRECT", "VMEMINFO_PGSTEAL_KSWAPD", "VMEMINFO_SWAP_RA",
        "VMEMINFO_SWAP_RA_HIT", "VMEMINFO_WORKINGSET_RESTORE"
    ]
    // sys.mem.total   sys.mem.free sys.mem.buffers sys.mem.cached  sys.mem.shmem  sys.mem.slab  sys.mem.swap.total
    // sys.mem.swap.free sys.mem.mapped  sys.mem.vmalloc.used  sys.mem.page.tables  sys.mem.kernel.stack
    // sys.mem.active sys.mem.inactive  sys.mem.unevictable  sys.mem.vmalloc.total sys.mem.slab.unreclaimable
    // sys.mem.cma.total sys.mem.cma.free
    static ABALITY_MEM_INFO = ["MEMINFO_MEM_TOTAL", "MEMINFO_MEM_FREE", "MEMINFO_BUFFERS", "MEMINFO_CACHED",
        "MEMINFO_SHMEM", "MEMINFO_SLAB", "MEMINFO_SWAP_TOTAL", "MEMINFO_SWAP_FREE", "MEMINFO_MAPPED",
        "MEMINFO_VMALLOC_USED", "MEMINFO_PAGE_TABLES", "MEMINFO_KERNEL_STACK", "MEMINFO_ACTIVE", "MEMINFO_INACTIVE",
        "MEMINFO_UNEVICTABLE", "MEMINFO_VMALLOC_TOTAL", "MEMINFO_SLAB_UNRECLAIMABLE", "MEMINFO_CMA_TOTAL",
        "MEMINFO_CMA_FREE", "MEMINFO_KERNEL_RECLAIMABLE"]

    schedulingEvents = [
        "sched/sched_switch",
        "power/suspend_resume",
        "sched/sched_wakeup",
        "sched/sched_wakeup_new",
        "sched/sched_waking",
        "sched/sched_process_exit",
        "sched/sched_process_free",
        "task/task_newtask",
        "task/task_rename"
    ]
    powerEvents = [
        "regulator/regulator_set_voltage",
        "regulator/regulator_set_voltage_complete",
        "power/clock_enable",
        "power/clock_disable",
        "power/clock_set_rate",
        "power/suspend_resume"
    ]
    cpuFreqEvents = [
        "power/cpu_frequency",
        "power/cpu_idle",
        "power/suspend_resume"
    ]
    sysCallsEvents = [
        "raw_syscalls/sys_enter",
        "raw_syscalls/sys_exit"
    ]
    highFrequencyEvents = [
        "mm_event/mm_event_record",
        "kmem/rss_stat",
        "ion/ion_stat",
        "dmabuf_heap/dma_heap_stat",
        "kmem/ion_heap_grow",
        "kmem/ion_heap_shrink"
    ]
    advancedConfigEvents = ["sched/sched_switch",
        "sched/sched_wakeup",
        "sched/sched_wakeup_new",
        "sched/sched_waking",
        "sched/sched_process_exit",
        "sched/sched_process_free",
        "irq/irq_handler_entry",
        "irq/irq_handler_exit",
        "irq/softirq_entry",
        "irq/softirq_exit",
        "irq/softirq_raise",
        "power/clock_disable",
        "power/clock_enable",
        "power/clock_set_rate",
        "power/cpu_frequency",
        "power/cpu_idle",
        "clk/clk_disable",
        "clk/clk_disable_complete",
        "clk/clk_enable",
        "clk/clk_enable_complete",
        "clk/clk_set_rate",
        "clk/clk_set_rate_complete",
        "binder/binder_transaction",
        "binder/binder_transaction_alloc_buf",
        "binder/binder_transaction_received",
        "binder/binder_lock",
        "binder/binder_locked",
        "binder/binder_unlock",
        "workqueue/workqueue_execute_start",
        "workqueue/workqueue_execute_end",
        "oom/oom_score_adj_update",
        "ftrace/print"
    ]
    private _menuItems: Array<MenuItem> | undefined

    public deviceSelect: HTMLSelectElement | undefined;

    private stopButtonEl: HTMLButtonElement | null | undefined;

    private recordButton: LitButton | undefined;
    private sp: SpApplication | undefined;
    private progressEL: LitProgressBar | undefined;
    private litSearch: LitSearch | undefined;
    private addButton: LitButton | undefined | null;

    private recordSetting: SpRecordSetting | undefined;
    private probesConfig: SpProbesConfig | undefined;
    private traceCommand: SpTraceCommand | undefined;
    private spAllocations: SpAllocations | undefined;
    private spRecordPerf: SpRecordPerf | undefined;
    private spFileSystem: SpFileSystem | undefined;
    private spSdkConfig: SpSdkConfig | undefined;
    private spVmTracker: SpVmTracker | undefined;

    private menuGroup: LitMainMenuGroup | undefined | null;
    private appContent: HTMLElement | undefined | null;

    compareArray(devs: Array<string>): boolean {
        let clearFlag: boolean = false;
        let optionArray = new Array();
        if (devs.length != this.deviceSelect!.options.length) {
            clearFlag = true
        } else {
            let optionArray = new Array();
            for (let i = 0; i < this.deviceSelect!.options.length; i++) {
                optionArray.push(this.deviceSelect!.options[i].value)
            }
            devs.forEach(value => {
                if (optionArray.indexOf(value) == -1) {
                    clearFlag = true
                }
            })
        }
        return clearFlag;
    }

    refreshDeviceList() {
        if (this.vs) {
            Cmd.execHdcCmd(CmdConstant.CMD_HDC_DEVICES, (res: string) => {
                let devs: string[] = res.trim().replace(/\r\n/g, "\r").replace(/\n/g, "\r").split(/\r/);
                if (devs.length == 1 && devs[0].indexOf("Empty") != -1) {
                    this.deviceSelect!.innerHTML = '';
                    return;
                }
                let clearFlag = this.compareArray(devs);
                if (clearFlag) {
                    this.deviceSelect!.innerHTML = '';
                    for (let i = 0; i < devs.length; i++) {
                        let dev = devs[i];
                        let option = document.createElement("option")
                        option.className = 'select'
                        option.textContent = dev;
                        this.deviceSelect!.appendChild(option)
                        if (i == 0) {
                            SpRecordTrace.serialNumber = option.value;
                        }
                    }
                }
            });
        } else {
            this.deviceSelect!.innerHTML = '';
            HdcDeviceManager.getDevices().then((devs: USBDevice[]) => {
                for (let len = 0; len < devs.length; len++) {
                    let dev = devs[len];
                    let option = document.createElement("option")
                    option.className = 'select'
                    if (typeof dev.serialNumber === "string") {
                        option.value = dev.serialNumber;
                    }
                    option.textContent = dev!.serialNumber ? dev!.serialNumber!.toString() : 'hdc Device';
                    this.deviceSelect!.appendChild(option)
                    if (len == 0) {
                        SpRecordTrace.serialNumber = option.value;
                        HdcDeviceManager.connect(option.value).then(() => {
                        });
                    }
                }
            });
        }
    }

    freshMenuDisable(disable: boolean) {
        let mainMenu = this.sp!.shadowRoot?.querySelector('#main-menu') as LitMainMenu
        mainMenu.menus?.forEach(men => {
                men.children.forEach(child => {
                        // @ts-ignore
                        child.disabled = disable
                    }
                )
            }
        )
        mainMenu.menus = mainMenu.menus;
    }

    set showHint(bool: boolean) {
        if (bool) {
            this.setAttribute("show_hint", '');
        } else {
            this.removeAttribute("show_hint");
        }
    }

    private refreshDeviceTimer: any;

    initElements(): void {
        let parentElement = this.parentNode as HTMLElement;
        parentElement.style.overflow = 'hidden'
        this.addButton = this.shadowRoot?.querySelector<LitButton>(".add");
        this.addButton!.addEventListener("click", () => {
            if (this.vs) {
                this.refreshDeviceList();
            } else {
                HdcDeviceManager.findDevice().then(usbDevices => {
                    log(usbDevices)
                    this.refreshDeviceList();
                });
            }
        })
        this.deviceSelect = this.shadowRoot?.querySelector("#device-select") as HTMLSelectElement;
        this.deviceSelect!.onchange = () => {
            let value = this.deviceSelect!.options[this.deviceSelect!.selectedIndex].value;
            SpRecordTrace.serialNumber = value;
            if (!this.vs) {
                HdcDeviceManager.connect(value).then(() => {
                });
            }
        }
        if (navigator.usb) {
            navigator.usb.addEventListener('connect', (ev: USBConnectionEvent) => {
                this.usbConnectionListener(ev);
            });
            navigator.usb.addEventListener('disconnect', (ev: USBConnectionEvent) => {
                this.usbDisConnectionListener(ev)
            });
        }
        this.recordSetting = new SpRecordSetting();
        this.probesConfig = new SpProbesConfig();
        this.traceCommand = new SpTraceCommand();
        this.spAllocations = new SpAllocations();
        this.spRecordPerf = new SpRecordPerf();
        this.spFileSystem = new SpFileSystem();
        this.spSdkConfig = new SpSdkConfig();
        this.spVmTracker = new SpVmTracker();
        this.recordButton = this.shadowRoot?.querySelector(".record") as LitButton;
        this.sp = document.querySelector("sp-application") as SpApplication;
        this.progressEL = this.sp.shadowRoot?.querySelector('.progress') as LitProgressBar
        this.litSearch = this.sp.shadowRoot?.querySelector('#lit-search') as LitSearch;
        this.recordButton!.addEventListener("click", () => {
            this.recordButtonListener()
        })
        this.spRecordPerf!.addEventListener("addProbe", (event: any) => {
            this.showHint = false;
        })
        this.spAllocations!.addEventListener("addProbe", (event: any) => {
            this.showHint = false;
        })
        this.probesConfig!.addEventListener("addProbe", (event: any) => {
            this.showHint = false;
        })

        this.stopButtonEl = this.traceCommand!.shadowRoot?.querySelector<HTMLButtonElement>('#stop-button');
        this.stopButtonEl!.addEventListener('click', ev => {
            this.stopRecordListener();
        })
        this.menuGroup = this.shadowRoot?.querySelector('#menu-group') as LitMainMenuGroup
        this.appContent = this.shadowRoot?.querySelector('#app-content') as HTMLElement
        this.appContent.append(this.recordSetting)
        this.initMenuItems();
    }

    stopRecordListener() {
        if (this.vs) {
            let cmd = Cmd.formatString(CmdConstant.CMS_HDC_STOP, [SpRecordTrace.serialNumber]);
            Cmd.execHdcCmd(cmd, (res: string) => {
                this.freshMenuDisable(false)
                this.freshConfigMenuDisable(false)
                this.progressEL!.loading = false
                this.sp!.search = false;
                this.litSearch!.clear();
                this.recordButton!.style.pointerEvents = 'auto';
                this.addButton!.style.pointerEvents = 'auto';
                this.deviceSelect!.style.pointerEvents = 'auto';
                this.traceCommand!.show = false;
            })
        } else {
            let selectedOption = this.deviceSelect!.options[this.deviceSelect!.selectedIndex] as HTMLOptionElement;
            HdcDeviceManager.connect(selectedOption.value).then(result => {
                if (result) {
                    this.freshMenuDisable(false)
                    this.freshConfigMenuDisable(false)
                    try {
                        this.progressEL!.loading = false
                        this.sp!.search = false;
                        this.litSearch!.clear();
                        this.recordButton!.style.pointerEvents = 'auto';
                        this.addButton!.style.pointerEvents = 'auto';
                        this.deviceSelect!.style.pointerEvents = 'auto';
                        HdcDeviceManager.stopHiprofiler(CmdConstant.CMS_STOP, true).then(result => {
                        })
                    } catch (exception) {
                        log(exception)
                    }
                    this.traceCommand!.show = false;
                }
            })
        }
    }

    private initMenuItems() {
        let that = this
        this._menuItems = [
            {
                title: "Record setting",
                icon: "properties",
                fileChoose: false,
                clickHandler: function (ev: InputEvent) {
                    that.appContent!.innerHTML = ""
                    that.appContent!.append(that.recordSetting!)
                    that.freshMenuItemsStatus('Record setting')
                }
            },
            {
                title: "Trace command",
                icon: "dbsetbreakpoint",
                fileChoose: false,
                clickHandler: function (ev: InputEvent) {
                    that.freshMenuItemsStatus('Trace command')
                    let request = that.makeRequest();
                    that.appContent!.innerHTML = ""
                    that.appContent!.append(that.traceCommand!)
                    that.traceCommand!.hdcCommon =
                        PluginConvertUtils.createHdcCmd(
                            PluginConvertUtils.BeanToCmdTxt(request, false), that.recordSetting!.output, that.recordSetting!.maxDur)
                }
            },
            {
                title: "Probes config", icon: "realIntentionBulb", fileChoose: false,
                clickHandler: function (ev: InputEvent) {
                    that.appContent!.innerHTML = ""
                    that.appContent!.append(that.probesConfig!)
                    that.freshMenuItemsStatus('Probes config')
                }
            },
            {
                title: "Native Memory",
                icon: "externaltools",
                fileChoose: false,
                clickHandler: function (ev: InputEvent) {
                    that.appContent!.innerHTML = ""
                    that.appContent!.append(that.spAllocations!)
                    that.freshMenuItemsStatus('Native Memory')
                }
            },
            {
                title: "Hiperf", icon: "realIntentionBulb", fileChoose: false,
                clickHandler: function (ev: InputEvent) {
                    that.appContent!.innerHTML = ""
                    that.appContent!.append(that.spRecordPerf!)
                    that.freshMenuItemsStatus('Hiperf')
                }
            },
            {
                title: "eBPF Config", icon: "file-config", fileChoose: false,
                clickHandler: function (ev: InputEvent) {
                    that.appContent!.innerHTML = ""
                    that.appContent!.append(that.spFileSystem!)
                    that.freshMenuItemsStatus('eBPF Config')
                }
            },
            {
                title: "VM Tracker", icon: "vm-tracker", fileChoose: false,
                clickHandler: function (ev: InputEvent) {
                    that.appContent!.innerHTML = ""
                    that.appContent!.append(that.spVmTracker!)
                    that.freshMenuItemsStatus('VM Tracker')
                }
            },
            {
                title: "SDK Config", icon: "file-config", fileChoose: false,
                clickHandler: function (ev: InputEvent) {
                    that.appContent!.innerHTML = ""
                    that.appContent!.append(that.spSdkConfig!)
                    that.freshMenuItemsStatus('SDK Config')
                }
            }
        ]
        this._menuItems?.forEach(item => {
            let th = new LitMainMenuItem();
            th.setAttribute('icon', item.icon || "");
            th.setAttribute('title', item.title || "");
            th.style.height = "60px"
            th.style.fontFamily = "Helvetica-Bold"
            th.style.fontSize = "16px"
            th.style.lineHeight = "28px"
            th.style.fontWeight = "700"
            th.style.opacity = "0.9"
            th.removeAttribute('file');
            th.addEventListener('click', e => {
                if (item.clickHandler) {
                    item.clickHandler(item)
                }
            })
            this.menuGroup!.appendChild(th);
        })
    }

    usbConnectionListener(event: USBConnectionEvent) {
        if (event.isTrusted) {
            let usbDevice: USBDevice = event.device;
            let option = document.createElement("option")
            option.className = 'select'
            if (typeof usbDevice.serialNumber === "string") {
                option.value = usbDevice.serialNumber;
            }
            option.selected = true;
            option.textContent = usbDevice!.serialNumber ? usbDevice!.serialNumber.replace(/"/g, "")
                : 'hdc Device';
            this.deviceSelect!.appendChild(option)
            SpRecordTrace.serialNumber = option.value;
            HdcDeviceManager.connect(option.value).then(() => {
            });
        }
    }

    usbDisConnectionListener(event: USBConnectionEvent) {
        let disConnectDevice: USBDevice = event.device;
        for (let index = 0; index < this.deviceSelect!.children.length; index++) {
            let option = this.deviceSelect!.children[index] as HTMLOptionElement;
            if (option.value == disConnectDevice.serialNumber) {
                let optValue = option.value;
                HdcDeviceManager.disConnect(optValue).then(() => {
                });
                this.deviceSelect!.removeChild(option);
                if (SpRecordTrace.serialNumber == optValue) {
                    let options = this.deviceSelect!.options
                    if (options.length > 0) {
                        let selectedOpt = options[this.deviceSelect!.selectedIndex]
                        SpRecordTrace.serialNumber = selectedOpt.value;
                    } else {
                        SpRecordTrace.serialNumber = '';
                    }
                }
            }
        }
    }

    recordButtonListener() {
        let request = this.makeRequest();
        if (request.pluginConfigs.length == 0) {
            this.showHint = true;
            return;
        } else {
            this.showHint = false;
        }
        let traceCommandStr = PluginConvertUtils.createHdcCmd(
            PluginConvertUtils.BeanToCmdTxt(request, false), this.recordSetting!.output, this.recordSetting!.maxDur)
        let selectedOption = this.deviceSelect!.options[this.deviceSelect!.selectedIndex] as HTMLOptionElement;
        if (selectedOption) {
            SpRecordTrace.serialNumber = selectedOption.value;
        } else {
            this.sp!.search = true;
            this.litSearch!.clear();
            this.progressEL!.loading = false
            this.litSearch!.setPercent("please connect device", -1);
        }
        if (this.vs) {
            this.appContent!.innerHTML = ""
            this.appContent!.append(this.traceCommand!)
            let config = this.makeRequest();
            this.traceCommand!.hdcCommon =
                PluginConvertUtils.createHdcCmd(
                    PluginConvertUtils.BeanToCmdTxt(config, false), this.recordSetting!.output, this.recordSetting!.maxDur)
            this.freshMenuItemsStatus('Trace command')
            Cmd.execHdcCmd(Cmd.formatString(CmdConstant.CMS_HDC_STOP, [SpRecordTrace.serialNumber]), (stopRes: string) => {
                let cmd = Cmd.formatString(CmdConstant.CMD_MOUNT_DEVICES, [SpRecordTrace.serialNumber]);
                Cmd.execHdcCmd(cmd, (res: string) => {
                    this.sp!.search = true;
                    this.progressEL!.loading = true
                    this.litSearch!.clear();
                    this.litSearch!.setPercent("tracing  " + this.recordSetting!.maxDur * 1000 + "ms", -1);
                    this.buttonDisable(true);
                    this.traceCommand!.show = true;
                    this.freshMenuDisable(true)
                    this.freshConfigMenuDisable(true)
                    Cmd.execHdcTraceCmd(traceCommandStr, SpRecordTrace.serialNumber, (traceResult: string) => {
                        if (traceResult.indexOf("DestroySession done") != -1) {
                            this.litSearch!.setPercent("tracing htrace down", -1);
                            let cmd = Cmd.formatString(CmdConstant.CMD_FIEL_RECV_DEVICES, [SpRecordTrace.serialNumber, this.recordSetting!.output])
                            Cmd.execFileRecv(cmd, this.recordSetting!.output, (rt: ArrayBuffer) => {
                                this.litSearch!.setPercent("downloading Hitrace file ", 101);
                                let fileName = this.recordSetting!.output.substring(this.recordSetting!.output.lastIndexOf("/") + 1)
                                let file = new File([rt], fileName);
                                let main = this!.parentNode!.parentNode!.querySelector("lit-main-menu") as LitMainMenu
                                let children = main.menus as Array<MenuGroup>;
                                let child = children[0].children as Array<MenuItem>
                                let fileHandler = child[0].fileHandler;
                                if (fileHandler) {
                                    this.freshMenuDisable(false)
                                    this.freshConfigMenuDisable(false)
                                    fileHandler({detail: file})
                                }
                            })
                        } else {
                            this.litSearch!.setPercent("tracing htrace failed, please check your config ", -1);
                        }
                        this.buttonDisable(false);
                    })
                })
            })
        } else {
            HdcDeviceManager.connect(selectedOption.value).then(result => {
                    log("result is " + result);
                    if (result) {
                        this.appContent!.innerHTML = ""
                        this.appContent!.append(this.traceCommand!)
                        let config = this.makeRequest();
                        this.traceCommand!.hdcCommon =
                            PluginConvertUtils.createHdcCmd(
                                PluginConvertUtils.BeanToCmdTxt(config, false), this.recordSetting!.output, this.recordSetting!.maxDur)
                        this.freshMenuItemsStatus('Trace command')
                        try {
                            HdcDeviceManager.stopHiprofiler(CmdConstant.CMS_STOP, true).then(() => {
                                HdcDeviceManager.shellResultAsString(CmdConstant.CMD_MOUNT, true).then(() => {
                                    this.sp!.search = true;
                                    this.progressEL!.loading = true
                                    this.litSearch!.clear();
                                    this.litSearch!.setPercent("tracing  " + this.recordSetting!.maxDur * 1000 + "ms", -1);
                                    this.buttonDisable(true);
                                    this.traceCommand!.show = true;
                                    this.freshMenuDisable(true)
                                    this.freshConfigMenuDisable(true)
                                    HdcDeviceManager.shellResultAsString(CmdConstant.CMD_SHELL + traceCommandStr, false).then(traceResult => {
                                        let re = this.isSuccess(traceResult)
                                        if (re == 0) {
                                            this.litSearch!.setPercent("tracing htrace down", -1);
                                            HdcDeviceManager.shellResultAsString(CmdConstant.CMD_TRACE_FILE_SIZE + this.recordSetting!.output, false).then(traceFileSize => {
                                                if (Number(traceFileSize) <= SpRecordTrace.MaxFileSize) {
                                                    HdcDeviceManager.fileRecv(this.recordSetting!.output, (perNumber: number) => {
                                                        this.litSearch!.setPercent("downloading Hitrace file ", perNumber);
                                                    }).then(pullRes => {
                                                        this.litSearch!.setPercent("downloading Hitrace file ", 101);
                                                        pullRes.arrayBuffer().then(buffer => {
                                                            let fileName = this.recordSetting!.output.substring(this.recordSetting!.output.lastIndexOf("/") + 1)
                                                            let file = new File([buffer], fileName);
                                                            let main = this!.parentNode!.parentNode!.querySelector("lit-main-menu") as LitMainMenu
                                                            let children = main.menus as Array<MenuGroup>;
                                                            let child = children[0].children as Array<MenuItem>
                                                            let fileHandler = child[0].fileHandler;
                                                            if (fileHandler) {
                                                                this.freshConfigMenuDisable(false);
                                                                this.freshMenuDisable(false)
                                                                fileHandler({detail: file})
                                                            }
                                                        })
                                                    });
                                                } else {
                                                    this.litSearch!.setPercent("htrace  file is too big", -1);
                                                }
                                            })
                                        } else if (re == 2) {
                                            this.litSearch!.setPercent("stop tracing htrace ", -1);
                                        } else if (re == -1) {
                                            this.litSearch!.setPercent("The device is abnormal", -1);
                                            this.progressEL!.loading = false
                                        } else {
                                            this.litSearch!.setPercent("tracing htrace failed, please check your config ", -1);
                                        }
                                        this.freshConfigMenuDisable(false);
                                        this.freshMenuDisable(false)
                                        this.buttonDisable(false);
                                    });
                                });
                            })
                        } catch (e) {
                            this.traceCommand!.show = false;
                            this.freshMenuDisable(false)
                            this.freshConfigMenuDisable(false)
                            this.buttonDisable(false);
                        }
                    } else {
                        this.sp!.search = true;
                        this.litSearch!.clear();
                        this.litSearch!.setPercent("please kill other hdc-server !", -1);
                    }
                }
            );
        }

    }

    private isSuccess(traceResult: string): number {
        if (traceResult.indexOf("CreateSession FAIL") != -1) {
            return 1;
        } else if (traceResult.indexOf("Signal") != -1) {
            return 2;
        } else if (traceResult.indexOf("The device is abnormal") != -1) {
            return -1
        } else {
            return 0;
        }
    }

    private makeRequest = () => {
        let request = this.createSessionRequest();
        let hasMonitorMemory = false;
        let hasSamps = false;
        if (this.probesConfig!.traceConfig.length > 0) {
            if (this.probesConfig!.traceConfig.find(value => {
                return value != "FPS" && value != "AbilityMonitor" && value != "HiSystemEvent"
            })) {
                request.pluginConfigs.push(this.createHtracePluginConfig())
            }
            if (this.probesConfig!.traceConfig.indexOf("FPS") != -1) {
                request.pluginConfigs.push(this.createFpsPluginConfig())
            }
            if (this.probesConfig!.traceConfig.indexOf("AbilityMonitor") != -1) {
                hasMonitorMemory = true;
                this.createMonitorPlugin(this, request);
            }
            if (this.probesConfig!.traceConfig.indexOf("HiSystemEvent") != -1) {
                request.pluginConfigs.push(this.createHiSystemEventPluginConfig())
            }
        }
        let reportingFrequency: number;
        if (this.recordSetting!.maxDur > 20) {
            reportingFrequency = 5
        } else {
            reportingFrequency = 2
        }
        if (this.spVmTracker!.startSamp && this.spVmTracker!.process != "") {
            hasSamps = true;
        }
        if (this.probesConfig!.memoryConfig.length > 0 || hasMonitorMemory || hasSamps) {
            request.pluginConfigs.push(this.createMemoryPluginConfig(reportingFrequency,this.probesConfig!.memoryConfig.length > 0, hasMonitorMemory, hasSamps))
        }
        if (this.spAllocations!.appProcess != "") {
            request.pluginConfigs.push(this.createNativePluginConfig(reportingFrequency))
        }
        if (this.spRecordPerf!.startSamp) {
            request.pluginConfigs.push(this.createHiperConfig(reportingFrequency))
        }
        if (this.spFileSystem!.startRecord) {
            request.pluginConfigs.push(this.createSystemConfig(reportingFrequency))
        }
        if (this.spSdkConfig!.startSamp && this.spSdkConfig!.getPlugName() != "") {
            request.pluginConfigs.push(this.createSdkConfig(reportingFrequency))
        }
        return request;
    }

    private createSessionRequest() {
        let bufferConfig: ProfilerSessionConfigBufferConfig = {
            pages: this.recordSetting!.bufferSize * 256,
            policy: ProfilerSessionConfigBufferConfigPolicy.RECYCLE
        }
        let sessionConfig: ProfilerSessionConfig = {
            buffers: [bufferConfig],
            sessionMode: ProfilerSessionConfigMode.OFFLINE,
            resultFile: this.recordSetting!.output,
            resultMaxSize: 0,
            sampleDuration: this.recordSetting!.maxDur * 1000,
            keepAliveTime: 0
        }
        let request: CreateSessionRequest = {
            requestId: 1,
            sessionConfig: sessionConfig,
            pluginConfigs: []
        }
        return request;
    }

    private createMonitorPlugin(that: this, request: CreateSessionRequest) {
        let processPlugin = that.createProcessPlugin();
        let cpuPlugin = that.createCpuPlugin();
        let diskIoPlugin = that.createDiskIOPlugin();
        let netWorkPlugin = that.createNetworkPlugin();
        request.pluginConfigs.push(processPlugin)
        request.pluginConfigs.push(cpuPlugin)
        request.pluginConfigs.push(diskIoPlugin)
        request.pluginConfigs.push(netWorkPlugin)
    }

    private createNetworkPlugin() {
        let netWorkConfig: NetworkConfig = {
            testFile: "/data/local/tmp/"
        }
        let netWorkPlugin: ProfilerPluginConfig<NetworkConfig> = {
            pluginName: "network-plugin",
            sampleInterval: 1000,
            configData: netWorkConfig
        }
        return netWorkPlugin;
    }

    private createDiskIOPlugin() {
        let diskIoConfig: DiskioConfig = {
            reportIoStats: "IO_REPORT"
        }
        let diskIoPlugin: ProfilerPluginConfig<DiskioConfig> = {
            pluginName: "diskio-plugin",
            sampleInterval: 1000,
            configData: diskIoConfig
        }
        return diskIoPlugin;
    }

    private createCpuPlugin() {
        let cpuConfig: CpuConfig = {
            pid: 0,
            reportProcessInfo: true
        }
        let cpuPlugin: ProfilerPluginConfig<CpuConfig> = {
            pluginName: "cpu-plugin",
            sampleInterval: 1000,
            configData: cpuConfig
        }
        return cpuPlugin;
    }

    private createProcessPlugin() {
        let processConfig: ProcessConfig = {
            report_process_tree: true,
            report_cpu: true,
            report_diskio: true,
            report_pss: true,
        }
        let processPlugin: ProfilerPluginConfig<ProcessConfig> = {
            pluginName: "process-plugin",
            sampleInterval: 1000,
            configData: processConfig
        }
        return processPlugin;
    }

    createTraceEvents(traceConfig: Array<string>): Array<string> {
        let traceEvents = new Set<string>();
        traceConfig.forEach(config => {
                switch (config) {
                    case "Scheduling details":
                        this.schedulingEvents.forEach((eve: string) => {
                            traceEvents.add(eve)
                        });
                        break;
                    case "CPU Frequency and idle states":
                        this.cpuFreqEvents.forEach((eve: string) => {
                            traceEvents.add(eve)
                        });
                        break;
                    case "High frequency memory":
                        this.highFrequencyEvents.forEach((eve: string) => {
                            traceEvents.add(eve)
                        });
                        break;
                    case "Advanced ftrace config":
                        this.advancedConfigEvents.forEach((eve: string) => {
                            traceEvents.add(eve)
                        });
                        break;
                    case "Syscalls":
                        this.sysCallsEvents.forEach((eve: string) => {
                            traceEvents.add(eve)
                        });
                        break;
                    case "Board voltages & frequency":
                        this.powerEvents.forEach((eve: string) => {
                            traceEvents.add(eve)
                        });
                        break;
                }
            }
        )
        let ftraceEventsArray: string[] = [];
        info("traceEvents length is: ", traceEvents.size)
        for (const ftraceEvent of traceEvents) {
            ftraceEventsArray.push(ftraceEvent)
        }
        return ftraceEventsArray
    }

    initHtml(): string {
        return `
        <style>
        :host{
            display: block;
            height: 100%;
            width: 100%;
            background-color: var(--dark-background5,#F6F6F6);
        }
        .container {
            background-color: var(--dark-background5,#F6F6F6);
            height:100%;
        }

        .header {
            padding-top: 30px;
            padding-bottom: 20px;
            background-color: var(--dark-background3,#FFFFFF);
            width: 100%;
        }

        .span-col-2{
             margin-left: 20px;
             display: flex;
             align-items: center
        }

        .header-right {
           display: flex;
           margin-left: auto;
           margin-right: 5%;
        }
        .header-des{
          font-family: PingFangSC-Regular;
          font-size: 1em;
          color:  #999999;
          text-align: left;
          font-weight: 400;
        }

        .target {
           opacity: 0.9;
           font-family: Helvetica;
           font-size: 14px;
           color: var(--dark-color2,#000000);
           line-height: 16px;
           font-weight: 400;
           white-space:nowrap;
           align-self: center;
        }

        .select{
           width: 300px;
           height: 32px;
           margin-left: 14px;
           margin-right: 24px;
           background: var(--dark-background1,#ffffff);
           border: 1px solid var(--dark-color1,#4D4D4D);
           border-radius: 16px;
           opacity: 0.6;
           font-family: Helvetica;
           font-size: 14px;
           color: var(--dark-color1,#000000);
           text-align: center;
           line-height: 20px;
           font-weight: 400;
           padding: 5px 10px 5px 10px;
           -webkit-appearance: none;
           background: url('img/down.png') no-repeat 96% center;
        }
        .body{
            width: 90%;
            height:80vh;
            margin-left: 3%;
            margin-top: 2%;
            margin-bottom: 2%;
            display: grid;
            grid-template-columns: min-content  1fr;
            background-color: var(--dark-background3,#FFFFFF);
            border-radius: 16px 16px 16px 16px;
        }

        .menugroup{
           height: 100%;
           background: var(--dark-background3,#FFFFFF);
        }
        .menuitem{
          background: var(--dark-background3,#FFFFFF);
        }
        .content{
          background: var(--dark-background3,#FFFFFF);
          border-style: none none none solid;
          border-width: 1px;
          border-color: rgba(166,164,164,0.2);
          border-radius: 0px 16px 16px 0px;
        }
        :host([show_hint]) #hint {
            display: block
        }
        #hint {
           display: none;
        }
        
        </style>
        <div class="container">
         <div class="header">
           <div style="display: flex;margin-bottom: 24px;margin-left:20px;">
             <span class="target">Target Platform:</span>
               <select class="select" id = "device-select">
               </select>
              <lit-button style="width: 180px"class="add" height="32px" width="164px" color="#0A59F7" font_size="14px" border="1px solid #0A59F7" 
              padding="0 0 0 12px" justify_content="left" icon="add" margin_icon="0 10px 0 8px">Add HDC Device</lit-button>
              <div class="header-right">
              <lit-button class="record" height="32px" width="96px" font_size="14px" justify_content="center" color="#FFFFFF"
              border_radius="16px" back='#0A59F7'>Record</lit-button>
              </div>
             </div>
              <div class="span-col-2" >
                 <span class="header-des" id="hint">It looks like you didn't add any probes. Please add at least one</span>
              </div>
         </div>

         <div class="body">
            <lit-main-menu-group class="menugroup" id= "menu-group" title="" nocollapsed radius></lit-main-menu-group>
            <div id="app-content" class="content">
            </div>
         </div>
        </div>
        `;
    }

    private createHilogConfig(probesConfig: SpProbesConfig, reportingFrequency: number) {
        let hilogConfig: HilogConfig = {
            deviceType: Type.HI3516,
            logLevel: levelFromJSON(probesConfig.hilogConfig[0]),
            needClear: true
        }
        let hilogConfigProfilerPluginConfig: ProfilerPluginConfig<HilogConfig> = {
            pluginName: "hilog-plugin",
            sampleInterval: reportingFrequency * 1000,
            configData: hilogConfig,
        }
        return hilogConfigProfilerPluginConfig;
    }

    private createHiperConfig(reportingFrequency: number) {
        let perfConfig = this.spRecordPerf!.getPerfConfig();
        let recordArgs = "";
        recordArgs = recordArgs + "-f " + perfConfig?.frequency;
        if (perfConfig?.process && !perfConfig?.process.includes("ALL") && perfConfig?.process.length > 0) {
            recordArgs = recordArgs + " -p " + perfConfig?.process;
        } else {
            recordArgs = recordArgs + " -a ";
        }
        if (perfConfig?.cpu && !perfConfig?.cpu.includes("ALL") && perfConfig?.cpu.length > 0) {
            recordArgs = recordArgs + " -c " + perfConfig?.cpu;
        }
        if (perfConfig?.cpuPercent != 0) {
            recordArgs = recordArgs + " --cpu-limit " + perfConfig?.cpuPercent;
        }
        if (perfConfig?.eventList && !perfConfig?.eventList.includes("NONE") && perfConfig?.eventList.length > 0) {
            recordArgs = recordArgs + " -e " + perfConfig?.eventList;
            if (perfConfig?.isOffCpu) {
                recordArgs = recordArgs + ",sched:sched_waking";
            }
        } else {
            recordArgs = recordArgs + " -e hw-cpu-cycles"
            if (perfConfig?.isOffCpu) {
                recordArgs = recordArgs + ",sched:sched_waking";
            }
        }
        if (perfConfig?.callStack != "none") {
            recordArgs = recordArgs + " --call-stack " + perfConfig?.callStack
        }

        if (perfConfig?.branch != "none") {
            recordArgs = recordArgs + " -j " + perfConfig?.branch
        }

        if (perfConfig?.clockType) {
            recordArgs = recordArgs + " --clockid " + perfConfig?.clockType
        }

        if (perfConfig?.isOffCpu) {
            recordArgs = recordArgs + " --offcpu"
        }

        if (perfConfig?.noInherit) {
            recordArgs = recordArgs + " --no-inherit"
        }

        if (perfConfig?.mmap) {
            recordArgs = recordArgs + " -m " + perfConfig.mmap;
        }
        info("record config Args is: ", recordArgs)
        let hiPerf: HiperfPluginConfig = {
            isRoot: false,
            outfileName: "/data/local/tmp/perf.data",
            recordArgs: recordArgs
        }
        let hiPerfPluginConfig: ProfilerPluginConfig<HiperfPluginConfig> = {
            pluginName: "hiperf-plugin",
            sampleInterval: reportingFrequency * 1000,
            configData: hiPerf,
        }
        return hiPerfPluginConfig;
    }

    private createSystemConfig(reportingFrequency: number) {
        let systemConfig = this.spFileSystem!.getSystemConfig();
        let recordArgs = "hiebpf";
        if (this.spFileSystem?.startFileSystem && this.spFileSystem?.startVirtualMemory) {
            recordArgs += " --events fs,ptrace "
        } else if (this.spFileSystem?.startFileSystem) {
            recordArgs += " --events fs "
        } else if (this.spFileSystem?.startVirtualMemory) {
            recordArgs += " --events ptrace "
        }
        recordArgs += "--duration " + this.recordSetting?.maxDur
        if (systemConfig?.process && !systemConfig?.process.includes("ALL") && systemConfig?.process.length > 0) {
            recordArgs = recordArgs + " --pids " + systemConfig?.process;
        }
        let systemPluginConfig: FileSystemConfig = {
            cmdLine: recordArgs,
            outfileName: "/data/local/tmp/ebpf.data",
        }
        let ebpfPluginConfig: ProfilerPluginConfig<FileSystemConfig> = {
            pluginName: "hiebpf-plugin",
            sampleInterval: 1000,
            configData: systemPluginConfig,
        }
        return ebpfPluginConfig;
    }

    private createNativePluginConfig(reportingFrequency: number) {
        let appProcess = this.spAllocations!.appProcess;
        let re = /^[0-9]+.?[0-9]*/;
        let pid = 0;
        let processName = "";
        let processId = "";
        if (appProcess.indexOf("(") != -1) {
            processId = appProcess.slice(appProcess.lastIndexOf("(") + 1, appProcess.lastIndexOf(")"))
        } else {
            processId = appProcess;
        }
        if (re.test(processId)) {
            pid = Number(processId);
        } else {
            processName = appProcess;
        }
        let nativeConfig: NativeHookConfig = {
            pid: pid,
            saveFile: false,
            fileName: "",
            filterSize: this.spAllocations!.filter,
            smbPages: this.spAllocations!.shared,
            maxStackDepth: this.spAllocations!.unwind,
            processName: processName,
            mallocFreeMatchingInterval: 1000,
            mallocFreeMatchingCnt: 1000,
            stringCompressed: true,
            fpUnwind: this.spAllocations!.fp_unwind
        }
        let nativePluginConfig: ProfilerPluginConfig<NativeHookConfig> = {
            pluginName: "nativehook",
            sampleInterval: reportingFrequency * 1000,
            configData: nativeConfig,
        }
        return nativePluginConfig;
    }

    private createMemoryPluginConfig(reportingFrequency: number, hasmemoryConfig: boolean, hasMonitorMemory: boolean, hasSmaps: boolean) {
        let memoryconfig: MemoryConfig = {
            reportProcessTree: false,
            reportSysmemMemInfo: false,
            sysMeminfoCounters: [],
            reportSysmemVmemInfo: false,
            sysVmeminfoCounters: [],
            reportProcessMemInfo: false,
            reportAppMemInfo: false,
            reportAppMemByMemoryService: false,
            pid: []
        }
        if (hasmemoryConfig || hasMonitorMemory) {
            memoryconfig.reportProcessTree = true;
            memoryconfig.reportSysmemMemInfo = true;
            memoryconfig.reportSysmemVmemInfo = true;
            memoryconfig.reportProcessMemInfo = true;
        }
        if (hasSmaps) {
            memoryconfig.reportSmapsMemInfo = true
            let pid = Number(this.spVmTracker?.process);
            memoryconfig.pid.push(pid)
        }
        if (hasMonitorMemory) {
            SpRecordTrace.ABALITY_MEM_INFO.forEach(va => {
                memoryconfig.sysMeminfoCounters.push(sysMeminfoTypeFromJSON(va));
            })
        }
        this.probesConfig!.memoryConfig.forEach(value => {
            if (value.indexOf("Kernel meminfo") != -1) {
                if (hasMonitorMemory) {
                    memoryconfig.sysMeminfoCounters = [];
                }
                SpRecordTrace.MEM_INFO.forEach(va => {
                    memoryconfig.sysMeminfoCounters.push(sysMeminfoTypeFromJSON(va));
                })
            }
            if (value.indexOf("Virtual memory stats") != -1) {
                SpRecordTrace.VMEM_INFO.forEach((me => {
                    memoryconfig.sysVmeminfoCounters.push(sysVMeminfoTypeFromJSON(me))
                }))
                SpRecordTrace.VMEM_INFO_SECOND.forEach((me => {
                    memoryconfig.sysVmeminfoCounters.push(sysVMeminfoTypeFromJSON(me))
                }))
                SpRecordTrace.VMEM_INFO_THIRD.forEach((me => {
                    memoryconfig.sysVmeminfoCounters.push(sysVMeminfoTypeFromJSON(me))
                }))
            }
        })
        let profilerPluginConfig: ProfilerPluginConfig<MemoryConfig> = {
            pluginName: "memory-plugin",
            sampleInterval: reportingFrequency * 1000,
            configData: memoryconfig,
        }
        return profilerPluginConfig;
    }

    private createFpsPluginConfig() {
        let fpsConfig: FpsConfig = {
            reportFps: true
        }
        let fpsPlugin: ProfilerPluginConfig<FpsConfig> = {
            pluginName: "hidump-plugin",
            sampleInterval: 1000,
            configData: fpsConfig
        }
        return fpsPlugin;
    }

    private createHiSystemEventPluginConfig() {
        let hiSystemEventConfig: HiSystemEventConfig = {
            msg: ''
        }
        let hiSystemEventPlugin: ProfilerPluginConfig<HiSystemEventConfig> = {
            pluginName: "hisysevent-plugin",
            sampleInterval: 1000,
            configData: hiSystemEventConfig
        }
        return hiSystemEventPlugin;
    }

    private createHtracePluginConfig() {
        let tracePluginConfig: TracePluginConfig = {
            ftraceEvents: this.createTraceEvents(this.probesConfig!.traceConfig),
            hitraceCategories: [],
            hitraceApps: [],
            bufferSizeKb: 2048,
            flushIntervalMs: 1000,
            flushThresholdKb: 4096,
            parseKsyms: true,
            clock: "mono",
            tracePeriodMs: 200,
            rawDataPrefix: "",
            traceDurationMs: 0,
            debugOn: false,
            hitraceTime: this.recordSetting!.maxDur
        }
        if (this.probesConfig!.traceEvents.length > 0) {
            tracePluginConfig.hitraceCategories = this.probesConfig!.traceEvents
        }
        let htraceProfilerPluginConfig: ProfilerPluginConfig<TracePluginConfig> = {
            pluginName: "ftrace-plugin",
            sampleInterval: 1000,
            configData: tracePluginConfig
        }
        return htraceProfilerPluginConfig;
    }

    private createSdkConfig(reportingFrequency: number) {
        let gpuConfig = this.spSdkConfig!.getGpuConfig();
        let gpuPluginConfig: ProfilerPluginConfig<any> = {
            pluginName: this.spSdkConfig!.getPlugName(),
            sampleInterval: this.spSdkConfig!.getSampleInterval(),
            configData: gpuConfig,
        }
        return gpuPluginConfig;
    }


    freshConfigMenuDisable(disable: boolean) {
        let querySelectors = this.shadowRoot?.querySelectorAll<LitMainMenuItem>('lit-main-menu-item')
        querySelectors!.forEach(item => {
            if (disable) {
                item.style.pointerEvents = 'none'
                this.traceCommand!.show = true;
            } else {
                item.style.pointerEvents = 'auto'
                this.traceCommand!.show = false;
            }
            item.disabled = disable;
        })
    }

    public startRefreshDeviceList() {
        if (this.refreshDeviceTimer == null) {
            this.refreshDeviceTimer = setInterval(() => {
                this.refreshDeviceList();
            }, 5000)
        }
    }

    buttonDisable(disable: boolean) {
        if (disable) {
            this.recordButton!.style.pointerEvents = 'none';
            this.addButton!.style.pointerEvents = 'none';
            this.deviceSelect!.style.pointerEvents = 'none';
        } else {
            this.recordButton!.style.pointerEvents = 'auto';
            this.addButton!.style.pointerEvents = 'auto';
            this.deviceSelect!.style.pointerEvents = 'auto';
        }
    }

    freshMenuItemsStatus(currentValue: string) {
        let litMainMenuGroup = this.shadowRoot?.querySelector<LitMainMenuGroup>('lit-main-menu-group');
        let litMainMenuItemNodeListOf = litMainMenuGroup!.querySelectorAll<LitMainMenuItem>('lit-main-menu-item');
        litMainMenuItemNodeListOf.forEach(item =>{
            item.back = item.title == currentValue;
        })
    }
}