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
import "./trace/TimerShaftElement.js";
import "./trace/base/TraceRow.js";
import {
    querySearchFunc,
    threadPool
} from "../database/SqlLite.js";
import {TraceRow} from "./trace/base/TraceRow.js";
import {TimerShaftElement} from "./trace/TimerShaftElement.js";
import {CpuStruct} from "../bean/CpuStruct.js";
import {CpuFreqStruct} from "../bean/CpuFreqStruct.js";
import {ColorUtils} from "./trace/base/ColorUtils.js";
import "./trace/base/TraceSheet.js";
import {TraceSheet} from "./trace/base/TraceSheet.js";
import {ThreadStruct} from "../bean/ThreadStruct.js";
import {ProcessMemStruct} from "../bean/ProcessMemStruct.js";
import {FuncStruct} from "../bean/FuncStruct.js";
import {FpsStruct} from "../bean/FpsStruct.js";
import {RangeSelect} from "./trace/base/RangeSelect.js";
import {SelectionParam} from "../bean/BoxSelection.js";
import {HeapStruct} from "../bean/HeapStruct.js";
import {procedurePool} from "../database/Procedure.js";
import {Utils} from "./trace/base/Utils.js";
import {SpApplication} from "../SpApplication.js";
import {SPT} from "../bean/StateProcessThread.js";
import {Flag} from "./trace/timer-shaft/Flag.js";
import {SportRuler} from "./trace/timer-shaft/SportRuler.js";
import {CpuAbilityMonitorStruct} from "../bean/CpuAbilityMonitorStruct.js";
import {MemoryAbilityMonitorStruct} from "../bean/MemoryAbilityMonitorStruct.js";
import {DiskAbilityMonitorStruct} from "../bean/DiskAbilityMonitorStruct.js";
import {NetworkAbilityMonitorStruct} from "../bean/NetworkAbilityMonitorStruct.js";
import {SpHiPerf} from "./chart/SpHiPerf.js";
import {perfDataQuery} from "./chart/PerfDataQuery.js";
import {SearchThreadProcessBean} from "../bean/SearchFuncBean.js";
import {error, info} from "../../log/Log.js";
import {ns2x} from "../database/ui-worker/ProcedureWorkerCommon.js";
import {SpChartManager} from "./chart/SpChartManager.js";
import {VirtualMemoryStruct} from "../database/ui-worker/ProcedureWorkerVirtualMemory.js";
import {ProcessStruct} from "../bean/ProcessStruct.js";
import {SpFileSystemChart} from "./chart/SpFileSystemChart.js";
import {CounterStruct, SdkSliceStruct} from "../bean/SdkStruct.js";
import {SpFreqChart} from "./chart/SpFreqChart.js";
import {EnergyStateStruct,EnergyAnomalyStruct, EnergyPowerStruct, EnergySystemStruct} from "../bean/EnergyStruct.js";
import {SmapsShowStruct} from "../bean/SmapsShowStruct.js";
import {CpuFreqLimitsStruct} from "../database/ui-worker/ProcedureWorkerCpuFreqLimits.js";

@element('sp-system-trace')
export class SpSystemTrace extends BaseElement {
    static scrollViewWidth = 0
    static isCanvasOffScreen = true;
    static SPT_DATA: Array<SPT> = [];
    static DATA_DICT: Map<number, string> = new Map<number, string>();
    static SDK_CONFIG_MAP: any;
    rowsEL: HTMLDivElement | undefined | null;
    spacerEL: HTMLDivElement | undefined | null;
    visibleRows: Array<TraceRow<any>> = [];
    keyboardEnable = true;
    currentRowType = "";/*保存当前鼠标所在行的类型*/
    observerScrollHeightEnable: boolean = false;
    observerScrollHeightCallback: Function | undefined;
    // @ts-ignore
    observer = new ResizeObserver((entries) => {
        if (this.observerScrollHeightEnable && this.observerScrollHeightCallback) {
            this.observerScrollHeightCallback();
        }
    });
    isMousePointInSheet = false;
    hoverFlag: Flag | undefined | null = undefined
    selectFlag: Flag | undefined | null = undefined
    public timerShaftEL: TimerShaftElement | null | undefined;
    private traceSheetEL: TraceSheet | undefined | null;
    private rangeSelect!: RangeSelect;
    private chartManager: SpChartManager | undefined | null;
    private loadTraceCompleted: boolean = false;

    initElements(): void {
        this.rowsEL = this.shadowRoot?.querySelector<HTMLDivElement>('.rows');
        this.spacerEL = this.shadowRoot?.querySelector<HTMLDivElement>('.spacer');
        this.timerShaftEL = this.shadowRoot?.querySelector('.timer-shaft');
        this.traceSheetEL = this.shadowRoot?.querySelector('.trace-sheet');
        this.rangeSelect = new RangeSelect(this.timerShaftEL);
        this.rangeSelect.rowsEL = this.rowsEL;
        document?.addEventListener("triangle-flag", (event: any) => {
            let temporaryTime = this.timerShaftEL?.drawTriangle(event.detail.time, event.detail.type);
            if (event.detail.timeCallback && temporaryTime) event.detail.timeCallback(temporaryTime);
        })

        document?.addEventListener("flag-change", (event: any) => {
            this.timerShaftEL?.modifyFlagList(event.detail)
            if (event.detail.hidden) {
                this.selectFlag = undefined;
                this.traceSheetEL?.setAttribute("mode", 'hidden');
                this.visibleRows.forEach(it => it.draw(true));
            }
        })

        SpSystemTrace.scrollViewWidth = this.getScrollWidth();
        this.rangeSelect.selectHandler = (rows, refreshCheckBox) => {
            if (rows.length == 0) {
                this.rowsEL!.querySelectorAll<TraceRow<any>>("trace-row").forEach(it => {
                    it.checkType = "-1"
                })
                this.getVisibleRows().forEach(it => {
                    it.draw(true);
                });
                this.traceSheetEL?.setAttribute("mode", 'hidden');
                return;
            }
            if (refreshCheckBox) {
                if (rows.length > 0) {
                    this.rowsEL?.querySelectorAll<TraceRow<any>>("trace-row").forEach(row => row.checkType = "0")
                    rows.forEach(it => it.checkType = "2")
                } else {
                    this.rowsEL?.querySelectorAll<TraceRow<any>>("trace-row").forEach(row => row.checkType = "-1")
                    return
                }
            }
            let selection = new SelectionParam();
            selection.leftNs = 0;
            selection.rightNs = 0;
            selection.recordStartNs = (window as any).recordStartNS
            let native_memory = ["All Heap & Anonymous VM", "All Heap", "All Anonymous VM"];
            rows.forEach(it => {
                if (it.rowType == TraceRow.ROW_TYPE_CPU) {
                    selection.cpus.push(parseInt(it.rowId!))
                    info("load CPU traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_CPU_STATE) {
                    let filterId = parseInt(it.rowId!);
                    if (selection.cpuStateFilterIds.indexOf(filterId) == -1) {
                        selection.cpuStateFilterIds.push(filterId);
                    }
                } else if(it.rowType == TraceRow.ROW_TYPE_CPU_FREQ){
                    let filterId = parseInt(it.rowId!);
                    if(selection.cpuFreqFilterIds.indexOf(filterId) == -1){
                        selection.cpuFreqFilterIds.push(filterId);
                    }
                } else if(it.rowType == TraceRow.ROW_TYPE_CPU_FREQ_LIMIT){
                    selection.cpuFreqLimitDatas.push(it.dataList!)
                } else if (it.rowType == TraceRow.ROW_TYPE_PROCESS) {
                    this.rowsEL?.querySelectorAll<TraceRow<any>>(`trace-row[row-parent-id='${it.rowId}']`).forEach(th => {
                        th.rangeSelect = true;
                        th.checkType = "2"
                        if (th.rowType == TraceRow.ROW_TYPE_THREAD) {
                            selection.threadIds.push(parseInt(th.rowId!))
                        } else if (th.rowType == TraceRow.ROW_TYPE_FUNC) {
                            if (th.asyncFuncName) {
                                selection.funAsync.push({
                                    name: th.asyncFuncName,
                                    pid: th.asyncFuncNamePID || 0,
                                })
                            } else {
                                selection.funTids.push(parseInt(th.rowId!))
                            }
                        } else if (th.rowType == TraceRow.ROW_TYPE_MEM) {
                            selection.processTrackIds.push(parseInt(th.rowId!))
                        }
                    })
                    info("load process traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_NATIVE_MEMORY) {
                    this.rowsEL?.querySelectorAll<TraceRow<any>>(`trace-row[row-parent-id='${it.rowId}']`).forEach(th => {
                        th.rangeSelect = true;
                        th.checkType = "2"
                        selection.nativeMemory.push(th.rowId!);
                    })
                    info("load nativeMemory traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_THREAD) {
                    selection.threadIds.push(parseInt(it.rowId!))
                    info("load thread traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_FUNC) {
                    if (it.asyncFuncName) {
                        selection.funAsync.push({
                            name: it.asyncFuncName,
                            pid: it.asyncFuncNamePID || 0,
                        })
                    } else {
                        selection.funTids.push(parseInt(it.rowId!))
                    }
                    info("load func traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_MEM || it.rowType == TraceRow.ROW_TYPE_VIRTUAL_MEMORY) {
                    if (it.rowType == TraceRow.ROW_TYPE_MEM) {
                        selection.processTrackIds.push(parseInt(it.rowId!))
                    } else {
                        selection.virtualTrackIds.push(parseInt(it.rowId!))
                    }
                    info("load memory traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_FPS) {
                    selection.hasFps = true;
                    info("load FPS traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_HEAP) {
                    if (native_memory.indexOf(it.rowId ?? "") != -1) {
                        selection.nativeMemory.push(it.rowId!);
                        info("load nativeMemory traceRow id is : ", it.rowId)
                    } else {
                        selection.heapIds.push(parseInt(it.rowId!))
                        info("load heap traceRow id is : ", it.rowId)
                    }
                } else if (it.rowType == TraceRow.ROW_TYPE_CPU_ABILITY) {
                    selection.cpuAbilityIds.push(it.rowId!)
                    info("load CPU Ability traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_MEMORY_ABILITY) {
                    selection.memoryAbilityIds.push(it.rowId!)
                    info("load Memory Ability traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_DISK_ABILITY) {
                    selection.diskAbilityIds.push(it.rowId!)
                    info("load DiskIo Ability traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_NETWORK_ABILITY) {
                    selection.networkAbilityIds.push(it.rowId!)
                    info("load Network Ability traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_SDK_COUNTER) {
                    selection.sdkCounterIds.push(it.rowId!)
                } else if (it.rowType == TraceRow.ROW_TYPE_SDK_SLICE) {
                    selection.sdkSliceIds.push(it.rowId!)
                } else if (it.rowType?.startsWith("hiperf")) {
                    if (it.rowType == TraceRow.ROW_TYPE_HIPERF_EVENT || it.rowType == TraceRow.ROW_TYPE_HIPERF_REPORT) {
                        return;
                    }
                    selection.perfSampleIds.push(1)
                    if (it.rowType == TraceRow.ROW_TYPE_HIPERF_PROCESS) {
                        this.rowsEL?.querySelectorAll<TraceRow<any>>(`trace-row[row-parent-id='${it.rowId}']`).forEach(th => {
                            th.rangeSelect = true;
                            th.checkType = "2"
                        })
                    }
                    if (it.rowType == TraceRow.ROW_TYPE_HIPERF || it.rowId == "HiPerf-cpu-merge") {
                        selection.perfAll = true;
                    }
                    if (it.rowType == TraceRow.ROW_TYPE_HIPERF_CPU) {
                        selection.perfCpus.push(it.index);
                    }
                    if (it.rowType == TraceRow.ROW_TYPE_HIPERF_PROCESS) {
                        selection.perfProcess.push(parseInt(it.rowId!.split("-")[0]));
                    }
                    if (it.rowType == TraceRow.ROW_TYPE_HIPERF_THREAD) {
                        selection.perfThread.push(parseInt(it.rowId!.split("-")[0]));
                    }
                } else if (it.rowType == TraceRow.ROW_TYPE_FILE_SYSTEM) {
                    if (it.rowId == "FileSystemLogicalWrite" || it.rowId == "FileSystemLogicalRead") {
                        selection.fileSystemType = [0, 1, 2, 3];
                    } else if (it.rowId == "FileSystemVirtualMemory") {
                        selection.fileSysVirtualMemory = true;
                    } else if (it.rowId == "FileSystemDiskIOLatency") {
                        selection.diskIOLatency = true;
                    } else {
                        let arr = it.rowId!.split("-").reverse();
                        let ipid = parseInt(arr[0]);
                        if (selection.diskIOipids.indexOf(ipid) == -1) {
                            selection.diskIOipids.push(ipid);
                        }
                    }
                } else if (it.rowType == TraceRow.ROW_TYPE_POWER_ENERGY) {
                    selection.powerEnergy.push(it.rowId!)
                } else if (it.rowType == TraceRow.ROW_TYPE_SYSTEM_ENERGY) {
                    selection.systemEnergy.push(it.rowId!)
                } else if (it.rowType == TraceRow.ROW_TYPE_ANOMALY_ENERGY) {
                    selection.anomalyEnergy.push(it.rowId!)
                } else if (it.rowType == TraceRow.ROW_TYPE_SYSTEM_ENERGY) {
                    info("load anomaly Energy traceRow id is : ", it.rowId)
                } else if (it.rowType == TraceRow.ROW_TYPE_SMAPS) {
                    selection.smapsType.push(it.rowId!)
                }
            })
            selection.leftNs = TraceRow.rangeSelectObject?.startNS || 0;
            selection.rightNs = TraceRow.rangeSelectObject?.endNS || 0;
            this.selectStructNull();
            this.timerShaftEL?.removeTriangle("inverted")
            this.traceSheetEL?.rangeSelect(selection);
        }
        // @ts-ignore
        new ResizeObserver((entries) => {
            let width = entries[0].contentRect.width - 1 - SpSystemTrace.scrollViewWidth;
            requestAnimationFrame(() => {
                this.timerShaftEL?.updateWidth(width)
                this.shadowRoot!.querySelectorAll<TraceRow<any>>("trace-row").forEach(it => it.updateWidth(width))
            })
        }).observe(this);

        new ResizeObserver((entries) => {
            this.getVisibleRows().forEach(it => {
                it.draw(true);
            });
            if (this.traceSheetEL!.getAttribute("mode") == "hidden") {
                this.timerShaftEL?.removeTriangle("triangle")
            }
        }).observe(this.rowsEL!);
        window.addEventListener("keydown", ev => {
            if (ev.key.toLocaleLowerCase() === "escape") {
                this.selectStructNull();
                this.timerShaftEL?.setSlicesMark();
                this.traceSheetEL?.setAttribute("mode", 'hidden');
                TraceRow.rangeSelectObject = undefined;
            }
        });
        this.chartManager = new SpChartManager(this);
    }

    getScrollWidth() {
        let totalScrollDiv, scrollDiv, overflowDiv = document.createElement('div');
        overflowDiv.style.cssText = 'position:absolute; top:-2000px;width:200px; height:200px; overflow:hidden;';
        totalScrollDiv = document.body.appendChild(overflowDiv).clientWidth;
        overflowDiv.style.overflowY = 'scroll';
        scrollDiv = overflowDiv.clientWidth;
        document.body.removeChild(overflowDiv);
        return totalScrollDiv - scrollDiv;
    }

    getVisibleRows(): Array<TraceRow<any>> {
        let scrollTop = this.rowsEL?.scrollTop || 0;
        let scrollHeight = this.rowsEL?.clientHeight || 0;
        let res = [...this.rowsEL!.querySelectorAll<TraceRow<any>>("trace-row")].filter((it) => {
            let tr = (it as TraceRow<any>);
            let top = it.offsetTop - (this.rowsEL?.offsetTop || 0);
            if ((top + it.clientHeight > scrollTop && top + it.clientHeight < scrollTop + scrollHeight + it.clientHeight) || it.collect) {
                it.sleeping = false;
                return true
            } else {
                if (!it.hasAttribute("collect-type")) {
                    it.sleeping = true;
                }
                return false;
            }
        })
        this.visibleRows = res;
        info("Visible TraceRow size is :", this.visibleRows!.length)
        return res;
    }

    timerShaftELFlagClickHandler = (flag: Flag | undefined | null) => {
        if (flag) {
            setTimeout(() => {
                this.traceSheetEL?.displayFlagData(flag);
            }, 100)
        }
    }

    timerShaftELFlagChange = (hoverFlag: Flag | undefined | null, selectFlag: Flag | undefined | null) => {
        this.hoverFlag = hoverFlag;
        this.selectFlag = selectFlag;
        this.visibleRows.forEach(it => it.draw(true));
    }

    timerShaftELRangeChange = (e: any) => {
        TraceRow.range = e;
        if (TraceRow.rangeSelectObject) {
            TraceRow.rangeSelectObject!.startX = Math.floor(ns2x(TraceRow.rangeSelectObject!.startNS!, TraceRow.range?.startNS!, TraceRow.range?.endNS!, TraceRow.range?.totalNS!, this.timerShaftEL!.sportRuler!.frame));
            TraceRow.rangeSelectObject!.endX = Math.floor(ns2x(TraceRow.rangeSelectObject!.endNS!, TraceRow.range?.startNS!, TraceRow.range?.endNS!, TraceRow.range?.totalNS!, this.timerShaftEL!.sportRuler!.frame));
        }
        //在rowsEL显示范围内的 trace-row组件将收到时间区间变化通知
        for (let i = 0; i < this.visibleRows.length; i++) {
            this.visibleRows[i].draw();
        }
    }

    rowsElOnScroll = (e: any) => {
        this.hoverStructNull();
        if (TraceRow.range) {
            TraceRow.range.refresh = true;
        }
        this.visibleRows = this.getVisibleRows();
        for (let index = 0; index < this.visibleRows.length; index++) {
            if (index == 0 || index == this.visibleRows.length - 1) {
                this.visibleRows[index].isHover = false;
            }
        }
    }

    documentOnMouseDown = (ev: MouseEvent) => {
        if (!this.loadTraceCompleted) return;
        TraceRow.isUserInteraction = true;
        if (this.isMouseInSheet(ev)) return;
        this.observerScrollHeightEnable = false;
        if (ev.offsetX > this.timerShaftEL!.canvas!.offsetLeft) {
            let x = ev.offsetX - this.timerShaftEL!.canvas!.offsetLeft;
            let y = ev.offsetY;
            this.timerShaftEL?.documentOnMouseDown(ev);
            if (this.timerShaftEL!.sportRuler!.frame.contains(x, y) && x > (TraceRow.rangeSelectObject?.startX || 0) && x < (TraceRow.rangeSelectObject?.endX || 0)) {
                let time = Math.round((x * (TraceRow.range?.endNS! - TraceRow.range?.startNS!) / this.timerShaftEL!.canvas!.offsetWidth) + TraceRow.range?.startNS!);
                this.timerShaftEL!.sportRuler!.drawTriangle(time, "triangle")
            } else {
                this.rangeSelect.mouseDown(ev)
            }
            this.visibleRows.forEach(it => it.draw());
        }
    }

    documentOnMouseUp = (ev: MouseEvent) => {
        if (!this.loadTraceCompleted) return;
        TraceRow.isUserInteraction = false;
        this.rangeSelect.isMouseDown = false;
        if (this.isMouseInSheet(ev)) return;
        let x = ev.offsetX - this.timerShaftEL!.canvas!.offsetLeft;
        let y = ev.offsetY;
        if (this.timerShaftEL!.sportRuler!.frame.contains(x, y) && x > (TraceRow.rangeSelectObject?.startX || 0) && x < (TraceRow.rangeSelectObject?.endX || 0)) {
        } else {
            this.rangeSelect.mouseUp(ev);
            this.timerShaftEL?.documentOnMouseUp(ev)
        }
    }

    documentOnMouseOut = (ev: MouseEvent) => {
        if (!this.loadTraceCompleted) return;
        if (this.isMouseInSheet(ev)) return;
        if (ev.offsetX > this.timerShaftEL!.canvas!.offsetLeft) {
            this.timerShaftEL?.documentOnMouseOut(ev)
        }
    }

    documentOnKeyPress = (ev: KeyboardEvent) => {
        if (!this.loadTraceCompleted) return;
        TraceRow.isUserInteraction = true;
        if (ev.key.toLocaleLowerCase() == "m") {
            if (CpuStruct.selectCpuStruct) {
                this.timerShaftEL?.setSlicesMark((CpuStruct.selectCpuStruct.startTime || 0), (CpuStruct.selectCpuStruct.startTime || 0) + (CpuStruct.selectCpuStruct.dur || 0));
            } else if (ThreadStruct.selectThreadStruct) {
                this.timerShaftEL?.setSlicesMark((ThreadStruct.selectThreadStruct.startTime || 0), (ThreadStruct.selectThreadStruct.startTime || 0) + (ThreadStruct.selectThreadStruct.dur || 0));
            } else if (FuncStruct.selectFuncStruct) {
                this.timerShaftEL?.setSlicesMark((FuncStruct.selectFuncStruct.startTs || 0), (FuncStruct.selectFuncStruct.startTs || 0) + (FuncStruct.selectFuncStruct.dur || 0));
            } else if (TraceRow.rangeSelectObject) {
                this.timerShaftEL?.setSlicesMark((TraceRow.rangeSelectObject.startNS || 0), (TraceRow.rangeSelectObject.endNS || 0));
            } else {
                this.timerShaftEL?.setSlicesMark();
            }
        }
        if (this.isMousePointInSheet) {
            return;
        }
        this.observerScrollHeightEnable = false;
        this.keyboardEnable && this.timerShaftEL!.documentOnKeyPress(ev);
    }

    documentOnKeyUp = (ev: KeyboardEvent) => {
        if (!this.loadTraceCompleted) return;
        TraceRow.isUserInteraction = false;
        this.observerScrollHeightEnable = false;
        this.keyboardEnable && this.timerShaftEL!.documentOnKeyUp(ev);
        if (ev.code == "Enter") {
            if (ev.shiftKey) {
                this.dispatchEvent(new CustomEvent("previous-data", {
                    detail: {},
                    composed: false
                }));
            } else {
                this.dispatchEvent(new CustomEvent("next-data", {
                    detail: {},
                    composed: false
                }));
            }
        }
    }

    isMouseInSheet = (ev: MouseEvent) => {
        this.isMousePointInSheet = this.traceSheetEL?.getAttribute("mode") != "hidden" && ev.offsetX > this.traceSheetEL!.offsetLeft && ev.offsetY > this.traceSheetEL!.offsetTop;
        return this.isMousePointInSheet;
    }

    favoriteChangeHandler = (row: TraceRow<any>) => {
        info("favoriteChangeHandler", row.frame, row.offsetTop, row.offsetHeight);
        this.getVisibleRows();
    }

    selectChangeHandler = (rows: Array<TraceRow<any>>) => {
        this.rangeSelect.rangeTraceRow = rows;
        this.rangeSelect.selectHandler?.(this.rangeSelect.rangeTraceRow, false);
    }

    documentOnMouseMove = (ev: MouseEvent) => {
        if ((window as any).isSheetMove) return;
        if (!this.loadTraceCompleted || (window as any).flagInputFocus) return;
        if (this.isMouseInSheet(ev)) {
            this.hoverStructNull();
            return;
        }
        let rows = this.visibleRows;
        if (this.timerShaftEL?.isScaling()) {
            return;
        }
        this.timerShaftEL?.documentOnMouseMove(ev)
        this.rangeSelect.mouseMove(rows, ev);
        if (this.rangeSelect.isMouseDown) {
            for (let i = 0; i < rows.length; i++) {
                rows[i].tipEL!.style.display = "none";
                rows[i].draw(true);
            }
        } else {
            for (let i = 0; i < rows.length; i++) {
                let tr = rows[i];
                let rowsELScrollTop = this.rowsEL?.scrollTop || 0;
                let x = ev.offsetX - (tr.canvasContainer?.offsetLeft || 0);
                let y = ev.offsetY - (tr.canvasContainer?.offsetTop || 0) + rowsELScrollTop;
                if ((!tr.collect && x > tr.frame.x && x < tr.frame.x + tr.frame.width && ev.offsetY + rowsELScrollTop > tr.offsetTop && ev.offsetY + rowsELScrollTop < tr.offsetTop + tr.frame.height) ||
                    (tr.collect && x > tr.frame.x && x < tr.frame.x + tr.frame.width && ev.offsetY > tr.offsetTop - 48 && ev.offsetY < tr.offsetTop - 48 + tr.frame.height)) {
                    tr.isHover = true;
                    tr.hoverX = x;
                    tr.hoverY = tr.collect ? (ev.offsetY + 48 - tr.offsetTop) : y;
                    if (tr.rowType === TraceRow.ROW_TYPE_CPU) {
                        this.currentRowType = TraceRow.ROW_TYPE_CPU;
                        CpuFreqStruct.hoverCpuFreqStruct = undefined;
                        SpFreqChart.hoverStateStruct = undefined;
                        CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct = undefined
                        if (CpuStruct.hoverCpuStruct) {
                            tr.tip = `<span>P：${CpuStruct.hoverCpuStruct.processName || "Process"} [${CpuStruct.hoverCpuStruct.processId}]</span><span>T：${CpuStruct.hoverCpuStruct.name} [${CpuStruct.hoverCpuStruct.tid}] [Prio:${CpuStruct.hoverCpuStruct.priority||0}]</span>`;
                        }
                        tr.setTipLeft(x, CpuStruct.hoverCpuStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_CPU_STATE) {
                        this.currentRowType = TraceRow.ROW_TYPE_CPU_STATE;
                        CpuFreqStruct.hoverCpuFreqStruct = undefined;
                        CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct = undefined

                        if (SpFreqChart.hoverStateStruct) {
                            tr.tip = `<span>State: ${SpFreqChart.hoverStateStruct.value}</span>`
                        }
                        tr.setTipLeft(x, SpFreqChart.hoverStateStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_CPU_FREQ_LIMIT){
                        CpuFreqStruct.hoverCpuFreqStruct = undefined;
                        SpFreqChart.hoverStateStruct = undefined;
                        if (CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct) {
                            tr.tip = `<span>Max Freq: ${ColorUtils.formatNumberComma(CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct.max!)} kHz</span><span>Min Freq: ${ColorUtils.formatNumberComma(CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct.min!)} kHz</span>`
                        }
                        tr.setTipLeft(x, CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct)
                    }else if (tr.rowType === TraceRow.ROW_TYPE_CPU_FREQ) {
                        this.currentRowType = TraceRow.ROW_TYPE_CPU_FREQ;
                        CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct = undefined
                        SpFreqChart.hoverStateStruct = undefined;
                        if (CpuFreqStruct.hoverCpuFreqStruct) {
                            CpuStruct.hoverCpuStruct = undefined;
                            tr.tip = `<span>${ColorUtils.formatNumberComma(CpuFreqStruct.hoverCpuFreqStruct.value!)} kHz</span>`
                        }
                        tr.setTipLeft(x, CpuFreqStruct.hoverCpuFreqStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_FPS) {
                        this.currentRowType = TraceRow.ROW_TYPE_FPS;
                        if (FpsStruct.hoverFpsStruct) {
                            tr.tip = `<span>${FpsStruct.hoverFpsStruct.fps}</span>`
                        }
                        tr.setTipLeft(x, FpsStruct.hoverFpsStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_THREAD) {
                        FuncStruct.hoverFuncStruct = undefined;
                        CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct = undefined
                        this.currentRowType = TraceRow.ROW_TYPE_THREAD;
                    } else if (tr.rowType === TraceRow.ROW_TYPE_FUNC) {
                        ThreadStruct.hoverThreadStruct = undefined;
                        CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct = undefined
                        this.currentRowType = TraceRow.ROW_TYPE_FUNC;
                    } else if (tr.rowType === TraceRow.ROW_TYPE_HEAP) {
                        this.currentRowType = TraceRow.ROW_TYPE_HEAP;
                        if (HeapStruct.hoverHeapStruct) {
                            if (tr.drawType === 1) {
                                tr.tip = `<span>${HeapStruct.hoverHeapStruct.heapsize}</span>`
                            } else {
                                tr.tip = `<span>${Utils.getByteWithUnit(HeapStruct.hoverHeapStruct.heapsize!)}</span>`
                            }
                        }
                        tr.setTipLeft(x, HeapStruct.hoverHeapStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_CPU_ABILITY) {
                        this.currentRowType = TraceRow.ROW_TYPE_CPU_ABILITY;
                        if (!SpSystemTrace.isCanvasOffScreen) CpuAbilityMonitorStruct.hoverCpuAbilityStruct = tr.onMouseHover(x, y);
                        if (CpuAbilityMonitorStruct.hoverCpuAbilityStruct) {
                            let monitorCpuTip = (CpuAbilityMonitorStruct.hoverCpuAbilityStruct.value!).toFixed(2) + "%"
                            tr.tip = `<span>${monitorCpuTip}</span>`
                        }
                        tr.setTipLeft(x, CpuAbilityMonitorStruct.hoverCpuAbilityStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_MEMORY_ABILITY) {
                        this.currentRowType = TraceRow.ROW_TYPE_MEMORY_ABILITY;
                        if (!SpSystemTrace.isCanvasOffScreen) MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct = tr.onMouseHover(x, y);
                        if (MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct) {
                            tr.tip = `<span>${Utils.getBinaryByteWithUnit(MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct.value!)}</span>`
                        }
                        tr.setTipLeft(x, MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_DISK_ABILITY) {
                        this.currentRowType = TraceRow.ROW_TYPE_DISK_ABILITY;
                        if (!SpSystemTrace.isCanvasOffScreen) DiskAbilityMonitorStruct.hoverDiskAbilityStruct = tr.onMouseHover(x, y);
                        if (DiskAbilityMonitorStruct.hoverDiskAbilityStruct) {
                            tr.tip = `<span>${DiskAbilityMonitorStruct.hoverDiskAbilityStruct.value!} KB/S</span>`
                        }
                        tr.setTipLeft(x, DiskAbilityMonitorStruct.hoverDiskAbilityStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_NETWORK_ABILITY) {
                        this.currentRowType = TraceRow.ROW_TYPE_NETWORK_ABILITY;
                        if (!SpSystemTrace.isCanvasOffScreen) NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct = tr.onMouseHover(x, y);
                        if (NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct) {
                            tr.tip = `<span>${Utils.getBinaryByteWithUnit(NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct.value!)}</span>`
                        }
                        tr.setTipLeft(x, NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_HIPERF_CPU) {
                        this.currentRowType = TraceRow.ROW_TYPE_HIPERF_CPU;
                        if (SpHiPerf.hoverCpuStruct) {
                            let num = Math.trunc((SpHiPerf.hoverCpuStruct.height || 0) / 40 * 100);
                            if (num > 0) {
                                if (tr.rowId == "HiPerf-cpu-merge") {
                                    tr.tip = `<span>${num * (this.chartManager!.perf!.maxCpuId + 1)}% (10.00ms)</span>`
                                } else {
                                    tr.tip = `<span>${num}% (10.00ms)</span>`
                                }
                            } else {
                                let perfCall = perfDataQuery.callChainMap.get(SpHiPerf.hoverCpuStruct.callchain_id || 0);
                                tr.tip = `<span>${perfCall ? perfCall.name : ''} (${perfCall ? perfCall.depth : '0'} other frames)</span>`
                            }
                        }
                        tr.setTipLeft(x, SpHiPerf.hoverCpuStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_HIPERF_EVENT) {
                        this.currentRowType = TraceRow.ROW_TYPE_HIPERF_EVENT;
                        if (SpHiPerf.hoverEventuctStruct) {
                            let num = Math.trunc((SpHiPerf.hoverEventuctStruct.sum || 0) / (SpHiPerf.hoverEventuctStruct.max || 0) * 100);
                            if (num > 0) {
                                tr.tip = `<span>${num}% (10.00ms)</span>`
                            } else {
                                let perfCall = perfDataQuery.callChainMap.get(SpHiPerf.hoverEventuctStruct.callchain_id || 0);
                                tr.tip = `<span>${perfCall ? perfCall.name : ''} (${perfCall ? perfCall.depth : '0'} other frames)</span>`
                            }
                        }
                        tr.setTipLeft(x, SpHiPerf.hoverEventuctStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_HIPERF_PROCESS) {
                        this.currentRowType = TraceRow.ROW_TYPE_HIPERF_PROCESS;
                        if (SpHiPerf.hoverProcessStruct) {
                            let num = Math.trunc((SpHiPerf.hoverProcessStruct.height || 0) / 40 * 100);
                            if (num > 0) {
                                tr.tip = `<span>${num}% (10.00ms)</span>`
                            } else {
                                let perfCall = perfDataQuery.callChainMap.get(SpHiPerf.hoverProcessStruct.callchain_id || 0);
                                tr.tip = `<span>${perfCall ? perfCall.name : ''} (${perfCall ? perfCall.depth : '0'} other frames)</span>`
                            }
                        }
                        tr.setTipLeft(x, SpHiPerf.hoverProcessStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_HIPERF_THREAD) {
                        this.currentRowType = TraceRow.ROW_TYPE_HIPERF_THREAD;
                        if (SpHiPerf.hoverThreadStruct) {
                            let num = Math.trunc((SpHiPerf.hoverThreadStruct.height || 0) / 40 * 100);
                            if (num > 0) {
                                tr.tip = `<span>${num}% (10.00ms)</span>`
                            } else {
                                let perfCall = perfDataQuery.callChainMap.get(SpHiPerf.hoverThreadStruct.callchain_id || -1);
                                tr.tip = `<span>${perfCall ? perfCall.name : ''} (${perfCall ? perfCall.depth : '0'} other frames)</span>`
                            }
                        }
                        tr.setTipLeft(x, SpHiPerf.hoverThreadStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_FILE_SYSTEM) {
                        this.currentRowType = TraceRow.ROW_TYPE_FILE_SYSTEM;
                        let num = 0;
                        if (SpFileSystemChart.hoverFileSysStruct) {
                            num = SpFileSystemChart.hoverFileSysStruct.size ?? 0;
                            let group10Ms = SpFileSystemChart.hoverFileSysStruct.group10Ms ?? false;
                            if (tr.rowId!.startsWith("FileSystemDiskIOLatency")) {
                                if (num > 0) {
                                    let tipStr = Utils.getProbablyTime(num);
                                    tr.tip = `<span>${tipStr} (10.00ms)</span>`
                                }
                            } else {
                                if (num > 0) {
                                    if (group10Ms) {
                                        tr.tip = `<span>${num} (10.00ms)</span>`
                                    } else {
                                        tr.tip = `<span>${num}</span>`
                                    }
                                }
                            }
                        }
                        tr.setTipLeft(x, num > 0 ? SpFileSystemChart.hoverFileSysStruct : null)
                    } else if (tr.rowType == TraceRow.ROW_TYPE_MEM) {
                        if (ProcessMemStruct.hoverProcessMemStruct) {
                            CpuStruct.hoverCpuStruct = undefined;
                            tr.tip = `<span>${ProcessMemStruct.hoverProcessMemStruct.value}</span>`
                        }
                        tr.setTipLeft(x, ProcessMemStruct.hoverProcessMemStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_SDK_COUNTER) {
                        this.currentRowType = TraceRow.ROW_TYPE_SDK_COUNTER;
                        if (!SpSystemTrace.isCanvasOffScreen) CounterStruct.hoverCounterStruct = tr.onMouseHover(x, y);
                        if (CounterStruct.hoverCounterStruct) {
                            let gpuTip = (CounterStruct.hoverCounterStruct.value!).toFixed(2)
                            tr.tip = `<span>${gpuTip}</span>`
                        }
                        tr.setTipLeft(x, CounterStruct.hoverCounterStruct)
                    } else if (tr.rowType === TraceRow.ROW_TYPE_SDK_SLICE) {
                        this.currentRowType = TraceRow.ROW_TYPE_SDK_SLICE;
                        if (!SpSystemTrace.isCanvasOffScreen) SdkSliceStruct.hoverSdkSliceStruct = tr.onMouseHover(x, y);
                        if (SdkSliceStruct.hoverSdkSliceStruct) {
                            tr.tip = `<span>${SdkSliceStruct.hoverSdkSliceStruct?.value}</span>`;
                        }
                        tr.setTipLeft(x, SdkSliceStruct.hoverSdkSliceStruct)
                    } else if (tr.rowType == TraceRow.ROW_TYPE_VIRTUAL_MEMORY) {
                        if (VirtualMemoryStruct.hoverStruct) {
                            CpuStruct.hoverCpuStruct = undefined;
                            tr.tip = `<span>value:${VirtualMemoryStruct.hoverStruct.value}</span>`
                        }
                        tr.setTipLeft(x, VirtualMemoryStruct.hoverStruct)
                    } else if (tr.rowType == TraceRow.ROW_TYPE_POWER_ENERGY) {
                        this.currentRowType = TraceRow.ROW_TYPE_POWER_ENERGY;
                        if (!SpSystemTrace.isCanvasOffScreen) EnergyPowerStruct.hoverEnergyPowerStruct = tr.onMouseHover(x, y);
                        if (EnergyPowerStruct.hoverEnergyPowerStruct) {
                            tr.tip = `<div style="width: 120px">
                                <div style="display: flex"><div style="width: 80%;text-align: left">CPU: </div><div style="width: 20%;text-align: left">${EnergyPowerStruct.hoverEnergyPowerStruct.cpu!}</div></div>
                                <div style="display: flex"><div style="width: 80%;text-align: left">location: </div><div style="width: 20%;text-align: left">${EnergyPowerStruct.hoverEnergyPowerStruct.location!}</div></div>
                                <div style="display: flex"><div style="width: 80%;text-align: left">GPU: </div><div style="width: 20%;text-align: left">${EnergyPowerStruct.hoverEnergyPowerStruct.gpu!}</div></div>
                                <div style="display: flex"><div style="width: 80%;text-align: left">display: </div><div style="width: 20%;text-align: left">${EnergyPowerStruct.hoverEnergyPowerStruct.display!}</div></div>
                                <div style="display: flex"><div style="width: 80%;text-align: left">camera: </div><div style="width: 20%;text-align: left">${EnergyPowerStruct.hoverEnergyPowerStruct.camera!}</div></div>       
                                <div style="display: flex"><div style="width: 80%;text-align: left">bluetooth: </div><div style="width: 20%;text-align: left">${EnergyPowerStruct.hoverEnergyPowerStruct.bluetooth!}</div></div>       
                                <div style="display: flex"><div style="width: 80%;text-align: left">flashlight: </div><div style="width: 20%;text-align: left">${EnergyPowerStruct.hoverEnergyPowerStruct.flashlight!}</div></div>       
                                <div style="display: flex"><div style="width: 80%;text-align: left">audio: </div><div style="width: 20%;text-align: left">${EnergyPowerStruct.hoverEnergyPowerStruct.audio!}</div></div>       
                                <div style="display: flex"><div style="width: 80%;text-align: left">wifiScan: </div><div style="width: 20%;text-align: left">${EnergyPowerStruct.hoverEnergyPowerStruct.wifiscan!}</div></div>       
                            </div>`
                        }
                        tr.setTipLeft(x, EnergyPowerStruct.hoverEnergyPowerStruct)
                    } else if (tr.rowType == TraceRow.ROW_TYPE_SYSTEM_ENERGY) {
                        this.currentRowType = TraceRow.ROW_TYPE_SYSTEM_ENERGY;
                        if (!SpSystemTrace.isCanvasOffScreen) EnergySystemStruct.hoverEnergySystemStruct = tr.onMouseHover(x, y);
                        if (EnergySystemStruct.hoverEnergySystemStruct) {
                            tr.tip = `<div style="width: 250px">
                                <div style="display: flex"><div style="width: 75%;text-align: left">WORKSCHEDULER: </div><div style="width: 20%;text-align: left">${EnergySystemStruct.hoverEnergySystemStruct.workScheduler!}</div></div>
                                <div style="display: flex"><div style="width: 75%;text-align: left">POWER_RUNNINGLOCK: </div><div style="width: 20%;text-align: left">${EnergySystemStruct.hoverEnergySystemStruct.power!}</div></div>
                                <div style="display: flex"><div style="width: 75%;text-align: left">LOCATION: </div><div style="width: 20%;text-align: left">${EnergySystemStruct.hoverEnergySystemStruct.location!}</div></div>   
                            </div>`
                        }
                        tr.setTipLeft(x, EnergySystemStruct.hoverEnergySystemStruct)
                    } else if (tr.rowType == TraceRow.ROW_TYPE_ANOMALY_ENERGY) {
                        this.currentRowType = TraceRow.ROW_TYPE_ANOMALY_ENERGY;
                        if (!SpSystemTrace.isCanvasOffScreen) EnergyAnomalyStruct.hoverEnergyAnomalyStruct = tr.onMouseHover(x, y);
                        if (EnergyAnomalyStruct.hoverEnergyAnomalyStruct) {
                            tr.tip = `<span>AnomalyName:${EnergyAnomalyStruct.hoverEnergyAnomalyStruct.eventName}</span>`
                        }
                        tr.setTipLeft(x, EnergyAnomalyStruct.hoverEnergyAnomalyStruct)
                    } else if (tr.rowType == TraceRow.ROW_TYPE_STATE_ENERGY) {
                        this.currentRowType = TraceRow.ROW_TYPE_STATE_ENERGY;
                        if (!SpSystemTrace.isCanvasOffScreen) EnergyStateStruct.hoverEnergyStateStruct = tr.onMouseHover(x, y);
                        if (EnergyStateStruct.hoverEnergyStateStruct) {
                            if (EnergyStateStruct.hoverEnergyStateStruct.type!.toLocaleLowerCase().includes("state")) {
                                tr.tip = `<span>Switch Status: ${EnergyStateStruct.hoverEnergyStateStruct.value == 1 ? 'disable' : 'enable'}</span>`
                            } else {
                                tr.tip = `<span>value: ${EnergyStateStruct.hoverEnergyStateStruct.value}</span>`
                            }
                        }
                        tr.setTipLeft(x, EnergyStateStruct.hoverEnergyStateStruct)
                    } else if (tr.rowType == TraceRow.ROW_TYPE_SMAPS) {
                        this.currentRowType = TraceRow.ROW_TYPE_SMAPS;
                        if (!SpSystemTrace.isCanvasOffScreen) SmapsShowStruct.hoverStruct = tr.onMouseHover(x, y);
                        if (SmapsShowStruct.hoverStruct) {
                            let value = 0;
                            if (SmapsShowStruct.hoverStruct.value != undefined) {
                                value = SmapsShowStruct.hoverStruct.value
                            }
                            tr.tip = `<span>${Utils.getBinaryByteWithUnit( value * 1024)}</span>`
                        }
                        tr.setTipLeft(x, SmapsShowStruct.hoverStruct)
                    } else {
                        this.hoverStructNull();
                    }
                    if (tr.isComplete) {
                        tr.draw(true);
                    }
                } else {
                    tr.onMouseLeave(x, y);
                    tr.isHover = false;
                    tr.hoverX = x;
                    tr.hoverY = y;
                }

            }
            if (ev.offsetX > this.timerShaftEL!.canvas!.offsetLeft!
                && ev.offsetX < this.timerShaftEL!.canvas!.offsetLeft! + this.timerShaftEL!.canvas!.offsetWidth!
                && ev.offsetY > this.rowsEL!.offsetTop
                && ev.offsetY < this.rowsEL!.offsetTop + this.rowsEL!.offsetHeight
            ) {
            } else {
                this.hoverStructNull();
                for (let i = 0, len = rows.length; i < len; i++) {
                    if (!(rows[i].rowType === TraceRow.ROW_TYPE_PROCESS) && this.currentRowType === rows[i].rowType) { //
                        if (rows[i].isComplete) {
                            rows[i].draw(true);
                        }
                    }
                }
            }
        }
    }

    hoverStructNull() {
        CpuStruct.hoverCpuStruct = undefined;
        CpuFreqStruct.hoverCpuFreqStruct = undefined;
        ThreadStruct.hoverThreadStruct = undefined;
        FuncStruct.hoverFuncStruct = undefined;
        SpHiPerf.hoverCpuStruct = undefined;
        SpFreqChart.hoverStateStruct = undefined;
        CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct = undefined
    }

    selectStructNull() {
        CpuStruct.selectCpuStruct = undefined;
        CpuStruct.wakeupBean = null;
        CpuFreqStruct.selectCpuFreqStruct = undefined;
        ThreadStruct.selectThreadStruct = undefined;
        FuncStruct.selectFuncStruct = undefined;
        SpHiPerf.selectCpuStruct = undefined;
        SpFreqChart.selectStateStruct = undefined;
        CpuFreqLimitsStruct.selectCpuFreqLimitsStruct = undefined
    }

    documentOnClick = (ev: MouseEvent) => {
        if (!this.loadTraceCompleted) return;
        if (this.isMouseInSheet(ev)) return;
        if ((window as any).isPackUpTable) {
            (window as any).isPackUpTable = false;
            return;
        }
        if (this.rangeSelect.isDrag()) {
            return;
        }
        let x = ev.offsetX - this.timerShaftEL!.canvas!.offsetLeft;
        let y = ev.offsetY;
        if (this.timerShaftEL!.sportRuler!.frame.contains(x, y) && x > (TraceRow.rangeSelectObject?.startX || 0) && x < (TraceRow.rangeSelectObject?.endX || 0)) {
        } else {
            this.onClickHandler();
            this.documentOnMouseMove(ev)
        }
    }

    onClickHandler() {
        if (!this.loadTraceCompleted) return;
        this.rowsEL?.querySelectorAll<TraceRow<any>>("trace-row").forEach(it => it.rangeSelect = false)
        this.selectStructNull();
        let threadClickHandler: any;
        let cpuClickHandler: any;
        threadClickHandler = (d: ThreadStruct) => {
            this.observerScrollHeightEnable = false;
            this.scrollToProcess(`${d.cpu}`, "", "cpu-data", true);
            let cpuRow = this.rowsEL?.querySelectorAll<TraceRow<CpuStruct>>(`trace-row[row-id='${d.cpu}'][row-type='cpu-data']`)[0];
            let findEntry = cpuRow!.dataList!.find((dat: any) => dat.startTime === d.startTime);
            if (findEntry!.startTime! + findEntry!.dur! < TraceRow.range!.startNS || findEntry!.startTime! > TraceRow.range!.endNS) {
                this.timerShaftEL?.setRangeNS(findEntry!.startTime! - findEntry!.dur! * 2, findEntry!.startTime! + findEntry!.dur! + findEntry!.dur! * 2);
            }
            this.hoverStructNull();
            this.selectStructNull();
            CpuStruct.hoverCpuStruct = findEntry;
            CpuStruct.selectCpuStruct = findEntry;
            this.timerShaftEL?.drawTriangle(findEntry!.startTime || 0, "inverted");
            cpuRow!.draw();
            this.traceSheetEL?.displayCpuData(CpuStruct.selectCpuStruct!, (wakeUpBean) => {
                CpuStruct.wakeupBean = wakeUpBean;
                this.visibleRows.forEach(it => it.draw());
            }, cpuClickHandler);
        }

        cpuClickHandler = (d: CpuStruct) => {
            this.observerScrollHeightEnable = true;
            let threadRow = this.rowsEL?.querySelectorAll<TraceRow<ThreadStruct>>(`trace-row[row-id='${d.tid}'][row-type='thread']`)[0];
            let task = () => {
                if(threadRow){
                    if (threadRow!.isComplete) {
                        let findEntry = threadRow!.dataList!.find((dat) => dat.startTime === d.startTime);
                        if (findEntry!.startTime! + findEntry!.dur! < TraceRow.range!.startNS || findEntry!.startTime! > TraceRow.range!.endNS) {
                            this.timerShaftEL?.setRangeNS(findEntry!.startTime! - findEntry!.dur! * 2, findEntry!.startTime! + findEntry!.dur! + findEntry!.dur! * 2);
                        }
                        this.hoverStructNull();
                        this.selectStructNull();
                        ThreadStruct.hoverThreadStruct = findEntry;
                        ThreadStruct.selectThreadStruct = findEntry;
                        this.closeAllExpandRows(d.processId + "")
                        this.timerShaftEL?.drawTriangle(findEntry!.startTime || 0, "inverted");
                        threadRow!.draw();
                        this.traceSheetEL?.displayThreadData(ThreadStruct.selectThreadStruct!, threadClickHandler, cpuClickHandler);
                        this.scrollToProcess(`${d.tid}`, `${d.processId}`, "thread", true)
                    } else {
                        threadRow!.onComplete = () => {
                            let findEntry = threadRow!.dataList!.find((dat) => dat.startTime === d.startTime);
                            if (findEntry!.startTime! + findEntry!.dur! < TraceRow.range!.startNS || findEntry!.startTime! > TraceRow.range!.endNS) {
                                this.timerShaftEL?.setRangeNS(findEntry!.startTime! - findEntry!.dur! * 2, findEntry!.startTime! + findEntry!.dur! + findEntry!.dur! * 2);
                            }
                            this.hoverStructNull();
                            this.selectStructNull();
                            ThreadStruct.hoverThreadStruct = findEntry;
                            ThreadStruct.selectThreadStruct = findEntry;
                            this.closeAllExpandRows(d.processId + "")
                            this.timerShaftEL?.drawTriangle(findEntry!.startTime || 0, "inverted");
                            threadRow!.draw();
                            this.traceSheetEL?.displayThreadData(ThreadStruct.selectThreadStruct!, threadClickHandler, cpuClickHandler);
                            this.scrollToProcess(`${d.tid}`, `${d.processId}`, "thread", false);
                        }
                    }
                }
            }
            this.observerScrollHeightCallback = () => task();
            if(threadRow){
                this.scrollToProcess(`${d.tid}`, `${d.processId}`, "thread", true);
            }
            task();
        }

        if (CpuStruct.hoverCpuStruct) {
            CpuStruct.selectCpuStruct = CpuStruct.hoverCpuStruct
            this.timerShaftEL?.drawTriangle(CpuStruct.selectCpuStruct!.startTime || 0, "inverted");
            this.traceSheetEL?.displayCpuData(CpuStruct.selectCpuStruct, (wakeUpBean) => {
                CpuStruct.wakeupBean = wakeUpBean;
                this.visibleRows.forEach(it => it.draw());
            }, cpuClickHandler);
            this.timerShaftEL?.modifyFlagList(undefined);
        } else if (ThreadStruct.hoverThreadStruct) {
            ThreadStruct.selectThreadStruct = ThreadStruct.hoverThreadStruct;
            this.timerShaftEL?.drawTriangle(ThreadStruct.selectThreadStruct!.startTime || 0, "inverted");
            this.traceSheetEL?.displayThreadData(ThreadStruct.selectThreadStruct, threadClickHandler, cpuClickHandler);
            this.timerShaftEL?.modifyFlagList(undefined);
        } else if (FuncStruct.hoverFuncStruct) {
            FuncStruct.selectFuncStruct = FuncStruct.hoverFuncStruct;
            this.timerShaftEL?.drawTriangle(FuncStruct.selectFuncStruct!.startTs || 0, "inverted");
            this.traceSheetEL?.displayFuncData(FuncStruct.hoverFuncStruct, (funcStract: any) => {
                this.observerScrollHeightEnable = true;
                this.moveRangeToCenter(funcStract.startTime!, funcStract.dur!)
                this.scrollToActFunc(funcStract, false)
            })
            this.timerShaftEL?.modifyFlagList(undefined);
        } else if (CpuFreqStruct.hoverCpuFreqStruct) {
            CpuFreqStruct.selectCpuFreqStruct = CpuFreqStruct.hoverCpuFreqStruct
            this.traceSheetEL?.displayFreqData()
            this.timerShaftEL?.modifyFlagList(undefined);
        }else if (SpFreqChart.hoverStateStruct) {
            SpFreqChart.selectStateStruct = SpFreqChart.hoverStateStruct;
            this.traceSheetEL?.displayCpuStateData()
            this.timerShaftEL?.modifyFlagList(undefined);
        } else if (CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct) {
            CpuFreqLimitsStruct.selectCpuFreqLimitsStruct = CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct
            this.traceSheetEL?.displayFreqLimitData()
            this.timerShaftEL?.modifyFlagList(undefined);
        } else {
            this.observerScrollHeightEnable = false;
            this.selectFlag = null;
            this.timerShaftEL?.removeTriangle("inverted");
            if (!SportRuler.isMouseInSportRuler) {
                this.traceSheetEL?.setAttribute("mode", 'hidden');
                this.getVisibleRows().forEach(it => it.draw(true));
            }
        }
    }

    connectedCallback() {
        /**
         * 监听时间轴区间变化
         */
        this.timerShaftEL!.rangeChangeHandler = this.timerShaftELRangeChange;
        this.timerShaftEL!.flagChangeHandler = this.timerShaftELFlagChange;
        this.timerShaftEL!.flagClickHandler = this.timerShaftELFlagClickHandler;
        /**
         * 监听rowsEL的滚动时间，刷新可见区域的trace-row组件的时间区间（将触发trace-row组件重绘）
         */
        this.rowsEL?.addEventListener('scroll', this.rowsElOnScroll)
        /**
         * 监听document的mousemove事件 坐标通过换算后找到当前鼠标所在的trace-row组件，将坐标传入
         */
        this.addEventListener('mousemove', this.documentOnMouseMove)
        this.addEventListener('click', this.documentOnClick)
        this.addEventListener('mousedown', this.documentOnMouseDown)
        this.addEventListener('mouseup', this.documentOnMouseUp)
        this.addEventListener('mouseout', this.documentOnMouseOut)
        document.addEventListener('keypress', this.documentOnKeyPress)
        document.addEventListener('keyup', this.documentOnKeyUp)
        SpApplication.skinChange2 = (val: boolean) => {
            this.timerShaftEL?.render()
            this.rowsEL!.querySelectorAll<TraceRow<any>>(`trace-row:not([sleeping])`).forEach(it => {
                this.hoverStructNull();
                it.draw();
            })
        }
    }

    scrollToProcess(rowId: string, rowParentId: string, rowType: string, smooth: boolean = true) {
        let row = this.shadowRoot!.querySelector<TraceRow<any>>(`trace-row[row-id='${rowParentId}'][folder]`);
        if (row) {
            row.expansion = true
        }
        let rootRow = this.shadowRoot!.querySelector<TraceRow<any>>(`trace-row[row-id='${rowId}'][row-type='${rowType}']`);
        this.rowsEL!.scroll({
            top: (rootRow?.offsetTop || 0) - this.rowsEL!.offsetTop - this.rowsEL!.offsetHeight + (rootRow?.offsetHeight || 0),
            left: 0,
            behavior: smooth ? "smooth" : undefined
        })
    }

    scrollToDepth(rowId: string, rowParentId: string, rowType: string, smooth: boolean = true, depth: number) {
        let row = this.shadowRoot!.querySelector<TraceRow<any>>(`trace-row[row-id='${rowParentId}'][folder]`);
        if (row) {
            row.expansion = true
        }
        let rootRow = this.shadowRoot!.querySelector<TraceRow<any>>(`trace-row[row-id='${rowId}'][row-type='${rowType}']`);
        this.rowsEL!.scroll({
            top: (rootRow?.offsetTop || 0) - this.rowsEL!.offsetTop - this.rowsEL!.offsetHeight + ((++depth) * 20 || 0),
            left: 0,
            behavior: smooth ? "smooth" : undefined
        })
    }

    scrollToFunction(rowId: string, rowParentId: string, rowType: string, smooth: boolean = true, afterScroll: any) {
        let row = this.shadowRoot!.querySelector<TraceRow<any>>(`trace-row[row-id='${rowParentId}'][folder]`);
        if (row) {
            row.expansion = true
        }
        let funcRow = this.shadowRoot!.querySelector<TraceRow<any>>(`trace-row[row-id='${rowId}'][row-type='${rowType}']`);
        if (funcRow == null) {
            let threadRow = this.shadowRoot!.querySelector<TraceRow<any>>(`trace-row[row-id='${rowId}'][row-type='thread']`);
            this.rowsEL!.scroll({
                top: threadRow!.offsetTop - this.rowsEL!.offsetTop - this.rowsEL!.offsetHeight + threadRow!.offsetHeight + threadRow!.offsetHeight,
                left: 0,
                behavior: smooth ? "smooth" : undefined
            })
            if (threadRow != null) {
                if (threadRow.isComplete) {
                    afterScroll()
                } else {
                    threadRow.onComplete = () => {
                        funcRow = this.shadowRoot!.querySelector<TraceRow<any>>(`trace-row[row-id='${rowId}'][row-type='${rowType}']`);
                        afterScroll()
                    }
                }
            }
        } else {
            afterScroll()
        }
    }

    rowScrollTo(offset: number, callback: Function) {
        const fixedOffset = offset;
        const onScroll = () => {
            if (this.rowsEL!.scrollTop === fixedOffset) {
                this.rowsEL!.removeEventListener('scroll', onScroll)
                callback()
            }
        }

        this.rowsEL!.addEventListener('scroll', onScroll)
        onScroll()
        this.rowsEL!.scrollTo({
            top: offset,
            behavior: 'smooth'
        })
    }

    disconnectedCallback() {
        this.timerShaftEL?.removeEventListener('range-change', this.timerShaftELRangeChange);
        this.rowsEL?.removeEventListener('scroll', this.rowsElOnScroll);
        this.removeEventListener('mousemove', this.documentOnMouseMove);
        this.removeEventListener('click', this.documentOnClick);
        this.removeEventListener('mousedown', this.documentOnMouseDown)
        this.removeEventListener('mouseup', this.documentOnMouseUp)
        this.removeEventListener('mouseout', this.documentOnMouseOut)
        document.removeEventListener('keypress', this.documentOnKeyPress)
        document.removeEventListener('keyup', this.documentOnKeyUp)
    }

    loadDatabaseUrl(url: string, progress: Function, complete?: ((res: { status: boolean, msg: string }) => void) | undefined) {
        this.observerScrollHeightEnable = false;
        this.init({url: url}, "", progress).then((res) => {
            if (complete) {
                complete(res);
            }
        })
    }

    loadDatabaseArrayBuffer(buf: ArrayBuffer, thirdPartyWasmConfigUrl: string, progress: ((name: string, percent: number) => void), complete?: ((res: { status: boolean, msg: string }) => void) | undefined) {
        this.observerScrollHeightEnable = false;
        this.init({buf}, thirdPartyWasmConfigUrl, progress).then((res) => {
            let scrollTop = this.rowsEL?.scrollTop || 0
            let scrollHeight = this.rowsEL?.clientHeight || 0
            this.rowsEL?.querySelectorAll("trace-row").forEach((it: any) => {
                this.observer.observe(it);
            })
            if (complete) {
                complete(res);
            }
        })
    }

    search(query: string) {
        this.shadowRoot?.querySelectorAll<TraceRow<any>>('trace-row').forEach(item => {
            if (query == null || query == undefined || query == '') {
                if (item.rowType == TraceRow.ROW_TYPE_CPU ||
                    item.rowType == TraceRow.ROW_TYPE_CPU_FREQ ||
                    item.rowType == TraceRow.ROW_TYPE_NATIVE_MEMORY ||
                    item.rowType == TraceRow.ROW_TYPE_FPS ||
                    item.rowType == TraceRow.ROW_TYPE_PROCESS ||
                    item.rowType == TraceRow.ROW_TYPE_CPU_ABILITY ||
                    item.rowType == TraceRow.ROW_TYPE_MEMORY_ABILITY ||
                    item.rowType == TraceRow.ROW_TYPE_DISK_ABILITY ||
                    item.rowType == TraceRow.ROW_TYPE_NETWORK_ABILITY) {
                    item.expansion = false;
                    item.rowHidden = false;
                } else {
                    item.rowHidden = true;
                }
            } else {
                if (item.name.toLowerCase().indexOf(query.toLowerCase()) >= 0) {
                    item.rowHidden = false;
                } else {
                    item.rowHidden = true;
                }
            }
        })
        this.getVisibleRows().forEach(it => it.rowHidden = false && it.draw(true))
    }

    searchCPU(query: string): Array<CpuStruct> {
        let searchResults: Array<CpuStruct> = []
        this.rowsEL!.querySelectorAll<TraceRow<any>>(`trace-row[row-type='cpu-data']`).forEach(item => {
            let res = item!.dataList!.filter(it => (it.name && it.name.search(query) >= 0) || it.tid == query
                || it.processId == query
                || (it.processName && it.processName.search(query) >= 0)
            )
            searchResults.push(...res);
        })
        searchResults.sort((a, b) => (a.startTime || 0) - (b.startTime || 0));
        return searchResults;
    }

    async searchFunction(cpuList: Array<any>, query: string): Promise<Array<any>> {
        let list = await querySearchFunc(query)
        cpuList = cpuList.concat(list)
        cpuList.sort((a, b) => (a.startTime || 0) - (b.startTime || 0));
        return cpuList
    }

    searchThreadsAndProcesses(query: string): Array<any> {
        let searchResults: Array<any> = []
        this.rowsEL!.querySelectorAll<TraceRow<any>>(`trace-row[row-type='thread'][row-type='process']`).forEach(item => {
            if (item!.name.search(query) >= 0) {
                let searchBean = new SearchThreadProcessBean()
                searchBean.name = item.name
                searchBean.rowId = item.rowId
                searchBean.type = "thread||process"
                searchBean.rowType = item.rowType
                searchBean.rowParentId = item.rowParentId
                searchResults.push(searchBean)
            }
        })
        return searchResults
    }

    showStruct(previous: boolean, currentIndex: number, structs: Array<any>) {
        if (structs.length == 0) {
            return 0;
        }
        let findIndex = -1;
        if (previous) {
            for (let i = structs.length - 1; i >= 0; i--) {
                let it = structs[i];
                if (i < currentIndex && (it.startTime!) >= (TraceRow.range!.startNS) && (it.startTime!) + (it.dur!) <= (TraceRow.range!.endNS)) {
                    findIndex = i;
                    break;
                }
            }
        } else {
            findIndex = structs.findIndex((it, idx) => {
                return idx > currentIndex && (it.startTime!) >= (TraceRow.range!.startNS) && (it.startTime!) + (it.dur!) <= (TraceRow.range!.endNS)
            })
        }
        let findEntry: any
        if (findIndex >= 0) {
            findEntry = structs[findIndex];
        } else {
            if (previous) {
                for (let i = structs.length - 1; i >= 0; i--) {
                    let it = structs[i];
                    if ((it.startTime! + it.dur!) < (TraceRow.range!.startNS)) {
                        findIndex = i;
                        break;
                    }
                }
                if (findIndex == -1) {
                    findIndex = structs.length - 1;
                }
            } else {
                findIndex = structs.findIndex((it) => (it.startTime!) > (TraceRow.range!.endNS))
                if (findIndex == -1) {
                    findIndex = 0;
                }
            }
            findEntry = structs[findIndex];
            this.moveRangeToCenter(findEntry.startTime!, findEntry.dur!)
        }
        this.rowsEL!.querySelectorAll<TraceRow<any>>(`trace-row`).forEach(item => {
            item.highlight = false;
            if (!item.sleeping) {
                item.draw(true)
            }
        })
        if (findEntry.type == 'thread') {
            CpuStruct.selectCpuStruct = findEntry;
            CpuStruct.hoverCpuStruct = CpuStruct.selectCpuStruct;
            this.rowsEL!.querySelectorAll<TraceRow<any>>(`trace-row[row-type='cpu-data']`).forEach(item => {
                item.highlight = item.rowId == `${findEntry.cpu}`;
                item.draw(true)
            })
            this.scrollToProcess(`${findEntry.cpu}`, "", "cpu-data", true)
            this.onClickHandler();
        } else if (findEntry.type == "func") {
            this.observerScrollHeightEnable = true;
            this.scrollToActFunc(findEntry, true)
        } else if (findEntry.type == "thread||process") {
            let threadProcessRow = this.rowsEL?.querySelectorAll<TraceRow<ThreadStruct>>(`trace-row[row-id='${findEntry.rowId}'][row-type='${findEntry.rowType}']`)[0];
            threadProcessRow!.highlight = true
            this.scrollToProcess(`${findEntry.rowId}`, `${findEntry.rowParentId}`, findEntry.rowType, true);
            let completeEntry = () => {
                let searchEntry = threadProcessRow!.dataList!.find((dat) => dat.startTime === findEntry.startTime);
                this.hoverStructNull();
                this.selectStructNull();
                ThreadStruct.hoverThreadStruct = searchEntry;
                ThreadStruct.selectThreadStruct = searchEntry;
                this.closeAllExpandRows(findEntry.rowParentId)
                threadProcessRow!.draw();
            }
            let scrollTimer: any;
            this.observerScrollHeightCallback = () => {
                if (threadProcessRow!.isComplete) {
                    completeEntry()
                    this.scrollToProcess(`${findEntry.rowId}`, `${findEntry.rowParentId}`, findEntry.rowType, true)
                } else {
                    threadProcessRow!.onComplete = () => {
                        completeEntry()
                        clearTimeout(scrollTimer);
                        scrollTimer = setTimeout(() => this.scrollToProcess(`${findEntry.rowId}`, `${findEntry.rowParentId}`, findEntry.rowType, false), 100)
                    }
                }
            }
        }
        this.timerShaftEL?.drawTriangle(findEntry.startTime || 0, "inverted");
        return findIndex;
    }

    scrollToActFunc(funcStract: any, highlight: boolean) {
        this.scrollToFunction(`${funcStract.tid}`, `${funcStract.pid}`, funcStract.type, false, () => {
            let funcRow = this.rowsEL?.querySelector<TraceRow<FuncStruct>>(`trace-row[row-id='${funcStract.tid}'][row-type='func']`);
            if (funcRow == null) return
            this.scrollToDepth(`${funcStract.tid}`, `${funcStract.pid}`, "func", true, funcStract.depth || 0)
            funcRow!.highlight = highlight
            let completeEntry = () => {
                if (funcRow == null) return
                let searchEntry = funcRow!.dataList!.find((dat) => dat.startTs === funcStract.startTime);
                this.hoverStructNull();
                this.selectStructNull();
                FuncStruct.hoverFuncStruct = searchEntry;
                FuncStruct.selectFuncStruct = searchEntry;
                this.closeAllExpandRows(funcStract.pid)
                this.visibleRows.forEach(it => it.draw());
            }
            let scrollTimer: any;
            this.observerScrollHeightCallback = () => {
                funcRow = this.rowsEL?.querySelector<TraceRow<FuncStruct>>(`trace-row[row-id='${funcStract.tid}'][row-type='func']`);
                if (funcRow == null) {
                    return
                }
                if (funcRow!.isComplete) {
                    completeEntry()
                    this.onClickHandler();
                    this.scrollToDepth(`${funcStract.tid}`, `${funcStract.pid}`, "func", false, funcStract.depth || 0)
                } else {
                    funcRow!.onComplete = () => {
                        completeEntry()
                        this.onClickHandler();
                        clearTimeout(scrollTimer);
                        scrollTimer = setTimeout(() => this.scrollToDepth(`${funcStract.tid}`, `${funcStract.pid}`, "func", false, funcStract.depth || 0), 100)
                    }
                }
            }
            if (funcRow?.isComplete) {
                completeEntry()
                this.onClickHandler();
                this.scrollToProcess(`${funcStract.tid}`, `${funcStract.pid}`, "thread", false)
                this.scrollToDepth(`${funcStract.tid}`, `${funcStract.pid}`, "func", true, funcStract.depth || 0)
            }
        });
    }

    closeAllExpandRows(pid: string) {
        let expandRows = this.rowsEL?.querySelectorAll<TraceRow<ProcessStruct>>(`trace-row[row-type='process'][expansion]`);
        expandRows?.forEach((row) => {
            if (row.rowId != pid) {
                row.expansion = false
            }
        })
    }

    moveRangeToCenter(startTime: number, dur: number) {
        let startNS = this.timerShaftEL?.getRange()?.startNS || 0;
        let endNS = this.timerShaftEL?.getRange()?.endNS || 0;
        let harfDur = Math.trunc((endNS - startNS) / 2 - dur / 2);
        this.timerShaftEL?.setRangeNS(startTime - harfDur, startTime + dur + harfDur);
    }

    showPreCpuStruct(currentIndex: number, cpuStructs: Array<CpuStruct>): number {
        if (cpuStructs.length == 0) {
            return 0;
        }
        let findIndex = -1;
        for (let i = cpuStructs.length - 1; i >= 0; i--) {
            let it = cpuStructs[i];
            if (i < currentIndex && (it.startTime!) >= (TraceRow.range!.startNS) && (it.startTime!) + (it.dur!) <= (TraceRow.range!.endNS)) {
                findIndex = i;
                break;
            }
        }
        if (findIndex >= 0) {
            let findEntry = cpuStructs[findIndex];
            CpuStruct.selectCpuStruct = findEntry;
            this.rowsEL!.querySelectorAll<TraceRow<any>>(`trace-row[row-type='cpu-data']`).forEach(item => {
                item.highlight = item.rowId == `${findEntry.cpu}`;
                item.draw(true);
            })
            this.timerShaftEL?.drawTriangle(findEntry.startTime || 0, "inverted");
        } else {
            for (let i = cpuStructs.length - 1; i >= 0; i--) {
                let it = cpuStructs[i];
                if ((it.startTime! + it.dur!) < (TraceRow.range!.startNS)) {
                    findIndex = i;
                    break;
                }
            }
            let findEntry: CpuStruct;
            if (findIndex == -1) {
                findIndex = cpuStructs.length - 1;
            }
            findEntry = cpuStructs[findIndex];
            CpuStruct.selectCpuStruct = findEntry;
            let startNS = this.timerShaftEL?.getRange()?.startNS || 0;
            let endNS = this.timerShaftEL?.getRange()?.endNS || 0;
            let harfDur = Math.trunc((endNS - startNS) / 2 - findEntry.dur! / 2);
            this.timerShaftEL?.setRangeNS(findEntry.startTime! - harfDur, findEntry.startTime! + findEntry.dur! + harfDur);
            this.rowsEL!.querySelectorAll<TraceRow<any>>(`trace-row[row-type='cpu-data']`).forEach(item => {
                item.highlight = item.rowId == `${findEntry.cpu}`;
                item.draw(true)
            })
            this.timerShaftEL?.drawTriangle(findEntry.startTime || 0, "inverted");
        }
        CpuStruct.hoverCpuStruct = CpuStruct.selectCpuStruct;
        this.onClickHandler();
        return findIndex;
    }

    showNextCpuStruct(currentIndex: number, cpuStructs: Array<CpuStruct>): number {
        if (cpuStructs.length == 0) {
            return 0;
        }
        let findIndex = cpuStructs.findIndex((it, idx) => {
            return idx > currentIndex && (it.startTime!) >= (TraceRow.range!.startNS) && (it.startTime!) + (it.dur!) <= (TraceRow.range!.endNS)
        })
        if (findIndex >= 0) {
            let findEntry = cpuStructs[findIndex];
            CpuStruct.selectCpuStruct = findEntry;
            this.rowsEL!.querySelectorAll<TraceRow<any>>(`trace-row[row-type='cpu-data']`).forEach(item => {
                item.highlight = item.rowId == `${findEntry.cpu}`;
                item.draw(true);
            })
            this.timerShaftEL?.drawTriangle(findEntry.startTime || 0, "inverted");
        } else {
            findIndex = cpuStructs.findIndex((it) => (it.startTime!) > (TraceRow.range!.endNS))
            let findEntry: CpuStruct;
            if (findIndex == -1) {
                findIndex = 0;
            }
            findEntry = cpuStructs[findIndex];
            CpuStruct.selectCpuStruct = findEntry;
            let startNS = this.timerShaftEL?.getRange()?.startNS || 0;
            let endNS = this.timerShaftEL?.getRange()?.endNS || 0;
            let harfDur = Math.trunc((endNS - startNS) / 2 - findEntry.dur! / 2);
            this.timerShaftEL?.setRangeNS(findEntry.startTime! - harfDur, findEntry.startTime! + findEntry.dur! + harfDur);
            this.rowsEL!.querySelectorAll<TraceRow<any>>(`trace-row[row-type='cpu-data']`).forEach(item => {
                item.highlight = item.rowId == `${findEntry.cpu}`;
                item.draw(true);
            })
            this.timerShaftEL?.drawTriangle(findEntry.startTime || 0, "inverted");
        }
        CpuStruct.hoverCpuStruct = CpuStruct.selectCpuStruct;
        this.onClickHandler();
        return findIndex;
    }

    reset(progress: Function | undefined | null) {
        this.loadTraceCompleted = false;
        if (this.rowsEL) this.rowsEL.innerHTML = ''
        this.spacerEL!.style.height = '0px';
        this.rangeSelect.rangeTraceRow = [];
        CpuStruct.wakeupBean = undefined;
        this.selectStructNull();
        this.hoverStructNull();
        this.traceSheetEL?.setAttribute("mode", "hidden")
        progress && progress("rest timershaft", 8);
        this.timerShaftEL?.reset();
        progress && progress("clear cache", 10);
        procedurePool.clearCache();
    }

    init = async (param: { buf?: ArrayBuffer, url?: string }, wasmConfigUri: string, progress: Function) => {
        progress("Load database", 6);
        this.reset(progress);
        if (param.buf) {
            let configJson = "";
            try {
                configJson = await fetch(wasmConfigUri).then(res => res.text());
            } catch (e) {
                error("getWasmConfigFailed", e)
            }
            let {status, msg, sdkConfigMap} = await threadPool.initSqlite(param.buf, configJson, progress);
            if (!status) {
                return {status: false, msg: msg}
            }
            SpSystemTrace.SDK_CONFIG_MAP = sdkConfigMap == undefined ? undefined : sdkConfigMap;
        }
        if (param.url) {
            let {status, msg} = await threadPool.initServer(param.url, progress);
            if (!status) {
                return {status: false, msg: msg}
            }
        }
        await this.chartManager?.init(progress);
        this.rowsEL?.querySelectorAll<TraceRow<any>>("trace-row").forEach((it: any) => {
            it.addEventListener('expansion-change', () => {
                this.getVisibleRows().forEach(it2 => it2.draw());
            })
        })
        progress("completed", 100);
        info("All TraceRow Data initialized")
        this.loadTraceCompleted = true;
        this.getVisibleRows().forEach(it => {
            it.draw();
        });
        return {status: true, msg: "success"}
    }

    initHtml(): string {
        return `
        <style>
        :host{
            display: block;
            width: 100%;
            height: 100%;
        }
        .timer-shaft{
            width: 100%;
            z-index: 2;
        }
        .rows{
            color: #fff;
            display: block;
            box-sizing: border-box;
            /*flex-direction: column;*/
            /*overflow-y: auto;*/
            overflow: overlay;
            overflow-anchor: none;
            max-height: calc(100vh - 147px - 48px);
            flex: 1;
            width: 100%;
            background: var(--dark-background4,#ffffff);
            /*scroll-behavior: smooth;*/
        }
        .container{
            width: 100%;
            box-sizing: border-box;
            height: 100%;
            display: grid;
            grid-template-columns: 1fr;
            grid-template-rows: min-content min-content 1fr min-content;
        }
        .trace-sheet{
            cursor: default;
        }

        </style>
        <div class="container">
            <timer-shaft-element class="timer-shaft">
            </timer-shaft-element>
            <div class="spacer"></div>
            <div class="rows"></div>
            <trace-sheet class="trace-sheet" mode="hidden">
            </trace-sheet>
        </div>
        `;
    }
}
