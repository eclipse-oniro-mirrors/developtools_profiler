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

import {BaseElement, element} from "../../../../../base-ui/BaseElement.js";
import {LitTable} from "../../../../../base-ui/table/lit-table.js";
import {SelectionParam} from "../../../../bean/BoxSelection.js";
import {getTabMemoryAbilityData, queryStartTime} from "../../../../database/SqlLite.js";
import {SystemMemorySummary} from "../../../../bean/AbilityMonitor.js";
import {Utils} from "../../base/Utils.js";
import "../../../SpFilter.js";
import {log} from "../../../../../log/Log.js";

@element('tabpane-memory-ability')
export class TabPaneMemoryAbility extends BaseElement {
    private tbl: LitTable | null | undefined;
    private source: Array<SystemMemorySummary> = [];
    private float: HTMLDivElement | null | undefined;
    private queryResult: Array<SystemMemorySummary> = []
    private search: HTMLInputElement | undefined | null

    set data(val: SelectionParam | any) {
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
        this.queryDataByDB(val)
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-memory-ability');
        this.tbl!.addEventListener('column-click', (evt) => {
            // @ts-ignore
            this.sortByColumn(evt.detail)
        });
    }

    connectedCallback() {
        super.connectedCallback();
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
                this.tbl?.reMeauseHeight()
            }
        }).observe(this.parentElement!);
    }

    filterData() {
        if (this.queryResult.length > 0) {
            let filter = this.queryResult.filter((item) => {
                let array = this.toMemoryAbilityArray(item)
                let isInclude = array.filter(value => value.indexOf(this.search!.value) > -1);
                return isInclude.length > 0
            });
            if (filter.length > 0) {
                this.source = filter;
                this.tbl!.recycleDataSource = this.source;
            } else {
                this.source = []
                this.tbl!.recycleDataSource = [];
            }
        }
    }

    toMemoryAbilityArray(systemMemorySummary: SystemMemorySummary): any[] {
        let array: Array<string> = []
        array.push(systemMemorySummary.startTimeStr)
        array.push(systemMemorySummary.durationStr)
        array.push(systemMemorySummary.memoryTotal)
        array.push(systemMemorySummary.cached)
        array.push(systemMemorySummary.swapTotal)
        return array
    }

    queryDataByDB(val: SelectionParam | any) {
        queryStartTime().then(res => {
            let startTime = res[0].start_ts;
            getTabMemoryAbilityData(val.leftNs + startTime, val.rightNs + startTime).then(items => {
                log("getTabMemoryAbilityData result size : " + items.length)
                this.source = []
                this.queryResult = [];
                if (items.length != null && items.length > 0) {
                    let lastTime = 0;
                    for (const item of items) {
                        let systemMemorySummary = new SystemMemorySummary()
                        if (item.startTime - startTime <= 0) {
                            systemMemorySummary.startTimeStr = '0:000.000.000';
                        } else {
                            systemMemorySummary.startTimeStr = Utils.getTimeStampHMS(item.startTime - startTime);
                        }
                        if (lastTime !== 0) {
                            systemMemorySummary.durationNumber = item.startTime - lastTime;
                            systemMemorySummary.durationStr = Utils.getDurString(systemMemorySummary.durationNumber);
                        } else {
                            systemMemorySummary.durationNumber = 0;
                            systemMemorySummary.durationStr = '-';
                        }
                        lastTime = item.startTime;
                        let memorys = item.value.split(",");
                        let names = item.name.split(",");
                        if (memorys.length != names.length) {
                            continue;
                        }
                        for (let i = 0; i < names.length; i++) {
                            switch (names[i]) {
                                case "sys.mem.total":
                                    systemMemorySummary.memoryTotal = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.free":
                                    systemMemorySummary.memFree = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.buffers":
                                    systemMemorySummary.buffers = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.cached":
                                    systemMemorySummary.cached = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.shmem":
                                    systemMemorySummary.shmem = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.slab":
                                    systemMemorySummary.slab = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.swap.total":
                                    systemMemorySummary.swapTotal = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.swap.free":
                                    systemMemorySummary.swapFree = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.mapped":
                                    systemMemorySummary.mapped = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.vmalloc.used":
                                    systemMemorySummary.vmallocUsed = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.page.tables":
                                    systemMemorySummary.pageTables = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.kernel.stack":
                                    systemMemorySummary.kernelStack = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.active":
                                    systemMemorySummary.active = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.inactive":
                                    systemMemorySummary.inactive = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.unevictable":
                                    systemMemorySummary.unevictable = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.vmalloc.total":
                                    systemMemorySummary.vmallocTotal = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.slab.unreclaimable":
                                    systemMemorySummary.sUnreclaim = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.cma.total":
                                    systemMemorySummary.cmaTotal = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.cma.free":
                                    systemMemorySummary.cmaFree = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.kernel.reclaimable":
                                    systemMemorySummary.kReclaimable = Utils.getBinaryByteWithUnit(Number(memorys[i]))
                                    break;
                                case "sys.mem.zram":
                                    systemMemorySummary.zram = Utils.getBinaryByteWithUnit(Number(memorys[i]) * 1000)
                                    break;
                            }
                        }
                        this.source.push(systemMemorySummary);
                    }
                    this.tbl!.recycleDataSource = this.source;
                } else {
                    this.source = []
                    this.tbl!.recycleDataSource = [];
                }
            })
        });
        if (this.tbl) {
            let th = this.tbl.shadowRoot?.querySelector<HTMLDivElement>(".th")
            th!.style.gridColumnGap = "5px";
        }
    }

    initHtml(): string {
        return `
<style>
:host{
    display: flex;
    flex-direction: column;
    padding: 10px 10px;
}
#tb-memory-ability{
  overflow-x:auto;     
}
</style>
   <lit-table id="tb-memory-ability" style="height: auto">
    <lit-table-column order width="150px" title="StartTime" data-index="startTimeStr" key="startTimeStr" align="flex-start"></lit-table-column>
    <lit-table-column order width="100px" title="Duration" data-index="durationStr" key="durationStr" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="MemTotal" data-index="memoryTotal" key="memoryTotal" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="MemFree" data-index="memFree" key="memFree" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="Buffers" data-index="buffers" key="buffers" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="Cached" data-index="cached" key="cached" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="Shmem" data-index="shmem" key="shmem" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="Slab" data-index="slab" key="slab" align="flex-start" ></lit-table-column>
    <lit-table-column order width="120px" title="SUnreclaim" data-index="sUnreclaim" key="sUnreclaim" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="SwapTotal" data-index="swapTotal" key="swapTotal" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="SwapFree" data-index="swapFree" key="swapFree" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="Mapped" data-index="mapped" key="mapped" align="flex-start" ></lit-table-column>
    <lit-table-column order width="120px" title="VmallocUsed" data-index="vmallocUsed" key="vmallocUsed" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="PageTables" data-index="pageTables" key="pageTables" align="flex-start" ></lit-table-column>
    <lit-table-column order width="120px" title="KernelStack" data-index="kernelStack" key="kernelStack" align="flex-start" ></lit-table-column>
    <lit-table-column order width="120px" title="KReclaimable" data-index="kReclaimable" key="kReclaimable" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="Active" data-index="active" key="active" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="Inactive" data-index="inactive" key="inactive" align="flex-start" ></lit-table-column>
    <lit-table-column order width="120px" title="Unevictable" data-index="unevictable" key="unevictable" align="flex-start" ></lit-table-column>
    <lit-table-column order width="120px" title="VmallocTotal" data-index="vmallocTotal" key="vmallocTotal" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="CmaTotal" data-index="cmaTotal" key="cmaTotal" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="CmaFree" data-index="cmaFree" key="cmaFree" align="flex-start" ></lit-table-column>
    <lit-table-column order width="100px" title="Zram" data-index="zram" key="zram" align="flex-start" ></lit-table-column>
</lit-table>
        `;
    }

    sortByColumn(detail: any) {
        // @ts-ignore
        function compare(property, sort, type) {
            return function (a: SystemMemorySummary, b: SystemMemorySummary) {
                if (type === 'number') {
                    // @ts-ignore
                    return sort === 2 ? parseFloat(b[property]) - parseFloat(a[property]) : parseFloat(a[property]) - parseFloat(b[property]);
                } else if (type === 'durationStr') {
                    return sort === 2 ? b.durationNumber - a.durationNumber : a.durationNumber - b.durationNumber;
                } else {
                    // @ts-ignore
                    if (b[property] > a[property]) {
                        return sort === 2 ? 1 : -1;
                    } else { // @ts-ignore
                        if (b[property] == a[property]) {
                            return 0;
                        } else {
                            return sort === 2 ? -1 : 1;
                        }
                    }
                }
            }
        }

        if (detail.key === 'startTime') {
            this.source.sort(compare(detail.key, detail.sort, 'string'))
        } else if (detail.key === 'durationStr') {
            this.source.sort(compare(detail.key, detail.sort, 'durationStr'))
        } else {
            this.source.sort(compare(detail.key, detail.sort, 'number'))
        }
        this.tbl!.recycleDataSource = this.source;
    }
}


