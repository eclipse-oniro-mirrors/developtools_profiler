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
import {getTabLiveProcessData} from "../../../../database/SqlLite.js";
import {LiveProcess} from "../../../../bean/AbilityMonitor.js";
import "../../../SpFilter.js";
import {Utils} from "../../base/Utils.js";
import {log} from "../../../../../log/Log.js";

@element('tabpane-live-processes')
export class TabPaneLiveProcesses extends BaseElement {
    private tbl: LitTable | null | undefined;
    private source: Array<LiveProcess> = [];
    private queryResult: Array<LiveProcess> = []
    private float: HTMLDivElement | null | undefined;
    private search: HTMLInputElement | undefined | null

    set data(val: SelectionParam | any) {
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
        this.queryDataByDB(val)
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-live-processes');
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
                let array = this.toLiveProcessArray(item)
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

    toLiveProcessArray(liveProcess: LiveProcess): any[] {
        let array: Array<string> = []
        array.push(liveProcess.processId.toString())
        array.push(liveProcess.processName)
        array.push(liveProcess.responsibleProcess)
        array.push(liveProcess.userName)
        array.push(liveProcess.threads.toString())
        array.push(liveProcess.cpu)
        array.push(liveProcess.memory)
        array.push(liveProcess.diskReads.toString())
        array.push(liveProcess.diskWrite.toString())
        return array
    }

    queryDataByDB(val: SelectionParam | any) {
        getTabLiveProcessData(val.leftNs, val.rightNs).then(item => {
            if (item.length != null && item.length > 0) {
                log("getTabLiveProcessData result size : " + item.length)
                for (const liveProcess of item) {
                    liveProcess.processName = liveProcess.processName + '(' + liveProcess.processId + ')'
                    liveProcess.memoryNumber = Number(liveProcess.memory);
                    liveProcess.memory = Utils.getBinaryByteWithUnit(liveProcess.memoryNumber)
                    if (Number(liveProcess.cpu) > 0) {
                        liveProcess.cpu = Number(Number(liveProcess.cpu).toFixed(3)) + "%"
                    } else {
                        liveProcess.cpu = "0%";
                    }
                    liveProcess.cpuTimeNumber = Number(liveProcess.cpuTime);
                    liveProcess.cpuTime = this.timeFormat(Number(liveProcess.cpuTime))
                }
                this.source = item
                this.queryResult = item;
                this.tbl!.recycleDataSource = this.source;
            } else {
                this.source = []
                this.queryResult = []
                this.tbl!.recycleDataSource = [];
            }
        })
    }


    timeFormat(ms: number): string {
        let currentMs = ms
        let hours = 3600000
        let minute1 = 60000
        let second1 = 1000;
        let res = "";
        if (currentMs >= hours) {
            res += Math.floor(currentMs / hours) + " h ";
            currentMs = currentMs - Math.floor(currentMs / hours) * hours
        }
        if (currentMs >= minute1) {
            res += Math.floor(currentMs / minute1) + " min ";
            currentMs = currentMs - Math.floor(currentMs / minute1) * minute1
        }
        if (currentMs >= second1) {
            res += Math.floor(currentMs / second1) + " s ";
            currentMs = currentMs - Math.floor(currentMs / second1) * second1;
        }
        if (currentMs > 0) {
            res += currentMs + " ms ";
        } else {
            res += "0 ms ";
        }
        return res
    }

    initHtml(): string {
        return `
<style>
:host{
    display: flex;
    flex-direction: column;
    padding: 10px 10px;
}
</style>
<lit-table id="tb-live-processes" style="height: auto">
    <lit-table-column order width="1fr" title="Process ID" data-index="processId" key="processId" align="flex-start"></lit-table-column>
    <lit-table-column order width="1fr" title="Process Name" data-index="processName" key="processName" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="Responsible Process" data-index="responsibleProcess" key="responsibleProcess" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="User ID" data-index="userName" key="userName" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="%CPU" data-index="cpu" key="cpu" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="CPU Time" data-index="cpuTime" key="cpuTime" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="#Threads" data-index="threads" key="threads" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="Memory" data-index="memory" key="memory" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="Disk Writes(B)" data-index="diskWrite" key="diskWrite" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="Disk Reads(B)" data-index="diskReads" key="diskReads" align="flex-start" ></lit-table-column>
</lit-table>
        `;
    }

    sortByColumn(detail: any) {
        // @ts-ignore
        function compare(property, sort, type) {
            return function (a: LiveProcess, b: LiveProcess) {
                if (type === 'number') {
                    // @ts-ignore
                    return sort === 2 ? parseFloat(b[property]) - parseFloat(a[property]) : parseFloat(a[property]) - parseFloat(b[property]);
                } else if (type === 'cpuTime') {
                    return sort === 2 ? b.cpuTimeNumber - a.cpuTimeNumber : a.cpuTimeNumber - b.cpuTimeNumber;
                } else if (type === 'memory') {
                    return sort === 2 ? b.memoryNumber - a.memoryNumber : a.memoryNumber - b.memoryNumber;
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

        if (detail.key == 'startTime' || detail.key == 'processName') {
            this.source.sort(compare(detail.key, detail.sort, 'string'))
        } else if (detail.key == 'cpuTime') {
            this.source.sort(compare(detail.key, detail.sort, 'cpuTime'))
        } else if (detail.key == 'memory') {
            this.source.sort(compare(detail.key, detail.sort, 'memory'))
        } else {
            this.source.sort(compare(detail.key, detail.sort, 'number'))
        }
        this.tbl!.recycleDataSource = this.source;
    }
}