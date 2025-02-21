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
import {getTabProcessHistoryData} from "../../../../database/SqlLite.js";
import {Utils} from "../../base/Utils.js";
import {ProcessHistory} from "../../../../bean/AbilityMonitor.js";
import "../../../SpFilter.js";
import {log} from "../../../../../log/Log.js";

@element('tabpane-history-processes')
export class TabPaneHistoryProcesses extends BaseElement {
    private tbl: LitTable | null | undefined;
    private source: Array<ProcessHistory> = [];
    private queryResult: Array<ProcessHistory> = []
    private float: HTMLDivElement | null | undefined;
    private search: HTMLInputElement | undefined | null

    set data(val: SelectionParam | any) {
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
        this.queryDataByDB(val)
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-history-processes');
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
                let array = this.toProcessHistoryArray(item)
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

    toProcessHistoryArray(process: ProcessHistory): any[] {
        let array: Array<string> = []
        array.push(process.processId.toString())
        array.push(process.processName)
        array.push(process.alive)
        array.push(process.firstSeen)
        array.push(process.lastSeen)
        array.push(process.responsibleProcess)
        array.push(process.userName)
        array.push(process.cpuTime)
        return array
    }

    queryDataByDB(val: SelectionParam | any) {
        getTabProcessHistoryData(val.leftNs, val.rightNs, val.processId, val.threadId).then(item => {
            if (item.length != null && item.length > 0) {
                log("getTabProcessHistoryData result size : " + item.length)
                for (const processHistory of item) {
                    processHistory.alive = processHistory.alive == '0' ? 'No' : 'Yes'
                    if (Number(processHistory.firstSeen) <= 0) {
                        processHistory.firstSeen = '0:000.000.000';
                        processHistory.firstSeenNumber = 0;
                    } else {
                        processHistory.firstSeenNumber = Number(processHistory.firstSeen);
                        processHistory.firstSeen = Utils.getTimeStampHMS(processHistory.firstSeenNumber)
                    }
                    processHistory.lastSeenNumber = Number(processHistory.lastSeen);
                    processHistory.lastSeen = Utils.getTimeStampHMS(Number(processHistory.lastSeenNumber))
                    processHistory.processName = processHistory.processName + '(' + processHistory.processId + ')'
                    processHistory.cpuTimeNumber = Number(processHistory.cpuTime);
                    processHistory.cpuTime = this.timeFormat(processHistory.cpuTimeNumber)
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
<lit-table id="tb-history-processes" style="height: auto">
    <lit-table-column order width="1fr" title="Process ID" data-index="processId" key="processId" align="flex-start"></lit-table-column>
    <lit-table-column order width="1fr" title="Alive" data-index="alive" key="alive" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="First Seen" data-index="firstSeen" key="firstSeen" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="Last Seen" data-index="lastSeen" key="lastSeen" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="Process Name" data-index="processName" key="processName" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="Responsible Process" data-index="responsibleProcess" key="responsibleProcess" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="User ID" data-index="userName" key="userName" align="flex-start" ></lit-table-column>
    <lit-table-column order width="1fr" title="CPU Time" data-index="cpuTime" key="cpuTime" align="flex-start" ></lit-table-column>
</lit-table>
        `;
    }

    sortByColumn(detail: any) {
        // @ts-ignore
        function compare(property, sort, type) {
            return function (a: ProcessHistory, b: ProcessHistory) {
                if (type === 'number') {
                    // @ts-ignore
                    return sort === 2 ? parseFloat(b[property]) - parseFloat(a[property]) : parseFloat(a[property]) - parseFloat(b[property]);
                } else if (type === 'cpuTime') {
                    return sort === 2 ? b.cpuTimeNumber - a.cpuTimeNumber : a.cpuTimeNumber - b.cpuTimeNumber;
                } else if (type === 'lastSeen') {
                    return sort === 2 ? b.lastSeenNumber - a.lastSeenNumber : a.lastSeenNumber - b.lastSeenNumber;
                } else if (type === 'firstSeen') {
                    return sort === 2 ? b.firstSeenNumber - a.firstSeenNumber : a.firstSeenNumber - b.firstSeenNumber;
                } else if (type === 'alive') {
                    let aaaa = 0;
                    let bbbb = 0;
                    // @ts-ignore
                    if (b[property] == "Yes") {
                        bbbb = 1;
                    }
                    // @ts-ignore
                    if (a[property] == "Yes") {
                        aaaa = 1;
                    }
                    if (aaaa - bbbb == 0) {
                        return 0;
                    }
                    return aaaa - bbbb ? -1 : 1
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

        if (detail.key === 'startTime' || detail.key === 'processName' ) {
            this.source.sort(compare(detail.key, detail.sort, 'string'))
        } else if (detail.key == 'cpuTime') {
            this.source.sort(compare(detail.key, detail.sort, 'cpuTime'))
        } else if (detail.key === 'alive') {
            this.source.sort(compare(detail.key, detail.sort, 'alive'))
        } else {
            this.source.sort(compare(detail.key, detail.sort, 'number'))
        }
        this.tbl!.recycleDataSource = this.source;
    }

}