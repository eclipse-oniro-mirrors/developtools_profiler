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

import {BaseElement, element} from "../../../../base-ui/BaseElement.js";
import {LitTable} from "../../../../base-ui/table/lit-table.js";
import {SelectionParam} from "../../../bean/BoxSelection.js";
import {getTabCpuFreq, getTabCpuUsage} from "../../../database/SqlLite.js";
import {CpuUsage, Freq} from "../../../bean/CpuUsage.js";

@element('tabpane-cpu-usage')
export class TabPaneCpuUsage extends BaseElement {
    private tbl: LitTable | null | undefined;
    private range: HTMLLabelElement | null | undefined;
    private orderByOldList: any[] = [];

    set data(val: SelectionParam | any) {
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
        this.range!.textContent = "Selected range: " + parseFloat(((val.rightNs - val.leftNs) / 1000000.0).toFixed(5)) + " ms"
        Promise.all([getTabCpuUsage(val.cpus, val.leftNs, val.rightNs), getTabCpuFreq(val.cpus, val.leftNs, val.rightNs)]).then((result) => {
            let usages = result[0];
            let freqMap = this.groupByCpuToMap(result[1])
            let data = [];
            let range = val.rightNs - val.leftNs;
            for (let cpu of val.cpus) {
                let usage = new CpuUsage();
                usage.cpu = cpu;
                let u = usages.find((e) => e.cpu == cpu);
                if (u != undefined && u != null) {
                    usage.usage = u.usage
                } else {
                    usage.usage = 0;
                }
                if (usage.usage > 1) {
                    usage.usage = 1;
                }
                usage.usageStr = (usage.usage * 100.0).toFixed(2) + "%"
                let arr = [];
                if (freqMap.has(usage.cpu)) {
                    let freqList = freqMap.get(usage.cpu)
                    let list = []
                    for (let i = 0; i < freqList!.length; i++) {
                        let freq = freqList![i];
                        if (i == freqList!.length - 1) {
                            freq.dur = val.rightNs - freq.startNs
                        } else {
                            freq.dur = freqList![i + 1].startNs - freq.startNs
                        }
                        if (freq.startNs + freq.dur > val.leftNs) {
                            list.push(freq);
                        }
                    }
                    if (list.length > 0) {
                        if (list[0].startNs < val.leftNs) {
                            list[0].dur = list[0].startNs + list[0].dur - val.leftNs
                            list[0].startNs = val.leftNs;
                        }
                    }
                    arr = this.sortFreq(list);
                    this.getFreqTop3(usage, arr[0], arr[1], arr[2], range)
                }
                data.push(usage)
            }
            this.tbl!.recycleDataSource = data;
            this.orderByOldList = [...data]
        })
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-cpu-usage');
        this.range = this.shadowRoot?.querySelector('#time-range')
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
                this.tbl?.reMeauseHeight()
            }
        }).observe(this.parentElement!)
        this.tbl?.addEventListener("column-click", event => {
            // @ts-ignore
            let orderType = event.detail;
            if (orderType.sort == 1) {//倒序   注意  sort会改变原数组，需要传入table上的数组 不能传入缓存排序数组
                this.sortTable(this.tbl!.recycleDataSource, orderType.key, false)
            } else if (orderType.sort == 2) {//正序
                this.sortTable(this.tbl!.recycleDataSource, orderType.key, true)
            } else {//默认排序
                this.tbl!.recycleDataSource = [...this.orderByOldList];
            }
        })
    }

    sortTable(arr: any[], key: string, sort: boolean) {
        this.tbl!.recycleDataSource = arr.sort((item1, item2) => {
            let value1 = Number(item1[key].toString().replace("%", ""));
            let value2 = Number(item2[key].toString().replace("%", ""));
            if (value1 > value2) {
                return sort ? -1 : 1
            } else if (value1 < value2) {
                return sort ? 1 : -1
            } else {
                return 0
            }
        });
    }

    sortFreq(arr: Array<Freq>): Array<Array<number>> {
        let map = new Map<number, number>();
        for (let freq of arr) {
            if (map.has(freq.value)) {
                let sumDur = map.get(freq.value)! + freq.dur;
                map.set(freq.value, sumDur)
            } else {
                map.set(freq.value, freq.dur);
            }
        }
        let array = Array.from(map);
        array.sort((a, b) => b[1] - a[1])
        return array
    }

    getFreqTop3(usage: CpuUsage, top1: Array<number>, top2: Array<number>, top3: Array<number>, range: number) {
        // @ts-ignore
        usage.top1 = top1 == undefined ? '-' : top1[0]
        usage.top1Percent = top1 == undefined ? 0 : top1[1] * 1.0 / range;
        usage.top1PercentStr = top1 == undefined ? "-" : (usage.top1Percent * 100).toFixed(2) + "%"
        // @ts-ignore
        usage.top2 = top2 == undefined ? '-' : top2[0]
        usage.top2Percent = top2 == undefined ? 0 : top2[1] * 1.0 / range;
        usage.top2PercentStr = top2 == undefined ? "-" : (usage.top2Percent * 100).toFixed(2) + "%"
        // @ts-ignore
        usage.top3 = top3 == undefined ? '-' : top3[0]
        usage.top3Percent = top3 == undefined ? 0 : top3[1] * 1.0 / range;
        usage.top3PercentStr = top3 == undefined ? "-" : (usage.top3Percent * 100).toFixed(2) + "%"
    }

    groupByCpuToMap(arr: Array<Freq>): Map<number, Array<Freq>> {
        let map = new Map<number, Array<Freq>>();
        for (let spt of arr) {
            if (map.has(spt.cpu)) {
                map.get(spt.cpu)!.push(spt);
            } else {
                let list: Array<Freq> = [];
                list.push(spt);
                map.set(spt.cpu, list);
            }
        }
        return map;
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
        <label id="time-range" style="width: 100%;height: 20px;text-align: end;font-size: 10pt;margin-bottom: 5px">Selected range:0.0 ms</label>
        <lit-table id="tb-cpu-usage" style="height: auto">
            <lit-table-column order width="1fr" title="CPU" data-index="cpu" key="cpu" align="flex-start">
            </lit-table-column>
            <lit-table-column order width="1fr" title="Usage" data-index="usageStr" key="usageStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="CPU Freq Top1(M)" data-index="top1" key="top1" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Top1 percent(%)" data-index="top1PercentStr" key="top1PercentStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="CPU Freq Top2(M)" data-index="top2" key="top2" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Top2 percent(%)" data-index="top2PercentStr" key="top2PercentStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="CPU Freq Top3(M)" data-index="top3" key="top3" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Top3 percent(%)" data-index="top3PercentStr" key="top3PercentStr" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }
}