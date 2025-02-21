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
import {
    getTabStatesGroupByProcess,
    getTabStatesGroupByProcessThread,
    getTabStatesGroupByStatePidTid
} from "../../../database/SqlLite.js";
import {StateProcessThread} from "../../../bean/StateProcessThread.js";
import {Utils} from "../base/Utils.js";
import {SpSystemTrace} from "../../SpSystemTrace.js";

@element('tabpane-pts')
export class TabPanePTS extends BaseElement {
    private tbl: LitTable | null | undefined;
    private range: HTMLLabelElement | null | undefined;
    private loadDataInCache: boolean = true;

    set data(val: SelectionParam | any) {
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
        this.range!.textContent = "Selected range: " + parseFloat(((val.rightNs - val.leftNs) / 1000000.0).toFixed(5)) + " ms"
        if (this.loadDataInCache) {
            this.queryDataInCacheData(val).then((arr) => {
                this.tbl!.recycleDataSource = arr;
            });
        } else {
            this.queryDataByDB(val)
        }
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-states');
        this.range = this.shadowRoot?.querySelector('#time-range')
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
                this.tbl?.reMeauseHeight()
            }
        }).observe(this.parentElement!)
    }

    async queryDataInCacheData(val: SelectionParam | any): Promise<Array<StateProcessThread>> {
        return new Promise<Array<StateProcessThread>>((resolve, reject) => {
            let pMap: Map<string, StateProcessThread> = new Map<string, StateProcessThread>();
            let ptMap: Map<string, StateProcessThread> = new Map<string, StateProcessThread>();
            let ptsMap: Map<string, StateProcessThread> = new Map<string, StateProcessThread>();
            SpSystemTrace.SPT_DATA.map((d) => {
                if (!(d.end_ts < val.leftNs || d.start_ts > val.rightNs)) {
                    if (pMap.has(d.processId + "")) {
                        let obj1 = pMap.get(d.processId + "");
                        obj1!.count++;
                        obj1!.wallDuration += d.dur;
                        obj1!.avgDuration = (obj1!.wallDuration / obj1!.count).toFixed(2);
                        if (d.dur > obj1!.maxDuration) {
                            obj1!.maxDuration = d.dur;
                        }
                        if (d.dur < obj1!.minDuration) {
                            obj1!.minDuration = d.dur;
                        }
                    } else {
                        let obj1 = new StateProcessThread();
                        obj1.id = "p" + d.processId;
                        obj1.title = (d.process == null || d.process == "" ? "Process" : d.process) + "(" + d.processId + ")";
                        obj1.process = d.process;
                        obj1.processId = d.processId;
                        obj1.minDuration = d.dur;
                        obj1.maxDuration = d.dur;
                        obj1.count = 1;
                        obj1.avgDuration = d.dur + "";
                        obj1.wallDuration = d.dur;
                        pMap.set(d.processId + "", obj1);
                    }
                    if (ptMap.has(d.processId + "_" + d.threadId)) {
                        let obj2 = ptMap.get(d.processId + "_" + d.threadId);
                        obj2!.count++;
                        obj2!.wallDuration += d.dur;
                        obj2!.avgDuration = (obj2!.wallDuration / obj2!.count).toFixed(2);
                        if (d.dur > obj2!.maxDuration) {
                            obj2!.maxDuration = d.dur;
                        }
                        if (d.dur < obj2!.minDuration) {
                            obj2!.minDuration = d.dur;
                        }
                    } else {
                        let obj2 = new StateProcessThread();
                        obj2.id = "p" + d.processId + "_" + "t" + d.threadId;
                        obj2.pid = "p" + d.processId;
                        obj2.title = (d.thread == null || d.thread == "" ? "Thread" : d.thread) + "(" + d.threadId + ")"
                        obj2.processId = d.processId;
                        obj2.process = d.process;
                        obj2.thread = d.thread;
                        obj2.threadId = d.threadId;
                        obj2.minDuration = d.dur;
                        obj2.maxDuration = d.dur;
                        obj2.count = 1;
                        obj2.avgDuration = d.dur + "";
                        obj2.wallDuration = d.dur;
                        ptMap.set(d.processId + "_" + d.threadId, obj2);
                    }
                    if (ptsMap.has(d.processId + "_" + d.threadId + "_" + d.state)) {
                        let obj3 = ptsMap.get(d.processId + "_" + d.threadId + "_" + d.state);
                        obj3!.count++;
                        obj3!.wallDuration += d.dur;
                        obj3!.avgDuration = (obj3!.wallDuration / obj3!.count).toFixed(2);
                        if (d.dur > obj3!.maxDuration) {
                            obj3!.maxDuration = d.dur;
                        }
                        if (d.dur < obj3!.minDuration) {
                            obj3!.minDuration = d.dur;
                        }
                    } else {
                        let obj3 = new StateProcessThread();
                        obj3.id = "p" + d.processId + "_" + "t" + d.threadId + "_" + (d.state == "R+" ? "RP" : d.state)
                        obj3.pid = "p" + d.processId + "_" + "t" + d.threadId;
                        obj3.title = Utils.getEndState(d.state)
                        obj3.processId = d.processId;
                        obj3.process = d.process;
                        obj3.thread = d.thread;
                        obj3.threadId = d.threadId;
                        obj3.state = d.state;
                        obj3.minDuration = d.dur;
                        obj3.maxDuration = d.dur;
                        obj3.count = 1;
                        obj3.avgDuration = d.dur + "";
                        obj3.wallDuration = d.dur;
                        ptsMap.set(d.processId + "_" + d.threadId + "_" + d.state, obj3);
                    }
                }
            })
            let arr: Array<StateProcessThread> = [];
            for (let key of pMap.keys()) {
                let s = pMap.get(key);
                s!.children = [];
                for (let ks of ptMap.keys()) {
                    if (ks.startsWith(key + "_")) {
                        let sp = ptMap.get(ks)
                        sp!.children = [];
                        for (let kst of ptsMap.keys()) {
                            if (kst.startsWith(ks + "_")) {
                                let spt = ptsMap.get(kst)
                                sp!.children.push(spt!);
                            }
                        }
                        s!.children.push(sp!)
                    }
                }
                arr.push(s!)
            }
            resolve(arr);
        });
    }

    queryDataByDB(val: SelectionParam | any) {
        Promise.all([
            getTabStatesGroupByProcess(val.leftNs, val.rightNs),
            getTabStatesGroupByProcessThread(val.leftNs, val.rightNs),
            getTabStatesGroupByStatePidTid(val.leftNs, val.rightNs)]).then((values) => {
            let processes = values[0];
            processes.map((spt) => {
                spt.id = "p" + spt.processId
                spt.title = (spt.process == null || spt.process == "" ? "Process" : spt.process) + "(" + spt.processId + ")"
            });
            let threadMap = this.groupByProcessToMap(values[1]);
            let stateMap = this.groupByProcessThreadToMap(values[2]);
            for (let process of processes) {
                let threads = threadMap.get(process.processId);
                if (threads != undefined) {
                    threads!.map((spt) => {
                        spt.id = "p" + spt.processId + "_" + "t" + spt.threadId;
                        spt.pid = "p" + spt.processId;
                        spt.title = (spt.thread == null || spt.thread == "" ? "Thread" : spt.thread) + "(" + spt.threadId + ")"
                    })
                }
                process.children = threads ?? [];
                let map = stateMap.get(process.processId);
                for (let thread of threads!) {
                    let states = map!.get(thread.threadId);
                    states!.map((spt) => {
                        spt.id = "p" + spt.processId + "_" + "t" + spt.threadId + "_" + (spt.state == "R+" ? "RP" : spt.state)
                        spt.pid = "p" + spt.processId + "_" + "t" + spt.threadId;
                        spt.title = Utils.getEndState(spt.state)
                    })
                    thread.children = states ?? [];
                }
            }
            this.tbl!.recycleDataSource = processes;
        })
    }

    groupByThreadToMap(arr: Array<StateProcessThread>): Map<number, Array<StateProcessThread>> {
        let map = new Map<number, Array<StateProcessThread>>();
        for (let spt of arr) {
            if (map.has(spt.threadId)) {
                map.get(spt.threadId)!.push(spt);
            } else {
                let list: Array<StateProcessThread> = [];
                list.push(spt);
                map.set(spt.threadId, list);
            }
        }
        return map;
    }

    groupByProcessToMap(arr: Array<StateProcessThread>): Map<number, Array<StateProcessThread>> {
        let map = new Map<number, Array<StateProcessThread>>();
        for (let spt of arr) {
            if (map.has(spt.processId)) {
                map.get(spt.processId)!.push(spt);
            } else {
                let list: Array<StateProcessThread> = [];
                list.push(spt);
                map.set(spt.processId, list);
            }
        }
        return map;
    }

    groupByProcessThreadToMap(arr: Array<StateProcessThread>): Map<number, Map<number, Array<StateProcessThread>>> {
        let map = new Map<number, Map<number, Array<StateProcessThread>>>();
        let processMap = this.groupByProcessToMap(arr);
        for (let key of processMap.keys()) {
            let threadMap = this.groupByThreadToMap(processMap.get(key)!)
            map.set(key, threadMap);
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
        <lit-table id="tb-states" style="height: auto" tree>
            <lit-table-column width="27%" title="Process/Thread/State" data-index="title" key="title" align="flex-start">
            </lit-table-column>
            <lit-table-column width="1fr" title="Count" data-index="count" key="count" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="1fr" title="Duration(ns)" data-index="wallDuration" key="wallDuration" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="1fr" title="Min Duration(ns)" data-index="minDuration" key="minDuration" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="1fr" title="Avg Duration(ns)" data-index="avgDuration" key="avgDuration" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="1fr" title="Max Duration(ns)" data-index="maxDuration" key="maxDuration" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }
}