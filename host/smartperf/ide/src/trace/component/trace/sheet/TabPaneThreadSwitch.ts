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
    getTabStatesGroupByState,
    getTabStatesGroupByStatePid,
    getTabStatesGroupByStatePidTid
} from "../../../database/SqlLite.js";
import {StateProcessThread} from "../../../bean/StateProcessThread.js";
import {Utils} from "../base/Utils.js";
import {SpSystemTrace} from "../../SpSystemTrace.js";
import {log} from "../../../../log/Log.js";

@element('tabpane-thread-switch')
export class TabPaneThreadSwitch extends BaseElement {
    private tbl: LitTable | null | undefined;
    private range: HTMLLabelElement | null | undefined;
    private loadDataInCache: boolean = true;

    set data(val: SelectionParam | any) {
        //@ts-ignore
        this.tbl?.shadowRoot?.querySelector(".table")?.style?.height = (this.parentElement!.clientHeight - 45) + "px";
        this.range!.textContent = "Selected range: " + parseFloat(((val.rightNs - val.leftNs) / 1000000.0).toFixed(5)) + " ms";
        if (this.loadDataInCache) {
            this.queryDataByCacheData(val).then((arr) => {
                this.tbl!.recycleDataSource = arr;
            });
        } else {
            this.queryDataByDB(val);
        }
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-ts');
        this.range = this.shadowRoot?.querySelector('#time-range');
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl?.shadowRoot?.querySelector(".table").style.height = (this.parentElement!.clientHeight - 45) + "px"
                this.tbl?.reMeauseHeight()
            }
        }).observe(this.parentElement!);
    }

    async queryDataByCacheData(val: SelectionParam | any): Promise<Array<StateProcessThread>> {
        //1. 框选时间区间的数据过滤出来
        log("queryDataByCacheData ")
        return new Promise<Array<StateProcessThread>>(((resolve, reject) => {
            let statesMap: Map<string, StateProcessThread> = new Map<string, StateProcessThread>();
            let spMap: Map<string, StateProcessThread> = new Map<string, StateProcessThread>();
            let sptMap: Map<string, StateProcessThread> = new Map<string, StateProcessThread>();
            SpSystemTrace.SPT_DATA.map((d) => {
                if (!(d.end_ts < val.leftNs || d.start_ts > val.rightNs)) {
                    if (statesMap.has(d.state)) {
                        let obj1 = statesMap.get(d.state);
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
                        obj1.id = (d.state == "R+" ? "RP" : d.state)
                        obj1.title = Utils.getEndState(d.state);
                        obj1.state = d.state;
                        obj1.minDuration = d.dur;
                        obj1.maxDuration = d.dur;
                        obj1.count = 1;
                        obj1.avgDuration = d.dur + "";
                        obj1.wallDuration = d.dur;
                        statesMap.set(d.state, obj1);
                    }
                    if (spMap.has(d.state + "_" + d.processId)) {
                        let obj2 = spMap.get(d.state + "_" + d.processId);
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
                        obj2.id = (d.state == "R+" ? "RP" : d.state) + "_" + d.processId;
                        obj2.pid = (d.state == "R+" ? "RP" : d.state);
                        obj2.title = (d.process == null || d.process == "" ? "Process" : d.process) + "(" + d.processId + ")"
                        obj2.processId = d.processId;
                        obj2.process = d.process;
                        obj2.state = d.state;
                        obj2.minDuration = d.dur;
                        obj2.maxDuration = d.dur;
                        obj2.count = 1;
                        obj2.avgDuration = d.dur + "";
                        obj2.wallDuration = d.dur;
                        spMap.set(d.state + "_" + d.processId, obj2);
                    }
                    if (sptMap.has(d.state + "_" + d.processId + "_" + d.threadId)) {
                        let obj3 = sptMap.get(d.state + "_" + d.processId + "_" + d.threadId);
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
                        obj3.id = (d.state == "R+" ? "RP" : d.state) + "_" + d.processId + "_" + d.threadId
                        obj3.pid = (d.state == "R+" ? "RP" : d.state) + "_" + d.processId
                        obj3.title = (d.thread == null || d.thread == "" ? "Thread" : d.thread) + "(" + d.threadId + ")"
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
                        sptMap.set(d.state + "_" + d.processId + "_" + d.threadId, obj3);
                    }
                }
            })
            let arr: Array<StateProcessThread> = [];
            for (let key of statesMap.keys()) {
                let s = statesMap.get(key);
                s!.children = [];
                for (let ks of spMap.keys()) {
                    if (ks.startsWith(key + "_")) {
                        let sp = spMap.get(ks)
                        sp!.children = [];
                        for (let kst of sptMap.keys()) {
                            if (kst.startsWith(ks + "_")) {
                                let spt = sptMap.get(kst)
                                sp!.children.push(spt!);
                            }
                        }
                        s!.children.push(sp!)
                    }
                }
                arr.push(s!)
            }
            resolve(arr);
        }));
    }

    queryDataByDB(val: SelectionParam | any) {
        Promise.all([
            getTabStatesGroupByState(val.leftNs, val.rightNs),
            getTabStatesGroupByStatePid(val.leftNs, val.rightNs),
            getTabStatesGroupByStatePidTid(val.leftNs, val.rightNs)]).then((values) => {
            let states = values[0];
            states.map((spt) => {
                spt.id = (spt.state == "R+" ? "RP" : spt.state)
                spt.title = Utils.getEndState(spt.state);
            });
            let processMap = this.groupByStateToMap(values[1]);
            let threadMap = this.groupByStateProcessToMap(values[2]);
            for (let state of states) {
                let processes = processMap.get(state.state);
                processes!.map((spt) => {
                    spt.id = (spt.state == "R+" ? "RP" : spt.state) + "_" + spt.processId;
                    spt.pid = (spt.state == "R+" ? "RP" : spt.state);
                    spt.title = (spt.process == null || spt.process == "" ? "Process" : spt.process) + "(" + spt.processId + ")"
                })
                state.children = processes ?? [];
                let map = threadMap.get(state.state);
                for (let process of processes!) {
                    let threads = map!.get(process.processId);
                    threads!.map((spt) => {
                        spt.id = (spt.state == "R+" ? "RP" : spt.state) + "_" + spt.processId + "_" + spt.threadId
                        spt.pid = (spt.state == "R+" ? "RP" : spt.state) + "_" + spt.processId
                        spt.title = (spt.thread == null || spt.thread == "" ? "Thread" : spt.thread) + "(" + spt.threadId + ")"
                    })
                    process.children = threads ?? [];
                }
            }
            this.tbl!.recycleDataSource = states;
        })
    }

    groupByStateToMap(arr: Array<StateProcessThread>): Map<string, Array<StateProcessThread>> {
        let map = new Map<string, Array<StateProcessThread>>();
        for (let spt of arr) {
            if (map.has(spt.state)) {
                map.get(spt.state)!.push(spt);
            } else {
                let list: Array<StateProcessThread> = [];
                list.push(spt);
                map.set(spt.state, list);
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

    groupByStateProcessToMap(arr: Array<StateProcessThread>): Map<string, Map<number, Array<StateProcessThread>>> {
        let map = new Map<string, Map<number, Array<StateProcessThread>>>();
        let stateMap = this.groupByStateToMap(arr);
        for (let key of stateMap.keys()) {
            let processMap = this.groupByProcessToMap(stateMap.get(key)!)
            map.set(key, processMap);
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
        <lit-table id="tb-ts" style="height: auto" tree>
            <lit-table-column width="500px" title="Event/Process/Thread" data-index="title" key="title" align="flex-start">
            </lit-table-column>
            <lit-table-column width="1fr" title="Count" data-index="count" key="count" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }
}