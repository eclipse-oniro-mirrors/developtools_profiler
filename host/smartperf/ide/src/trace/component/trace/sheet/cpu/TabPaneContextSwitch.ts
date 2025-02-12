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
import {
    getStatesProcessThreadDataByRange

} from "../../../../database/SqlLite.js";
import {SPT, StateProcessThread} from "../../../../bean/StateProcessThread.js";
import {Utils} from "../../base/Utils.js";
import {SpSystemTrace} from "../../../SpSystemTrace.js";

@element('tabpane-context-switch')
export class TabPaneContextSwitch extends BaseElement {
    private tbl: LitTable | null | undefined;
    private range: HTMLLabelElement | null | undefined;
    private loadDataInCache: boolean = true;
    private selectionParam:SelectionParam | null | undefined;

    set data(val: SelectionParam | any) {
        if(val == this.selectionParam){
            return;
        }
        this.selectionParam = val;
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
        this.range!.textContent = "Selected range: " + parseFloat(((val.rightNs - val.leftNs) / 1000000.0).toFixed(5)) + " ms"
        if (this.loadDataInCache) {
            this.getDataBySPT(val.leftNs,val.rightNs,SpSystemTrace.SPT_DATA)
        } else {
            this.queryDataByDB(val)
        }
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-cs');
        this.range = this.shadowRoot?.querySelector('#time-range')
    }

    connectedCallback() {
        super.connectedCallback();
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
                this.tbl?.reMeauseHeight()
            }
        }).observe(this.parentElement!)
    }

    getDataBySPT(leftNs:number,rightNs:number,source:Array<SPT>){
        let pMap: Map<string, StateProcessThread> = new Map<string, StateProcessThread>();
        let ptMap: Map<string, StateProcessThread> = new Map<string, StateProcessThread>();
        let ptsMap: Map<string, StateProcessThread> = new Map<string, StateProcessThread>();
        source.map((d) => {
            if (!(d.end_ts < leftNs || d.start_ts > rightNs)) {
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
        this.tbl!.recycleDataSource = arr;
    }

    queryDataByDB(val: SelectionParam | any) {
        getStatesProcessThreadDataByRange(val.leftNs,val.rightNs).then(result => {
            this.getDataBySPT(val.leftNs,val.rightNs,result);
        })
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
        <lit-table id="tb-cs" style="height: auto" tree>
            <lit-table-column width="500px" title="Process/Thread/Event" data-index="title" key="title" align="flex-start">
            </lit-table-column>
            <lit-table-column width="1fr" title="Count" data-index="count" key="count" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }
}