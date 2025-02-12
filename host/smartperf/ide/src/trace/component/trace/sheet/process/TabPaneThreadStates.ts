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
import {SelectionData, SelectionParam} from "../../../../bean/BoxSelection.js";
import "../../../StackBar.js"
import {getTabThreadStates} from "../../../../database/SqlLite.js";
import {Utils} from "../../base/Utils.js";
import {StackBar} from "../../../StackBar.js";
import {log} from "../../../../../log/Log.js";

@element('tabpane-thread-states')
export class TabPaneThreadStates extends BaseElement {
    private tbl: LitTable | null | undefined;
    private range: HTMLLabelElement | null | undefined;
    private stackBar: StackBar | null | undefined;
    private source: Array<SelectionData> = []

    set data(val: SelectionParam | any) {
        //@ts-ignore
        this.tbl?.shadowRoot?.querySelector(".table")?.style?.height = (this.parentElement!.clientHeight - 45) + "px";
        // // @ts-ignore
        this.range!.textContent = "Selected range: " + ((val.rightNs - val.leftNs) / 1000000.0).toFixed(5) + " ms"
        getTabThreadStates(val.threadIds, val.leftNs, val.rightNs).then((result) => {
            if (result != null && result.length > 0) {
                log("getTabThreadStates result size : " + result.length)
                let sumWall = 0.0;
                let sumOcc = 0;
                for (let e of result) {
                    e.process = e.process == null || e.process.length == 0 ? "[NULL]" : e.process
                    e.thread = e.thread == null || e.thread.length == 0 ? "[NULL]" : e.thread
                    sumWall += e.wallDuration
                    sumOcc += e.occurrences
                    e.stateJX = e.state
                    e.state = Utils.getEndState(e.stateJX);
                    e.wallDuration = parseFloat((e.wallDuration / 1000000.0).toFixed(5));
                    e.avgDuration = parseFloat((e.avgDuration / 1000000.0).toFixed(5));
                }
                let count = new SelectionData()
                count.process = " "
                count.state = " "
                count.wallDuration = parseFloat((sumWall / 1000000.0).toFixed(5));
                count.occurrences = sumOcc;
                result.splice(0, 0, count)
                this.source = result;
                this.tbl!.recycleDataSource = result
                this.stackBar!.data = result;
            } else {
                this.source = []
                this.stackBar!.data = []
                this.tbl!.recycleDataSource = []
            }
        })
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-thread-states');
        this.range = this.shadowRoot?.querySelector('#time-range');
        this.stackBar = this.shadowRoot?.querySelector('#stack-bar');
        this.tbl!.addEventListener('column-click', (evt: any) => {
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
        }).observe(this.parentElement!)
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
        <div style="display: flex;height: 20px;align-items: center;flex-direction: row;margin-bottom: 5px">
            <stack-bar id="stack-bar" style="flex: 1"></stack-bar>
            <label id="time-range"  style="width: auto;text-align: end;font-size: 10pt;">Selected range:0.0 ms</label>
        </div>
        <lit-table id="tb-thread-states" style="height: auto">
            <lit-table-column width="25%" title="Process" data-index="process" key="process"  align="flex-start" order>
            </lit-table-column>
            <lit-table-column width="1fr" title="PID" data-index="pid" key="pid"  align="flex-start" order >
            </lit-table-column>
            <lit-table-column width="20%" title="Thread" data-index="thread" key="thread"  align="flex-start" order >
            </lit-table-column>
            <lit-table-column width="1fr" title="TID" data-index="tid" key="tid"  align="flex-start" order >
            </lit-table-column>
            <lit-table-column width="1fr" title="State" data-index="state" key="state"  align="flex-start" order >
            </lit-table-column>
            <lit-table-column width="1fr" title="Wall duration(ms)" data-index="wallDuration" key="wallDuration"  align="flex-start" order >
            </lit-table-column>
            <lit-table-column width="1fr" title="Avg Wall duration(ms)" data-index="avgDuration" key="avgDuration"  align="flex-start" order >
            </lit-table-column>
            <lit-table-column width="1fr" title="Occurrences" data-index="occurrences" key="occurrences"  align="flex-start" order >
            </lit-table-column>
        </lit-table>
        `;
    }

    sortByColumn(detail: any) {
        function compare(property: any, sort: any, type: any) {
            return function (a: SelectionData | any, b: SelectionData | any) {
                if (a.process == " " || b.process == " ") {
                    return 0;
                }
                if (type === 'number') {
                    return sort === 2 ? parseFloat(b[property]) - parseFloat(a[property]) : parseFloat(a[property]) - parseFloat(b[property]);
                } else {
                    if (b[property] > a[property]) {
                        return sort === 2 ? 1 : -1;
                    } else if (b[property] == a[property]) {
                        return 0;
                    } else {
                        return sort === 2 ? -1 : 1;
                    }
                }
            }
        }

        if (detail.key === "name" || detail.key === "thread" || detail.key === "state") {
            this.source.sort(compare(detail.key, detail.sort, 'string'))
        } else {
            this.source.sort(compare(detail.key, detail.sort, 'number'))
        }
        this.tbl!.recycleDataSource = this.source;
    }

}