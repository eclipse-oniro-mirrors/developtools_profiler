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
import {getTabFps} from "../../../database/SqlLite.js";
import {Utils} from "../base/Utils.js";
import {log} from "../../../../log/Log.js";

@element('tabpane-fps')
export class TabPaneFps extends BaseElement {
    private tbl: LitTable | null | undefined;
    private range: HTMLLabelElement | null | undefined;

    set data(val: SelectionParam | any) {
        this.range!.textContent = "Selected range: " + parseFloat(((val.rightNs - val.leftNs) / 1000000.0).toFixed(5)) + " ms"
        getTabFps(val.leftNs, val.rightNs).then((result) => {
            if (result != null && result.length > 0) {
                log("getTabFps result size : " + result.length)

                let index = result.findIndex((d) => d.startNS >= val.leftNs);
                if (index != -1) {
                    let arr = result.splice(index > 0 ? index - 1 : index)
                    arr.map(e => e.timeStr = Utils.getTimeString(e.startNS))
                    this.tbl!.recycleDataSource = arr
                } else {
                    let last = result[result.length - 1]
                    last.timeStr = Utils.getTimeString(last.startNS)
                    this.tbl!.recycleDataSource = [last]
                }
            } else {
                this.tbl!.recycleDataSource = []
            }
        });
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-fps');
        this.range = this.shadowRoot?.querySelector('#time-range')
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
        <label id="time-range" style="width: 100%;height: 20px;text-align: end;font-size: 10pt;margin-bottom: 5px">Selected range:0.0 ms</label>
        <lit-table id="tb-fps" style="height: auto">
            <lit-table-column width="1fr" title="Time" data-index="timeStr" key="timeStr" align="flex-start">
            </lit-table-column>
            <lit-table-column width="1fr" title="FPS" data-index="fps" key="fps" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }
}