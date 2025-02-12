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
import {ColorUtils} from "../../base/ColorUtils.js";
import {Utils} from "../../base/Utils.js";

@element('tabpane-freq-limit')
export class TabPaneFreqLimit extends BaseElement {
    private tbl: LitTable | null | undefined;

    set data(freq:any) {
        if(freq){
            this.tbl!.dataSource = [{
                startNs:Utils.getTimeString(freq.startNs),
                dur:Utils.getProbablyTime(freq.dur),
                maxFreq:`${ColorUtils.formatNumberComma(freq.max!)} kHz`,
                minFreq:`${ColorUtils.formatNumberComma(freq.min!)} kHz`,
                cpu:`Cpu ${freq.cpu}`
            }]
        }
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-freq');
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
        <lit-table id="tb-freq" style="height: auto">
            <lit-table-column width="1fr" title="StartTime" data-index="startNs" key="startNs" align="flex-start">
            </lit-table-column>
            <lit-table-column width="1fr" title="Duration" data-index="dur" key="dur" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="1fr" title="Cpu" data-index="cpu" key="cpu" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="1fr" title="Max Frequency" data-index="maxFreq" key="maxFreq" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="1fr" title="Min Frequency" data-index="minFreq" key="minFreq" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }

}