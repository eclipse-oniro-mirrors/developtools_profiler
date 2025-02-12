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
import {CpuStruct} from "../../../bean/CpuStruct.js";

@element('tabpane-cpu')
export class TabPaneCpu extends BaseElement {
    private tbl: LitTable | null | undefined;

    set data(val: CpuStruct) {
        this.tbl!.dataSource = [
            {name: 'Process', value: `${val.processName || 'Process'} [${val.processId}]`},
            {name: 'Thread', value: `${val.name || 'Thread'} [${val.tid}]`},
            {name: 'Cmdline', value: val.processCmdLine},
            {name: 'Start time', value: val.startTime},
            {name: 'Duration', value: val.dur},
            {name: 'Prio', value: val.priority},
            {name: 'End State', value: val.end_state},
            {name: 'Slice ID', value: val.id}
        ]
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tbl3');
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
        <label style="font-size: 15pt">Slice Details</label>
        <lit-table id="tbl3" no-head style="height: auto">
            <lit-table-column title="name" data-index="name" key="name" align="flex-start"  width="150px">
            </lit-table-column>
            <lit-table-column title="value" data-index="value" key="value" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }
}