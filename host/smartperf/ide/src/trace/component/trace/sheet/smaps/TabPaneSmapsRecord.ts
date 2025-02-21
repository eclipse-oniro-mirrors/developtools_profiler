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
import {getTabSmapsData,} from "../../../../database/SqlLite.js";
import {Utils} from "../../base/Utils.js";
import {log} from "../../../../../log/Log.js";
import {Smaps} from "../../../../bean/SmapsStruct.js";

@element('tabpane-smaps-record')
export class TabPaneSmapsRecord extends BaseElement {
    private tbl: LitTable | null | undefined;
    private source: Array<Smaps> = [];
    private queryResult: Array<Smaps> = []

    set data(val: SelectionParam | any) {
        // @ts-ignore
        this.tbl?.shadowRoot?.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
        this.queryDataByDB(val)
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-smaps-record');
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

    queryDataByDB(val: SelectionParam | any) {
        getTabSmapsData(val.leftNs, val.rightNs).then(result => {
            log("getTabSmapsData size :" + result.length);
            if (result.length != null && result.length > 0) {
                for (const smaps of result) {
                    switch (smaps.permission.trim()) {
                        case "rw-":
                            smaps.type = "DATA"
                            break;
                        case "r-x":
                            smaps.type = "TEXT"
                            break;
                        case "r--":
                            smaps.type = "CONST"
                            break;
                        default:
                            smaps.type = "OTHER"
                            break;
                    }
                    smaps.address = smaps.start_addr  + " - " + smaps.end_addr
                    smaps.dirtyStr = Utils.getBinaryByteWithUnit(smaps.dirty * 1024)
                    smaps.swapperStr = Utils.getBinaryByteWithUnit(smaps.swapper * 1024)
                    smaps.rssStr = Utils.getBinaryByteWithUnit(smaps.rss * 1024)
                    smaps.pssStr = Utils.getBinaryByteWithUnit(smaps.pss * 1024)
                    smaps.sizeStr = Utils.getBinaryByteWithUnit(smaps.size * 1024)
                    let resideS = smaps.reside.toFixed(2)
                    if (resideS == "0.00") {
                        smaps.resideStr = "0 %"
                    } else {
                        smaps.resideStr = resideS + "%"
                    }
                }
                this.source = result
                this.queryResult = result;
                this.tbl!.recycleDataSource = this.source
            } else {
                this.source = []
                this.queryResult = []
                this.tbl!.recycleDataSource = []
            }
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
        <lit-table id="tb-smaps-record" style="height: auto">
            <lit-table-column order width="80px" title="Type" data-index="type" key="type" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="250px" title="Address Range" data-index="address" key="address" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="0.5fr" title="Dirty Size" data-index="dirtyStr" key="dirtyStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="0.5fr" title="Swapped" data-index="swapperStr" key="swapperStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="0.5fr" title="Resident Size" data-index="rssStr" key="rssStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="0.5fr" title="Virtual Size" data-index="sizeStr" key="sizeStr" align="flex-start" >
            </lit-table-column>
              <lit-table-column order width="0.5fr" title="Pss" data-index="pssStr" key="pssStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="0.5fr" title="Reside" data-index="resideStr" key="resideStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="0.5fr" title="Protection" data-index="permission" key="permission" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1.5fr" title="Path" data-index="path" key="path" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }

    sortByColumn(detail: any) {
        // @ts-ignore
        function compare(property, sort, type) {
            return function (a: Smaps, b: Smaps) {
                if (type === 'number') {
                    // @ts-ignore
                    return sort === 2 ? parseFloat(b[property]) - parseFloat(a[property]) : parseFloat(a[property]) - parseFloat(b[property]);
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

        if (detail.key === 'dirtyStr' || detail.key === 'swapperStr' || detail.key === 'rssStr' || detail.key === 'sizeStr' || detail.key === 'resideStr') {
            let key = detail.key.substring(0, detail.key.indexOf("Str"))
            this.source.sort(compare(key, detail.sort, 'number'))
        }  else {
            this.source.sort(compare(detail.key, detail.sort, 'string'))
        }
        this.tbl!.recycleDataSource = this.source;
    }
}