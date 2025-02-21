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
import {getTabSmapsData, getTabSmapsMaxRss,} from "../../../../database/SqlLite.js";
import {Smaps, SmapsTreeObj} from "../../../../bean/SmapsStruct.js";
import {Utils} from "../../base/Utils.js";

@element('tabpane-smaps-statistics')
export class TabPaneSmapsStatistics extends BaseElement {
    private tbl: LitTable | null | undefined;

    set data(val: SelectionParam | any) {
        // @ts-ignore
        this.tbl?.shadowRoot?.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
        this.queryDataByDB(val)
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-smaps-statistics');
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
        getTabSmapsMaxRss(val.leftNs, val.rightNs).then(maxRes => {
            let sumRss = maxRes[0].max_value
            let allTree: SmapsTreeObj = new SmapsTreeObj("All", "", "*All*");
            let dataTree: SmapsTreeObj = new SmapsTreeObj("DATA", "", "DATA");
            let textTree: SmapsTreeObj = new SmapsTreeObj("TEXT", "", "TEXT");
            let constTree: SmapsTreeObj = new SmapsTreeObj("CONST", "", "CONST");
            let otherTree: SmapsTreeObj = new SmapsTreeObj("OTHER", "", "OTHER");
            getTabSmapsData(val.leftNs, val.rightNs).then(result => {
                if (result.length != null && result.length > 0) {
                    for (let id = 0; id < result.length; id++) {
                        let smaps = result[id]
                        switch (smaps.permission.trim()) {
                            case "rw-":
                                smaps.type = "DATA"
                                this.handleTree(smaps, id, "DATA", dataTree, sumRss);
                                break;
                            case "r-x":
                                smaps.type = "TEXT"
                                this.handleTree(smaps, id, "TEXT", textTree, sumRss);
                                break;
                            case "r--":
                                smaps.type = "CONST"
                                this.handleTree(smaps, id, "CONST", constTree, sumRss);
                                break;
                            default:
                                smaps.type = "OTHER"
                                this.handleTree(smaps, id, "OTHER", otherTree, sumRss);
                                break;
                        }
                        this.handleAllDataTree(smaps, id, "All", allTree, sumRss);
                        if (id == result.length - 1) {
                            this.handleSmapsTreeObj(dataTree, sumRss)
                            this.handleSmapsTreeObj(textTree, sumRss)
                            this.handleSmapsTreeObj(constTree, sumRss)
                            this.handleSmapsTreeObj(otherTree, sumRss)
                            this.handleSmapsTreeObj(allTree, sumRss)
                        }
                    }
                    this.tbl!.recycleDataSource = [allTree, dataTree, textTree, constTree, otherTree]
                } else {
                    this.tbl!.recycleDataSource = []
                }
            })
        })

    }

    private handleSmapsTreeObj(smapsTreeObj: SmapsTreeObj, sumRss: number) {
        smapsTreeObj.rsspro = (smapsTreeObj.rss / sumRss) * 100
        smapsTreeObj.rssproStr = smapsTreeObj.rsspro.toFixed(2) + "%"
        smapsTreeObj.regStr = smapsTreeObj.reg + ""
        smapsTreeObj.rssStr = Utils.getBinaryByteWithUnit(smapsTreeObj.rss * 1024)
        smapsTreeObj.dirtyStr = Utils.getBinaryByteWithUnit(smapsTreeObj.dirty * 1024)
        smapsTreeObj.swapperStr = Utils.getBinaryByteWithUnit(smapsTreeObj.swapper * 1024)
        smapsTreeObj.sizeStr = Utils.getBinaryByteWithUnit(smapsTreeObj.size * 1024)
        smapsTreeObj.respro = smapsTreeObj.rss / smapsTreeObj.size * 100
        smapsTreeObj.pssStr = Utils.getBinaryByteWithUnit(smapsTreeObj.pss * 1024)
        smapsTreeObj.resproStr = smapsTreeObj.respro.toFixed(2) + "%"
    }


    private handleAllDataTree(smaps: Smaps, id: number, parentId: string, dataTree: SmapsTreeObj, sumRss: number) {
        let type = smaps.type
        let obj = new SmapsTreeObj(id + "", parentId, type);
        obj.path = smaps.path
        obj.rss = smaps.rss
        obj.rsspro = (smaps.rss / sumRss) * 100
        obj.rssproStr = obj.rsspro.toFixed(2) + "%"
        obj.rssStr = Utils.getBinaryByteWithUnit(smaps.rss * 1024)
        obj.dirty = smaps.dirty
        obj.dirtyStr = Utils.getBinaryByteWithUnit(smaps.dirty * 1024)
        obj.swapper = smaps.swapper
        obj.swapperStr = Utils.getBinaryByteWithUnit(smaps.swapper * 1024)
        obj.size = smaps.size
        obj.sizeStr = Utils.getBinaryByteWithUnit(smaps.size * 1024)
        obj.pss = smaps.pss
        obj.pssStr = Utils.getBinaryByteWithUnit(smaps.pss * 1024)
        obj.respro = smaps.reside
        obj.resproStr = smaps.reside.toFixed(2) + "%"
        dataTree.reg += 1
        if (dataTree.children.length > 1 && dataTree.path != "< multiple >") {
            dataTree.path = "< multiple >"
        }
        dataTree.rss += smaps.rss
        dataTree.dirty += smaps.dirty
        dataTree.swapper += smaps.swapper
        dataTree.size += smaps.size
        dataTree.respro += smaps.reside
        dataTree.pss += smaps.pss
        dataTree.children.push(obj)
    }

    private handleTree(smaps: Smaps, id: number, parentId: string, dataTree: SmapsTreeObj, sumRss: number) {
        let type = smaps.start_addr + " (" + smaps.size / 4 + " pages)"
        let obj = new SmapsTreeObj(id + "", parentId, type);
        obj.path = smaps.path
        obj.rss = smaps.rss
        obj.rsspro = (smaps.rss / sumRss) * 100
        obj.rssproStr = obj.rsspro.toFixed(2) + "%"
        obj.rssStr = Utils.getBinaryByteWithUnit(smaps.rss * 1024)
        obj.dirty = smaps.dirty
        obj.dirtyStr = Utils.getBinaryByteWithUnit(smaps.dirty * 1024)
        obj.swapper = smaps.swapper
        obj.swapperStr = Utils.getBinaryByteWithUnit(smaps.swapper * 1024)
        obj.size = smaps.size
        obj.sizeStr = Utils.getBinaryByteWithUnit(smaps.size * 1024)
        obj.pss = smaps.pss
        obj.pssStr = Utils.getBinaryByteWithUnit(smaps.pss * 1024)
        obj.respro = smaps.reside
        obj.resproStr = smaps.reside.toFixed(2) + "%"
        dataTree.reg += 1
        if (dataTree.children.length > 1 && dataTree.path != "< multiple >") {
            dataTree.path = "< multiple >"
        }
        dataTree.rss += smaps.rss
        dataTree.dirty += smaps.dirty
        dataTree.swapper += smaps.swapper
        dataTree.size += smaps.size
        dataTree.pss += smaps.pss
        dataTree.children.push(obj)
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
        <lit-table id="tb-smaps-statistics" style="height: auto" tree>
            <lit-table-column width="250px" title="Type" data-index="type" key="type" align="flex-start" >
            </lit-table-column> 
             <lit-table-column width="0.3fr" title="% of Res." data-index="rssproStr" key="rssproStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="0.5fr" title="# Regs" data-index="regStr" key="regStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="2fr" title="Path" data-index="path" key="path" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="0.5fr" title="Resident Size" data-index="rssStr" key="rssStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="0.5fr" title="Dirty Size" data-index="dirtyStr" key="dirtyStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="0.5fr" title="Swapped" data-index="swapperStr" key="swapperStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column  width="0.5fr" title="Virtual Size" data-index="sizeStr" key="sizeStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column  width="0.5fr" title="Pss" data-index="pssStr" key="pssStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column width="0.5fr" title="Res. %" data-index="resproStr" key="resproStr" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }
}