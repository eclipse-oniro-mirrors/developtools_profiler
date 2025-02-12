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
import {getTabDiskAbilityData} from "../../../database/SqlLite.js";
import {SystemDiskIOSummary} from "../../../bean/AbilityMonitor.js";
import {Utils} from "../base/Utils.js";
import {ColorUtils} from "../base/ColorUtils.js";
import "../../../component/SpFilter.js";
import {log} from "../../../../log/Log.js";

@element('tabpane-disk-ability')
export class TabPaneDiskAbility extends BaseElement {
    private tbl: LitTable | null | undefined;
    private source: Array<SystemDiskIOSummary> = [];
    private queryResult: Array<SystemDiskIOSummary> = []
    private search: HTMLInputElement | undefined | null

    set data(val: SelectionParam | any) {
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
        this.queryDataByDB(val)
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-disk-ability');
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl!.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
                this.tbl!.reMeauseHeight()
            }
        }).observe(this.parentElement!)
        this.tbl!.addEventListener('column-click', (evt) => {
            // @ts-ignore
            this.sortByColumn(evt.detail)
        });
    }

    filterData() {
        if (this.queryResult.length > 0) {
            let filter = this.queryResult.filter((item) => {
                let array = this.toDiskAbilityArray(item)
                let isInclude = array.filter(value => value.indexOf(this.search!.value) > -1);
                return isInclude.length > 0
            });
            if (filter.length > 0) {
                this.source = filter;
                this.tbl!.recycleDataSource = this.source;
            } else {
                this.source = []
                this.tbl!.recycleDataSource = [];
            }
        }
    }

    toDiskAbilityArray(systemDiskIOSummary: SystemDiskIOSummary): any[] {
        let array: Array<string> = []
        array.push(systemDiskIOSummary.startTimeStr)
        array.push(systemDiskIOSummary.durationStr)
        array.push(systemDiskIOSummary.dataReadStr)
        array.push(systemDiskIOSummary.dataReadSecStr)
        array.push(systemDiskIOSummary.dataWriteStr)
        array.push(systemDiskIOSummary.readsInStr)
        array.push(systemDiskIOSummary.readsInSecStr)
        array.push(systemDiskIOSummary.writeOutStr)
        array.push(systemDiskIOSummary.writeOutSecStr)
        return array
    }

    queryDataByDB(val: SelectionParam | any) {
        getTabDiskAbilityData(val.leftNs, val.rightNs).then((result) => {
            log("getTabDiskAbilityData result size : " + result.length)
            if (result.length != null && result.length > 0) {
                for (const systemDiskIOSummary of result) {
                    if (systemDiskIOSummary.startTime <= 0) {
                        systemDiskIOSummary.startTimeStr = '0:000.000.000';
                    } else {
                        systemDiskIOSummary.startTimeStr = Utils.getTimeStampHMS(systemDiskIOSummary.startTime);
                    }
                    systemDiskIOSummary.durationStr = Utils.getDurString(systemDiskIOSummary.duration);
                    systemDiskIOSummary.dataReadStr = systemDiskIOSummary.dataRead + "KB";
                    systemDiskIOSummary.dataReadSecStr = systemDiskIOSummary.dataReadSec + "KB/S";
                    systemDiskIOSummary.dataWriteStr = systemDiskIOSummary.dataWrite + "KB";
                    systemDiskIOSummary.dataWriteSecStr = systemDiskIOSummary.dataWriteSec + "KB/S";
                    systemDiskIOSummary.readsInStr = ColorUtils.formatNumberComma(systemDiskIOSummary.readsIn);
                    systemDiskIOSummary.readsInSecStr = systemDiskIOSummary.readsInSec.toString();
                    systemDiskIOSummary.writeOutStr = ColorUtils.formatNumberComma(systemDiskIOSummary.writeOut);
                    systemDiskIOSummary.writeOutSecStr = systemDiskIOSummary.writeOutSec.toString();
                }
                this.source = result;
                this.queryResult = result;
                this.tbl!.recycleDataSource = result;
            } else {
                this.source = [];
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
        <lit-table id="tb-disk-ability" style="height: auto">
            <lit-table-column order width="1fr" title="StartTime" data-index="startTimeStr" key="startTimeStr" align="flex-start">
            </lit-table-column>
            <lit-table-column order width="1fr" title="Duration" data-index="durationStr" key="durationStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Data Read" data-index="dataReadStr" key="dataReadStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Data Read/sec" data-index="dataReadSecStr" key="dataReadSecStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Data Write" data-index="dataWriteStr" key="dataWriteStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Data Write/sec" data-index="dataWriteSecStr" key="dataWriteSecStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Reads In" data-index="readsIn" key="readsInStr" align="flex-startStr" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Reads In/sec" data-index="readsInSecStr" key="readsInSecStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Write Out" data-index="writeOutStr" key="writeOutStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Write Out/sec" data-index="writeOutSecStr" key="writeOutSecStr" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }

    sortByColumn(detail: any) {
        // @ts-ignore
        function compare(property, sort, type) {
            return function (a: SystemDiskIOSummary, b: SystemDiskIOSummary) {
                if (type === 'number') {
                    // @ts-ignore
                    return sort === 2 ? parseFloat(b[property]) - parseFloat(a[property]) : parseFloat(a[property]) - parseFloat(b[property]);
                } else if (type === 'durationStr') {
                    return sort === 2 ? b.duration - a.duration : a.duration - b.duration;
                } else if (type === 'dataReadStr') {
                    return sort === 2 ? b.dataRead - a.dataRead : a.dataRead - b.dataRead;
                } else if (type === 'dataReadSecStr') {
                    return sort === 2 ? b.dataReadSec - a.dataReadSec : a.dataReadSec - b.dataReadSec;
                } else if (type === 'dataWriteStr') {
                    return sort === 2 ? b.dataWrite - a.dataWrite : a.dataWrite - b.dataWrite;
                } else if (type === 'dataWriteSecStr') {
                    return sort === 2 ? b.dataWriteSec - a.dataWriteSec : a.dataWriteSec - b.dataWriteSec;
                } else if (type === 'readsInStr') {
                    return sort === 2 ? b.readsIn - a.readsIn : a.readsIn - b.readsIn;
                } else if (type === 'readsInSecStr') {
                    return sort === 2 ? b.readsInSec - a.readsInSec : a.readsInSec - b.readsInSec;
                } else if (type === 'writeOutStr') {
                    return sort === 2 ? b.writeOut - a.writeOut : a.writeOut - b.writeOut;
                } else if (type === 'writeOutSecStr') {
                    return sort === 2 ? b.writeOutSec - a.writeOutSec : a.writeOutSec - b.writeOutSec;
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

        if (detail.key === 'startTime') {
            this.source.sort(compare(detail.key, detail.sort, 'string'))
        } else if (detail.key === 'durationStr') {
            this.source.sort(compare(detail.key, detail.sort, 'durationStr'))
        } else if (detail.key === 'dataReadStr') {
            this.source.sort(compare(detail.key, detail.sort, 'dataReadStr'))
        } else if (detail.key === 'dataReadSecStr') {
            this.source.sort(compare(detail.key, detail.sort, 'dataReadSecStr'))
        } else if (detail.key === 'dataWriteStr') {
            this.source.sort(compare(detail.key, detail.sort, 'dataWriteStr'))
        } else if (detail.key === 'dataWriteSecStr') {
            this.source.sort(compare(detail.key, detail.sort, 'dataWriteSecStr'))
        } else if (detail.key === 'readsInStr') {
            this.source.sort(compare(detail.key, detail.sort, 'readsInStr'))
        } else if (detail.key === 'readsInSecStr') {
            this.source.sort(compare(detail.key, detail.sort, 'readsInSecStr'))
        } else if (detail.key === 'writeOutStr') {
            this.source.sort(compare(detail.key, detail.sort, 'writeOutStr'))
        } else if (detail.key === 'writeOutSecStr') {
            this.source.sort(compare(detail.key, detail.sort, 'writeOutSecStr'))
        } else {
            this.source.sort(compare(detail.key, detail.sort, 'number'))
        }
        this.tbl!.recycleDataSource = this.source;
    }

}