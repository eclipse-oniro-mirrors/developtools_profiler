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

import {BaseElement, element} from "../../base-ui/BaseElement.js";
import {querySelectTraceStats, queryTraceMetaData,} from "../database/SqlLite.js";
import {LitTable} from "../../base-ui/table/lit-table.js";
import "../../base-ui/table/lit-table.js";
import {info} from "../../log/Log.js";
import {LitProgressBar} from "../../base-ui/progress-bar/LitProgressBar.js";

@element('sp-info-and-stats')
export class SpInfoAndStats extends BaseElement {
    private metaData: Array<MetaDataTable> = [];
    private infoData: Array<InfoDataTable> = [];
    private metaTableEl: LitTable | undefined;
    private infoTableEl: LitTable | undefined;
    private th: HTMLElement | undefined;
    private backgroundMetaTable: HTMLDivElement | undefined;
    private backgroundInfoTable: HTMLDivElement | undefined;
    private progressLoad: LitProgressBar | undefined;

    static get observedAttributes() {
        return []
    }

    initElements(): void {
        this.progressLoad = this.shadowRoot?.querySelector(".load-metric") as LitProgressBar;
        this.metaTableEl = this.shadowRoot!.querySelector<LitTable>('#metaData-table') as LitTable;
        this.infoTableEl = this.shadowRoot!.querySelector<LitTable>('#stats-table') as LitTable;

        this.infoTableEl.style.overflow = 'visible'
        this.metaTableEl.style.overflow = 'visible'
        this.infoTableEl.style.width = 'auto'
        this.metaTableEl.style.width = 'auto'
        this.th = this.shadowRoot!.querySelector('.th') as HTMLElement;
    }

    initInfoAndStatsData() {
        this.progressLoad!.loading = true
        let time = new Date().getTime();
        this.initMetricItemData().then(() => {
            let durTime = new Date().getTime() - time;
            info("InfoAndStatsData query time is: " + durTime + "ms")
            if (this.metaData.length > 0) {
                this.metaTableEl!.recycleDataSource = this.metaData;
            } else {
                this.metaTableEl!.recycleDataSource = [];
            }
            new ResizeObserver(() => {
                if (this.parentElement?.clientHeight != 0) {
                    this.metaTableEl!.style.height = '100%'
                    this.metaTableEl!.reMeauseHeight()
                }
            }).observe(this.parentElement!)
            info("metaData(metric) size is: ", this.metaData.length)
            if (this.infoData.length > 0) {
                this.infoTableEl!.recycleDataSource = this.infoData;
            } else {
                this.infoTableEl!.recycleDataSource = []
            }
            new ResizeObserver(() => {
                if (this.parentElement?.clientHeight != 0) {
                    this.infoTableEl!.reMeauseHeight()
                }
            }).observe(this.parentElement!)
            info("infoData(metric) size is: ", this.infoData.length)
            let metaDataStyle: HTMLDivElement | undefined | null = this.shadowRoot?.querySelector('#metaData-table')?.shadowRoot?.querySelector('div.body') as HTMLDivElement
            let metaDataHeadStyle: HTMLDivElement | undefined | null = this.shadowRoot?.querySelector('#metaData-table')?.shadowRoot?.querySelector('div.thead') as HTMLDivElement
            let statsStyle: HTMLDivElement | undefined | null = this.shadowRoot?.querySelector('#stats-table')?.shadowRoot?.querySelector('div.body') as HTMLDivElement
            let statsHeadStyle: HTMLDivElement | undefined | null = this.shadowRoot?.querySelector('#stats-table')?.shadowRoot?.querySelector('div.thead') as HTMLDivElement

            setTimeout(()=>{
                this.initDataTableStyle(metaDataStyle!);
                this.initDataTableStyle(metaDataHeadStyle!);
                this.initDataTableStyle(statsStyle!);
                this.initDataTableStyle(statsHeadStyle!);
            }, 20)

            this.progressLoad!.loading = false
        });
    }

    initDataTableStyle(styleTable: HTMLDivElement): void {
        for (let index = 0; index < styleTable.children.length; index++) {
            // @ts-ignore
            styleTable.children[index].style.backgroundColor = 'var(--dark-background5,#F6F6F6)'
        }
        this.metaTableEl!.style.height = 'auto'
        this.metaTableEl!.style.minHeight = '80%'
        this.metaTableEl!.style.borderRadius = '16'
        this.infoTableEl!.style.height = 'auto'
        this.infoTableEl!.style.minHeight = '80%'
        this.infoTableEl!.style.borderRadius = '16'
    }

    async initMetricItemData() {
        this.metaData = []
        this.infoData = []
        let mete = await queryTraceMetaData();
        if (mete) {
            for (let index = 0; index < mete.length; index++) {
                this.metaData.push({name: mete[index].name, value: mete[index].valueText})
            }
        }
        let info = await querySelectTraceStats();
        if (info) {
            for (let index = 0; index < info.length; index++) {
                this.infoData.push({
                    event_name: info[index].event_name,
                    stat_type: info[index].stat_type,
                    count: info[index].count
                })
            }
        }
    }

    connectedCallback() {
    }

    disconnectedCallback() {
    }

    attributeChangedCallback(name: string, oldValue: string, newValue: string) {
    }

    initHtml(): string {
        return `
        <style>
            :host{
                width: 100%;
                background-color: var(--dark-background5,#F6F6F6);
                margin: 0;
                padding: 0;
            }
        
            .info-stats{
                display: flex;
                flex-direction: column;
                background-color: var(--dark-background5,#F6F6F6);
                position: absolute;
                top: 0;
                bottom: 0;
                left: 0;
                right: 0;
                grid-row-gap: 30px;
            }
        
            .metadata{
                width: 90%;
                color: #121212;
                padding: 1% 2% 0 2%;
                margin: 1% 2.5% 0 2.5%;
                border-radius: 16px;
                background-color: var(--dark-background3,#FFFFFF);
                position: relative;
            }
       
            #metaData-table{
                background-color: var(--dark-background5,#F6F6F6);
                margin-left: 10px;
                min-height: inherit;
                max-height: inherit;
                padding: 10px;
            }
            
            #stats-table{
                margin-bottom: 2%;
                margin-left: 10px;
                padding: 10px;
            }
            
            #dataValueResult{
                overflow-y: auto;
                background-color: var(--dark-background5,#F6F6F6);
                border-radius: 16px;
                min-height: inherit;
                max-height: inherit;
                margin-bottom: 1%;
            }
            
            #dataKeyResult{
                overflow-y: auto;
                background-color: var(--dark-background5,#F6F6F6);
                border-radius: 16px;
                min-height: inherit;
                max-height: inherit;
                margin-bottom: 2%;
            }
            
            p{
                 display: table-cell;
                 padding: 7px 10px 20px 10px;
                 color: #999999;
                 font-size:14px;
                 line-height: 20px;
                 font-weight: 400;
                 text-align: left;
            }
            
            .stats{
               flex-grow: 1;
               height: min-content;
               margin-bottom: 1%;
               max-height: 37vh;
               min-height: inherit;
               display: flex;
               flex-direction: column;
            }
            
            .info{
               max-height: inherit;
               min-height: inherit;
            }
            
            .tr{
               background-color: var(--dark-background5,#F6F6F6); 
            }
            
            .load-metric{
                width: 95%;
                bottom: 0;
            }

        </style>

        <div class="info-stats">
            <div class="metadata info">
                <p>System info and metadata</p>
                <div id="dataKeyResult">
                    <lit-table id="metaData-table">
                            <lit-table-column title="name" data-index="name" key="name" align="flex-start">
                            </lit-table-column>
                            <lit-table-column title="value" data-index="value" key="value" align="flex-start">
                            </lit-table-column>
                    </lit-table>
                </div>
                <lit-progress-bar class="load-metric"></lit-progress-bar>
            </div>
            <div class="metadata stats">
                <p>Debugging stats</p>
                <div id="dataValueResult">
                    <lit-table id="stats-table">
                            <lit-table-column title="name" data-index="event_name" key="name" align="flex-start">
                            </lit-table-column>
                            <lit-table-column title="value" data-index="count" key="value" align="flex-start">
                            </lit-table-column>
                            <lit-table-column title="type" data-index="stat_type" key="type" align="flex-start">
                            </lit-table-column>
                    </lit-table>
                </div>
            </div>
        </div>
        `;
    }
}

export class MetaDataTable {
    name: string | undefined;
    value: string | undefined;
    type?: string | undefined;
}

export class InfoDataTable {
    event_name: string | undefined;
    stat_type: string | undefined;
    count: number | undefined;
    source?: string | undefined;
    serverity?: string | undefined;
}
