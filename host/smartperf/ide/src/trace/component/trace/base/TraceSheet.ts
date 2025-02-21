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
import {LitTabs} from "../../../../base-ui/tabs/lit-tabs.js";
import {CpuStruct} from "../../../bean/CpuStruct.js";
import {LitTabpane} from "../../../../base-ui/tabs/lit-tabpane.js";
import {BoxJumpParam, SelectionParam} from "../../../bean/BoxSelection.js";
import {TabPaneCurrentSelection} from "../sheet/TabPaneCurrentSelection.js";
import {FuncStruct} from "../../../bean/FuncStruct.js";
import {ProcessMemStruct} from "../../../bean/ProcessMemStruct.js";
import {ThreadStruct} from "../../../bean/ThreadStruct.js";
import {TabPaneFlag} from "../timer-shaft/TabPaneFlag.js";
import {Flag} from "../timer-shaft/Flag.js";
import {WakeupBean} from "../../../bean/WakeupBean.js";
import {LitIcon} from "../../../../base-ui/icon/LitIcon.js";
import {CpuFreqStruct} from "../../../bean/CpuFreqStruct.js";
import {tabConfig} from "./TraceSheetConfig.js";
import {TabPaneBoxChild} from "../sheet/cpu/TabPaneBoxChild.js";
import {CpuStateStruct} from "../../../database/ui-worker/ProcedureWorkerCpuState.js";
import {SpFreqChart} from "../../chart/SpFreqChart.js";
import {CpuFreqLimitsStruct} from "../../../database/ui-worker/ProcedureWorkerCpuFreqLimits.js";


@element("trace-sheet")
export class TraceSheet extends BaseElement {
    private litTabs: LitTabs | undefined | null
    private nav: HTMLDivElement | undefined | null
    private selection: SelectionParam | undefined | null;
    private currentPaneID: string = "current-selection";

    static get observedAttributes() {
        return ['mode'];
    }

    buildTabs(litTabs: LitTabs | undefined | null) {
        Reflect.ownKeys(tabConfig).forEach((key, index) => {
            let pane = new LitTabpane();
            pane.id = key.toString();
            pane.className = "tabHeight";
            pane.tab = tabConfig[key].title;
            pane.hidden = true;
            pane.key = `${tabConfig[key].key || index}`;
            let cls = tabConfig[key].type;
            let node = new cls();
            pane.append(node)
            litTabs!.append(pane);
        })
    }

    displayTab<T>(...names: string[]): T {
        this.setAttribute("mode", "max")
        this.shadowRoot?.querySelectorAll<LitTabpane>("#tabs lit-tabpane").forEach(it => it.hidden = !names.some(k => k === it.id))
        let litTabpane = this.shadowRoot?.querySelector<LitTabpane>(`#tabs lit-tabpane[id='${names[0]}']`);
        this.shadowRoot?.querySelector<LitTabs>("#tabs")?.activePane(litTabpane!.key)
        return litTabpane!.children.item(0) as unknown as T;
    }

    getComponentByID<T>(id: string): T {
        return (this.getPaneByID(id)!.children.item(0) as unknown as T);
    }

    getPaneByID(id: string): LitTabpane {
        return this.shadowRoot!.querySelector(`#${id}`)!;
    }

    initElements(): void {
        this.litTabs = this.shadowRoot?.querySelector("#tabs");
        this.buildTabs(this.litTabs);
        let minBtn = this.shadowRoot?.querySelector("#min-btn");
        minBtn?.addEventListener('click', () => {
        });
        this.litTabs!.onTabClick = (e: any) => this.loadTabPaneData(e.detail.key)
        this.litTabs!.addEventListener("close-handler", () => {
            Reflect.ownKeys(tabConfig).reverse().forEach(id => {
                let element = tabConfig[id];
                let pane = this.shadowRoot!.querySelector<LitTabpane>(`#${id as string}`);
                if (element.require) {
                    pane!.hidden = !element.require(this.selection);
                } else {
                    pane!.hidden = true;
                }
            })
            this.litTabs?.activeByKey(`${this.getPaneByID(this.currentPaneID).key}`);
        })
        this.getComponentByID<any>("box-spt")!.addEventListener("row-click", this.rowClickHandler.bind(this));
        this.getComponentByID<any>("box-pts")!.addEventListener("row-click", this.rowClickHandler.bind(this));
        this.getComponentByID<any>("box-cs")!.addEventListener("row-click", this.rowClickHandler.bind(this));
        this.getComponentByID<any>("box-ts")!.addEventListener("row-click", this.rowClickHandler.bind(this));
        this.getComponentByID<any>("box-native-statstics")!.addEventListener("row-click", (e: any) => {
            this.selection!.statisticsSelectData = e.detail
            let pane = this.getPaneByID("box-native-memory");
            this.litTabs?.activeByKey(pane.key);
            (pane.children.item(0) as any)!.fromStastics(this.selection)
        });
        this.getComponentByID<any>("box-virtual-memory-statistics")!.addEventListener("row-click", (e: any) => {
            this.selection!.fileSystemVMData = {path:e.detail.path}
            let pane = this.getPaneByID("box-vm-events");
            this.litTabs?.activeByKey(pane.key);
            if (e.detail.path) {
                (pane.children.item(0) as any)!.fromStastics(this.selection)
            }
        });
    }

    connectedCallback() {
        this.nav = this.shadowRoot?.querySelector("#tabs")?.shadowRoot?.querySelector('.tab-nav-container')
        let tabs: HTMLDivElement | undefined | null = this.shadowRoot?.querySelector('#tabs')
        let navRoot: HTMLDivElement | null | undefined = this.shadowRoot?.querySelector("#tabs")?.shadowRoot?.querySelector('.nav-root')
        let search: HTMLDivElement | undefined | null = document.querySelector("body > sp-application")?.shadowRoot?.querySelector("div > div.search-container")
        let timerShaft: HTMLDivElement | undefined | null = this.parentElement?.querySelector(".timer-shaft")
        let spacer: HTMLDivElement | undefined | null = this.parentElement?.querySelector(".spacer")
        let borderTop: number = 1;
        let initialHeight = {tabs: `calc(30vh + 39px)`, node: "30vh"};
        this.nav!.onmousedown = (event) => {
            (window as any).isSheetMove = true;
            let litTabpane: NodeListOf<HTMLDivElement> | undefined | null = this.shadowRoot?.querySelectorAll("#tabs > lit-tabpane")
            let preY = event.pageY;
            let preHeight = tabs!.offsetHeight;
            document.onmousemove = function (event) {
                let moveY: number = preHeight - (event.pageY - preY)
                litTabpane!.forEach((node: HTMLDivElement) => {
                    if (navRoot!.offsetHeight <= moveY && (search!.offsetHeight + timerShaft!.offsetHeight + borderTop + spacer!.offsetHeight) <= (window.innerHeight - moveY)) {
                        tabs!.style.height = moveY + "px"
                        node!.style.height = (moveY - navRoot!.offsetHeight) + "px"
                        tabsPackUp!.name = "down"
                    } else if (navRoot!.offsetHeight >= moveY) {
                        tabs!.style.height = navRoot!.offsetHeight + "px"
                        node!.style.height = "0px"
                        tabsPackUp!.name = "up"
                    } else if ((search!.offsetHeight + timerShaft!.offsetHeight + borderTop + spacer!.offsetHeight) >= (window.innerHeight - moveY)) {
                        tabs!.style.height = (window.innerHeight - search!.offsetHeight - timerShaft!.offsetHeight - borderTop - spacer!.offsetHeight) + "px"
                        node!.style.height = (window.innerHeight - search!.offsetHeight - timerShaft!.offsetHeight - navRoot!.offsetHeight - borderTop - spacer!.offsetHeight) + "px"
                        tabsPackUp!.name = "down"
                    }
                })
            }
            document.onmouseup = function () {
                (window as any).isSheetMove = false;
                litTabpane!.forEach((node: HTMLDivElement) => {
                    if (node!.style.height !== "0px" && tabs!.style.height != "") {
                        initialHeight.node = node!.style.height;
                        initialHeight.tabs = tabs!.style.height;
                    }
                })
                this.onmousemove = null;
                this.onmouseup = null;
            }
        }
        let tabsOpenUp: LitIcon | undefined | null = this.shadowRoot?.querySelector<LitIcon>("#tabs > div > lit-icon:nth-child(1)")
        let tabsPackUp: LitIcon | undefined | null = this.shadowRoot?.querySelector<LitIcon>("#tabs > div > lit-icon:nth-child(2)")
        tabsOpenUp!.onclick = () => {
            tabs!.style.height = (window.innerHeight - search!.offsetHeight - timerShaft!.offsetHeight - borderTop) + "px"
            let litTabpane: NodeListOf<HTMLDivElement> | undefined | null = this.shadowRoot?.querySelectorAll("#tabs > lit-tabpane")
            litTabpane!.forEach((node: HTMLDivElement) => {
                node!.style.height = (window.innerHeight - search!.offsetHeight - timerShaft!.offsetHeight - navRoot!.offsetHeight - borderTop) + "px"
                initialHeight.node = node!.style.height;
            })
            initialHeight.tabs = tabs!.style.height;
            tabsPackUp!.name = "down"
        }
        tabsPackUp!.onclick = () => {
            let litTabpane: NodeListOf<HTMLDivElement> | undefined | null = this.shadowRoot?.querySelectorAll("#tabs > lit-tabpane")
            if (tabsPackUp!.name == "down") {
                tabs!.style.height = navRoot!.offsetHeight + "px"
                litTabpane!.forEach((node: HTMLDivElement) => node!.style.height = "0px")
                tabsPackUp!.name = "up";
                (window as any).isPackUpTable = true;
            } else {
                tabsPackUp!.name = "down"
                tabs!.style.height = initialHeight.tabs;
                litTabpane!.forEach((node: HTMLDivElement) => node!.style.height = initialHeight.node)
            }
        }
    }

    initHtml(): string {
        return `
            <style>
                :host([mode='hidden']){
                    display: none;
                }
                :host{
                    display: block;
                    background-color: rebeccapurple;
                }
                .tabHeight{
                    height: 30vh;
                    background-color: var(--dark-background,#FFFFFF);
                }
            </style>
            <div style="border-top: 1px solid var(--dark-border1,#D5D5D5);">
                <lit-tabs id="tabs" position="top-left" activekey="1" mode="card" >
                    <div slot="right" style="margin: 0 10px; color: var(--dark-icon,#606060);display: flex;align-items: center;">
                        <lit-icon id="max-btn" name="vertical-align-top" style="font-weight: bold;cursor: pointer;margin-right: 5px" size="20">
                        </lit-icon>
                        <lit-icon id="min-btn" name="down" style="font-weight: bold;cursor: pointer;" size="20">
                        </lit-icon>
                    </div>
                </lit-tabs>
            </div>`;
    }

    displayThreadData = (data: ThreadStruct, scrollCallback: ((e: ThreadStruct) => void) | undefined, scrollWakeUp: (d: any) => void | undefined) =>
        this.displayTab<TabPaneCurrentSelection>("current-selection").setThreadData(data, scrollCallback, scrollWakeUp)
    displayMemData = (data: ProcessMemStruct) =>
        this.displayTab<TabPaneCurrentSelection>("current-selection").setMemData(data);
    displayFuncData = (data: FuncStruct, scrollCallback: Function) =>
        this.displayTab<TabPaneCurrentSelection>("current-selection").setFunctionData(data, scrollCallback);
    displayCpuData = (data: CpuStruct, callback: ((data: WakeupBean | null) => void) | undefined = undefined, scrollCallback?: (data: CpuStruct) => void) =>
        this.displayTab<TabPaneCurrentSelection>("current-selection").setCpuData(data, callback, scrollCallback);
    displayFlagData = (flagObj: Flag) => this.displayTab<TabPaneFlag>("box-flag").setFlagObj(flagObj);
    displayFreqData = () => this.displayTab<TabPaneCurrentSelection>("box-freq").data = CpuFreqStruct.selectCpuFreqStruct;
    displayCpuStateData = () => this.displayTab<TabPaneCurrentSelection>("cpu-state-click").data = SpFreqChart.selectStateStruct;
    displayFreqLimitData = () => this.displayTab<TabPaneCurrentSelection>("box-freq-limit").data = CpuFreqLimitsStruct.selectCpuFreqLimitsStruct;

    rangeSelect(selection: SelectionParam): boolean {
        this.selection = selection;
        Reflect.ownKeys(tabConfig).reverse().forEach(id => {
            let element = tabConfig[id];
            if (element.require) {
                if (element.require(selection)) {
                    let pane = this.shadowRoot!.querySelector<LitTabpane>(`#${id as string}`);
                    pane!.hidden = false;
                } else {
                    this.shadowRoot!.querySelector<LitTabpane>(`#${id as string}`)!.hidden = true;
                }
            } else {
                this.shadowRoot!.querySelector<LitTabpane>(`#${id as string}`)!.hidden = true;
            }
        })
        let firstPane = this.shadowRoot!.querySelector<LitTabpane>(`lit-tabpane[hidden='false']`);
        if (firstPane) {
            this.litTabs?.activeByKey(firstPane.key)
            this.loadTabPaneData(firstPane.key)
            this.setAttribute("mode", "max")
            return true;
        } else {
            this.setAttribute("mode", "hidden")
            return false;
        }
    }

    loadTabPaneData(key: string) {
        let component: any = this.shadowRoot?.querySelector<LitTabpane>(`#tabs lit-tabpane[key='${key}']`)?.children.item(0);
        if (component) {
            component.data = this.selection;
        }
    }

    rowClickHandler(e: any) {
        this.currentPaneID = e.target.parentElement.id
        this.shadowRoot!.querySelectorAll<LitTabpane>(`lit-tabpane`)
            .forEach(it => it.id != this.currentPaneID ? (it.hidden = true) : (it.hidden = false));
        let pane = this.getPaneByID("box-cpu-child");
        pane.closeable = true;
        pane.hidden = false;
        this.litTabs!.activeByKey(pane.key)
        pane.tab = e.detail.title
        let param = new BoxJumpParam();
        param.leftNs = this.selection!.leftNs;
        param.rightNs = this.selection!.rightNs;
        param.state = e.detail.state;
        param.threadId = e.detail.threadId;
        param.processId = e.detail.processId;
        (pane.children.item(0) as TabPaneBoxChild).data = param;
    }
}
