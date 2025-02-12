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

import {BaseElement, element} from "../../../base-ui/BaseElement.js";
import {checkDesBean, SpCheckDesBox} from "./SpCheckDesBox.js";
import {LitCheckBox} from "../../../base-ui/checkbox/LitCheckBox.js";
import {LitRadioGroup} from "../../../base-ui/radiobox/LitRadioGroup.js";
import {info, log} from "../../../log/Log.js";

@element('probes-config')
export class SpProbesConfig extends BaseElement {
    private traceConfigList: Array<checkDesBean> | undefined
    private memoryConfigList: Array<checkDesBean> | undefined
    private hitraceConfigList: Array<any> | undefined;
    private hitrace: SpCheckDesBox | undefined

    private _traceConfig: HTMLElement | undefined;
    private _memoryConfig: HTMLElement | undefined | null;

    get traceConfig() {
        let selectedTrace = this._traceConfig?.querySelectorAll<SpCheckDesBox>(`check-des-box[checked]`) || [];
        let values = []
        for (const litCheckBoxElement of selectedTrace) {
            values.push(litCheckBoxElement.value)
        }
        if (this.hitrace && this.hitrace.checked) {
            values.push(this.hitrace.value)
        }
        info("traceConfig is :", values)
        return values;
    }

    get memoryConfig() {
        let values = []
        let selectedMemory = this._memoryConfig?.querySelectorAll<SpCheckDesBox>(`check-des-box[checked]`) as NodeListOf<SpCheckDesBox>
        for (const litCheckBoxElement of selectedMemory) {
            values.push(litCheckBoxElement.value)
        }
        log("memoryConfig size is :" + values.length)
        return values
    }

    get traceEvents() {
        let values = []
        if (this.hitrace && this.hitrace.checked) {
            let parent = this.shadowRoot?.querySelector('.user-events') as Element
            const siblingNode = parent?.querySelectorAll<LitCheckBox>(`lit-check-box[name=userEvents][checked]`);
            for (const litCheckBoxElement of siblingNode) {
                values.push(litCheckBoxElement.value)
            }
        }
        log("traceEvents size is :" + values.length)
        return values;
    }

    get hilogConfig() {
        let logLevel = this.shadowRoot?.getElementById('logLevel') as LitCheckBox;
        if (logLevel.checked) {
            let logRadio = this.shadowRoot?.getElementById('log-radio') as LitRadioGroup;
            return logRadio.value;
        } else {
            return []
        }
    }

    initElements(): void {
        this.traceConfigList = [
            {value: 'Scheduling details', isSelect: false, des: "enables high-detailed tracking of scheduling events"},
            {
                value: "CPU Frequency and idle states", isSelect: false,
                des: "Records cpu frequency and idle state change viaftrace"
            },
            {
                value: "Advanced ftrace config", isSelect: false,
                des: "Enable individual events and tune the kernel-tracng(ftrace) module."
                    + "The events enabled here are in addition to those from"
                    + " enabled by other probes."
            },
            {
                value: "AbilityMonitor",
                isSelect: false,
                des: "Tracks the AbilityMonitor"
            },
            {
                value: "HiSystemEvent",
                isSelect: false,
                des: "Tracks the HiSystemEvent"
            }]
        this._traceConfig = this.shadowRoot?.querySelector(".trace-config") as HTMLElement
        this.traceConfigList.forEach(configBean => {
            let checkDesBox = new SpCheckDesBox();
            checkDesBox.value = configBean.value;
            checkDesBox.checked = configBean.isSelect;
            checkDesBox.des = configBean.des;
            checkDesBox.addEventListener("onchange", (ev: any) => {
                this.dispatchEvent(new CustomEvent('addProbe', {}));
            })
            this._traceConfig?.appendChild(checkDesBox)
        })
        this.memoryConfigList = [
            {value: 'Kernel meminfo', isSelect: false, des: "polling of /proc/meminfo"},
            {
                value: 'Virtual memory stats',
                isSelect: false,
                des: "Periodically polls virtual memory stats from /proc/vmstat."
                    + " Allows to gather statistics about swap,"
                    + "eviction, compression and pagecache efficiency"
            }]
        this._memoryConfig = this.shadowRoot?.querySelector(".memory-config")
        this.memoryConfigList.forEach(configBean => {
            let checkDesBox = new SpCheckDesBox();
            checkDesBox.value = configBean.value;
            checkDesBox.checked = configBean.isSelect;
            checkDesBox.des = configBean.des;
            checkDesBox.addEventListener("onchange", (ev: any) => {
                this.dispatchEvent(new CustomEvent('addProbe', {}));
            })
            this._memoryConfig?.appendChild(checkDesBox)
        })
        this.hitraceConfigList = ["ability", "ace", "app", "ark", "binder", "disk", "distributeddatamgr"
            , "dsoftbus", "freq", "graphic", "i2c", "idle", "irq", "mdfs", "memory", "memreclaim", "misc", "mmc",
            "msdp", "multimodalinput", "notification", "ohos", "pagecache", "regulators", "rpc", "sched", "sensors", "sync"
            , "window", "workq", "zaudio", "zcamera", "zimage", "zmedia"]
        this.hitrace = this.shadowRoot?.getElementById("hitrace") as SpCheckDesBox
        let parent = this.shadowRoot?.querySelector('.user-events') as Element
        this.hitraceConfigList?.forEach(value => {
            let litCheckBox = new LitCheckBox();
            litCheckBox.setAttribute("name", "userEvents")
            litCheckBox.value = value;
            litCheckBox.addEventListener("change", (ev: any) => {
                let detail = ev.detail;
                if (this.hitrace?.checked == false) {
                    this.hitrace.checked = detail.checked
                }
                if (detail.checked == false && this.hitrace?.checked == true) {
                    let hasChecked = false;
                    const nodes = parent?.querySelectorAll<LitCheckBox>(`lit-check-box[name=userEvents]`);
                    nodes.forEach(vv => {
                        if (vv.checked) {
                            hasChecked = true;
                        }
                    })
                    if (!hasChecked) {
                        this.hitrace.checked = hasChecked
                    }
                }
                this.dispatchEvent(new CustomEvent('addProbe', {}));
            })
            parent.append(litCheckBox)
        })
    }

    initHtml(): string {
        return `
        <style>
        :host{
            display: inline-block;
            width: 100%;
            height: 100%;
            background: var(--dark-background3,#FFFFFF);
            border-radius: 0px 16px 16px 0px;
        }

        .root {
            padding-top: 30px;
            padding-left: 54px;
            margin-right: 30px;
            font-size:16px;
            margin-bottom: 30px;
        }
        .recordText {
           font-family: Helvetica-Bold;
           font-size: 1em;
           color: var(--dark-color1,#000000);
           line-height: 28px;
           font-weight: 700;
           margin-bottom: 20px;
        }

        .config-page {
            height: 95%;
            font-size: 0.875em;
        }

        .trace-config{
           display: grid;
           grid-template-columns: repeat(2, 1fr);
           gap: 10px;
           margin-bottom: 20px;
        }

        .memory-config{
           display: grid;
           grid-template-columns: repeat(2, 1fr);
           border-style: solid none none none;
           border-color: #D5D5D5;
           padding-top: 15px;
           margin-top: 15px;
           gap: 10px;
        }

        .span-col-2{
           grid-column: span 2 / auto;
        }

        .log-config{
           display: grid;
           grid-template-columns: repeat(2, 1fr);
           border-style: solid none none none;
           border-color: #D5D5D5;
           padding-top: 15px;
           gap: 10px;
        }

        #hitrace-cat{
           display: grid;
           grid-template-columns: 1fr 1fr;
        }
        .user-events{
           display: grid;
           grid-template-columns: repeat(4, 1fr);
           grid-template-rows: repeat(2, 1fr);
           gap: 10px;
           margin-left: 15px;;
        }
        </style>
        <div class="root">
            <div class="recordText" >Record mode</div>
            <div class="config-page">
                <div>
                    <div class="trace-config"></div>
                    <div class="span-col-2" id="hitrace-cat">
                      <check-des-box id="hitrace" value ="Hitrace categories" des="Enables C++ codebase annotations (HTRACE_BEGIN() / os.Trace())">
                      </check-des-box>
                      <div class="user-events">
                          <slot></slot>
                      </div>
                    </div>
                </div>
                <div class="memory-config">
                    <div class="span-col-2">
                      <span>Memory Config</span>
                    </div>
                </div>
            </div>
        </div>
        `;
    }

    //当 custom element首次被插入文档DOM时，被调用。
    public connectedCallback() {
        let parent = this.shadowRoot?.querySelector('.user-events') as Element
        const siblingNode = parent?.querySelectorAll<LitCheckBox>(`lit-check-box[name=userEvents]`);
        this.hitrace!.addEventListener('onchange', (ev: any) => {
            let detail = ev.detail;
            siblingNode.forEach(node => {
                node.checked = detail.checked
            })
            this.dispatchEvent(new CustomEvent('addProbe', {}));
        })
    }
}