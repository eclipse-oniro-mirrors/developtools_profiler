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
import {LitSelectV} from "../../../base-ui/select/LitSelectV.js";
import LitSwitch from "../../../base-ui/switch/lit-switch.js";
import "../../../base-ui/select/LitSelectV.js";
import "../../../base-ui/select/LitSelect.js";

import "../../../base-ui/switch/lit-switch.js";
import {LitSelect} from "../../../base-ui/select/LitSelect.js";
import {SpRecordTrace} from "../SpRecordTrace.js";
import {Cmd} from "../../../command/Cmd.js";
import {CmdConstant} from "../../../command/CmdConstant.js";
import {HdcDeviceManager} from "../../../hdc/HdcDeviceManager.js";

@element("sp-file-system")
export class SpFileSystem extends BaseElement {
    private processInput: LitSelectV | undefined | null;
    private maximum: HTMLInputElement | undefined | null;
    private selectProcess: HTMLInputElement | undefined | null;

    private configList: Array<any> = [];
    private list: Array<any> = [];

    private eventList: Array<any> = [
        "open",
        "close",
        "read",
        "write"
    ];

    set startRecord(start: boolean) {
        if (start) {
            this.unDisable();
            this.setAttribute("startRecord", "");
            this.selectProcess!.removeAttribute("readonly");
        } else {
            if(!this.startFileSystem && !this.startVirtualMemory) {
                this.removeAttribute("startRecord")
                this.disable();
                this.selectProcess!.setAttribute("readonly", "readonly")
            }
        }
    }

    get startRecord(): boolean {
        return this.hasAttribute("startRecord");
    }

    set startFileSystem(start: boolean) {
        if (start) {
            this.setAttribute("startSamp", "");
        } else {
            this.removeAttribute("startSamp")
        }
        this.startRecord = start;
    }

    get startFileSystem(): boolean {
        return this.hasAttribute("startSamp");
    }

    set startVirtualMemory(start: boolean) {
        if (start) {
            this.setAttribute("virtual", "");
        } else {
            this.removeAttribute("virtual")
        }
        this.startRecord = start;
    }

    get startVirtualMemory(): boolean {
        return this.hasAttribute("virtual");
    }

    set startIo(start: boolean) {
        if (start) {
            this.setAttribute("io", "");
        } else {
            this.removeAttribute("io")
        }
        this.startRecord = start;
    }

    get startIo(): boolean {
        return this.hasAttribute("io");
    }

    getSystemConfig(): SystemConfig | undefined {
        let configVal = this.shadowRoot?.querySelectorAll<HTMLElement>(".config");
        let systemConfig: SystemConfig = {
            process: "",
        };
        configVal!.forEach(value => {
            switch (value.title) {
                case "Process":
                    let processSelect = value as LitSelectV;
                    if (processSelect.all) {
                        systemConfig.process = "ALL"
                        break
                    }
                    if (processSelect.value.length > 0) {
                        let result = processSelect.value.match(/\((.+?)\)/g)
                        if (result) {
                            systemConfig.process = result.toString().replaceAll("(", "").replaceAll(")", "")
                        } else {
                            systemConfig.process = processSelect.value;
                        }
                    }
                    break;
            }
        });
        return systemConfig;
    }

    initElements(): void {
        this.initConfigList();
        let configList = this.shadowRoot?.querySelector<HTMLDivElement>(".configList");
        this.configList.forEach(config => {
            let div = document.createElement("div");
            if (config.hidden) {
                div.className = "config-div hidden";
            } else {
                div.className = "config-div";
            }
            let headDiv = document.createElement("div");
            div.appendChild(headDiv);
            let title = document.createElement("span");
            title.className = "title";
            title.textContent = config.title;
            headDiv.appendChild(title);
            let des = document.createElement("span");
            des.textContent = config.des;
            des.className = "des";
            headDiv.appendChild(des);
            switch (config.type) {
                case "select-multiple":
                    let html = '';
                    let placeholder = config.selectArray[0];
                    if (config.title == "Process") {
                    } else if (config.title == "SystemCall Event") {
                        placeholder = "ALL-Event"
                    }
                    html += `<lit-select-v default-value="" rounded="" class="select config" mode="multiple" canInsert="" title="${config.title}" rounded placement = "bottom" placeholder="${placeholder}">`
                    config.selectArray.forEach((value: string) => {
                        html += `<lit-select-option value="${value}">${value}</lit-select-option>`
                    });
                    html += `</lit-select-v>`;
                    div.innerHTML = div.innerHTML + html;
                    break;
                case "input":
                    let input = document.createElement("input");
                    input.className = "input config";
                    input.textContent = config.value;
                    input.value = config.value;
                    input.title = config.title;
                    if (config.title == "Record Time") {
                        input.oninput = (ev) => {
                            input.value = input.value.replace(/\D/g, '')
                        };
                    }
                    div.appendChild(input);
                    break;
                case "select":
                    let html1 = '';
                    html1 += `<lit-select rounded="" default-value="" class="select config" placement="bottom" title="${config.title}"  placeholder="${config.selectArray[0]}">`
                    config.selectArray.forEach((value: string) => {
                        html1 += `<lit-select-option value="${value}">${value}</lit-select-option>`
                    })
                    html1 += `</lit-select>`
                    div.innerHTML = div.innerHTML + html1;
                    break;
                case "switch":
                    let switch1 = document.createElement("lit-switch") as LitSwitch;
                    switch1.className = "config";
                    switch1.title = config.title;
                    if (config.value) {
                        switch1.checked = true;
                    } else {
                        switch1.checked = false;
                    }
                    if (config.title == "Start FileSystem Record") {
                        switch1.addEventListener("change", (event: any) => {
                            let detail = event.detail;
                            if (detail.checked) {
                                this.startFileSystem = true;
                            } else {
                                this.startFileSystem = false;
                            }
                        })
                    }
                    if (config.title == "Start Virtual Memory Record") {
                        switch1.addEventListener("change", (event: any) => {
                            let detail = event.detail;
                            if (detail.checked) {
                                this.startVirtualMemory = true;
                            } else {
                                this.startVirtualMemory = false;
                            }
                        })
                    }
                    headDiv.appendChild(switch1);
                    break;
                default:
                    break;
        }
            configList!.appendChild(div);
        });
        this.processInput = this.shadowRoot?.querySelector<LitSelectV>("lit-select-v[title='Process']");
        this.maximum = this.shadowRoot?.querySelector<HTMLInputElement>("input[title='Max Unwind Level']");
        this.selectProcess = this.processInput!.shadowRoot?.querySelector("input") as HTMLInputElement;
        let processData: Array<string> = []
        this.selectProcess!.addEventListener('mousedown', ev => {
            if (SpRecordTrace.serialNumber == '') {
                this.processInput!.dataSource([], '')
            }
        })
        this.selectProcess!.addEventListener('mouseup', () => {
            if (SpRecordTrace.serialNumber == '') {
                this.processInput?.dataSource([], 'ALL-Process')
            } else {
                if (SpRecordTrace.isVscode) {
                    let cmd = Cmd.formatString(CmdConstant.CMD_GET_PROCESS_DEVICES, [SpRecordTrace.serialNumber])
                    Cmd.execHdcCmd(cmd, (res: string) => {
                        processData = []
                        let lineValues: string[] = res.replace(/\r\n/g, "\r").replace(/\n/g, "\r").split(/\r/);
                        for (let lineVal of lineValues) {
                            if (lineVal.indexOf("__progname") != -1 || lineVal.indexOf("PID CMD") != -1) {
                                continue;
                            }
                            let process: string[] = lineVal.trim().split(" ");
                            if (process.length == 2) {
                                let processId = process[0]
                                let processName = process[1]
                                processData.push(processName + "(" + processId + ")")
                            }
                        }
                        if(processData.length > 0 && this.startRecord){
                            this.processInput!.setAttribute("readonly", "readonly")
                        }
                        this.processInput?.dataSource(processData, 'ALL-Process')
                    })
                } else {
                    HdcDeviceManager.connect(SpRecordTrace.serialNumber).then(conn => {
                        if (conn) {
                            HdcDeviceManager.shellResultAsString(CmdConstant.CMD_GET_PROCESS, false).then(res => {
                                processData = []
                                if (res) {
                                    let lineValues: string[] = res.replace(/\r\n/g, "\r").replace(/\n/g, "\r").split(/\r/);
                                    for (let lineVal of lineValues) {
                                        if (lineVal.indexOf("__progname") != -1 || lineVal.indexOf("PID CMD") != -1) {
                                            continue;
                                        }
                                        let process: string[] = lineVal.trim().split(" ");
                                        if (process.length == 2) {
                                            let processId = process[0]
                                            let processName = process[1]
                                            processData.push(processName + "(" + processId + ")")
                                        }
                                    }
                                }
                                if(processData.length > 0 && this.startRecord){
                                    this.selectProcess!.setAttribute("readonly", "readonly")
                                }
                                this.processInput?.dataSource(processData, 'ALL-Process')
                            })
                        }
                    })
                }
            }
        });
        this.disable();
    }

    private unDisable() {
        let configVal = this.shadowRoot?.querySelectorAll<HTMLElement>(".config");
        configVal!.forEach(configVal1 => {
            configVal1.removeAttribute("disabled")
        })
    }

    private disable() {
        let configVal = this.shadowRoot?.querySelectorAll<HTMLElement>(".config");
        configVal!.forEach(configVal1 => {
            if (configVal1.title == "Start FileSystem Record" || configVal1.title == "Start Virtual Memory Record") {
            } else {
                configVal1.setAttribute("disabled", '')
            }
        })
    }

    initConfigList(): void {
        this.configList = [
            {
                title: "Start FileSystem Record",
                des: "",
                hidden: false,
                type: "switch",
                value: false
            },
            {
                title: "Start Virtual Memory Record",
                des: "",
                hidden: false,
                type: "switch",
                value: false
            },
            {
                title: "Process",
                des: "Record process",
                hidden: false,
                type: "select-multiple",
                selectArray: [
                    ""
                ]
            }
        ]
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

        .config-div {
           width: 80%;
           display: flex;
           flex-direction: column;
           margin-top: 5vh;
           margin-bottom: 5vh;
           gap: 25px;
        }
        
        .title {
          opacity: 0.9;
          font-family: Helvetica-Bold;
          font-size: 18px;
          text-align: center;
          line-height: 40px;
          font-weight: 700;
          margin-right: 10px;
        }

        .des {
          opacity: 0.6;
          font-family: Helvetica;
          font-size: 14px;
          text-align: center;
          line-height: 35px;
          font-weight: 400;
        }

        .select {
          border-radius: 15px;
        }

        lit-switch {
          display:inline;
          float: right;
          height: 38px;
          margin-top: 10px;
        }
        input {
           height: 25px;
           outline:none;
           border-radius: 16px;
           text-indent:2%
        }
        input::-webkit-input-placeholder{
            color:var(--bark-prompt,#999999);
        }

        .input {
            border: 1px solid var(--dark-background5,#ccc);
            font-family: Helvetica;
            font-size: 14px;
            color: var(--dark-color1,#212121);
            text-align: left;
            line-height: 20px;
            font-weight: 400;
        }
        
        :host([startSamp]) .input {
            background: var(--dark-background5,#FFFFFF);
        }
        
        :host(:not([startSamp])) .input {
            color: #999999;
        }
        </style>
        <div class="root">
            <div class="configList">
            </div>
        </div>
        `;
    }
}

export interface SystemConfig {
    process: string;
}
