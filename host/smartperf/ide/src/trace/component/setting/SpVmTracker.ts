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
import LitSwitch from "../../../base-ui/switch/lit-switch.js";
import "../../../base-ui/select/LitAllocationSelect.js";

import "../../../base-ui/switch/lit-switch.js";
import {LitAllocationSelect} from "../../../base-ui/select/LitAllocationSelect.js";
import {SpRecordTrace} from "../SpRecordTrace.js";
import {Cmd} from "../../../command/Cmd.js";
import {CmdConstant} from "../../../command/CmdConstant.js";
import {HdcDeviceManager} from "../../../hdc/HdcDeviceManager.js";

@element("sp-vm-tracker")
export class SpVmTracker extends BaseElement {
    private processInput: LitAllocationSelect | undefined | null;
    private selectProcess: HTMLInputElement | undefined | null;
    private configList: Array<any> = [];

    set startSamp(start: boolean) {
        if (start) {
            this.setAttribute("startSamp", "");
            this.selectProcess!.removeAttribute("readonly");
        } else {
            this.removeAttribute("startSamp")
            this.selectProcess!.setAttribute("readonly", "readonly")
        }
    }

    get process():string{
        if (this.processInput!.value.length > 0) {
            let result = this.processInput!.value.match(/\((.+?)\)/g)
            if (result) {
                return result.toString().replace("(", "").replace(")", "")
            } else {
                return this.processInput!.value;
            }
        }
        return ""
    }

    get startSamp(): boolean {
        return this.hasAttribute("startSamp");
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
                case "select":
                    let html1 = '';
                    html1 += `<lit-allocation-select style="width: 100%;" rounded="" default-value="" class="select config" placement="bottom" title="${config.title}"  placeholder="${config.selectArray[0]}">`
                    html1 += `</lit-allocation-select>`
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
                    if (config.title == "Start VM Tracker Record") {
                        switch1.addEventListener("change", (event: any) => {
                            let detail = event.detail;
                            if (detail.checked) {
                                this.startSamp = true;
                                this.unDisable();
                            } else {
                                this.startSamp = false;
                                this.disable();
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
        this.processInput = this.shadowRoot?.querySelector<LitAllocationSelect>("lit-allocation-select[title='Process']");
        let inputDiv = this.processInput?.shadowRoot?.querySelector('.multipleSelect') as HTMLDivElement
        this.selectProcess = this.processInput!.shadowRoot?.querySelector("input") as HTMLInputElement;
        let processData: Array<string> = []
        inputDiv!.addEventListener('mousedown', ev => {
            if (SpRecordTrace.serialNumber == '') {
                this.processInput!.processData = []
                this.processInput!.initData()
            }
        })
        inputDiv!.addEventListener('mouseup', () => {
            if (SpRecordTrace.serialNumber == '') {
                this.processInput!.processData = []
                this.processInput!.initData()
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
                        if (processData.length > 0 && this.startSamp) {
                            this.processInput!.setAttribute("readonly", "readonly")
                        }
                        this.processInput!.processData = processData
                        this.processInput!.initData()
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
                                if (processData.length > 0 && this.startSamp) {
                                    this.selectProcess!.setAttribute("readonly", "readonly")
                                }
                                this.processInput!.processData = processData
                                this.processInput!.initData()
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
            if (configVal1.title != "Start VM Tracker Record") {
                configVal1.setAttribute("disabled", '')
            }
        })
    }

    initConfigList(): void {
        this.configList = [
            {
                title: "Start VM Tracker Record",
                des: "",
                hidden: false,
                type: "switch",
                value: false
            },
            {
                title: "Process",
                des: "Record process",
                hidden: false,
                type: "select",
                selectArray: [
                    ''
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