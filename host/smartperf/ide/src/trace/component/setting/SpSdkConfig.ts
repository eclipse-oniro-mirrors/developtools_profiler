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
import "../../../base-ui/select/LitSelectV.js";
import "../../../base-ui/select/LitSelect.js";

import "../../../base-ui/switch/lit-switch.js";
import LitSwitch from "../../../base-ui/switch/lit-switch.js";
import {LitSelectV} from "../../../base-ui/select/LitSelectV.js";
import {LitAllocationSelect} from "../../../base-ui/select/LitAllocationSelect.js";
import {SpRecordTrace} from "../SpRecordTrace.js";

@element("sp-sdk-config")
export class SpSdkConfig extends BaseElement {
    private worker: Worker | undefined;
    private configList: any;
    private customConfig: HTMLDivElement | undefined | null;
    private selectConfig: LitAllocationSelect | undefined | null;
    private list: Array<HTMLElement> | undefined
    private pluginName:string = "";
    private sampleInterval: number = 5000;

    static get observedAttributes() {
        return ["configName","value","type"]
    }

    get show(): boolean {
        return this.hasAttribute("show");
    }

    set show(show: boolean) {
        if (show) {
            this.setAttribute("show", "");
        } else {
            this.removeAttribute("show")
        }
    }

    set startSamp(start: boolean) {
        if (start) {
            this.setAttribute("startSamp", "");
        } else {
            this.removeAttribute("startSamp")
        }
    }

    get startSamp(): boolean {
        return this.hasAttribute("startSamp");
    }

    set configName(configName:string) {
        if (configName != '') {
            this.setAttribute("configName",configName );
        } else {
            this.removeAttribute("configName")
        }
    }

    get configName():string{
        return this.getAttribute('configName') || ''
    }

    get type():string{
        return this.getAttribute('type') || ''
    }

    set type(type:string) {
        if (type != '') {
            this.setAttribute("type",type );
        } else {
            this.removeAttribute("type")
        }
    }

    private wasmMap: Map<string, any> = new Map<string, any>();
    private wasmList: Array<string> = []

    private changGpu(gpuName: string) {
        let config = this.wasmMap.get(gpuName);
        this.pluginName = config?.pluginName;
        this.sampleInterval = config?.sampleInterval;
        let pam = {
            action: "open",
            componentId: config.componentId,
            wasmJsName: config.wasmJsName,
            WasmName: config.wasmName,
        }
        this.worker!.postMessage(pam)
        this.worker!.onmessage = (event: MessageEvent) => {
            let results = event.data.results;
            this.configList = results.settingConfig;
            this.initConfig()
        }
    }

    getPlugName(): string{
        return this.pluginName
    }

    getSampleInterval(): number{
        return this.sampleInterval
    }

    getGpuConfig(): any {
        let configVal = this.shadowRoot?.querySelectorAll<HTMLElement>(".config");
        let gpuConfig:any = {}
        for (let i = 0;i<configVal!.length;i++) {
            let configName = configVal![i].getAttribute("configName")
            let type = configVal![i].getAttribute("type");
            if(type == 'enum'){
                gpuConfig[configName!] = configVal![i].getAttribute("value")
            } else if(type == 'number' || type == 'integer'){
                // @ts-ignore
                gpuConfig[configName!] = Number(configVal![i].value)
            } else if(type == 'boolean' ){
                gpuConfig[configName!] = Boolean(configVal![i].getAttribute("value"))
            } else {
                // @ts-ignore
                gpuConfig[configName!] = configVal![i].value
            }
        }
        return gpuConfig
    }

    initElements(): void {
        try {
            let spApplication = document.querySelector<HTMLElement>("sp-application");
            let wasmJsonUrl = `https://${window.location.host.split(':')[0]}:${window.location.port}/application/wasm.json`
            if (spApplication!.hasAttribute("vs")) {
                wasmJsonUrl = `http://${window.location.host.split(':')[0]}:${window.location.port}/wasm.json`
            }
            fetch(wasmJsonUrl).then(res => {
                    if (res.ok) {
                        res.text().then(text => {
                                this.wasmMap = new Map();
                                this.wasmList = [];
                                let wasmJson = JSON.parse(text)
                                let wasmFiles = wasmJson.WasmFiles
                                wasmFiles.forEach((wasmFile: any) => {
                                    this.wasmMap.set(wasmFile.disPlayName, wasmFile)
                                    this.wasmList.push(wasmFile.disPlayName);
                                })

                            }
                        )
                    }
                }
            );
            if (this.worker == null) {
                this.worker = new Worker("trace/database/ConfigWorker.js");
            }
        } catch (e) {

        }
        this.customConfig = this.shadowRoot?.querySelector<HTMLDivElement>(".configList");
        let switchButton = this.shadowRoot?.querySelector(".config_switch") as LitSwitch;
        switchButton.addEventListener("change", (event: any) => {
            let detail = event.detail;
            if (detail.checked) {
                this.startSamp = true;
                this.isAbleShowConfig(false);
            } else {
                this.startSamp = false;
                this.isAbleShowConfig(true);
            }
        })
        this.selectConfig = this.shadowRoot?.querySelector<LitAllocationSelect>('lit-allocation-select');
        let inputDiv = this.selectConfig?.shadowRoot?.querySelector('.multipleSelect') as HTMLDivElement
        let input = this.selectConfig?.shadowRoot?.querySelector<HTMLInputElement>('#input')
        if (input) {
            input.readOnly = true
            inputDiv.addEventListener('inputClick', () => {
                this.selectConfig!.processData = this.wasmList
                this.selectConfig!.initData()
            })
            inputDiv.addEventListener('valuable', ev => {
                this.changGpu(input!.value);
            })
        }
        this.list = []
        this.list.push(this.selectConfig!)
        this.isAbleShowConfig(true);
    }

    initConfig() {
        this.customConfig!.innerHTML = ''
        this.list = []
        this.list.push(this.selectConfig!)
        let switch1 = document.createElement("lit-switch") as LitSwitch;
        for (let key in this.configList.configuration) {
            let html = '';
            let div = document.createElement("div")
            div.className = "config-div";
            let headDiv = document.createElement("div")
            div.appendChild(headDiv);
            let title = document.createElement("span")
            title.className = "title";
            title.textContent = key;
            headDiv.appendChild(title);
            let des = document.createElement("span")
            des.textContent = this.configList.configuration[key].description;
            des.className = "des"
            headDiv.appendChild(des);
            switch (this.configList.configuration[key].type) {
                case "string":
                    if (this.configList.configuration[key].enum) {
                        let placeholder = ''
                        if(this.configList.configuration[key].default){
                            placeholder = this.configList.configuration[key].default
                        }
                        html += `<lit-select-v id="${key}" type="${this.configList.configuration[key].type}" default-value="" rounded="" class="select config" mode="multiple" canInsert="" rounded placement = "bottom" configName ="${key}" placeholder="${placeholder}"></lit-select-v>`
                        div.innerHTML = div.innerHTML + html;
                    } else {
                        let inputElement = document.createElement("input");
                        inputElement.className = "input config";
                        if(this.configList.configuration[key].default){
                            inputElement.value = this.configList.configuration[key].default;
                        }
                        inputElement.setAttribute("configName",key)
                        inputElement.setAttribute("type",this.configList.configuration[key].type)
                        div.appendChild(inputElement);
                        this.list.push(inputElement)
                    }
                    break;
                case "number":
                    let numberInput = document.createElement("input");
                    numberInput.className = "input config";
                    if(this.configList.configuration[key].default){
                        numberInput.value = this.configList.configuration[key].default;
                    }
                    numberInput.setAttribute("configName",key)
                    numberInput.setAttribute("type",this.configList.configuration[key].type)
                    numberInput.oninput = (ev) => {
                        let inputValue = this.checkFloatInput(numberInput.value)
                        numberInput.value = inputValue
                    }
                    div.appendChild(numberInput);
                    this.list.push(numberInput);
                    break;
                case "integer":
                    let input = document.createElement("input");
                    input.className = "input config";
                    if(this.configList.configuration[key].default){
                        input.value = this.configList.configuration[key].default;
                    }
                    input.setAttribute("configName",key)
                    input.setAttribute("type",this.configList.configuration[key].type)
                    input.oninput = (ev) => {
                        let inputValue = this.checkIntegerInput(input.value)
                        input.value = inputValue
                        title.setAttribute("value", input.value)
                    }
                    div.appendChild(input);
                    this.list.push(input);
                    break;
                case "boolean":
                    switch1.className = "switch1 config";
                    switch1.setAttribute("configName",key)
                    switch1.setAttribute("type",this.configList.configuration[key].type)
                    if (this.configList.configuration[key].default == 'true') {
                        switch1.setAttribute('checked', '');
                        switch1.setAttribute("value","true")
                    } else {
                        switch1.removeAttribute('checked');
                        switch1.setAttribute("value","false")
                    }
                    headDiv.appendChild(switch1);
                    this.list.push(switch1)
                    break;
            }
            this.customConfig!.appendChild(div);
            if (this.configList.configuration[key].enum) {
                let select = this.shadowRoot!.querySelector<LitSelectV>(`#${key}`);
                select!.setAttribute("type","enum")
                select!.setAttribute("value",this.configList.configuration[key].default)
                select!.dataSource(this.configList.configuration[key].enum, '');
                this.list.push(select!)
                select!.addEventListener("click", (event: any) => {
                    select!.setAttribute("value",select!.value)
                })
            }
        }
        switch1.addEventListener("change", (event: any) => {
            if(switch1.hasAttribute("checked")){
                switch1.setAttribute("value","true")
            } else {
                switch1.setAttribute("value","false")
            }
        })
    }

    checkIntegerInput(value: string): string {
        let inputValue = value.replace(/[^\-\d]|\-{2,}/g, "")
            .replace(/(\d)\-|-(0+)|^0+(\d)/g, "$1")
            .replace(/(-?\d{15})\d*/, '$1');
        return inputValue
    }

    checkFloatInput(value: string): string {
        let inputValue = value.replace(/[^\-\d.]|\-{2,}/g, '')
            .replace(/^\.|^0+(\d)/g, '')
            .replace(/(\.\d+)\.|(-)\.|(\d+|\.)-/g, '$1')
        return inputValue.replace(/\.{2,}|-(0){2,}|(-)0+(\d+)/g, '.')
    }

    isAbleShowConfig(isAbleShow: boolean) {
        if(this.list!){
            if (isAbleShow) {
                this.list!.forEach(item => {
                    item.setAttribute("disabled", '');
                })
            } else {
                this.list!.forEach(item => {
                    item.removeAttribute("disabled");
                })
            }
        }
    }

    initConfigList(): void {
        this.configList =
            {
                "name": "",
                "configuration": {
                    "ss": {
                        "type": "string",
                        "default": "strsadsa",
                        "description": "xxxx",
                    },
                    "aa": {
                        "type": "string",
                        "default": "11",
                        "enum": [
                            "consistent",
                            "11",
                            "delegated"
                        ]
                    },
                    "cc": {
                        "type": "number",
                        "description": "number1111",
                    },
                    "ee": {
                        "type": "integer",
                        "default": "12",
                        "description": "integer1222",
                    },
                    "ff": {
                        "type": "boolean",
                        "description": "switchhh",
                    }
                }
            }
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
           gap: 15px;
        }

        :host([show]) .config-div {
           display: flex;
           flex-direction: column;
           margin-bottom: 1vh;
        }

        :host(:not([show])) .config-div {
           margin-top: 5vh;
           margin-bottom: 5vh;
           gap: 25px;
        }
        
        :host(:not([show])) .hidden {
           display: none;
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
            color: var(--dark-color1,#212121);
        }
       
        </style>
        <div class="root">
            <div class="config-div">
                <div>
                    <span class="title">Start Custom Config</span>
                    <lit-switch class="config_switch" ></lit-switch>
                </div>
            </div>
            <div class="config-div" id="select_config">
                <lit-allocation-select show-search class="processSelect" rounded default-value="" id="pid" placement="bottom" style="width:100%"></lit-allocation-select>
            </div>
            <div class="configList">
            </div>
        </div>
        `;
    }
}
