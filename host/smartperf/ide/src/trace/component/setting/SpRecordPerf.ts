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
import {LitSelect} from "../../../base-ui/select/LitSelect.js";
import {LitSlider} from "../../../base-ui/slider/LitSlider.js";
import LitSwitch from "../../../base-ui/switch/lit-switch.js";
import "../../../base-ui/select/LitSelectV.js";
import "../../../base-ui/select/LitSelect.js";

import "../../../base-ui/switch/lit-switch.js";
import {info, log} from "../../../log/Log.js";
import {HdcDeviceManager} from "../../../hdc/HdcDeviceManager.js";
import {SpRecordTrace} from "../SpRecordTrace.js";
import {SpApplication} from "../../SpApplication.js";
import {LitSearch} from "../trace/search/Search.js";
import {Cmd} from "../../../command/Cmd.js";
import {CmdConstant} from "../../../command/CmdConstant.js";

@element("sp-record-perf")
export class SpRecordPerf extends BaseElement {
    private addOptionButton: HTMLButtonElement | undefined | null;
    private processSelect: LitSelectV | undefined | null;
    private cpuSelect: LitSelectV | undefined | null;
    private eventSelect: LitSelectV | undefined | null;

    private frequencySetInput: HTMLInputElement | undefined | null;
    private processInput: HTMLInputElement | undefined | null;
    private offCPUSwitch: LitSwitch | undefined | null;
    private callSelect: LitSelect | undefined | null;
    private configList: Array<any> = [];

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
            this.processInput!.removeAttribute("readonly");
        } else {
            this.removeAttribute("startSamp")
            this.processInput!.setAttribute("readonly", 'readonly');
        }
    }

    get startSamp(): boolean {
        return this.hasAttribute("startSamp");
    }

    getPerfConfig(): PerfConfig | undefined {
        let configVal = this.shadowRoot?.querySelectorAll<HTMLElement>(".config");
        let perfConfig: PerfConfig = {
            process: "ALL",
            cpu: "select ALL",
            eventList: "NONE",
            cpuPercent: 100,
            frequency: 1000,
            period: 1,
            isOffCpu: true,
            noInherit: false,
            callStack: "dwarf",
            branch: "none",
            mmap: 256,
            clockType: "monotonic"
        }
        configVal!.forEach(value => {
            switch (value.title) {
                case "Process":
                    let processSelect = value as LitSelectV;
                    if (processSelect.all) {
                        perfConfig.process = "ALL"
                        break
                    }
                    if (processSelect.value.length > 0) {
                        let result = processSelect.value.match(/\((.+?)\)/g)
                        if (result) {
                            perfConfig.process = result.toString().replaceAll("(", "").replaceAll(")", "")
                        } else {
                            perfConfig.process = processSelect.value;
                        }
                    }
                    break;
                case "CPU":
                    let selectV = value as LitSelectV;
                    if (selectV.value.length > 0) {
                        perfConfig.cpu = selectV.value
                    }
                    break;
                case "Event List":
                    let selectList = value as LitSelectV;
                    if (selectList.value.length > 0) {
                        perfConfig.eventList = selectList.value.replace(/\s/g, ",");
                    }
                    break;
                case "CPU Percent":
                    let selectSlider = value as LitSlider;
                    let parEle = value.parentElement;
                    if (parEle!.hasAttribute("percent")) {
                        let percent = parEle!.getAttribute("percent");
                        perfConfig.cpuPercent = Number(percent);
                    }
                    break;
                case "Frequency":
                    let input = value as HTMLInputElement;
                    if (input.value != "") {
                        perfConfig.frequency = Number(input.value);
                    }
                    break;
                case "Period":
                    let periodInput = value as HTMLInputElement;
                    if (periodInput.value != "") {
                        perfConfig.period = Number(periodInput.value);
                    }
                    break;
                case "Off CPU":
                    let cpuImage = value as LitSwitch;
                    perfConfig.isOffCpu = cpuImage.checked;
                    break;
                case "No Inherit":
                    let InheritImage = value as LitSwitch;
                    perfConfig.noInherit = InheritImage.checked;
                    break;
                case "Call Stack":
                    let callStack = value as LitSelect;
                    if (callStack.value != "") {
                        perfConfig.callStack = callStack.value;
                    }
                    break;
                case "Branch":
                    let branch = value as LitSelect;
                    if (branch.value != "") {
                        perfConfig.branch = branch.value;
                    }
                    break;
                case "Mmap Pages":
                    let pages = value as LitSlider;
                    let parent = value.parentElement;
                    if (parent!.hasAttribute("percent")) {
                        let pagesPercent = parent!.getAttribute("percent");
                        perfConfig.mmap = Math.pow(2, Number(pagesPercent));
                    }
                    break;
                case "Clock Type":
                    let clock = value as LitSelect;
                    if (clock.value != "") {
                        perfConfig.clockType = clock.value;
                    }
                    break;
            }
        })
        info("perfConfig  is : ", perfConfig)
        return perfConfig;
    }

    initElements(): void {
        let that = this
        this.initConfigList();
        let configList = this.shadowRoot?.querySelector<HTMLDivElement>(".configList");
        this.addOptionButton = this.shadowRoot?.querySelector<HTMLButtonElement>("#addOptions");
        this.configList.forEach(config => {
            let div = document.createElement("div")
            if (config.hidden) {
                div.className = "config-div hidden";
            } else {
                div.className = "config-div";
            }
            let headDiv = document.createElement("div")
            div.appendChild(headDiv);
            let title = document.createElement("span")
            title.className = "title"
            title.textContent = config.title
            headDiv.appendChild(title)
            let des = document.createElement("span")
            des.textContent = config.des
            des.className = "des"
            headDiv.appendChild(des);
            switch (config.type) {
                case "select-multiple":
                    let html = '';
                    let placeholder = config.selectArray[0]
                    if (config.title == "Event List") {
                        placeholder = "NONE"
                    }
                    html += `<lit-select-v default-value="" rounded="" class="select config" mode="multiple" canInsert="" title="${config.title}" rounded placement = "bottom" placeholder="${placeholder}">`
                    config.selectArray.forEach((value: string) => {
                        html += `<lit-select-option value="${value}">${value}</lit-select-option>`
                    })
                    html += `</lit-select-v>`
                    div.innerHTML = div.innerHTML + html;
                    break;
                case "lit-slider":
                    let silder = `<div class="sliderBody"><lit-slider defaultColor="var(--dark-color3,#46B1E3)" open dir="right" class="silderclass config" title="${config.title}"></lit-slider>
                              <input readonly class="sliderInput" type="text" value = '    ${config.litSliderStyle.defaultValue} ${config.litSliderStyle.resultUnit}' >
                               </div>`
                    div.innerHTML = div.innerHTML + silder;
                    let litSlider = div.querySelector<LitSlider>(".silderclass");
                    litSlider!.percent = config.litSliderStyle.defaultValue
                    let sliderBody = div.querySelector<HTMLDivElement>(".sliderBody");
                    let bufferInput = div?.querySelector('.sliderInput') as HTMLInputElement;
                    litSlider!.addEventListener('input', evt => {
                        bufferInput.value = sliderBody!.getAttribute("percent") + config.litSliderStyle.resultUnit;
                    })
                    litSlider!.sliderStyle = config.litSliderStyle;
                    break;
                case "Mmap-lit-slider":
                    let defaultValue = Math.pow(2, config.litSliderStyle.defaultValue);
                    let mapsilder = `<div class="sliderBody"><lit-slider defaultColor="var(--dark-color3,#46B1E3)" open dir="right" class="silderclass config" title="${config.title}"></lit-slider>
                              <input readonly class="sliderInput" type="text" value = '    ${defaultValue} ${config.litSliderStyle.resultUnit}' >
                               </div>`
                    div.innerHTML = div.innerHTML + mapsilder;
                    let maplitSlider = div.querySelector<LitSlider>(".silderclass");
                    maplitSlider!.percent = config.litSliderStyle.defaultValue
                    let mapsliderBody = div.querySelector<HTMLDivElement>(".sliderBody");
                    let mapbufferInput = div?.querySelector('.sliderInput') as HTMLInputElement;
                    maplitSlider!.addEventListener('input', evt => {
                        let percnet = mapsliderBody!.getAttribute("percent");
                        if (percnet != null) {
                            mapbufferInput.value = Math.pow(2, Number(percnet)) + config.litSliderStyle.resultUnit;
                        }
                    })
                    maplitSlider!.sliderStyle = config.litSliderStyle;
                    break;
                case "input":
                    let input = document.createElement("input");
                    input.className = "input config";
                    input.textContent = config.value;
                    input.value = config.value;
                    input.title = config.title;
                    input.oninput = (ev) => {
                        input.value = input.value.replace(/\D/g, '')
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
                    switch1.className = "config"
                    switch1.title = config.title;
                    if (config.value) {
                        switch1.checked = true;
                    } else {
                        switch1.checked = false;
                    }
                    if (config.title == "Start Hiperf Sampling") {
                        switch1.addEventListener("change", (event: any) => {
                            let detail = event.detail;
                            if (detail.checked) {
                                this.startSamp = true;
                                this.unDisable();
                                this.dispatchEvent(new CustomEvent('addProbe', {}));
                            } else {
                                this.startSamp = false;
                                this.addOptionButton!.style.display = "unset";
                                this.disable();
                                this.show = false;
                            }
                        })
                    }
                    headDiv.appendChild(switch1);
                    break;
                default:
                    break;
            }
            configList!.appendChild(div);
        })
        let sp = document.querySelector("sp-application") as SpApplication;
        let litSearch = sp?.shadowRoot?.querySelector('#lit-search') as LitSearch;
        this.processSelect = this.shadowRoot?.querySelector<LitSelectV>("lit-select-v[title='Process']");
        this.processInput = this.processSelect?.shadowRoot?.querySelector<HTMLInputElement>('input');
        let querySelector = this.processSelect!.shadowRoot?.querySelector("input") as HTMLInputElement;
        let processData: Array<string> = []
        querySelector.addEventListener('mousedown', ev => {
            if (SpRecordTrace.serialNumber == '') {
                this.processSelect!.dataSource([], 'ALL-Process')
            }
        })
        querySelector!.addEventListener('mouseup', () => {
            if (SpRecordTrace.serialNumber == '') {
                this.processSelect?.dataSource([], 'ALL-Process')
            } else {
                if (sp.search) {
                    sp.search = false;
                    litSearch.clear();
                }
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
                        if(processData.length > 0 && this.startSamp){
                            this.processInput!.setAttribute("readonly", "readonly")
                        }
                        this.processSelect?.dataSource(processData, 'ALL-Process')
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
                                if(processData.length > 0 && this.startSamp){
                                    this.processInput!.setAttribute("readonly", "readonly")
                                }
                                this.processSelect?.dataSource(processData, 'ALL-Process')
                            })
                        } else {
                            sp.search = true;
                            litSearch.clear();
                            litSearch.setPercent("please kill other hdc-server !", -1);
                        }
                    })
                }
            }
        })

        this.cpuSelect = this.shadowRoot?.querySelector<LitSelectV>("lit-select-v[title='CPU']");
        let inputCpu = this.cpuSelect!.shadowRoot?.querySelector("input") as HTMLInputElement;
        let cpuData: Array<string> = []
        inputCpu.addEventListener('mousedown', ev => {
            if (SpRecordTrace.serialNumber == '') {
                this.cpuSelect!.dataSource([], 'ALL-CPU')
            }
        })
        inputCpu!.addEventListener("mouseup", () => {
            if (SpRecordTrace.serialNumber == '') {
                this.cpuSelect?.dataSource([], '')
            } else {
                if (sp.search) {
                    sp.search = false;
                    litSearch.clear();
                }
                if (SpRecordTrace.isVscode) {
                    let cmd = Cmd.formatString(CmdConstant.CMD_GET_CPU_COUNT_DEVICES, [SpRecordTrace.serialNumber])
                    Cmd.execHdcCmd(cmd, (res: string) => {
                        cpuData = []
                        let cpuCount = res!.trim();
                        let cpus = Number(cpuCount);
                        for (let index = 0; index < cpus; index++) {
                            cpuData.push(String(index))
                        }
                        this.cpuSelect?.dataSource(cpuData, 'ALL-CPU');
                    })
                } else {
                    HdcDeviceManager.connect(SpRecordTrace.serialNumber).then(conn => {
                        cpuData = []
                        if (conn) {
                            HdcDeviceManager.shellResultAsString(CmdConstant.CMD_GET_CPU_COUNT, false).then(res => {
                                let cpuCount = res!.trim();
                                let cpus = Number(cpuCount);
                                for (let index = 0; index < cpus; index++) {
                                    cpuData.push(String(index))
                                }
                                this.cpuSelect?.dataSource(cpuData, 'ALL-CPU');
                            })
                        } else {
                            sp.search = true;
                            litSearch.clear();
                            litSearch.setPercent("please kill other hdc-server !", -1);
                        }
                    });
                }
            }
        })
        this.eventSelect = this.shadowRoot?.querySelector<LitSelectV>("lit-select-v[title='Event List']");
        let inputEvent = this.eventSelect!.shadowRoot?.querySelector("input") as HTMLInputElement;
        let eventData: Array<string> = [];
        inputEvent.addEventListener('mousedown', ev => {
            if (SpRecordTrace.serialNumber == '') {
                this.eventSelect!.dataSource([], '')
            }
        })
        inputEvent!.addEventListener("click", () => {
            if (SpRecordTrace.serialNumber == '') {
                this.eventSelect?.dataSource(["hw-cpu-cycles",
                    "hw-instructions",
                    "hw-cache-references",
                    "hw-cache-misses",
                    "hw-branch-instructions",
                    "hw-branch-misses",
                    "hw-bus-cycles",
                    "hw-stalled-cycles-backend",
                    "hw-stalled-cycles-frontend",
                    "sw-cpu-clock",
                    "sw-task-clock",
                    "sw-page-faults",
                    "sw-context-switches",
                    "sw-cpu-migrations",
                    "sw-page-faults-min",
                    "sw-page-faults-maj",
                    "sw-alignment-faults",
                    "sw-emulation-faults",
                    "sw-dummy",
                    "sw-bpf-output"], '');
            } else {
                if (sp.search) {
                    sp.search = false;
                    litSearch.clear();
                }
                if (SpRecordTrace.isVscode) {
                    let cmd = Cmd.formatString(CmdConstant.CMD_GET_HIPERF_EVENTS_DEVICES, [SpRecordTrace.serialNumber]);
                    Cmd.execHdcCmd(cmd, (res: string) => {
                        let eventMap = that.parseEvent(res);
                        let eventList = that.getSoftHardWareEvents(eventMap);
                        if (eventList) {
                            for (let eventListElement of eventList) {
                                eventData.push(eventListElement.trim())
                            }
                        }
                        this.eventSelect!.dataSource(eventData, '');
                    });
                } else {
                    HdcDeviceManager.connect(SpRecordTrace.serialNumber).then(conn => {
                        eventData = [];
                        if (conn) {
                            HdcDeviceManager.shellResultAsString(CmdConstant.CMD_GET_HIPERF_EVENTS, false).then(res => {
                                if (res) {
                                    let eventMap = that.parseEvent(res);
                                    let eventList = that.getSoftHardWareEvents(eventMap);
                                    if (eventList) {
                                        for (let eventListElement of eventList) {
                                            eventData.push(eventListElement.trim())
                                        }
                                    }
                                    this.eventSelect!.dataSource(eventData, '');
                                }
                            })
                        } else {
                            sp.search = true;
                            litSearch.clear();
                            litSearch.setPercent("please kill other hdc-server !", -1);
                        }
                    });
                }
            }
        })

        this.frequencySetInput = this.shadowRoot?.querySelector<HTMLInputElement>("input[title='Frequency']");
        this.offCPUSwitch = this.shadowRoot?.querySelector<LitSwitch>("lit-switch[title='Off CPU']");
        this.callSelect = this.shadowRoot?.querySelector<LitSelect>("lit-select[title='Call Stack']");
        this.addOptionButton!.addEventListener("click", (event) => {
            if (!this.startSamp) {
                return;
            }
            this.addOptionButton!.style.display = "none";
            this.show = true;
        });
        this.disable();
    }

    getSoftHardWareEvents(eventListResult: Map<string, string[]>) {
        let shEvents = [];
        let hardwareEvents = eventListResult.get("hardware");
        if (hardwareEvents) {
            for (let hardwareEvent of hardwareEvents) {
                shEvents.push(hardwareEvent);
            }
        }
        let softwareEvents = eventListResult.get("software");
        if (softwareEvents) {
            for (let softwareEvent of softwareEvents) {
                shEvents.push(softwareEvent);
            }
        }
        return shEvents;
    }

    parseEvent(eventListResult: string): Map<string, Array<string>> {
        let eventMap: Map<string, Array<string>> = new Map<string, Array<string>>();
        let events: Array<string> = [];
        let type: string = "";
        let lineValues: string[] = eventListResult.replace(/\r\n/g, "\r").replace(/\n/g, "\r").split(/\r/);
        for (let line of lineValues) {
            if (line.startsWith("Supported")) {
                let startSign: string = "for";
                type = line.substring(line.indexOf(startSign) + startSign.length, line.lastIndexOf(":")).trim();
                events = new Array();
                eventMap.set(type, events);
            } else if (line.indexOf("not support") != -1 || line.trim().length == 0 || line.indexOf("Text file busy") != -1) {
                // do not need deal with it
            } else {
                let event: string = line.split(" ")[0];
                let ventMap = eventMap.get(type);
                if (ventMap != null) {
                    ventMap.push(event);
                }
            }
        }
        return eventMap;
    }


    private unDisable() {
        if (this.processSelect) {
            this.processSelect.removeAttribute("disabled");
        }
        if (this.frequencySetInput) {
            this.frequencySetInput!.disabled = false;
        }
        if (this.offCPUSwitch) {
            this.offCPUSwitch!.disabled = false;
        }
        if (this.callSelect) {
            this.callSelect!.removeAttribute("disabled");
        }
        if (this.addOptionButton) {
            this.addOptionButton.disabled = false;
        }
    }

    private disable() {
        if (this.processSelect) {
            this.processSelect.setAttribute("disabled", '');
        }
        if (this.frequencySetInput) {
            this.frequencySetInput!.disabled = true;
        }
        if (this.offCPUSwitch) {
            this.offCPUSwitch!.disabled = true;
        }
        if (this.callSelect) {
            this.callSelect!.setAttribute("disabled", '');
        }
        if (this.addOptionButton) {
            this.addOptionButton.disabled = true;
        }
    }

    initConfigList(): void {
        this.configList = [
            {
                title: "Start Hiperf Sampling",
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
            },
            {
                title: "CPU",
                des: "Record assign cpu num such as 0,1,2",
                hidden: true,
                type: "select-multiple",
                selectArray: [
                    ""
                ]
            }, {
                title: "Event List",
                des: "Event type Default is cpu cycles",
                hidden: true,
                type: "select-multiple",
                selectArray: [
                    ""
                ]
            }, {
                title: "CPU Percent",
                des: "Set the max percent of cpu time used for recording",
                hidden: true,
                type: "lit-slider",
                litSliderStyle: {
                    minRange: 0,
                    maxRange: 100,
                    defaultValue: '100',
                    resultUnit: "%",
                    stepSize: 1,
                    lineColor: "var(--dark-color3,#a88888)",
                    buttonColor: "#a88888"
                }
            },
            {
                title: "Frequency",
                des: "Set event sampling frequency",
                hidden: false,
                type: "input",
                value: "1000"
            },
            {
                title: "Period",
                des: "Set event sampling period for trace point events2",
                hidden: true,
                type: "input",
                value: "1"
            },
            {
                title: "Off CPU",
                des: "Trace when threads are scheduled off cpu",
                hidden: false,
                type: "switch",
                value: true
            },
            {
                title: "No Inherit",
                des: "Don't trace child processes",
                hidden: true,
                type: "switch",
                value: false
            },
            {
                title: "Call Stack",
                des: "Setup and enable call stack recording",
                hidden: false,
                type: "select",
                selectArray: ["dwarf", "fp", "none"]
            },
            {
                title: "Branch",
                des: "Taken branch stack sampling",
                hidden: true,
                type: "select",
                selectArray: ["none", "any", "any_call", "any_ret", "ind_call", "call", "user", "kernel"]
            },
            {
                title: "Mmap Pages",
                des: "Used to receiving record data from kernel",
                hidden: true,
                type: "Mmap-lit-slider",
                litSliderStyle: {
                    minRange: 1,
                    maxRange: 10,
                    defaultValue: "8",
                    resultUnit: "MB",
                    stepSize: 1,
                    lineColor: "var(--dark-color3,#46B1E3)",
                    buttonColor: "#999999"
                }
            },
            {
                title: "Clock Type",
                des: "Set the clock id to use for the various time fields in the perf_event_type records",
                hidden: true,
                type: "select",
                selectArray: ["realtime", "monotonic", "monotonic_raw", "boottime", "perf"]
            },
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

        #addOptions {
           border-radius: 15px;
           border-color:rgb(0,0,0,0.1);
           width: 150px;
           height: 40px;
           font-family: Helvetica;
           font-size: 1em;
           color: #FFFFFF;
           text-align: center;
           line-height: 20px;
           font-weight: 400;
           margin-right: 20%;
           float: right;
        }
        
        :host(:not([startSamp])) #addOptions {
           background: #999999;
        }
        :host([startSamp]) #addOptions {
           background: #3391FF;
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
     
        .sliderBody{
            width: 100%;
            height: min-content;
            display: grid;
            grid-template-columns: 1fr min-content;
        }

        .sliderInput {
            margin: 0 0 0 0;
            height: 40px;
            background-color: var(--dark-background5,#F2F2F2);
            -webkit-appearance:none;
            outline:0;
            font-size:14px;
            border-radius:20px;
            border:1px solid var(--dark-border,#c8cccf);
            color:var(--dark-color,#6a6f77);
            text-align: center;
        }
        </style>
        <div class="root">
            <div class="configList">
            </div>
            <button id ="addOptions">Advance Options</button>
        </div>
        `;
    }
}

export interface PerfConfig {
    process: string;
    cpu: string;
    eventList: string;
    cpuPercent: number;
    frequency: number;
    period: number;
    isOffCpu: boolean;
    noInherit: boolean;
    callStack: string;
    branch: string;
    mmap: number;
    clockType: string;
}
