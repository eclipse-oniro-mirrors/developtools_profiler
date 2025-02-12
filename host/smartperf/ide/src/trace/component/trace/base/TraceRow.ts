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

import {element} from "../../../../base-ui/BaseElement.js";
import {TimeRange} from "../timer-shaft/RangeRuler.js";
import '../../../../base-ui/icon/LitIcon.js'
import {Rect} from "../timer-shaft/Rect.js";
import {BaseStruct} from "../../../bean/BaseStruct.js";
import {SpSystemTrace} from "../../SpSystemTrace.js";
import {ns2x} from "../TimerShaftElement.js";
import {TraceRowObject} from "./TraceRowObject.js";
import {LitCheckBox} from "../../../../base-ui/checkbox/LitCheckBox.js";
import {LitIcon} from "../../../../base-ui/icon/LitIcon";
import "../../../../base-ui/popover/LitPopoverV.js"
import {LitPopover} from "../../../../base-ui/popover/LitPopoverV.js";
import {info} from "../../../../log/Log.js";
import {ColorUtils} from "./ColorUtils.js";

export class RangeSelectStruct {
    startX: number | undefined
    endX: number | undefined
    startNS: number | undefined
    endNS: number | undefined
}

let collectList: Array<any> = [];
let rowDragElement: EventTarget | undefined | null;
let dragDirection: string = "";

@element('trace-row')
export class TraceRow<T extends BaseStruct> extends HTMLElement {
    static ROW_TYPE_CPU = "cpu-data"
    static ROW_TYPE_CPU_STATE = "cpu-state"
    static ROW_TYPE_CPU_FREQ = "cpu-freq"
    static ROW_TYPE_CPU_FREQ_LIMIT = "cpu-limit-freq"
    static ROW_TYPE_FPS = "fps"
    static ROW_TYPE_NATIVE_MEMORY = "native-memory"
    static ROW_TYPE_HIPERF = "hiperf"
    static ROW_TYPE_HIPERF_CPU = "hiperf-cpu"
    static ROW_TYPE_HIPERF_PROCESS = "hiperf-process"
    static ROW_TYPE_HIPERF_THREAD = "hiperf-thread"
    static ROW_TYPE_HIPERF_REPORT = "hiperf-report"
    static ROW_TYPE_HIPERF_EVENT = "hiperf-event"
    static ROW_TYPE_PROCESS = "process"
    static ROW_TYPE_THREAD = "thread"
    static ROW_TYPE_MEM = "mem"
    static ROW_TYPE_VIRTUAL_MEMORY_GROUP = "virtual-memory-group"
    static ROW_TYPE_VIRTUAL_MEMORY = "virtual-memory-cell"
    static ROW_TYPE_FILE_SYSTEM_GROUP = "file-system-group"
    static ROW_TYPE_FILE_SYSTEM = "file-system-cell"
    static ROW_TYPE_HEAP = "heap"
    static ROW_TYPE_FUNC = "func"
    static ROW_TYPE_MONITOR = "ability-monitor"
    static ROW_TYPE_CPU_ABILITY = "cpu-ability"
    static ROW_TYPE_MEMORY_ABILITY = "memory-ability"
    static ROW_TYPE_DISK_ABILITY = "disk-ability"
    static ROW_TYPE_NETWORK_ABILITY = "network-ability"
    static ROW_TYPE_SDK = "sdk"
    static ROW_TYPE_SDK_COUNTER = "sdk-counter"
    static ROW_TYPE_SDK_SLICE = "sdk-slice"
    static ROW_TYPE_ENERGY = "energy"
    static ROW_TYPE_ANOMALY_ENERGY = "anomaly-energy"
    static ROW_TYPE_SYSTEM_ENERGY = "system-energy"
    static ROW_TYPE_POWER_ENERGY = "power-energy"
    static ROW_TYPE_STATE_ENERGY = "state-energy"
    static ROW_TYPE_SMAPS = "smaps"
    static range: TimeRange | undefined | null;
    static rangeSelectObject: RangeSelectStruct | undefined
    public obj: TraceRowObject<any> | undefined | null;
    isHover: boolean = false;
    hoverX: number = 0;
    hoverY: number = 0;
    index: number = 0;
    public must: boolean = false;
    public isTransferCanvas = false;
    onComplete: Function | undefined;
    isComplete: boolean = false;
    public dataList: undefined | Array<T>;
    public describeEl: HTMLElement | null | undefined;
    public canvas: Array<HTMLCanvasElement> = [];
    public canvasContainer: HTMLDivElement | null | undefined;
    public tipEL: HTMLDivElement | null | undefined;
    public checkBoxEL: LitCheckBox | null | undefined;
    public collectEL: LitIcon | null | undefined;
    public onThreadHandler: ((useCache: boolean, buf: ArrayBuffer | undefined | null) => void) | undefined | null
    public onDrawTypeChangeHandler: ((type: number) => void) | undefined | null
    public supplier: (() => Promise<Array<T>>) | undefined | null
    public favoriteChangeHandler: ((fav: TraceRow<any>) => void) | undefined | null
    public selectChangeHandler: ((list: Array<TraceRow<any>>) => void) | undefined | null
    dpr = window.devicePixelRatio || 1;
    // @ts-ignore
    offscreen: Array<OffscreenCanvas | undefined> = [];
    canvasWidth = 0
    canvasHeight = 0
    public _frame: Rect | undefined;
    public isLoading: boolean = false
    public readonly args: any;
    private rootEL: HTMLDivElement | null | undefined;
    private nameEL: HTMLLabelElement | null | undefined;
    private _rangeSelect: boolean = false;
    private _drawType: number = 0
    private folderIconEL: LitIcon | null | undefined;
    online: boolean = false;
    static isUserInteraction: boolean;
    asyncFuncName: string | undefined | null;
    asyncFuncNamePID: number | undefined | null;

    constructor(args: { canvasNumber: number, alpha: boolean, contextId: string, isOffScreen: boolean, skeleton?: boolean } = {
        canvasNumber: 1, alpha: false, contextId: "2d", isOffScreen: true, skeleton: false
    }) {
        super();
        this.args = args;
        this.attachShadow({mode: 'open'}).innerHTML = this.initHtml();
        this.initElements();
    }

   static skeleton<T extends BaseStruct>(): TraceRow<T> {
        let tr= new TraceRow<T>({
            alpha: false, canvasNumber: 0, contextId: "", isOffScreen: false, skeleton: true
        });
        tr.isTransferCanvas=true;
        return tr;
    }

    static get observedAttributes() {
        return ["folder", "name", "expansion", "children", "height", "row-type", "row-id", "row-parent-id", "sleeping",
            "check-type",
            "collect-type",
            "disabled-check",
            "row-discard",
        ];
    }

    get rowDiscard(): boolean {
        return this.hasAttribute("row-discard");
    }

    set rowDiscard(value: boolean) {
        if (value) {
            this.setAttribute("row-discard", "")
            this.style.display = "none";
        } else {
            this.removeAttribute("row-discard")
            this.style.display = "block";
        }
    }

    get collect() {
        return this.hasAttribute("collect-type")
    }

    set collect(value) {
        if (value) {
            this.setAttribute("collect-type", "")
        } else {
            this.removeAttribute("collect-type")
        }
    }

    get rangeSelect(): boolean {
        return this._rangeSelect;
    }

    set rangeSelect(value: boolean) {
        this._rangeSelect = value;
    }

    get sleeping(): boolean {
        return this.hasAttribute("sleeping");
    }

    set sleeping(value: boolean) {
        if (value) {
            this.setAttribute("sleeping", "")
        } else {
            this.removeAttribute("sleeping")
            this.draw();
        }
    }

    get rowType(): string | undefined | null {
        return this.getAttribute("row-type");
    }

    set rowType(val) {
        this.setAttribute("row-type", val || "")
    }

    get rowId(): string | undefined | null {
        return this.getAttribute("row-id");
    }

    set rowId(val) {
        this.setAttribute("row-id", val || "")
    }

    get rowParentId(): string | undefined | null {
        return this.getAttribute("row-parent-id");
    }

    set rowParentId(val) {
        this.setAttribute("row-parent-id", val || "")
    }

    set rowHidden(val: boolean) {
        if (val) {
            this.setAttribute("row-hidden", "")
        } else {
            this.removeAttribute("row-hidden")
        }
    }

    get name(): string {
        return this.getAttribute("name") || ""
    }

    set name(value: string) {
        this.setAttribute("name", value)
    }

    get folder(): boolean {
        return this.hasAttribute("folder");
    }

    set folder(value: boolean) {
        if (value) {
            this.setAttribute("folder", '')
        } else {
            this.removeAttribute('folder')
        }
    }

    get expansion(): boolean {
        return this.hasAttribute("expansion")
    }

    set expansion(value) {
        if (value) {
            this.setAttribute("expansion", '');
        } else {
            this.removeAttribute('expansion')
        }
        this.parentElement?.querySelectorAll<TraceRow<any>>(`trace-row[row-parent-id='${this.rowId}']`).forEach(it => {
            if (!it.collect) {
                it.rowHidden = !this.expansion;
            }
            if (it.folder && !value && it.expansion) {
                it.expansion = value;
            }
        })
        this.dispatchEvent(new CustomEvent("expansion-change", {
            detail: {
                expansion: this.expansion,
                rowType: this.rowType,
                rowId: this.rowId,
                rowParentId: this.rowParentId
            }
        }))
    }

    set tip(value: string) {
        if (this.tipEL) {
            this.tipEL.innerHTML = value;
        }
    }

    get frame(): Rect | any {
        let cHeight = 0;
        this.canvas.forEach(it => {
            cHeight += (it?.clientHeight || 40);
        })
        if(cHeight == 0) cHeight = 40;
        if (this._frame) {
            this._frame.width = (this.parentElement?.clientWidth || 0) - 248 - SpSystemTrace.scrollViewWidth;
            this._frame.height = cHeight;
            return this._frame;
        } else {
            this._frame = new Rect(0, 0, (this.parentElement?.clientWidth || 0) - 248 - SpSystemTrace.scrollViewWidth, cHeight);
            return this._frame;
        }
    }

    set frame(f: Rect) {
        this._frame = f;
    }

    get disabledCheck(): boolean {
        return this.hasAttribute("disabled-check");
    }

    set disabledCheck(value: boolean) {
        if (value) {
            this.setAttribute("disabled-check", '')
            this.checkBoxEL!.style.display = "none";
        } else {
            this.removeAttribute('disabled-check')
            this.checkBoxEL!.style.display = "flex";
        }
    }

    get checkType(): string {
        return this.getAttribute("check-type") || "";
    }

    set checkType(value: string) {
        if (!value || value.length == 0) {
            this.removeAttribute("check-type");
            return;
        }
        this.setAttribute("check-type", value);
        if (this.hasAttribute("disabled-check")) {
            this.checkBoxEL!.style.display = "none";
            return;
        }
        switch (value) {
            case "-1":
                this.checkBoxEL!.style.display = "none";
                this.rangeSelect = false;
                break;
            case "0":
                this.checkBoxEL!.style.display = "flex";
                this.checkBoxEL!.checked = false;
                this.checkBoxEL!.indeterminate = false;
                this.rangeSelect = false;
                break;
            case "1":
                this.checkBoxEL!.style.display = "flex";
                this.checkBoxEL!.checked = false
                this.checkBoxEL!.indeterminate = true;
                this.rangeSelect = false;
                break;
            case "2":
                this.rangeSelect = true;
                this.checkBoxEL!.style.display = "flex";
                this.checkBoxEL!.checked = true;
                this.checkBoxEL!.indeterminate = false;
                break;
        }
    }

    get drawType(): number {
        return this._drawType;
    }

    set drawType(value: number) {
        this._drawType = value;
        let radioList: NodeListOf<any> = this.shadowRoot!.querySelectorAll("input[type=radio][name=status]")
        if (radioList!.length > 0) {
            radioList[Number(value)].checked = true
        }
    }

    get highlight(): boolean {
        return this.hasAttribute("expansion");
    }

    set highlight(value: boolean) {
        if (value) {
            this.setAttribute("highlight", '')
        } else {
            this.removeAttribute('highlight')
        }
    }

    set folderPaddingLeft(value: number) {
        this.folderIconEL!.style.marginLeft = value + "px";
    }

    initElements(): void {
        this.rootEL = this.shadowRoot?.querySelector('.root')
        this.checkBoxEL = this.shadowRoot?.querySelector<LitCheckBox>('.lit-check-box')
        this.collectEL = this.shadowRoot?.querySelector<LitIcon>('.collect')
        this.describeEl = this.shadowRoot?.querySelector('.describe')
        this.folderIconEL = this.shadowRoot?.querySelector<LitIcon>('.icon')
        this.nameEL = this.shadowRoot?.querySelector('.name')
        this.canvasContainer = this.shadowRoot?.querySelector('.panel-container')
        this.tipEL = this.shadowRoot?.querySelector('.tip')
        let canvasNumber = this.args["canvasNumber"];
        if (!this.args["skeleton"]) {
            for (let i = 0; i < canvasNumber; i++) {
                let canvas = document.createElement('canvas');
                canvas.className = "panel";
                this.canvas.push(canvas);
                this.canvasContainer!.appendChild(canvas);
            }
        }
        this.describeEl?.addEventListener('click', () => {
            if (this.folder) {
                this.expansion = !this.expansion
            }
        })
    }

    initCanvas(list: Array<HTMLCanvasElement>): void {
        let timerShaftEL = document!.querySelector("body > sp-application")!.shadowRoot!.querySelector("#sp-system-trace")!.shadowRoot!.querySelector("div > timer-shaft-element");
        let timerShaftCanvas = timerShaftEL!.shadowRoot!.querySelector<HTMLCanvasElement>("canvas");
        let tempHeight: number = 0;
        if (this.rowType == TraceRow.ROW_TYPE_FUNC) {
            tempHeight = 20;
        } else if (this.rowType == TraceRow.ROW_TYPE_THREAD) {
            tempHeight = 30;
        } else if (this.rowType == TraceRow.ROW_TYPE_SYSTEM_ENERGY) {
            tempHeight = 90;
        } else if (this.rowType == TraceRow.ROW_TYPE_POWER_ENERGY) {
            tempHeight = 200;
        } else if (this.rowType == TraceRow.ROW_TYPE_ANOMALY_ENERGY) {
            tempHeight = 55;
        } else {
            tempHeight = 40;
        }
        this.dpr = window.devicePixelRatio || 1;
        list.forEach((canvas, i) => {
            this.rootEL!.style.height = `${this.getAttribute("height") || '40'}px`
            canvas.style.width = timerShaftCanvas!.style.width;
            canvas.style.height = tempHeight + 'px';
            this.canvasWidth = timerShaftCanvas!.width;
            this.canvasHeight = Math.ceil(tempHeight * this.dpr);
            canvas.width = this.canvasWidth;
            canvas.height = this.canvasHeight;
            // @ts-ignore
            this.offscreen.push(canvas!.transferControlToOffscreen());
        })
    }

    updateWidth(width: number) {
        this.dpr = window.devicePixelRatio || 1;
        let tempHeight: number = 0;
        if (this.rowType == TraceRow.ROW_TYPE_FUNC) {
            tempHeight = 20;
        } else if (this.rowType == TraceRow.ROW_TYPE_THREAD) {
            tempHeight = 30;
        } else if (this.rowType == TraceRow.ROW_TYPE_SYSTEM_ENERGY) {
            tempHeight = 90;
        } else if (this.rowType == TraceRow.ROW_TYPE_POWER_ENERGY) {
            tempHeight = 200;
        } else if (this.rowType == TraceRow.ROW_TYPE_ANOMALY_ENERGY) {
            tempHeight = 55;
        } else {
            tempHeight = 40;
        }
        if (this.canvas.length > 1) {
            tempHeight = 20;
        }
        this.canvas.forEach(it => {
            this.canvasWidth = Math.ceil((width - (this.describeEl?.clientWidth || 248)) * this.dpr);
            this.canvasHeight = Math.ceil(tempHeight * this.dpr);
            it!.style.width = (width - (this.describeEl?.clientWidth || 248)) + 'px';
            if (this.args.isOffScreen) {
                this.draw(true);
            }
        })
    }

    drawLine(item: HTMLDivElement, direction: string/*string[top|bottom]*/) {
        if (!item) return;
        switch (direction) {
            case "top":
                item.classList.remove("line-bottom");
                item.classList.add("line-top");
                break;
            case "bottom":
                item.classList.remove("line-top");
                item.classList.add("line-bottom");
                break;
            case "":
                item.classList.remove("line-top");
                item.classList.remove("line-bottom");
                break;
        }
    }

    connectedCallback() {
        this.checkBoxEL!.onchange = (ev: any) => {
            info("checkBoxEL onchange ");
            if (!ev.target.checked) {
                info("checkBoxEL target not checked");
                this.rangeSelect = false;
                this.checkType = "0"
                this.draw();
            } else {
                this.rangeSelect = true;
                this.checkType = "2"
                this.draw();
            }
            this.setCheckBox(ev.target.checked);
        }
        this.describeEl!.ondragstart = (ev: DragEvent) => this.rowDragstart(ev);
        this.describeEl!.ondragleave = (ev: any) => {
            this.drawLine(ev.currentTarget, '');
            return undefined;
        }
        this.describeEl!.ondragend = (ev: any) => {
            rowDragElement = null;
            ev.target.classList.remove("drag")
            this.drawLine(ev.currentTarget, '');
            return undefined;
        }
        this.describeEl!.ondragover = (ev: any) => {
            if (!this.collect) return;
            if (rowDragElement === this) return;
            let rect = ev.currentTarget.getBoundingClientRect();
            if (ev.clientY >= rect.top && ev.clientY < rect.top + rect.height / 2) {//上面
                dragDirection = 'top';
                this.drawLine(ev.currentTarget, 'top');
            } else if (ev.clientY <= rect.bottom && ev.clientY > rect.top + rect.height / 2) {//下面
                dragDirection = 'bottom';
                this.drawLine(ev.currentTarget, 'bottom');
            }
            return undefined;
        }
        this.describeEl!.ondrop = (ev: any) => {
            if (!this.collect) return;
            this.drawLine(ev.currentTarget, '');
            let spacer = this.parentElement!.previousElementSibling! as HTMLDivElement;
            let startDragNode = collectList.findIndex((it) => it === rowDragElement);
            let endDragNode = collectList.findIndex((it) => it === this);
            if (startDragNode === -1 || endDragNode === -1) return;
            if (startDragNode < endDragNode && dragDirection === "top") {
                endDragNode--;
            } else if (startDragNode > endDragNode && dragDirection === "bottom") {
                endDragNode++;
            }
            collectList.splice(endDragNode, 0, ...collectList.splice(startDragNode, 1))
            collectList.forEach((it, i) => {
                if (i == 0) {
                    it.style.top = `${spacer.offsetTop + 48}px`;
                } else {
                    it.style.top = `${collectList[i - 1].offsetTop + collectList[i - 1].offsetHeight}px`;
                }
            })
        }
        this.collectEL!.onclick = (e) => {
            this.collect = !this.collect;
            if (this.collect) {
                this.describeEl!.draggable = true;
            } else {
                this.describeEl!.draggable = false;
            }
            let spacer = this.parentElement!.previousElementSibling! as HTMLDivElement;
            if (this.collect) {
                let nodeList = this.parentElement!.querySelectorAll<TraceRow<any>>(`trace-row[collect-type]`);
                if (nodeList.length == 1) collectList = [];
                collectList.push(this);
                spacer.style.height = `${spacer.offsetHeight + this.offsetHeight!}px`;
            } else {
                collectList.splice(collectList.findIndex((it) => it === this), 1);
                spacer.style.height = `${spacer.offsetHeight - this.offsetHeight!}px`;
                let parent = this.parentElement!.querySelector<TraceRow<any>>(`trace-row[row-id='${this.rowParentId}']`);
                if (parent) {
                    this.rowHidden = !parent.expansion;
                }
            }
            collectList.forEach((it, i) => {
                if (i == 0) {
                    it.style.top = `${spacer.offsetTop + 48}px`;
                } else {
                    it.style.top = `${collectList[i - 1].offsetTop + collectList[i - 1].offsetHeight}px`;
                }
            })
            this.favoriteChangeHandler?.(this)
        }
        if (!this.args["skeleton"]) {
            this.initCanvas(this.canvas);
        }
        let radioList = this.shadowRoot!.querySelectorAll("input[type=radio][name=status]")
        let popover = this.shadowRoot!.querySelector<LitPopover>(".popover")
        this.shadowRoot?.querySelector<HTMLDivElement>("#first-radio")?.addEventListener("click", (e) => {
            // @ts-ignore
            radioList[0]!.checked = true;
            // @ts-ignore
            popover!.visible = false
            setTimeout(() => {
                this.onDrawTypeChangeHandler?.(0);
            }, 300);
        })
        this.shadowRoot?.querySelector<HTMLDivElement>("#second-radio")?.addEventListener('click', (e) => {
            // @ts-ignore
            radioList[1]!.checked = true;
            // @ts-ignore
            popover!.visible = false
            setTimeout(() => {
                this.onDrawTypeChangeHandler?.(1);
            }, 300);
        })
    }

    rowDragstart(ev: any) {
        rowDragElement = this;
        ev.target.classList.add("drag")
    }

    setCheckBox(isCheck: boolean) {
        if (this.folder) {
            let allRow = this.parentElement?.querySelectorAll<TraceRow<any>>(`trace-row[row-parent-id='${this.rowId}'][check-type]`)
            allRow!.forEach((ck) => {
                ck.setAttribute("check-type", isCheck ? "2" : "0")
                let allCheck: LitCheckBox | null | undefined = ck?.shadowRoot?.querySelector(".lit-check-box")
                allCheck!.checked = isCheck
            })
        } else if (this.rowParentId == "" && !this.folder) {
            this.selectChangeHandler?.([...this.parentElement!.querySelectorAll<TraceRow<any>>("trace-row[check-type='2']")])
            return;
        }
        let checkList = this.parentElement?.querySelectorAll<TraceRow<any>>(`trace-row[row-parent-id='${this.folder ? this.rowId : this.rowParentId}'][check-type="2"]`)
        let unselectedList = this.parentElement?.querySelectorAll<TraceRow<any>>(`trace-row[row-parent-id='${this.folder ? this.rowId : this.rowParentId}'][check-type="0"]`)
        let parentRow = this.parentElement?.querySelector<TraceRow<any>>(`trace-row[row-id='${this.folder ? this.rowId : this.rowParentId}'][folder]`)
        let parentCheck: LitCheckBox | null | undefined = parentRow?.shadowRoot?.querySelector(".lit-check-box")

        if (unselectedList!.length == 0) {
            parentRow!.setAttribute("check-type", "2")
            parentCheck!.checked = true
            parentCheck!.indeterminate = false;
            checkList?.forEach((it) => {
                it.checkType = "2";
                it.rangeSelect = true;
                it.draw()
            })
        } else {
            parentRow!.setAttribute("check-type", "1")
            parentCheck!.checked = false
            parentCheck!.indeterminate = true;
            checkList?.forEach((it) => {
                it.checkType = "2";
                it.rangeSelect = true;
                it.draw()
            })
            unselectedList?.forEach((it) => {
                it.checkType = "0";
                it.rangeSelect = false;
                it.draw()
            })
        }

        if (checkList!.length == 0) {
            parentRow!.setAttribute("check-type", "0")
            parentCheck!.checked = false
            parentCheck!.indeterminate = false;
            unselectedList?.forEach((it) => {
                it.checkType = "0";
                it.rangeSelect = false;
                it.draw()
            })
        }
        this.selectChangeHandler?.([...this.parentElement!.querySelectorAll<TraceRow<any>>("trace-row[check-type='2']")])
    }

    onMouseHover(x: number, y: number, tip: boolean = true): T | undefined | null {
        if (this.tipEL) {
            this.tipEL.style.display = 'none';
        }
        return null;
    }

    setTipLeft(x: number, struct: any) {
        if (struct == null && this.tipEL) {
            this.tipEL.style.display = 'none';
            return
        }
        if (this.tipEL) {
            this.tipEL.style.display = 'flex';
            if (x + this.tipEL.clientWidth > (this.canvas[0]!.clientWidth || 0)) {
                this.tipEL.style.transform = `translateX(${x - this.tipEL.clientWidth - 1}px)`;
            } else {
                this.tipEL.style.transform = `translateX(${x}px)`;
            }
        }
    }

    onMouseLeave(x: number, y: number) {
        if (this.tipEL) {
            this.tipEL.style.display = 'none';
        }
    }

    draw(useCache: boolean = false) {
        this.dpr = window.devicePixelRatio || 1;
        if (this.sleeping) {
            return;
        }
        if (this.online) {
            if (!useCache && !TraceRow.isUserInteraction) {
                this.supplier?.().then(res => {
                    this.onThreadHandler?.(useCache, res as any);
                });
            }
            this.onThreadHandler?.(useCache, null);
            return;
        }
        if (!this.isComplete) {
            if (this.supplier && !this.isLoading) {
                this.isLoading = true;
                this.must = true;
                if (this.supplier) {
                    let promise = this.supplier();
                    if (promise) {
                        promise.then(res => {
                            this.dataList = res
                            if (this.onComplete) {
                                this.onComplete();
                            }
                            this.isComplete = true;
                            this.isLoading = false;
                            this.draw(false);
                        })
                    } else {
                        this.isLoading = false;
                        this.draw(false);
                    }
                }
            }
        } else {
            if (this.onThreadHandler && this.dataList) {
                this.onThreadHandler!(useCache, null);
            }
        }
    }

    clearCanvas(ctx: CanvasRenderingContext2D) {
        if (ctx) {
            this.canvas.forEach(it => {
                ctx.clearRect(0, 0, it!.clientWidth || 0, it!.clientHeight || 0)
            })
        }
    }

    drawLines(ctx: CanvasRenderingContext2D) {
        if (ctx) {
            ctx.lineWidth = 1;
            ctx.strokeStyle = this.getLineColor();
            TraceRow.range?.xs.forEach(it => {
                ctx.moveTo(Math.floor(it), 0)
                ctx.lineTo(Math.floor(it), this.shadowRoot?.host.clientHeight || 0)
            })
            ctx.stroke();
        }
    }

    getLineColor() {
        return window.getComputedStyle(this.rootEL!, null).getPropertyValue("border-bottom-color")
    }

    drawSelection(ctx: CanvasRenderingContext2D) {
        if (this.rangeSelect) {
            TraceRow.rangeSelectObject!.startX = Math.floor(ns2x(TraceRow.rangeSelectObject!.startNS!, TraceRow.range!.startNS, TraceRow.range!.endNS, TraceRow.range!.totalNS!, this.frame));
            TraceRow.rangeSelectObject!.endX = Math.floor(ns2x(TraceRow.rangeSelectObject!.endNS!, TraceRow.range!.startNS, TraceRow.range!.endNS, TraceRow.range!.totalNS!, this.frame));
            if (ctx) {
                ctx.globalAlpha = 0.5
                ctx.fillStyle = "#666666"
                ctx.fillRect(TraceRow.rangeSelectObject!.startX!, this.frame.y, TraceRow.rangeSelectObject!.endX! - TraceRow.rangeSelectObject!.startX!, this.frame.height)
                ctx.globalAlpha = 1
            }
        }
    }

    isInTimeRange(startTime: number, duration: number): boolean {
        return ((startTime || 0) + (duration || 0) > (TraceRow.range?.startNS || 0) && (startTime || 0) < (TraceRow.range?.endNS || 0));
    }

    buildArgs(obj: any) {
        let result: any = {
            list: this.must ? this.dataList : undefined,
            offscreen: !this.isTransferCanvas ? this.offscreen[0] : undefined,//是否离屏
            dpr: this.dpr,//屏幕dpr值
            xs: TraceRow.range?.xs,//线条坐标信息
            isHover: this.isHover,
            hoverX: this.hoverX,
            hoverY: this.hoverY,
            canvasWidth: this.canvasWidth,
            canvasHeight: this.canvasHeight,
            isRangeSelect: this.rangeSelect,
            rangeSelectObject: TraceRow.rangeSelectObject,
            lineColor: this.getLineColor(),
            chartColor: ColorUtils.MD_PALETTE[0],
            startNS: TraceRow.range?.startNS || 0,
            endNS: TraceRow.range?.endNS || 0,
            totalNS: TraceRow.range?.totalNS || 0,
            slicesTime: TraceRow.range?.slicesTime,
            range: TraceRow.range,
            frame: this.frame,
            flagMoveInfo: null,
            flagSelectedInfo: null,
            wakeupBean: null
        };
        Reflect.ownKeys(obj).forEach(it => {
            result[it] = obj[it];
        })
        return result;
    }

    getTransferArray() {
        let tsf = [];
        if (!this.isTransferCanvas) {
            tsf.push(this.offscreen[0]);
        }
        if (this.must && this.dataList instanceof ArrayBuffer) {
            tsf.push(this.dataList);
        }
        return tsf;
    }

    attributeChangedCallback(name: string, oldValue: string, newValue: string) {
        switch (name) {
            case "name":
                if (this.nameEL) {
                    this.nameEL.textContent = newValue;
                    this.nameEL.title = newValue;
                }
                break;
            case "height":
                if (newValue != oldValue) {
                    if (!this.args.isOffScreen) {
                    }
                }
                break;
            case "check-type":
                if (newValue === "check") {
                    this.checkBoxEL?.setAttribute("checked", "");
                } else {
                    this.checkBoxEL?.removeAttribute("checked");
                }
                break;
        }
    }

    initHtml(): string {
        return `
        <style>
        *{
            box-sizing: border-box;
        }
        :host(:not([row-hidden])){
            box-sizing: border-box;
            display: block;
            width: 100%;
            height: min-content;
        }
        :host([row-hidden]){
            width: 100%;
            display: none;
        }
        .root{
            height: 40px;
            width: 100%;
            display: grid;
            grid-template-rows: 100%;
            grid-template-columns: 248px 1fr;
            border-bottom: 1px solid var(--dark-border1,#dadada);
            box-sizing: border-box;
        }
        .root .drag{
            background-color: var(--dark-background1,#eee);
            box-shadow: 0 4px 12px -4px #999 inset;
        }
        .root .line-top{
            box-shadow: 0 4px 2px -1px #4d7ab3 inset; 
            transition: all 0.2s;
        }
        .root .line-bottom{
            box-shadow: 0 -4px 2px -1px #4d7ab3 inset; 
            transition: all 0.2s;
        }
        .describe{
            box-sizing: border-box;
            border-right: 1px solid var(--dark-border1,#c9d0da);
            background-color: transparent;
            align-items: center;
            position: relative;
        }
        .panel{
            width: 100%;
            height: 100%;
            overflow: visible;
            background-color: transparent;
            display: block;
        }
        .panel-container{
            width: 100%;
            position: relative;
            pointer-events: none;
        }
        .tip{
            position:absolute;
            top: 0;
            left: 0;
            height: 100%;
            background-color: white;
            border: 1px solid #f9f9f9;
            width: auto;
            font-size: 8px;
            color: #50809e;
            flex-direction: column;
            justify-content: center;
            align-items: flex-start;
            padding: 2px 10px;
            display: none;
            user-select: none;
        }
        .name{
            color: var(--dark-color1,#4b5766);
            margin-left: 10px;
            font-size: .9rem;
            font-weight: normal;
            width: 100%;
            max-height: 100%;
            text-align: left;
            overflow: hidden;
            user-select: none;
            text-overflow: ellipsis;
        }
        :host([highlight]) .name{
            color: #4b5766;
        }
        .icon{
            color: var(--dark-color1,#151515);
            margin-left: 10px;
        }
        .describe:hover {
            cursor: pointer;
        }
        :host([folder]) .describe:hover > .icon{
            color:#ecb93f;
            margin-left: 10px;
        }
        :host([folder]){
            /*background-color: var(--dark-background1,#f5fafb);*/
        }
        :host([folder]) .icon{
            display: flex;
        }
        :host(:not([folder])){
            /*background-color: var(--dark-background,#FFFFFF);*/
        }
        :host(:not([folder]):not([children])) {
        }
        :host(:not([folder]):not([children])) .icon{
            display: none;
        }
        :host(:not([folder])[children]) .icon{
            visibility: hidden;
            color:#fff
        }

        :host(:not([folder])[children]) .name{
        }
        :host([expansion]) {
            background-color: var(--bark-expansion,#0C65D1);
        }
        :host([expansion]) .name,:host([expansion]) .icon{
            color: #fff;
        }
        :host([expansion]) .describe{
            border-right: 0px;
        }
        :host([expansion]:not(sleeping)) .panel-container{
            display: none;
        }
        :host([expansion]) .children{
            flex-direction: column;
            width: 100%;
        }
        :host([expansion]) .icon{
            transform: rotateZ(0deg);
        }
        :host(:not([expansion])) .children{
            display: none;
            flex-direction: column;
            width: 100%;
        }
        :host(:not([expansion])) .icon{
            transform: rotateZ(-90deg);
        }
        :host([sleeping]) .describe{
            display: none;
        }
        :host([sleeping]) .panel-container{
            display: none;
        }
        :host([sleeping]) .children{
            display: none;
        }
        :host(:not([sleeping])) .describe{
            display: flex;;
        }
        :host(:not([sleeping])) .panel-container{
            display: block;
        }
        :host(:not([sleeping])) .children{
            display: flex;
        }
        :host([folder]) .lit-check-box{
            display: none;
        }
        :host(:not([check-type])) .lit-check-box{
            display: none;
        }
        :host([collect-type]) {
            position:fixed;
            z-index:1000;
        }
        :host(:not([collect-type])) {
            position:static;
        }
        :host([collect-type]) .collect{
            display: block;
            color: #5291FF;
        }
        :host(:not([collect-type])) .collect{
            display: none;
            color: var(--dark-icon,#666666);
        }
        .collect{
            margin-right: 5px;
        }
        :host(:not([folder])) .describe:hover .collect{
            display: block;
        }
        :host([row-type="native-memory"]) #nativeRadioList{
            display: flex;
        }
        .popover{
            color: var(--dark-color1,#4b5766);
            display: none;
            justify-content: center;
            align-items: center;
            margin-right: 5px;
        }
        .radio{
            margin-right: 10px;

        }
        #setting{
            color: var(--dark-color1,#606060);
        }
        :host([expansion]) #setting{
            color: #FFFFFF;
        }
        :host([highlight]) .flash{
            background-color: #ffe263;
        }
        
        :host([row-type="energy"]) #appNameList{
            display: flex;
        }
        
         #listprocess::-webkit-scrollbar{
         width: 6px;
        }
        
        /*定义滑块 内阴影+圆角*/
        #listprocess::-webkit-scrollbar-thumb
        {
          border-radius: 6px;
          background-color: var(--dark-background7,#e7c9c9);
        }

        </style>
        <div class="root">
            <div class="describe flash">
                <lit-icon class="icon" name="caret-down" size="13"></lit-icon>
                <label class="name"></label>
                <lit-icon class="collect" name="star-fill" size="17"></lit-icon>
                <lit-popover placement="bottomLeft" trigger="click" id = "nativeRadioList" class="popover" haveRadio="true">
                    <div style="display: block" slot="content">
                        <div id="first-radio" style="margin-bottom: 5px">
                        <input class="radio" name="status" type="radio" value="0" />Current Bytes</div>
                        <div id="second-radio" style="margin-bottom: 5px">
                        <input class="radio" name="status" type="radio" value="1" />Native Memory Density</div>
                    </div>
                    <lit-icon name="setting" size="17" id="setting"></lit-icon>
                </lit-popover>
                <lit-popover placement="bottomLeft" trigger="click" id="appNameList" class="popover" haveRadio="true">
                    <div slot="content" id="listprocess" style="height:200px;overflow-y:auto">
                    </div>
                    <lit-icon name="setting" size="17" id="setting"></lit-icon>
                </lit-popover>
                <lit-check-box class="lit-check-box"></lit-check-box>
            </div>
            <div class="panel-container">
                <div class="tip">
                    P:process [1573]<br>
                    T:Thread [675]
                </div>
            </div>
        </div>
        `;
    }
}
