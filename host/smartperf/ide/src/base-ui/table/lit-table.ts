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

import {LitTableColumn} from "./lit-table-column.js";
import {element} from "../BaseElement.js";
import "../utils/Template.js"
import {TableRowObject} from "./TableRowObject.js";

@element('lit-table')
export class LitTable extends HTMLElement {
    meauseRowElement: HTMLDivElement | undefined
    currentRecycleList: HTMLDivElement[] = []
    currentTreeDivList: HTMLDivElement[] = []
    public rememberScrollTop = false
    private ds: Array<any> = []
    private recycleDs: Array<any> = []
    private normalDs: Array<any> = []
    private gridTemplateColumns: any
    /*Grid css layout descriptions are obtained according to the clustern[] nested structure*/
    private st: HTMLSlotElement | null | undefined
    private tableElement: HTMLDivElement | null | undefined
    private theadElement: HTMLDivElement | null | undefined
    private columns: Array<Element> | null | undefined
    private tbodyElement: HTMLDivElement | undefined | null
    private treeElement: HTMLDivElement | undefined | null
    private tableColumns: NodeListOf<LitTableColumn> | undefined
    private colCount: number = 0
    private currentScrollTop: number = 0
    private isRecycleList: boolean = true
    private isScrollXOutSide: boolean = false;
    constructor() {
        super();
        const shadowRoot = this.attachShadow({mode: 'open'});
        shadowRoot.innerHTML = `
        <style>
        :host{
            display: grid;
            grid-template-columns: repeat(1,1fr);
            width: 100%;
            flex:1;
        }
        .tr{
            display: grid;
            grid-column-gap: 5px;
            min-width:100%;
        }
        .tr:nth-of-type(even){
        }

        .tr{
            background-color: var(--dark-background,#FFFFFF);
        }
        .tr:hover{
            background-color: var(--dark-background6,#DEEDFF);
        }
        .td{
            box-sizing: border-box;
            padding: 3px;
            display: flex;
            justify-content: flex-start;
            align-items: center;
            width: 100%;
            height: auto;
            cursor: pointer;
        }
        .td text{
            overflow: hidden; 
            text-overflow: ellipsis; 
            white-space: nowrap;
        }
        .tr[selected]{
            background-color: var(--dark-background6,#DEEDFF);
        }
        .td-order{
        }
        .td-order:before{

        }
        :host([grid-line]) .td{
            border-left: 1px solid #f0f0f0;
        }
        :host([grid-line]) .td:last-of-type{
            border-right: 1px solid #f0f0f0;
        }
        .table{
            width: 100%;
             color: var(--dark-color2,#262626);
        }
        .thead{
            display: grid;
            position: sticky;
            top: 0;
            font-weight: bold;
            font-size: .9rem;
            color: var(--dark-color1,#000);
            background-color: var(--dark-background,#FFFFFF);
            z-index: 1;
        }
        .tbody{
            width: 100%;
            top: 0;
            left: 0;
            right:0;
            bottom:0;
            display: flex;
            flex-direction: row
            row-gap: 1px;
            column-gap: 1px;
        }
        .tree{
            overflow-x:hidden;
            overflow-y:hidden;
            display: grid;
            grid-template-columns: 1fr;
            row-gap: 1px;
            column-gap: 1px;
            position:relative;
        }
        .tree:hover{
            overflow-x: overlay;
        }
        .tree-first-body{
            min-width: 100%;
            box-sizing: border-box;
            display:flex;
            align-items:center;
            white-space: nowrap;
            cursor: pointer;
        }
        .tree-first-body:hover{
            background-color: var(--dark-background6,#DEEDFF); /*antd #fafafa 42b983*/
        }
        .body{
            display: grid;
            grid-template-columns: 1fr;
            row-gap: 1px;
            column-gap: 1px;
            flex:1;
            position: relative;
        }
        :host([grid-line])  .tbody{
            border-bottom: 1px solid #f0f0f0;
            background-color: #f0f0f0;
        }
        .th{
            grid-column-gap: 5px;
            display: grid;
            background-color: var(--dark-background,#FFFFFF);
        }

        .tree-icon{
            font-size: 1.2rem;
            width: 20px;
            height: 20px;
            padding-right: 5px;
            padding-left: 5px;
            cursor: pointer;
        }
        .tree-icon:hover{
            color: #42b983;
        }
        .row-checkbox,row-checkbox-all{

        }
        :host([no-head]) .thead{
            display: none;
        }
        .up-svg{
            position: absolute;
            right: 5px;
            top: 8px;
            bottom: 8px;
            width: 15px;
            height: 15px;
        }
        .down-svg{
            position: absolute;
            top: 8px;
            right: 5px;
            bottom: 8px;
            width: 15px;
            height: 15px;
        }
        .mouse-select{
            background-color: var(--dark-background6,#DEEDFF);
        }
        .mouse-in{
            background-color: var(--dark-background6,#DEEDFF);
        }
        .export{
            width:30px;
            height:30px;
            cursor:pointer;
            color:var(--dark-background6,#262626);
            box-sizing: border-box;
            position:fixed;
            right:30px;
            bottom:15px;
        }
        </style>

        <slot id="slot" style="display: none"></slot>
        <slot name="head"></slot>
        <div class="table" style="overflow-x:auto;">
            <div class="thead"></div>
            <div class="tbody">
                <div class="tree"></div>
                <div class="body"></div>
        </div>
        </div>
        `
    }

    static get observedAttributes() {
        return ['scroll-y', 'selectable', 'no-head', 'grid-line', 'defaultOrderColumn']
    }

    get selectable() {
        return this.hasAttribute('selectable');
    }

    set selectable(value) {
        if (value) {
            this.setAttribute('selectable', '');
        } else {
            this.removeAttribute('selectable');
        }
    }

    get scrollY() {
        return this.getAttribute('scroll-y') || 'auto';
    }

    set scrollY(value) {
        this.setAttribute('scroll-y', value);
    }


    get dataSource() {
        return this.ds || [];
    }

    set dataSource(value) {
        this.ds = value;
        this.isRecycleList = false
        if (this.hasAttribute('tree')) {
            this.renderTreeTable();
        } else {
            this.renderTable();
        }
    }

    get recycleDataSource() {
        return this.ds || [];
    }

    set recycleDataSource(value) {
        this.isScrollXOutSide = this.tableElement!.scrollWidth > this.tableElement!.clientWidth
        this.isRecycleList = true
        this.ds = value;
        if (this.rememberScrollTop) {
            this.currentScrollTop = this.tableElement!.scrollTop;
            this.tableElement!.scrollTop = 0
        } else {
            this.tableElement!.scrollTop = 0
        }
        if (this.hasAttribute('tree')) {
            this.recycleDs = this.meauseTreeRowElement(value)
        } else {
            this.recycleDs = this.meauseAllRowHeight(value)
        }
    }

    move1px() {
        this.tableElement!.scrollTop = this.tableElement!.scrollTop + 1
    }

    dataExportInit() {
        let exportDiv = this.shadowRoot!.querySelector<HTMLDivElement>(".export")
        exportDiv && (exportDiv.onclick = () => {
            this.exportData()
        });
        let tab = document?.querySelector("body > sp-application")?.shadowRoot?.querySelector("#sp-system-trace")
            ?.shadowRoot?.querySelector("div > trace-sheet")?.shadowRoot?.querySelector("#tabs");
        if (tab != undefined) {
            new ResizeObserver(() => {
                if (tab && tab.clientHeight > (38 + 70)) {
                    exportDiv!.style.visibility = "visible";
                } else {
                    exportDiv!.style.visibility = "hidden";
                }
            }).observe(tab)
        }
    }

    exportData() {
        let formatData: any[] = this.formatExportData(this.ds)
        let link = document.createElement('a')
        link.download = new Date().getTime() + '.json'
        link.href = 'data:text/plain,' + JSON.stringify(formatData, null, 4)
        link.click()
    }

    formatExportData(dataSource: any[]): any[] {
        if (dataSource == undefined || dataSource.length == 0) {
            return []
        }
        if (this.columns == undefined) {
            return []
        }
        return dataSource.map((item) => {
            let formatData: any = {}
            this.columns!.forEach((column) => {
                let dataIndex = column.getAttribute('data-index')
                let columnName = column.getAttribute('title')
                if (columnName == "") {
                    columnName = dataIndex
                }
                if (dataIndex && columnName && item[dataIndex] != undefined) {
                    formatData[columnName] = item[dataIndex]
                }
            })
            if (item.children != undefined) {
                formatData.children = this.formatExportData(item.children)
            }
            return formatData
        })
    }


    //当 custom element首次被插入文档DOM时，被调用。
    connectedCallback() {
        this.st = this.shadowRoot?.querySelector('#slot');
        this.tableElement = this.shadowRoot?.querySelector('.table');
        this.theadElement = this.shadowRoot?.querySelector('.thead');
        this.treeElement = this.shadowRoot?.querySelector('.tree');
        this.tbodyElement = this.shadowRoot?.querySelector('.body');
        this.tableColumns = this.querySelectorAll<LitTableColumn>('lit-table-column');
        this.colCount = this.tableColumns!.length;
        this.tableElement?.addEventListener("copy",(e)=>{
            // @ts-ignore
            let clipboardData = e.clipboardData || window.clipboardData;
            if(!clipboardData) return ;
            // @ts-ignore
            let text = window.getSelection().toString();
            if(text){
                e.preventDefault();
                let length = this.tableColumns?.length||1;
                let strings = text.split("\n");
                let formatStr = ""
                for (let i = 0; i < strings.length; i++) {
                    if(i%length != 0){
                        formatStr+="    "
                    }
                    formatStr+=strings[i]
                    if(i!=0&&i%length == length - 1){
                        formatStr += "\n"
                    }
                }
                clipboardData.setData('text/plain', formatStr)
            }
        })
        this.st?.addEventListener('slotchange', () => {
            this.theadElement!.innerHTML = '';
            setTimeout(() => {
                this.columns = this.st!.assignedElements();
                let rowElement = document.createElement('div');
                rowElement.classList.add('th');
                if (this.selectable) {
                    let box = document.createElement('div');
                    box.style.display = 'flex';
                    box.style.justifyContent = 'center';
                    box.style.alignItems = 'center';
                    box.style.gridArea = "_checkbox_";
                    box.classList.add('td');
                    box.style.backgroundColor = "#ffffff66";
                    let checkbox = document.createElement('lit-checkbox');
                    checkbox.classList.add('row-checkbox-all');
                    checkbox.onchange = (e: any) => {
                        this.shadowRoot!.querySelectorAll('.row-checkbox').forEach((a: any) => a.checked = e.detail.checked);
                        if (e.detail.checked) {
                            this.shadowRoot!.querySelectorAll('.tr').forEach(a => a.setAttribute('checked', ''));
                        } else {
                            this.shadowRoot!.querySelectorAll('.tr').forEach(a => a.removeAttribute('checked'));
                        }
                    }
                    box.appendChild(checkbox);
                    rowElement.appendChild(box);
                }
                let area: Array<any> = [], gridTemplateColumns: Array<any> = [];
                let resolvingArea = (columns: any, x: any, y: any) => {
                    columns.forEach((a: any, i: any) => {
                        if (!area[y]) area[y] = []
                        let key = a.getAttribute('key') || a.getAttribute('title')
                        if (a.tagName === 'LIT-TABLE-GROUP') {
                            let len = a.querySelectorAll('lit-table-column').length;
                            let children = [...a.children].filter(a => a.tagName !== 'TEMPLATE');
                            if (children.length > 0) {
                                resolvingArea(children, x, y + 1);
                            }
                            for (let j = 0; j < len; j++) {
                                area[y][x] = {x, y, t: key};
                                x++;
                            }
                            let h = document.createElement('div');
                            h.classList.add('td');
                            h.style.justifyContent = a.getAttribute('align')
                            h.style.borderBottom = '1px solid #f0f0f0'
                            h.style.gridArea = key;
                            h.innerText = a.title;
                            if (a.hasAttribute('fixed')) {
                                this.fixed(h, a.getAttribute('fixed'), "#42b983")
                            }
                            rowElement.append(h);
                        } else if (a.tagName === 'LIT-TABLE-COLUMN') {
                            area[y][x] = {x, y, t: key};
                            x++;
                            let h: any = document.createElement('div');
                            h.classList.add('td');
                            if (a.hasAttribute('order')) {
                                h.sortType = 0;
                                h.classList.add('td-order');
                                h.style.position = "relative"
                                let NS = "http://www.w3.org/2000/svg";
                                let upSvg: any = document.createElementNS(NS, "svg");
                                let upPath: any = document.createElementNS(NS, "path");
                                upSvg.setAttribute('fill', 'var(--dark-color1,#212121)');
                                upSvg.setAttribute('viewBox', '0 0 1024 1024');
                                upSvg.setAttribute('stroke', 'var(--dark-color1,#212121)');
                                upSvg.classList.add('up-svg');
                                upPath.setAttribute("d", "M858.9 689L530.5 308.2c-9.4-10.9-27.5-10.9-37 0L165.1 689c-12.2 14.2-1.2 35 18.5 35h656.8c19.7 0 30.7-20.8 18.5-35z");
                                upSvg.appendChild(upPath);
                                let downSvg: any = document.createElementNS(NS, "svg");
                                let downPath: any = document.createElementNS(NS, "path");
                                downSvg.setAttribute('fill', 'var(--dark-color1,#212121)');
                                downSvg.setAttribute('viewBox', '0 0 1024 1024');
                                downSvg.setAttribute('stroke', 'var(--dark-color1,#212121)');
                                downSvg.classList.add('down-svg');
                                downPath.setAttribute("d", "M840.4 300H183.6c-19.7 0-30.7 20.8-18.5 35l328.4 380.8c9.4 10.9 27.5 10.9 37 0L858.9 335c12.2-14.2 1.2-35-18.5-35z");
                                downSvg.appendChild(downPath)
                                if (i == 0) {
                                    h.sortType = 0; // 默认以第一列 降序排序 作为默认排序
                                    upSvg.setAttribute('fill', 'var(--dark-color1,#212121)');
                                    downSvg.setAttribute('fill', 'var(--dark-color1,#212121)');
                                }
                                upSvg.style.display = 'none';
                                downSvg.style.display = 'none';
                                h.appendChild(upSvg);
                                h.appendChild(downSvg);
                                h.onclick = () => {
                                    this?.shadowRoot?.querySelectorAll('.td-order svg').forEach((it: any) => {
                                        it.setAttribute('fill', 'var(--dark-color1,#212121)');
                                        it.sortType = 0;
                                        it.style.display = 'none';
                                    })
                                    if (h.sortType == undefined || h.sortType == null) {
                                        h.sortType = 0;
                                    } else if (h.sortType === 2) {
                                        h.sortType = 0;
                                    } else {
                                        h.sortType += 1;
                                    }
                                    switch (h.sortType) {
                                        case 1:
                                            upSvg.setAttribute('fill', 'var(--dark-color1,#212121)');
                                            downSvg.setAttribute('fill', 'var(--dark-color1,#212121)');
                                            upSvg.style.display = 'block';
                                            downSvg.style.display = 'none';
                                            break;
                                        case 2:
                                            upSvg.setAttribute('fill', 'var(--dark-color1,#212121)');
                                            downSvg.setAttribute('fill', 'var(--dark-color1,#212121)');
                                            upSvg.style.display = 'none';
                                            downSvg.style.display = 'block';
                                            break;
                                        default:
                                            upSvg.setAttribute('fill', "var(--dark-color1,#212121)");
                                            downSvg.setAttribute('fill', "var(--dark-color1,#212121)");
                                            upSvg.style.display = 'none';
                                            downSvg.style.display = 'none';
                                            break;
                                    }
                                    this.dispatchEvent(new CustomEvent("column-click", {
                                        detail: {
                                            sort: h.sortType, key: key
                                        }, composed: true
                                    }))
                                }
                            }
                            h.style.justifyContent = a.getAttribute('align')
                            gridTemplateColumns.push(a.getAttribute('width') || '1fr');
                            h.style.gridArea = key;
                            let titleLabel = document.createElement("label");
                            titleLabel.textContent = a.title;
                            h.appendChild(titleLabel);
                            if (a.hasAttribute('fixed')) {
                                this.fixed(h, a.getAttribute('fixed'), "#42b983")
                            }
                            rowElement.append(h);
                        }
                    })
                }
                resolvingArea(this.columns, 0, 0);
                area.forEach((rows, j, array) => {
                    for (let i = 0; i < this.colCount; i++) {
                        if (!rows[i]) rows[i] = array[j - 1][i];
                    }
                })
                this.gridTemplateColumns = gridTemplateColumns.join(' ');
                if (this.selectable) {
                    let s = area.map(a => '"_checkbox_ ' + (a.map((aa: any) => aa.t).join(' ')) + '"').join(' ');
                    rowElement.style.gridTemplateColumns = "60px " + gridTemplateColumns.join(' ');
                    rowElement.style.gridTemplateRows = `repeat(${area.length},1fr)`
                    rowElement.style.gridTemplateAreas = s
                } else {
                    let s = area.map(a => '"' + (a.map((aa: any) => aa.t).join(' ')) + '"').join(' ');
                    rowElement.style.gridTemplateColumns = gridTemplateColumns.join(' ');
                    rowElement.style.gridTemplateRows = `repeat(${area.length},1fr)`
                    rowElement.style.gridTemplateAreas = s
                }
                this.theadElement!.innerHTML = ''
                this.theadElement!.append(rowElement);
                this.treeElement!.style.top = this.theadElement?.clientHeight + "px"
            });

        });

        this.shadowRoot!.addEventListener("load", function (event) {
        });
    }

    // Is called when the custom element is removed from the document DOM.
    disconnectedCallback() {

    }

    // It is called when the custom element is moved to a new document.
    adoptedCallback() {
    }

    // It is called when a custom element adds, deletes, or modifies its own properties.
    attributeChangedCallback(name: string, oldValue: string, newValue: string) {

    }

    fixed(td: HTMLElement, placement: string, bgColor: string) {
        td.style.position = 'sticky';
        if (placement === "left") {
            td.style.left = '0px';
            td.style.boxShadow = '3px 0px 5px #33333333'
        } else if (placement === "right") {
            td.style.right = '0px';
            td.style.boxShadow = '-3px 0px 5px #33333333'
        }
    }

    renderTable() {
        if (!this.columns) return;
        if (!this.ds) return; // If no data source is set, it is returned directly
        this.normalDs = []
        this.tbodyElement!.innerHTML = '';// Clear the table contents
        this.ds.forEach((rowData: any) => {
            let rowElement = document.createElement('div');
            rowElement.classList.add('tr');
            // @ts-ignore
            rowElement.data = rowData;
            let gridTemplateColumns: Array<any> = []
            // If the table is configured with selectable (select row mode) add a checkbox at the head of the line alone
            if (this.selectable) {
                let box = document.createElement('div');
                box.style.display = 'flex';
                box.style.justifyContent = 'center';
                box.style.alignItems = 'center';
                box.classList.add('td');
                let checkbox = document.createElement('lit-checkbox');
                checkbox.classList.add('row-checkbox');
                checkbox.onchange = (e: any) => {// Checkbox checking affects whether the div corresponding to the row has a checked attribute for marking
                    if (e.detail.checked) {
                        rowElement.setAttribute('checked', "");
                    } else {
                        rowElement.removeAttribute('checked');
                    }
                }
                box.appendChild(checkbox);
                rowElement.appendChild(box);
            }
            this.tableColumns!.forEach(cl => {
                let dataIndex = cl.getAttribute('data-index') || '1';
                gridTemplateColumns.push(cl.getAttribute('width') || '1fr')
                if (cl.template) {// If you customize the rendering, you get the nodes from the template
                    // @ts-ignore
                    let cloneNode = cl.template.render(rowData).content.cloneNode(true);
                    let d = document.createElement('div');
                    d.classList.add('td');
                    d.style.wordBreak = 'break-all'
                    d.style.whiteSpace = 'pre-wrap'
                    d.style.justifyContent = cl.getAttribute('align') || ''
                    if (cl.hasAttribute('fixed')) {
                        this.fixed(d, cl.getAttribute('fixed') || '', "#ffffff")
                    }
                    d.append(cloneNode);
                    rowElement.append(d);
                } else {
                    let td = document.createElement('div');
                    td.classList.add('td');
                    td.style.wordBreak = 'break-all'
                    td.style.whiteSpace = 'pre-wrap'
                    td.title = rowData[dataIndex]
                    td.style.justifyContent = cl.getAttribute('align') || ''
                    if (cl.hasAttribute('fixed')) {
                        this.fixed(td, cl.getAttribute('fixed') || '', "#ffffff")
                    }
                    td.innerHTML = this.formatName(rowData[dataIndex]);
                    rowElement.append(td);
                }

            })
            if (this.selectable) { // If the table with selection is preceded by a 60px column
                rowElement.style.gridTemplateColumns = '60px ' + gridTemplateColumns.join(' ');
            } else {
                rowElement.style.gridTemplateColumns = gridTemplateColumns.join(' ');
            }
            rowElement.onclick = e => {
                this.dispatchEvent(new CustomEvent('row-click', {
                    detail: {
                        rowData, data: rowData, callBack: (isSelected: boolean) => {//是否爲单选
                            if (isSelected) {
                                this.clearAllSelection(rowData)
                            }
                            this.setSelectedRow(rowData.isSelected, [rowElement])
                        }
                    }, composed: true
                }));
            }
            this.normalDs.push(rowElement);
            this.tbodyElement!.append(rowElement);
        })
    }


    renderTreeTable() {
        if (!this.columns) return;
        if (!this.ds) return;
        this.tbodyElement!.innerHTML = '';
        this.treeElement!.innerHTML = '';
        let ids = JSON.parse(this.getAttribute('tree') || `["id","pid"]`);
        let toTreeData = (data: any, id: any, pid: any) => {
            let cloneData = JSON.parse(JSON.stringify(data));
            return cloneData.filter((father: any) => {
                let branchArr = cloneData.filter((child: any) => father[id] == child[pid]);
                branchArr.length > 0 ? father['children'] = branchArr : '';
                return !father[pid];
            });
        }
        let treeData = toTreeData(this.ds, ids[0], ids[1]);
        let offset = 30;
        let offsetVal = offset;
        const drawRow = (arr: any, parentNode: any) => {
            arr.forEach((rowData: any) => {
                let rowElement = document.createElement('div');
                rowElement.classList.add('tr');
                // @ts-ignore
                rowElement.data = rowData;
                let gridTemplateColumns: Array<any> = [];
                if (this.selectable) {
                    let box = document.createElement('div');
                    box.style.display = 'flex';
                    box.style.justifyContent = 'center';
                    box.style.alignItems = 'center';
                    box.classList.add('td');
                    let checkbox = document.createElement('lit-checkbox');
                    checkbox.classList.add('row-checkbox');
                    checkbox.onchange = (e: any) => {
                        if (e.detail.checked) {
                            rowElement.setAttribute('checked', "");
                        } else {
                            rowElement.removeAttribute('checked');
                        }
                        const changeChildNode = (rowElement: any, checked: any) => {
                            let id = rowElement.getAttribute('id');
                            let pid = rowElement.getAttribute('pid');
                            this.shadowRoot!.querySelectorAll(`div[pid=${id}]`).forEach(a => {
                                // @ts-ignore
                                a.querySelector('.row-checkbox')!.checked = checked;
                                if (checked) {
                                    a.setAttribute('checked', '');
                                } else {
                                    a.removeAttribute('checked');
                                }
                                changeChildNode(a, checked);
                            });
                        };
                        changeChildNode(rowElement, e.detail.checked);
                    }
                    box.appendChild(checkbox);
                    rowElement.appendChild(box);
                }
                this.tableColumns!.forEach((cl, index) => {
                    let dataIndex = cl.getAttribute('data-index');
                    let td;
                    if (index !== 0) {
                        gridTemplateColumns.push(cl.getAttribute('width') || '1fr')
                        if (cl.template) {
                            // @ts-ignore
                            let cloneNode = cl.template.render(rowData).content.cloneNode(true);
                            td = document.createElement('div');
                            td.classList.add('td');
                            td.style.wordBreak = 'break-all'
                            td.style.justifyContent = cl.getAttribute('align') || ''
                            if (cl.hasAttribute('fixed')) {
                                this.fixed(td, cl.getAttribute('fixed') || '', "#ffffff")
                            }
                            td.append(cloneNode);
                        } else {
                            td = document.createElement('div');
                            td.classList.add('td');
                            td.style.wordBreak = 'break-all'
                            td.style.justifyContent = cl.getAttribute('align') || ''
                            if (cl.hasAttribute('fixed')) {
                                this.fixed(td, cl.getAttribute('fixed') || '', "#ffffff")
                            }
                            // @ts-ignore
                            td.innerHTML = this.formatName(rowData[dataIndex]);
                        }
                        rowElement.append(td)
                    } else {
                        this.treeElement!.style.width = cl.getAttribute('width') || "260px"
                        let treeElement = document.createElement('div');
                        treeElement.classList.add("tree-first-body")
                        if (cl.template) {
                            // @ts-ignore
                            let cloneNode = cl.template.render(rowData).content.cloneNode(true);
                            td = document.createElement('div');
                            td.classList.add('td');
                            td.style.justifyContent = cl.getAttribute('align') || ''
                            if (cl.hasAttribute('fixed')) {
                                this.fixed(td, cl.getAttribute('fixed') || '', "#ffffff")
                            }
                            td.append(cloneNode);
                        } else {
                            td = document.createElement('div');
                            td.classList.add('td');
                            td.style.justifyContent = cl.getAttribute('align') || ''
                            if (cl.hasAttribute('fixed')) {
                                this.fixed(td, cl.getAttribute('fixed') || '', "#ffffff")
                            }
                            // @ts-ignore
                            td.innerHTML = this.formatName(rowData[dataIndex]);
                        }
                        if (rowData.children && rowData.children.length > 0) {
                            let btn = document.createElement('lit-icon');
                            btn.classList.add('tree-icon');
                            // @ts-ignore
                            btn.name = 'minus-square';
                            treeElement.append(btn);
                            treeElement.append(td)
                            treeElement.style.paddingLeft = (offsetVal - 30) + 'px';
                        } else {
                            treeElement.append(td)
                            treeElement.style.paddingLeft = offsetVal + 'px';
                        }
                        this.treeElement!.append(treeElement);
                    }

                })
                if (this.selectable) {
                    rowElement.style.gridTemplateColumns = '60px ' + gridTemplateColumns.join(' ');
                } else {
                    rowElement.style.gridTemplateColumns = gridTemplateColumns.join(' ');
                }
                rowElement.onclick = e => {
                    this.dispatchEvent(new CustomEvent('row-click', {detail: rowData, composed: true}));
                }
                rowElement.style.cursor = 'pointer'
                parentNode.append(rowElement);
                rowElement.setAttribute('id', rowData[ids[0]]);
                rowElement.setAttribute('pid', rowData[ids[1]]);
                rowElement.setAttribute('expend', '');
                if (rowData.children && rowData.children.length > 0) {
                    offsetVal = offsetVal + offset;
                    drawRow(rowData.children, parentNode);
                    offsetVal = offsetVal - offset;
                }
            });
        };
        drawRow(treeData, this.tbodyElement);
    }

    getCheckRows() {
        // @ts-ignore
        return [...this.shadowRoot!.querySelectorAll('div[class=tr][checked]')].map(a => a.data).map(a => {
            delete a['children'];
            return a;
        });
    }

    deleteRowsCondition(fn: any) {
        this.shadowRoot!.querySelectorAll("div[class=tr]").forEach(tr => {
            // @ts-ignore
            if (fn(tr.data)) {
                tr.remove();
            }
        })
    }

    meauseElementHeight(rowData: any) {
        return 27;
    }

    meauseTreeElementHeight(rowData: any, depth: number) {
        return 27;
    }

    meauseAllRowHeight(list: any[]): TableRowObject[] {
        this.tbodyElement!.innerHTML = '';
        this.meauseRowElement = undefined
        let head = this.shadowRoot!.querySelector(".th");
        this.tbodyElement && (this.tbodyElement.style.width = head?.clientWidth + "px")
        this.currentRecycleList = []
        let headHeight = 0
        let totalHeight = headHeight;
        let visibleObjects: TableRowObject[] = [];
        list.forEach((rowData, index) => {
            let height = this.meauseElementHeight(rowData);
            let tableRowObject = new TableRowObject();
            tableRowObject.height = height
            tableRowObject.top = totalHeight
            tableRowObject.data = rowData
            tableRowObject.rowIndex = index
            if (Math.max(totalHeight, this.tableElement!.scrollTop + headHeight) <= Math.min(totalHeight + height, this.tableElement!.scrollTop + this.tableElement!.clientHeight + headHeight)) {
                let newTableElement = this.createNewTableElement(tableRowObject);
                newTableElement.style.transform = `translateY(${totalHeight}px)`
                this.tbodyElement?.append(newTableElement)
                this.currentRecycleList.push(newTableElement)
            }
            totalHeight += height
            visibleObjects.push(tableRowObject)
        })
        this.tbodyElement && (this.tbodyElement.style.height = totalHeight + (this.isScrollXOutSide?0:0) + "px")
        this.tableElement && (this.tableElement.onscroll = (event) => {
            let top = this.tableElement!.scrollTop;
            let skip = 0;
            for (let i = 0; i < visibleObjects.length; i++) {
                if (visibleObjects[i].top <= top && visibleObjects[i].top + visibleObjects[i].height >= top) {
                    skip = i
                    break;
                }
            }
            let reduce = this.currentRecycleList.map((item) => item.clientHeight).reduce((a, b) => a + b, 0);
            if (reduce == 0) {
                return
            }
            while (reduce <= this.tableElement!.clientHeight) {
                let newTableElement = this.createNewTableElement(visibleObjects[skip]);
                this.tbodyElement?.append(newTableElement)
                this.currentRecycleList.push(newTableElement)
                reduce += newTableElement.clientHeight
            }
            for (let i = 0; i < this.currentRecycleList.length; i++) {
                this.freshCurrentLine(this.currentRecycleList[i], visibleObjects[i + skip])
            }
        })
        return visibleObjects
    }

    meauseTreeRowElement(list: any[]): TableRowObject[] {
        this.meauseRowElement = undefined
        this.tbodyElement!.innerHTML = '';
        this.treeElement!.innerHTML = '';
        let headHeight = this.theadElement?.clientHeight || 0
        let totalHeight = 0
        let visibleObjects: TableRowObject[] = []
        this.currentRecycleList = []
        this.currentTreeDivList = []
        let resetAllHeight = (list: any[], depth: number, parentNode?: TableRowObject) => {
            list.forEach((item) => {
                let tableRowObject = new TableRowObject();
                tableRowObject.depth = depth
                tableRowObject.data = item
                tableRowObject.top = totalHeight
                tableRowObject.height = this.meauseTreeElementHeight(tableRowObject, depth)
                if (parentNode != undefined) {
                    parentNode.children.push(tableRowObject)
                }
                if (Math.max(totalHeight, this.tableElement!.scrollTop) <= Math.min(totalHeight + tableRowObject.height, this.tableElement!.scrollTop + this.tableElement!.clientHeight - headHeight)) {
                    let newTableElement = this.createNewTreeTableElement(tableRowObject);
                    newTableElement.style.transform = `translateY(${totalHeight}px)`
                    this.tbodyElement?.append(newTableElement)
                    if (this.treeElement?.lastChild) {
                        (this.treeElement?.lastChild as HTMLElement).style.height = tableRowObject.height + "px";
                    }
                    this.currentRecycleList.push(newTableElement)
                }
                totalHeight += tableRowObject.height
                visibleObjects.push(tableRowObject)
                if (item.children != undefined && item.children.length > 0) {
                    resetAllHeight(item.children, depth + 1, tableRowObject)
                }
            })
        }
        resetAllHeight(list, 0)
        this.tbodyElement && (this.tbodyElement.style.height = totalHeight + "px")
        this.treeElement!.style.height = (this.tableElement!.clientHeight - this.theadElement!.clientHeight) + "px"
        this.tableElement && (this.tableElement.onscroll = (event) => {
            let visibleObjects = this.recycleDs.filter((item) => {
                return !item.rowHidden
            })
            let top = this.tableElement!.scrollTop;
            this.treeElement!.style.transform = `translateY(${top}px)`
            let skip = 0;
            for (let i = 0; i < visibleObjects.length; i++) {
                if (visibleObjects[i].top <= top && visibleObjects[i].top + visibleObjects[i].height >= top) {
                    skip = i
                    break;
                }
            }
            let reduce = this.currentRecycleList.map((item) => item.clientHeight).reduce((a, b) => a + b, 0);
            if (reduce == 0) {
                return
            }
            while (reduce <= this.tableElement!.clientHeight) {
                let newTableElement = this.createNewTreeTableElement(visibleObjects[skip]);
                this.tbodyElement?.append(newTableElement)
                if (this.treeElement?.lastChild) {
                    (this.treeElement?.lastChild as HTMLElement).style.height = visibleObjects[skip].height + "px";
                }
                this.currentRecycleList.push(newTableElement)
                reduce += newTableElement.clientHeight
            }
            for (let i = 0; i < this.currentRecycleList.length; i++) {
                this.freshCurrentLine(this.currentRecycleList[i], visibleObjects[i + skip], (this.treeElement?.children[i] as HTMLElement));
            }
        })
        return visibleObjects
    }


    createNewTreeTableElement(rowData: TableRowObject): any {
        let newTableElement = document.createElement('div');
        newTableElement.classList.add('tr');
        let gridTemplateColumns: Array<any> = [];
        let treeTop = 0;
        if (this.treeElement!.children?.length > 0) {
            let transX = Number((this.treeElement?.lastChild as HTMLElement).style.transform.replace(/[^0-9]/ig, ""));
            treeTop += (transX + rowData.height)
        }
        this?.columns?.forEach((column: any, index) => {
            let dataIndex = column.getAttribute('data-index') || '1';
            let td: any
            if (index === 0) {
                if (column.template) {
                    td = column.template.render(rowData.data).content.cloneNode(true);
                    td.template = column.template
                } else {
                    td = document.createElement('div')
                    td.innerHTML = this.formatName(rowData.data[dataIndex]);
                    td.dataIndex = dataIndex
                }
                if (rowData.data.children && rowData.data.children.length > 0) {
                    let btn = this.createExpandBtn(rowData)
                    td.insertBefore(btn, td.firstChild);
                    td.style.paddingLeft = rowData.depth * 15 + 'px';
                } else {
                    td.style.paddingLeft = rowData.depth * 15 + 20 + 'px';
                }
                (td as any).data = rowData.data
                td.classList.add('tree-first-body');
                td.style.position = 'absolute';
                td.style.top = '0px'
                td.style.left = '0px'
                td.onmouseenter = () => {
                    let indexOf = this.currentTreeDivList.indexOf(td);
                    this.currentRecycleList.forEach((row)=>{
                        row.classList.remove('mouse-in')
                    })
                    if (indexOf >= 0 && indexOf < this.currentRecycleList.length && td.innerHTML != "") {
                        this.setMouseIn(true, [newTableElement]);
                    }
                }
                td.onmouseleave = () => {
                    let indexOf = this.currentTreeDivList.indexOf(td);
                    if (indexOf >= 0 && indexOf < this.currentRecycleList.length) {
                        this.setMouseIn(false, [newTableElement]);
                    }
                }
                td.onclick = () => {
                    let indexOf = this.currentTreeDivList.indexOf(td);
                    this.dispatchRowClickEvent(rowData, [(this.treeElement?.children[indexOf] as HTMLElement), newTableElement])
                }
                this.treeElement!.style.width = column.getAttribute('width')
                this.treeElement?.append(td)
                this.currentTreeDivList.push(td)
            } else {
                gridTemplateColumns.push(column.getAttribute('width') || '1fr')
                td = document.createElement('div')
                td.classList.add('td');
                td.style.overflow = 'hidden'
                td.style.textOverflow = 'ellipsis'
                td.style.whiteSpace = "nowrap"
                td.title = rowData.data[dataIndex]
                td.dataIndex = dataIndex
                td.style.justifyContent = column.getAttribute('align') || 'flex-start'
                if (column.template) {
                    td.appendChild(column.template.render(rowData.data).content.cloneNode(true));
                    td.template = column.template
                } else {
                    td.innerHTML = this.formatName(rowData.data[dataIndex]);
                }
                newTableElement.append(td)
            }
        });
        (this.treeElement?.lastChild as HTMLElement).style.transform = `translateY(${treeTop}px)`;
        (newTableElement as any).data = rowData.data
        newTableElement.style.gridTemplateColumns = gridTemplateColumns.join(' ');
        newTableElement.style.position = 'absolute';
        newTableElement.style.top = '0px'
        newTableElement.style.left = '0px'
        newTableElement.style.cursor = 'pointer'
        newTableElement.onmouseenter = () => {
            if ((newTableElement as any).data.isSelected) return;
            let indexOf = this.currentRecycleList.indexOf(newTableElement);
            this.currentTreeDivList.forEach((row)=>{
                row.classList.remove('mouse-in')
            })
            if (indexOf >= 0 && indexOf < this.treeElement!.children.length) {
                this.setMouseIn(true, [(this.treeElement?.children[indexOf] as HTMLElement)]);
            }
        }
        newTableElement.onmouseleave = () => {
            if ((newTableElement as any).data.isSelected) return;
            let indexOf = this.currentRecycleList.indexOf(newTableElement);
            if (indexOf >= 0 && indexOf < this.treeElement!.children.length) {
                this.setMouseIn(false, [(this.treeElement?.children[indexOf] as HTMLElement)]);
            }
        }
        newTableElement.onclick = e => {
            let indexOf = this.currentRecycleList.indexOf(newTableElement);
            this.dispatchRowClickEvent(rowData, [(this.treeElement?.children[indexOf] as HTMLElement), newTableElement])
        }
        return newTableElement
    }

    createExpandBtn(rowData: any) {
        let btn: any = document.createElement('lit-icon');
        btn.classList.add('tree-icon');
        // @ts-ignore
        if (rowData.expanded) {
            btn.name = 'minus-square';
        } else {
            btn.name = 'plus-square';
        }
        btn.onclick = (e: Event) => {
            const resetNodeHidden = (hidden: boolean, rowData: any) => {
                if (rowData.children.length > 0) {
                    if (hidden) {
                        rowData.children.forEach((child: any) => {
                            child.rowHidden = true
                            resetNodeHidden(hidden, child)
                        })
                    } else {
                        rowData.children.forEach((child: any) => {
                            child.rowHidden = !rowData.expanded
                            if (rowData.expanded) {
                                resetNodeHidden(hidden, child)
                            }
                        })
                    }
                }
            }
            const foldNode = () => {
                rowData.expanded = false
                resetNodeHidden(true, rowData)
            };
            const expendNode = () => {
                rowData.expanded = true
                resetNodeHidden(false, rowData)
            }
            if (rowData.expanded) {
                foldNode()
            } else {
                expendNode()
            }
            this.reMeauseHeight()
            e.stopPropagation();
        };
        return btn
    }

    reMeauseHeight() {
        if (this.currentRecycleList.length == 0) {
            return
        }
        let totalHeight = 0
        this.recycleDs.forEach((it) => {
            if (!it.rowHidden) {
                it.top = totalHeight
                totalHeight += it.height
            }
        })
        this.tbodyElement && (this.tbodyElement.style.height = totalHeight + (this.isScrollXOutSide?0:0) + "px")
        this.treeElement!.style.height = (this.tableElement!.clientHeight - this.theadElement!.clientHeight) + "px"
        let visibleObjects = this.recycleDs.filter((item) => {
            return !item.rowHidden
        })
        let top = this.tableElement!.scrollTop;
        let skip = 0;
        for (let i = 0; i < visibleObjects.length; i++) {
            if (visibleObjects[i].top <= top && visibleObjects[i].top + visibleObjects[i].height >= top) {
                skip = i
                break;
            }
        }
        let reduce = this.currentRecycleList.map((item) => item.clientHeight).reduce((a, b) => a + b, 0);
        if (reduce == 0) {
            return
        }
        while (reduce <= this.tableElement!.clientHeight) {
            let newTableElement
            if (this.hasAttribute('tree')) {
                newTableElement = this.createNewTreeTableElement(visibleObjects[skip]);
            } else {
                newTableElement = this.createNewTableElement(visibleObjects[skip])
            }
            this.tbodyElement?.append(newTableElement)
            if (this.hasAttribute('tree')) {
                if (this.treeElement?.lastChild) {
                    (this.treeElement?.lastChild as HTMLElement).style.height = visibleObjects[skip].height + "px";
                }
            }
            this.currentRecycleList.push(newTableElement)
            reduce += newTableElement.clientHeight
        }
        for (let i = 0; i < this.currentRecycleList.length; i++) {
            if (this.hasAttribute('tree')) {
                this.freshCurrentLine(this.currentRecycleList[i], visibleObjects[i + skip], (this.treeElement?.children[i] as HTMLElement))
            } else {
                this.freshCurrentLine(this.currentRecycleList[i], visibleObjects[i + skip])
            }
        }
    }

    createNewTableElement(rowData: any): any {
        let newTableElement = document.createElement('div');
        newTableElement.classList.add('tr');
        let gridTemplateColumns: Array<any> = [];
        this?.columns?.forEach((column: any) => {
            let dataIndex = column.getAttribute('data-index') || '1';
            gridTemplateColumns.push(column.getAttribute('width') || '1fr')
            let td: any
            td = document.createElement('div')
            td.classList.add('td');
            td.style.overflow = 'hidden'
            td.style.textOverflow = 'ellipsis'
            td.style.whiteSpace = "nowrap"
            td.dataIndex = dataIndex
            td.style.justifyContent = column.getAttribute('align') || 'flex-start'
            td.title = rowData.data[dataIndex]
            if (column.template) {
                td.appendChild(column.template.render(rowData.data).content.cloneNode(true));
                td.template = column.template
            } else {
                td.innerHTML = this.formatName(rowData.data[dataIndex]);
            }
            newTableElement.append(td)
        })
        newTableElement.onclick = () => {
            this.dispatchRowClickEvent(rowData, [newTableElement])
        }
        if (rowData.data.isSelected != undefined) {
            this.setSelectedRow(rowData.data.isSelected, [newTableElement])
        }
        (newTableElement as any).data = rowData.data
        newTableElement.style.cursor = "pointer"
        newTableElement.style.gridTemplateColumns = gridTemplateColumns.join(' ');
        newTableElement.style.position = 'absolute';
        newTableElement.style.top = '0px'
        newTableElement.style.left = '0px'
        return newTableElement
    }

    freshCurrentLine(element: HTMLElement, rowObject: TableRowObject, firstElement?: HTMLElement) {
        if (!rowObject) {
            if (firstElement) {
                firstElement.style.display = 'none'
            }
            element.style.display = 'none'
            return
        }
        let childIndex = -1
        element.childNodes.forEach((child) => {
            if (child.nodeType != 1) return
            childIndex++;
            let idx = firstElement != undefined ? childIndex + 1 : childIndex;
            if (firstElement != undefined && childIndex == 0) {
                (firstElement as any).data = rowObject.data
                if ((this.columns![0] as any).template) {
                    firstElement.innerHTML = (this.columns![0] as any).template.render(rowObject.data).content.cloneNode(true).innerHTML
                } else {
                    let dataIndex = this.columns![0].getAttribute('data-index') || '1';
                    firstElement.innerHTML = this.formatName(rowObject.data[dataIndex])
                    firstElement.title = rowObject.data[dataIndex]
                }
                if (rowObject.children && rowObject.children.length > 0) {
                    let btn = this.createExpandBtn(rowObject)
                    firstElement.insertBefore(btn, firstElement.firstChild);
                    firstElement.style.paddingLeft = 15 * rowObject.depth + "px"
                } else {
                    firstElement.style.paddingLeft = 20 + 15 * rowObject.depth + "px"
                }
                firstElement.onclick = () => {
                    this.dispatchRowClickEvent(rowObject, [firstElement, element])
                }
                firstElement.style.transform = `translateY(${rowObject.top - this.tableElement!.scrollTop}px)`
                if (rowObject.data.isSelected != undefined) {
                    this.setSelectedRow(rowObject.data.isSelected, [firstElement])
                } else {
                    this.setSelectedRow(false, [firstElement])
                }
            }
            let dataIndex = this.columns![idx].getAttribute('data-index') || '1';
            if ((this.columns![idx] as any).template) {
                (child as HTMLElement).innerHTML = "";
                (child as HTMLElement).appendChild((this.columns![idx] as any).template.render(rowObject.data).content.cloneNode(true));
                (child as HTMLElement).title = rowObject.data[dataIndex];
            } else {
                (child as HTMLElement).innerHTML = this.formatName(rowObject.data[dataIndex]);
                (child as HTMLElement).title = rowObject.data[dataIndex];
            }
        })
        if (element.style.display == 'none') {
            element.style.display = 'grid'
        }
        element.style.transform = `translateY(${rowObject.top}px)`
        if (firstElement && firstElement.style.display == 'none') {
            firstElement.style.display = 'flex'
        }
        element.onclick = e => {
            if (firstElement != undefined) {
                this.dispatchRowClickEvent(rowObject, [firstElement, element])
            } else {
                this.dispatchRowClickEvent(rowObject, [element])
            }
        }
        (element as any).data = rowObject.data
        if (rowObject.data.isSelected != undefined) {
            this.setSelectedRow(rowObject.data.isSelected, [element])
        } else {
            this.setSelectedRow(false, [element])
        }
    }

    setSelectedRow(isSelected: boolean, rows: any[]) {
        if (isSelected) {
            rows.forEach((row) => {
                if (row.classList.contains("mouse-in")) row.classList.remove('mouse-in');
                row.classList.add('mouse-select')
            })
        } else {
            rows.forEach((row) => {
                row.classList.remove('mouse-select')
            })
        }
    }

    setMouseIn(isMouseIn: boolean, rows: any[]) {
        if (isMouseIn) {
            rows.forEach((row) => {
                row.classList.add('mouse-in')
            })
        } else {
            rows.forEach((row) => {
                row.classList.remove('mouse-in')
            })
        }
    }

    scrollToData(data: any) {
        if (this.isRecycleList) {
            if (this.recycleDs.length > 0) {
                let filter = this.recycleDs.filter((item) => {
                    return item.data == data
                });
                if (filter.length > 0) {
                    this.tableElement!.scrollTop = filter[0].top
                }
                this.setCurrentSelection(data)
            }
        } else {
            if (this.normalDs.length > 0) {
                let filter = this.normalDs.filter((item) => {
                    return item.data == data
                });
                if (filter.length > 0) {
                    this.tableElement!.scrollTop = filter[0].top
                }
            }
        }


    }

    expandList(datasource: any[]) {
        let filter = this.recycleDs.filter((item) => {
            return datasource.indexOf(item.data) != -1
        });
        if (filter.length > 0) {
            filter.forEach((item) => {
                item.expanded = true
                item.rowHidden = false
            })
        }
        this.reMeauseHeight()
    }

    clearAllSelection(rowObjectData: any) {
        if (this.isRecycleList) {
            this.recycleDs.forEach((item) => {
                if (item.data != rowObjectData && item.data.isSelected) {
                    item.data.isSelected = false
                }
            })
            this.setSelectedRow(false, this.currentTreeDivList)
            this.setSelectedRow(false, this.currentRecycleList)
        } else {
            this.dataSource.forEach((item) => {
                if (item != rowObjectData && item.isSelected) {
                    item.isSelected = false
                }
            })
            this.setSelectedRow(false, this.normalDs)
        }

    }

    setCurrentSelection(data: any) {
        if (this.isRecycleList) {
            if (data.isSelected != undefined) {
                this.currentTreeDivList.forEach((item) => {
                    if ((item as any).data == data) {
                        this.setSelectedRow(data.isSelected, [item])
                    }
                })
                this.currentRecycleList.forEach((item) => {
                    if ((item as any).data == data) {
                        this.setSelectedRow(data.isSelected, [item])
                    }
                })
            }
        } else {
            if (data.isSelected != undefined) {
                this.normalDs.forEach((item) => {
                    if ((item as any).data == data) {
                        this.setSelectedRow(data.isSelected, [item])
                    }
                })
            }
        }

    }

    dispatchRowClickEvent(rowObject: any, elements: any[]) {
        this.dispatchEvent(new CustomEvent('row-click', {
            detail: {
                ...rowObject.data, data: rowObject.data, callBack: (isSelected: boolean) => {//是否爲单选
                    if (isSelected) {
                        this.clearAllSelection(rowObject.data)
                    }
                    this.setSelectedRow(rowObject.data.isSelected, elements)
                }
            }, composed: true,
        }));
    }

    formatName(name:any){
        if(name!=undefined&&name!==null){
            return name.toString().replace("<","&lt;").replace(">","&gt;")
        }
        return ""
    }
}
