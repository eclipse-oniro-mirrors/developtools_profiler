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

// @ts-ignore
import {LitTable} from "../../../dist/base-ui/table/lit-table.js";
import {LitTableColumn} from "../../../src/base-ui/table/lit-table-column.js";

describe('LitTable Test', () => {
    window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));
    let litTable = new LitTable();
    litTable.selectable = true
    litTable.selectable = false
    litTable.scrollY = 'scrollY'

    litTable.dataSource = []

    litTable.dataSource = [{
        id: 1,
        name: 'name'
    }, {
        id: 2,
        name: 'nameValue'
    }]
    const td = {
        style: {
            position: 'sticky',
            left: '0px',
            right: '0px',
            boxShadow: '3px 0px 5px #33333333'
        }
    }
    const placement = "left"

    const element = {
        style: {
            display: 'none',
            transform: 'translateY'
        },
        childNodes:{forEach:true},
        onclick: 1
    }
    const rowObject = {
        children: {
            length: 1,
        },
        data: [{isSelected:undefined}],
        depth: 1,
        top: 1
    }
    const firstElement = {
        style: {
            display: 'none',
            paddingLeft: "",
            transform: 'translateY'

        },
        innerHTML: "",
        title: "",
        firstChild: null,
        onclick: 1

    }||undefined

    JSON.parse = jest.fn(() => [['children', 'father'], ['children', 'father']])

    litTable.columns = litTable.columns || jest.fn(() => true)
    litTable.ds = jest.fn(() => [{
        id: 1,
        name: 'name'
    }, {
        id: 2,
        name: 'nameValue'
    }])

    litTable.tbodyElement = jest.fn(() => ({
        innerHTML: ''
    }))

    litTable.tableColumns = jest.fn(() => [])

    litTable.tableColumns.forEach = jest.fn(() => [])


    it('LitTableTest01', () => {
        expect(litTable.adoptedCallback()).toBeUndefined();
    })

    it('LitTableTest02', () => {
        litTable.ds.forEach = jest.fn(() => true)
        expect(litTable.renderTable()).toBeUndefined();
    })

    it('LitTableTest04', () => {
        litTable.switch = document.querySelector("#switch") as HTMLInputElement;
        expect(litTable.connectedCallback()).toBeUndefined()
    })

    it('LitTableTest05', () => {
        let rowLength = litTable.getCheckRows().length == 0;
        expect(rowLength).toBeTruthy()
    })

    it('LitTableTest06', () => {
        expect(litTable.deleteRowsCondition(() => {
            return true
        })).toBeUndefined()
    })

    it('LitTableTest07', () => {
        expect(litTable.selectable).not.toBeUndefined()
    })

    it('LitTableTest08', () => {
        litTable.selectable = true
        expect(litTable.selectable).toBeTruthy()
    })

    it('LitTableTest09', () => {
        expect(litTable.scrollY).not.toBeUndefined()
    })

    it('LitTableTest10', () => {
        expect(litTable.dataSource).not.toBeUndefined()
    })

    it('LitTableTest11', () => {
        expect(litTable.recycleDataSource).not.toBeUndefined()
    })

    it('LitTableTest12', () => {
        expect(litTable.fixed(td, placement)).toBeUndefined()
    })

    it('LitTableTest13', () => {
        expect(litTable.fixed(td, "right")).toBe(undefined)
    })

    it('LitTableTest14', () => {
        expect(litTable.meauseElementHeight()).toBe(27)
    })

    it('LitTableTest15', () => {
        expect(litTable.meauseTreeElementHeight()).toBe(27)
    })

    it('LitTableTest16', () => {
        document.body.innerHTML = "<lit-table id='tab' tree></lit-table>"
       let table = document.querySelector("#tab") as LitTable;
        let htmlElement = document.createElement('lit-table-column') as LitTableColumn;
        htmlElement.setAttribute('title', "1");
        htmlElement.setAttribute('data-index', "1");
        htmlElement.setAttribute('key', "1");
        htmlElement.setAttribute('align', 'flex-start');
        htmlElement.setAttribute('height', '32px');
        table!.appendChild(htmlElement);
        setTimeout(() => {
            table.recycleDataSource = [{
                id: 1,
                name: 'name'
            }, {
                id: 2,
                name: 'nameValue'
            }]
            expect(table.meauseTreeElementHeight()).toBe(27)
        }, 20)
    })

    it('LitTableTest17', () => {
         expect(litTable.shadowRoot.innerHTML).toMatchInlineSnapshot(`
"
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

        <slot id=\\"slot\\" style=\\"display: none\\"></slot>
        <slot name=\\"head\\"></slot>
        <div class=\\"table\\" style=\\"overflow-x:auto;\\">
            <div class=\\"thead\\"></div>
            <div class=\\"tbody\\">
                <div class=\\"tree\\"></div>
                <div class=\\"body\\"></div>
        </div>
        </div>
        "
`);
    })

    it('LitTableTest18', () => {
        expect(litTable.createExpandBtn({expanded:false})).not.toBeUndefined()
    })

    it('LitTableTest19', () => {
        expect(litTable.reMeauseHeight()).toBeUndefined();
    })

    it('LitTableTest20', () => {
        const rowData= {
            data:[{
                isSelected:undefined
            }],
        }
        litTable.columns.forEach = jest.fn(()=>true)
        expect(litTable.createNewTableElement(rowData)).not.toBeUndefined();
    })

    it('LitTableTest21', () => {
        expect(litTable.freshCurrentLine(element)).toBeUndefined();
    })

    it('LitTableTest22', () => {
        litTable.recycleDs.length = 1
        litTable.setCurrentSelection = jest.fn(()=>true)
        expect(litTable.scrollToData()).toBeUndefined();
    })

    it('LitTableTest23', () => {
        expect(litTable.expandList()).toBeUndefined();
    })

    it('LitTableTest24', () => {
        expect(litTable.clearAllSelection()).toBeUndefined();
    })

    it('LitTableTest25', () => {
        expect(litTable.dispatchRowClickEvent({data:{isSelected:""}})).toBeUndefined();
    })

    it('LitTableTest26', () => {
        litTable.treeElement = jest.fn(()=>undefined)
        litTable.treeElement.children = jest.fn(()=>[1])
        litTable.columns.forEach = jest.fn(()=>true)
        litTable.treeElement.lastChild= jest.fn(()=>true)
        litTable.treeElement.lastChild.style= jest.fn(()=>true)
        expect(litTable.createNewTreeTableElement({data:""})).not.toBeUndefined();
    });

    it('LitTableTest27', () => {
        litTable.tableElement = jest.fn(()=>undefined)
        litTable.tableElement.scrollTop = jest.fn(()=>1)
        expect(litTable.move1px()).toBeUndefined();
    })

    it('LitTableTest28', () => {
        document.body.innerHTML = `<lit-table id="aaa"></lit-table>`
        let litTable = document.querySelector('#aaa') as LitTable
        expect(litTable.renderTreeTable()).toBeUndefined();
    })

    it('LitTableTest29', () => {
        document.body.innerHTML = `<lit-table id="aaa"></lit-table>`
        let litTable = document.querySelector('#aaa') as LitTable
        expect(litTable.setMouseIn(true,[])).toBeUndefined();
    })

    it('LitTableTest30', () => {
        document.body.innerHTML = `<lit-table id="aaa"></lit-table>`
        let litTable = document.querySelector('#aaa') as LitTable
        const data = {
            isSelected:true
        }
        expect(litTable.setCurrentSelection(data)).toBeUndefined();
    })

    it("LitTableTest31",() => {
        document.body.innerHTML = `<lit-table id="aaa"></lit-table>`;
        let litTable = document.querySelector('#aaa') as LitTable;
        litTable.formatName =true;
        expect(litTable.formatName).toBeTruthy();
    })
    it("LitTableTest32",() => {
        let litTable =new LitTable();
        expect(litTable.formatName()).toBe("");
    })

    it("LitTableTest33",() => {
        let litTable =new LitTable();
        expect(litTable.dataExportInit()).toBeUndefined();
    })
    it("LitTableTest34",() => {
        let litTable =new LitTable();
        expect(litTable.exportData()).toBeUndefined();
    })

    it('LitTableTest35', () => {
        expect(litTable.formatExportData()).not.toBeUndefined();
    })

    it('LitTableTest36', () => {
        expect(litTable.setSelectedRow(true,[])).toBeUndefined();

    })

    it('LitTableTest37', () => {
        document.body.innerHTML = `<lit-table id="aaa"></lit-table>`;
        let litTable = document.querySelector('#aaa') as LitTable;
        litTable.setAttribute('tree',true);
        expect(litTable.dataSource).toStrictEqual([]);
    });

    it('LitTableTest38', () => {
        document.body.innerHTML = `<lit-table id="aaa"></lit-table>`;
        let litTable = document.querySelector('#aaa') as LitTable;
        litTable.rememberScrollTop = true;
        expect(litTable.recycleDataSource).toStrictEqual([]);
    });

    it("LitTableTest39",() => {
        let litTable =new LitTable();
        expect(litTable.dataExportInit()).toBeUndefined();
    });

    it('LitTableTest40', () => {
        litTable.columns = undefined;
        expect(litTable.formatExportData()).toStrictEqual([]);
    });

})

