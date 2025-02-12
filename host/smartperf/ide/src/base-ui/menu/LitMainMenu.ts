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


import {BaseElement, element} from "../BaseElement.js";
import './LitMainMenuItem.js'
import './LitMainMenuGroup.js'
import {LitMainMenuGroup} from "./LitMainMenuGroup.js";
import {LitMainMenuItem} from "./LitMainMenuItem.js";

@element('lit-main-menu')
export class LitMainMenu extends BaseElement {
    private slotElements: Element[] | undefined;
    private _menus: Array<MenuGroup> | undefined

    static get observedAttributes() {
        return []
    }

    get menus(): Array<MenuGroup> | undefined {
        return this._menus;
    }

    set menus(value: Array<MenuGroup> | undefined) {
        this._menus = value;
        this.shadowRoot?.querySelectorAll('lit-main-menu-group').forEach(a => a.remove());
        let menuBody = this.shadowRoot?.querySelector('.menu-body');
        value?.forEach(it => {
            let group = new LitMainMenuGroup();
            group.setAttribute('title', it.title || "");
            group.setAttribute('describe', it.describe || "");
            if (it.collapsed) {
                group.setAttribute('collapsed', '');
            } else {
                group.removeAttribute('collapsed');
            }
            menuBody?.appendChild(group);
            it.children?.forEach((item: any) => {
                let th = new LitMainMenuItem();
                th.setAttribute('icon', item.icon || "");
                th.setAttribute('title', item.title || "");
                if (item.fileChoose) {
                    th.setAttribute('file', "");
                    th.addEventListener('file-change', e => {
                        if (item.fileHandler && !th.disabled) {
                            item.fileHandler(e)
                        }
                    })
                } else {
                    th.removeAttribute('file');
                    th.addEventListener('click', e => {
                        if (item.clickHandler && !th.disabled) {
                            item.clickHandler(item)
                        }
                    })
                }
                if (item.disabled != undefined) {
                    th.disabled = item.disabled
                }
                group?.appendChild(th);
            })
        })
    }

    initElements(): void {
        let st: HTMLSlotElement | null | undefined = this.shadowRoot?.querySelector('#st');
        st?.addEventListener('slotchange', e => {
            this.slotElements = st?.assignedElements();
            this.slotElements?.forEach(it => {
                it.querySelectorAll("lit-main-menu-item").forEach(cell => {
                })
            })
        })
        let versionDiv: HTMLElement | null | undefined = this.shadowRoot?.querySelector<HTMLElement>('.version');
        versionDiv!.innerText = (window as any).version || ""
    }

    initHtml(): string {
        return `
        <style>
        :host{
            display: flex;
            flex-direction: column;
            width: 248px;
            background-color: var(--dark-background,#FFFFFF);
            height: 100vh;
        }
        .menu-body ::-webkit-scrollbar-track
        {
            border-radius:10px;
            background-color:#F5F5F5;
        }
        .menu-body ::-webkit-scrollbar-thumb
        {
            border-radius:10px;
            background-color: var(--dark-background,#FFFFFF);

        }
        .header{
            display: grid;
            background-color: var(--dark-background1,#FFFFFF);
            border-bottom: 1px solid var(--dark-background1,#EFEFEF);
            color: #47A7E0;
            font-size: 1.4rem;
            padding-left: 20px;
            /*padding-right: 10px;*/
            gap: 0 20px;
            box-sizing: border-box;
            width: 100%;
            height: 56px;
            grid-template-columns: min-content 1fr min-content;
            grid-template-rows: auto;
        }
        .header *{
            align-self: center;
            user-select: none;
        }
        .version{
            color: #94979d;
            padding: 20px;
            font-size: 0.6rem;
            width: 100%;
            text-align: right;
        }
        *{
            box-sizing: border-box;
        }
        .menu-button{
            height: 47px;
            width: 48px;
            display: flex;
            align-content: center;
            justify-content: right;
            cursor: pointer;
        }
        </style>
        <div name="header" class="header">
            <img src="img/logo.png"/>
                <div class="menu-button">
                    <lit-icon name="menu" size="20" color="var(--dark-color1,#4D4D4D)"></lit-icon>
                </div>
            </div>
            <div class="menu-body" style="overflow: auto;overflow-x:hidden;height: 100%">
                <slot id="st" ></slot>
            </div>
        <div class="version" style="">
        </div>
        `;
    }
}

export interface MenuGroup {
    title: string
    describe: string
    collapsed: boolean
    children: Array<MenuItem>
}

export interface MenuItem {
    icon: string
    title: string
    fileChoose?: boolean
    clickHandler?: Function
    fileHandler?: Function
}
