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

@element('lit-main-menu-group')
export class LitMainMenuGroup extends BaseElement {
    protected _collapsed: boolean | undefined;
    private groupNameEl: HTMLElement | null | undefined;
    private groupDescEl: HTMLElement | null | undefined;

    static get observedAttributes() {
        return ['title', 'describe', 'collapsed', 'nocollapse', "radius"]
    }

    get collapsed(): boolean {
        return this.hasAttribute('collapsed')
    }

    set collapsed(value: boolean) {
        if (value) {
            this.setAttribute('collapsed', '')
        } else {
            this.removeAttribute('collapsed')
        }
    }

    get nocollapsed() {
        return this.hasAttribute('nocollapsed')
    }

    set nocollapsed(value: boolean) {
        if (value) {
            this.setAttribute('nocollapsed', '')
        } else {
            this.removeAttribute('nocollapsed')
        }
    }

    get radius() {
        return this.hasAttribute("radius")
    }

    initElements(): void {
        this.groupNameEl = this.shadowRoot?.querySelector('.group-name');
        this.groupDescEl = this.shadowRoot?.querySelector('.group-describe');
        this.addEventListener('click', (e) => {
            if (this.nocollapsed) {
                return;
            }
            this.collapsed = !this.collapsed
        })
    }

    initHtml(): string {
        return `
        <style>
        :host{
            transition: background-color .3s;
            user-select: none;
        }
        :host(:not([collapsed])){ 
            display: flex;
            flex-direction: column;
            width: 248px;
            background-color: var(--dark-background,#FFFFFF);
            cursor: pointer;
        }
        :host(:not([collapsed])) ::slotted(lit-main-menu-item){
            display: flex;
        }
        :host(:not([collapsed])) .group-describe{
            visibility: hidden;
            height: 0;
        }
        :host([collapsed]){
            display: flex;
            flex-direction: column;
            width: 248px;
            background-color: var(--dark-background,#FFFFFF);
            cursor: pointer;
        }
        :host([collapsed]):hover){
            background-color: #FFFFFF;
        }
        :host([collapsed]) ::slotted(lit-main-menu-item){
            display: none;
        }
        :host([collapsed]) .group-describe{
            visibility: visible;
            height: auto;
        }
        :host([radius]) {
            border-radius: 16px 0px 0px 16px ;
        }
        .group-name{
            font-family: Helvetica;
            font-size: 14px;
            color: var(--dark-color1,#212121);
            text-align: left;
            line-height: 16px;
            font-weight: 400;
            padding: 20px 24px 0px 24px;
        }
        .group-describe{
            color:#92959b;
            padding: 4px 24px 20px 24px;
            font-size: .6rem;
        }
       
        </style>
        <div class="group-name"></div>
        <div class="group-describe"></div>
        <slot></slot>
        `;
    }

    attributeChangedCallback(name: string, oldValue: string, newValue: string) {
        switch (name) {
            case "title":
                if (this.groupNameEl) this.groupNameEl.textContent = newValue
                break;
            case "describe":
                if (this.groupDescEl) this.groupDescEl.textContent = newValue
                break;
        }
    }
}
