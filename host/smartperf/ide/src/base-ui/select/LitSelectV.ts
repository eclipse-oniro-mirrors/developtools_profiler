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
import {LitSelectOption} from "./LitSelectOption.js";

@element('lit-select-v')
export class LitSelectV extends BaseElement {
    showItems: Array<string> = [];
    itemValue: Array<string> = [];
    customItem: Array<string> = [];
    private focused: any;
    private inputElement: any;
    private iconElement: any;
    private options: HTMLDivElement | undefined;
    private valueStr: string = '';

    static get observedAttributes() {
        return [
            'value',
            'default-value',
            'placeholder',
            'disabled',
            'show-search',
            'border',
            'mode',
        ];
    }

    get value() {
        return this.inputElement!.value || this.defaultValue;
    }

    get rounded() {
        return this.hasAttribute("rounded");
    }

    set rounded(rounded: boolean) {
        if (rounded) {
            this.setAttribute("rounded", '');
        } else {
            this.removeAttribute("rounded");
        }
    }

    get placement(): string {
        return this.getAttribute("placement") || "";
    }

    set placement(placement: string) {
        if (placement) {
            this.setAttribute("placement", placement);
        } else {
            this.removeAttribute("placement");
        }
    }

    get border() {
        return this.getAttribute('border') || 'true';
    }

    set border(value) {
        if (value) {
            this.setAttribute('border', 'true');
        } else {
            this.setAttribute('border', 'false');
        }
    }

    get defaultPlaceholder() {
        return this.getAttribute('placeholder') || '';
    }

    get defaultValue() {
        return this.getAttribute('default-value') || '';
    }

    set defaultValue(value) {
        this.setAttribute('default-value', value);
    }

    get placeholder() {
        return this.getAttribute('placeholder') || this.defaultPlaceholder;
    }

    set placeholder(value) {
        this.setAttribute('placeholder', value);
    }

    set all(isAll: boolean) {
        if (isAll) {
            this.setAttribute('is-all', '');
        } else {
            this.removeAttribute('is-all');
        }
    }

    get all() {
        return this.hasAttribute('is-all');
    }

    dataSource(value: Array<string>, valueStr: string) {
        this.options!.innerHTML = '';
        if (value.length > 0) {
            this.options!.style.display = "block"
            this.valueStr = valueStr;
            this.itemValue = value;
            if (valueStr != "") {
                let option = document.createElement("lit-select-option");
                if (this.all) {
                    option.setAttribute("selected", "");
                    this.showItems = value
                }
                option.setAttribute('value', valueStr);
                option.textContent = valueStr;
                this.options!.appendChild(option);
                this.initDataItem(value);
                this.initCustomOptions()
            } else {
                this.initDataItem(value);
                this.initOptions()
            }
        } else {
            this.options!.style.display = "none"
        }
        if (this.title == 'Event List') {
            let inputElement = this.shadowRoot?.querySelector('input') as HTMLInputElement;
            inputElement.readOnly = false
        }
    }

    initDataItem(value: Array<string>) {
        value.forEach(
            item => {
                let option = document.createElement("lit-select-option");
                if (this.showItems.indexOf(item) > -1 || this.all) {
                    option.setAttribute("selected", "")
                }
                option.setAttribute('value', item);
                option.textContent = item;
                this.options!.appendChild(option);
            }
        )
    }

    initElements(): void {
        this.tabIndex = 0;
        this.focused = false;
        this.inputElement = this.shadowRoot!.querySelector('input') as HTMLInputElement;
        this.options = this.shadowRoot!.querySelector('.body') as HTMLDivElement;
        this.iconElement = this.shadowRoot!.querySelector('.icon');
        this.onclick = (ev: any) => {
            if (this.focused === false) {
                this.focused = true;
            } else {
                this.focused = false;
            }
        }

        this.onmouseout = this.onblur = ev => {
            this.focused = false;
        }
        this.inputElement.onfocus = (ev: any) => {
            if (this.hasAttribute('disabled')) return;
        }
        this.inputElement.onblur = (ev: any) => {
            if (this.hasAttribute('disabled')) return;
        }
    }

    initHtml() {
        return `
        <style>
        :host{
            display: inline-flex;
            position: relative;
            overflow: visible;
            cursor: pointer;
            border-radius: 2px;
            outline: none;
            -webkit-user-select:none ;
            -moz-user-select:none;
            user-select:none;
        }
        :host(:not([border])),
        :host([border='true']){
            border: 1px solid var(--bark-prompt,#dcdcdc);
        }
        input{
            border: 0;
            outline: none;
            background-color: transparent;
            cursor: pointer;
            -webkit-user-select:none ;
            -moz-user-select:none;
            user-select:none;
            display: inline-flex;
            color: var(--dark-color2,rgba(0,0,0,0.9));
        }
        :host([highlight]) input {
            color: rgba(255,255,255,0.9);
        }
        input{
            width: 100%;
        }
        :host([mode])  input{
            padding: 6px 0px;
        }
        :host([mode])  .root{
            padding: 1px 8px;
        }
        .root{
            position: relative;
            padding: 3px 6px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-radius: 2px;
            outline: none;
            font-size: 1rem;
            z-index: 2;
            -webkit-user-select:none ;
            -moz-user-select:none;
            user-select:none;
            width: 100%;
        }
        .body{
            max-height: 256px;
            position: absolute;
            bottom: 100%;
            z-index: 99;
            padding-top: 5px;
            margin-top: 2px;
            background-color: var(--dark-background4,#fff);
            width: 100%;
            transform: scaleY(.6);
            visibility: hidden;
            opacity: 0;
            transform-origin: bottom center;
            display: block;
            flex-direction: column;
            box-shadow: 0 5px 15px 0px #00000033;
            border-radius: 2px;
            overflow: auto;
        }
        .body-bottom{
            bottom: auto;
            top: 100%;
            transform-origin: top center;
        }
        :host([placement="bottom"]) .body{
            bottom:unset;
            top: 100%;
            transition: none;
            transform: none;
        }

        :host([rounded]) .body {
            border-radius: 16px;
        }
        :host([rounded]) .root {
            border-radius: 16px;
            height: 25px;
        }
        .icon{
            pointer-events: none;
        }
        .noSelect{
          -moz-user-select:none;
          -ms-user-select:none;
          user-select:none;
          -khtml-user-select:none;
          -webkit-touch-callout:none;
          -webkit-user-select:none;
        }

        :host(:not([border]):not([disabled]):focus),
        :host([border='true']:not([disabled]):focus),
        :host(:not([border]):not([disabled]):hover),
        :host([border='true']:not([disabled]):hover){
            border:1px solid var(--bark-prompt,#ccc)
        }
        :host(:not([disabled]):focus) .body,
        :host(:not([disabled]):focus-within) .body{
            transform: scaleY(1);
            opacity: 1;
            z-index: 99;
            visibility: visible;
        }
        :host(:not([disabled]):focus)  input{
            color: var(--dark-color,#bebebe);
        }
        input::-webkit-input-placeholder {
                color: var(--dark-color,#aab2bd);
        }
        :host(:not([border])[disabled]) *,
        :host([border='true'][disabled]) *{
            background-color: var(--dark-background1,#f5f5f5);
            color: #b7b7b7;
            cursor: not-allowed;
        }
        :host([border='false'][disabled]) *{
            color: #b7b7b7;
            cursor: not-allowed;
        }
        .loading{
            display: none;
        }
        .icon{
            display: flex;
        }

        </style>
        <div class="root noSelect" tabindex="0" hidefocus="true">
            <input placeholder="${this.placeholder}" tabindex="0" readonly="readonly">
            <lit-icon class="icon" name='down' color="#c3c3c3"></lit-icon>
        </div>
        <div class="body">
            <slot></slot>
            <slot name="footer"></slot>
        </div>
        `
    }

    connectedCallback() {
    }

    initCustomOptions() {
        let querySelector = this.shadowRoot?.querySelector(`lit-select-option[value="${this.valueStr}"]`) as LitSelectOption;
        this.shadowRoot?.querySelectorAll('lit-select-option').forEach(a => {
            a.setAttribute('check', '');
            a.addEventListener('onSelected', (e: any) => {
                if (a.hasAttribute("selected")) {
                    let number = this.showItems.indexOf(a.textContent!);
                    if (number > -1) {
                        this.showItems!.splice(number, 1);
                        this.inputElement!.value = this.showItems;
                    }
                    this.all = false
                    querySelector.removeAttribute("selected");
                    a.removeAttribute("selected");
                    return;
                } else {
                    let index = this.itemValue.indexOf(a.textContent!);
                    let value = this.showItems.indexOf(a.textContent!);
                    if (index > -1 && value == -1) {
                        this.showItems.push(a.textContent!);
                        this.inputElement!.value = this.showItems;
                    }
                    if (this.showItems.length >= this.itemValue.length) {
                        querySelector.setAttribute('selected', '')
                        this.all = true;
                    } else {
                        querySelector.removeAttribute('selected')
                        this.all = false;
                    }
                    a.setAttribute('selected', '')
                }
            })
        })
        this.selectAll(querySelector);
    }


    initOptions() {
        this.options!.addEventListener('click', ev => {
            let items = this.inputElement!.value.split(",");
            this.customItem = []
            items.forEach((item: string) => {
                if (item.trim() != "") {
                    let indexItem = this.itemValue.indexOf(item.trim());
                    if (indexItem == -1) {
                        this.customItem.push(item.trim())
                    }
                }
            });
            if (this.customItem.length > 0) {
                this.inputElement.value = this.customItem.concat(this.showItems);
            } else {
                this.inputElement.value = this.showItems
            }
        })
        this.shadowRoot?.querySelectorAll('lit-select-option').forEach(a => {
            a.setAttribute('check', '');
            a.addEventListener('onSelected', (e: any) => {
                if (a.hasAttribute("selected")) {
                    let number = this.showItems.indexOf(a.textContent!);
                    if (number > -1) {
                        this.showItems.splice(number, 1)
                    }
                    a.removeAttribute("selected");
                    return;
                } else {
                    let index = this.itemValue.indexOf(a.textContent!);
                    if (index > -1) {
                        this.showItems.push(a.textContent!);
                    }
                    a.setAttribute('selected', '')
                }
            })
        })
    }

    selectAll(querySelector: LitSelectOption) {
        querySelector?.addEventListener("click", ev => {
            if (querySelector.hasAttribute("selected")) {
                this.shadowRoot?.querySelectorAll('lit-select-option').forEach(a => {
                    a.setAttribute('selected', '');
                    this.all = true
                })
                this.itemValue.forEach(i => {
                    this.showItems.push(i)
                })
                this.inputElement.value = this.itemValue;
            } else {
                this.shadowRoot?.querySelectorAll('lit-select-option').forEach(i => {
                    i.removeAttribute('selected');
                    this.all = false
                })
                this.showItems = [];
                this.inputElement.value = "";
            }
        })
    }

    attributeChangedCallback(name: any, oldValue: any, newValue: any) {
    }

}
