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

@element('lit-select')
export class LitSelect extends BaseElement {
    private focused: any;
    private inputElement: any;
    private clearElement: any;
    private iconElement: any;
    private searchElement: any;
    private multipleRootElement: any;

    static get observedAttributes() {
        return [
            'value',
            'default-value',
            'placeholder',
            'disabled',
            'loading',
            'allow-clear',
            'show-search',
            'list-height',
            'border',
            'mode',
        ];
    }

    get value() {
        return this.getAttribute('value') || this.defaultValue;
    }

    set value(value) {
        this.setAttribute('value', value);
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

    get listHeight() {
        return this.getAttribute('list-height') || '256px';
    }

    set listHeight(value) {
        this.setAttribute('list-height', value);
    }

    get defaultPlaceholder() {
        return this.getAttribute('placeholder') || '请选择';
    }

    set canInsert(can:boolean) {
        if (can) {
            this.setAttribute("canInsert",'');
        } else {
            this.removeAttribute("canInsert")
        }
    }

    get canInsert() {
        return this.hasAttribute("canInsert")
    }
    get showSearch() {
        return this.hasAttribute('show-search');
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

    get loading() {
        return this.hasAttribute('loading');
    }

    set loading(value) {
        if (value) {
            this.setAttribute('loading', '');
        } else {
            this.removeAttribute('loading')
        }
    }

    set dataSource(value: any) {
        value.forEach((a: any) => {
            let option = document.createElement('lit-select-option');
            option.setAttribute('value', a.key);
            option.textContent = a.val;
            this.append(option)
        })
        this.initOptions();
    }

    initElements(): void {
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
            /*width: 100%;*/
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
        :host(:not([mode]))  input{
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
            max-height: ${this.listHeight};
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
        .multipleRoot input::-webkit-input-placeholder {
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
        :host([loading]) .loading{
            display: flex;
        }
        :host([loading]) .icon{
            display: none;
        }
        :host(:not([loading])) .loading{
            display: none;
        }
        :host(:not([loading])) .icon{
            display: flex;
        }
        :host(:not([allow-clear])) .clear{
            display: none;
        }
        .clear{
            display: none;
            color: #bfbfbf;
        }
        .clear:hover{
            color: #8c8c8c;
        }
        .search{
            display: none;
            color: #bfbfbf;
        }
        .multipleRoot{
            display: flex;
            flex-direction: column;
            flex-wrap: wrap;
            flex-flow: wrap;
            align-items: center;
        }
        .tag{
            display: inline-flex;
            align-items: center;
            background-color: #f5f5f5;
            padding: 1px 4px;
            height: auto;
            font-size: .75rem;
            font-weight: bold;
            color: #242424;
            overflow: auto;
            position: relative;
            margin-right: 4px;
            margin-top: 1px;
            margin-bottom: 1px;
        }
        .tag-close{
            font-size: .8rem;
            padding: 2px;
            margin-left: 0px;
            color: #999999;
        }
        .tag-close:hover{
            color: #333;
        }

        </style>
        <div class="root noSelect" tabindex="0" hidefocus="true">
            <div class="multipleRoot">
            <input placeholder="${this.placeholder}" autocomplete="off" ${this.showSearch || this.canInsert ? '' : 'readonly'} tabindex="0"></div>
            <lit-loading class="loading" size="12"></lit-loading>
            <lit-icon class="icon" name='down' color="#c3c3c3"></lit-icon>
            <lit-icon class="clear" name='close-circle-fill'></lit-icon>
            <lit-icon class="search" name='search'></lit-icon>
        </div>
        <div class="body">
            <slot></slot>
            <slot name="footer"></slot>
        </div>
        `
    }

    isMultiple() {
        return this.hasAttribute('mode') && this.getAttribute('mode') === 'multiple'
    }

    newTag(value: any, text: any) {
        let tag: any = document.createElement('div');
        let icon: any = document.createElement('lit-icon');
        icon.classList.add('tag-close')
        icon.name = 'close'
        let span = document.createElement('span');
        tag.classList.add('tag');
        span.dataset['value'] = value;
        span.textContent = text;
        tag.append(span);
        tag.append(icon);
        icon.onclick = (ev: any) => {
            tag.parentElement.removeChild(tag);
            this.querySelector(`lit-select-option[value=${value}]`)!.removeAttribute('selected')
            if (this.shadowRoot!.querySelectorAll('.tag').length == 0) {
                this.inputElement.style.width = 'auto';
                this.inputElement.placeholder = this.defaultPlaceholder;
            }
            ev.stopPropagation();
        }
        tag.value = value;
        tag.dataset['value'] = value;
        tag.text = text;
        tag.dataset['text'] = text;
        return tag;
    }

    connectedCallback() {
        this.tabIndex = 0;
        this.focused = false;
        this.inputElement = this.shadowRoot!.querySelector('input');
        this.clearElement = this.shadowRoot!.querySelector('.clear');
        this.iconElement = this.shadowRoot!.querySelector('.icon');
        this.searchElement = this.shadowRoot!.querySelector('.search');
        this.multipleRootElement = this.shadowRoot!.querySelector('.multipleRoot');
        this.clearElement.onclick = (ev: any) => {
            if (this.isMultiple()) {
                let delNodes: Array<any> = []
                this.multipleRootElement.childNodes.forEach((a: any) => {
                    if (a.tagName === 'DIV') {
                        delNodes.push(a);
                    }
                })
                for (let i = 0; i < delNodes.length; i++) {
                    delNodes[i].remove();
                }
                if (this.shadowRoot!.querySelectorAll('.tag').length == 0) {
                    this.inputElement.style.width = 'auto';
                    this.inputElement.placeholder = this.defaultPlaceholder;
                }
            }
            this.querySelectorAll('lit-select-option').forEach(a => a.removeAttribute('selected'));
            this.inputElement.value = ''
            this.clearElement.style.display = 'none';
            this.iconElement.style.display = 'flex';
            this.blur();
            ev.stopPropagation();
            this.dispatchEvent(new CustomEvent('onClear', {detail: ev}))
        }
        this.initOptions();
        this.onclick = (ev: any) => {
            if (ev.target.tagName === 'LIT-SELECT') {
                if (this.focused === false) {
                    this.inputElement.focus();
                    this.focused = true;
                } else {
                    this.blur();
                    this.focused = false;
                }
            }
        }
        this.onmouseover = this.onfocus = ev => {
            if (this.focused === false && this.hasAttribute("adaptive-expansion")) {
                let body = this.shadowRoot!.querySelector(".body");
                if (this.parentElement!.offsetTop < body!.clientHeight) {
                    body!.classList.add('body-bottom');
                } else {
                    body!.classList.remove('body-bottom');
                }
            }
            if (this.hasAttribute('allow-clear')) {
                if (this.inputElement.value.length > 0 || this.inputElement.placeholder !== this.defaultPlaceholder) {
                    this.clearElement.style.display = 'flex'
                    this.iconElement.style.display = 'none';
                } else {
                    this.clearElement.style.display = 'none'
                    this.iconElement.style.display = 'flex';
                }
            }
        }
        this.onmouseout = this.onblur = ev => {
            if (this.hasAttribute('allow-clear')) {
                this.clearElement.style.display = 'none';
                this.iconElement.style.display = 'flex';
            }
            this.focused = false;
        }
        this.inputElement.onfocus = (ev: any) => {
            if (this.hasAttribute('disabled')) return;
            if (this.inputElement.value.length > 0) {
                this.inputElement.placeholder = this.inputElement.value;
                this.inputElement.value = ''
            }
            if (this.hasAttribute('show-search')) {
                this.searchElement.style.display = 'flex';
                this.iconElement.style.display = 'none';
            }
            this.querySelectorAll('lit-select-option').forEach(a => {
                // @ts-ignore
                a.style.display = 'flex';
            })
        }
        this.inputElement.onblur = (ev: any) => {
            if (this.hasAttribute('disabled')) return;
            if (this.isMultiple()) {
                if (this.hasAttribute('show-search')) {
                    this.searchElement.style.display = 'none';
                    this.iconElement.style.display = 'flex';
                }
            } else {
                if (this.inputElement.placeholder !== this.defaultPlaceholder) {
                    this.inputElement.value = this.inputElement.placeholder;
                    this.inputElement.placeholder = this.defaultPlaceholder;
                }
                if (this.hasAttribute('show-search')) {
                    this.searchElement.style.display = 'none';
                    this.iconElement.style.display = 'flex';
                }
            }
        }
        this.inputElement.oninput = (ev: any) => {
            let els = [...this.querySelectorAll('lit-select-option')];
            if(this.hasAttribute("show-search")) {
                if (!ev.target.value) {
                    els.forEach((a: any) => a.style.display = 'flex');
                } else {
                    els.forEach((a: any) => {
                        let value = a.getAttribute('value');
                        if (value.toLowerCase().indexOf(ev.target.value.toLowerCase()) !== -1 ||
                            a.textContent.toLowerCase().indexOf(ev.target.value.toLowerCase()) !== -1) {
                            a.style.display = 'flex';
                        } else {
                            a.style.display = 'none';
                        }
                    })
                }
            } else {
                this.value = ev.target.value
            }
        }
        this.inputElement.onkeydown = (ev: any) => {
            if (ev.key === 'Backspace') {
                if (this.isMultiple()) {
                    let tag = this.multipleRootElement.lastElementChild.previousElementSibling;
                    if (tag) {
                        this.querySelector(`lit-select-option[value=${tag.value}]`)?.removeAttribute('selected');
                        tag.remove()
                        if (this.shadowRoot!.querySelectorAll('.tag').length == 0) {
                            this.inputElement.style.width = 'auto';
                            this.inputElement.placeholder = this.defaultPlaceholder;
                        }
                    }
                } else {
                    this.clear();
                    this.dispatchEvent(new CustomEvent('onClear', {detail: ev}))//向外派发清理事件
                }
            } else if (ev.key === 'Enter') {
                if (!this.canInsert) {
                    let filter = [...this.querySelectorAll('lit-select-option')].filter((a: any) => a.style.display !== 'none');
                    if (filter.length > 0) {
                        this.inputElement.value = filter[0].textContent;
                        this.inputElement.placeholder = filter[0].textContent;
                        this.blur();
                        // @ts-ignore
                        this.value = filter[0].getAttribute('value')
                        this.dispatchEvent(new CustomEvent('change', {
                            detail: {
                                selected: true,
                                value: filter[0].getAttribute('value'),
                                text: filter[0].textContent
                            }
                        }));
                    }
                }
            }
        }
    }

    initOptions() {
        this.querySelectorAll('lit-select-option').forEach(a => {
            if (this.isMultiple()) {
                a.setAttribute('check', '');
                if (a.getAttribute('value') === this.defaultValue) {
                    let tag = this.newTag(a.getAttribute('value'), a.textContent);
                    this.multipleRootElement.insertBefore(tag, this.inputElement);
                    this.inputElement.placeholder = '';
                    this.inputElement.value = '';
                    this.inputElement.style.width = '1px';
                    a.setAttribute('selected', '');
                }
            } else {
                if (a.getAttribute('value') === this.defaultValue) {
                    this.inputElement.value = a.textContent;
                    a.setAttribute('selected', '');
                }
            }
            a.addEventListener('mouseup',(e)=>{
               e.stopPropagation()
            });
            a.addEventListener('mousedown',(e)=>{
                e.stopPropagation()
            });
            a.addEventListener('onSelected', (e: any) => {
                if (this.isMultiple()) {
                    if (a.hasAttribute('selected')) {
                        let tag = this.shadowRoot!.querySelector(`div[data-value=${e.detail.value}]`) as HTMLElement;
                        if (tag)  {
                            tag.parentElement!.removeChild(tag);
                        }
                        e.detail.selected = false;
                    } else {
                        let tag = this.newTag(e.detail.value, e.detail.text);
                        this.multipleRootElement.insertBefore(tag, this.inputElement);
                        this.inputElement.placeholder = '';
                        this.inputElement.value = '';
                        this.inputElement.style.width = '1px';
                    }
                    if (this.shadowRoot!.querySelectorAll('.tag').length == 0) {
                        this.inputElement.style.width = 'auto';
                        this.inputElement.placeholder = this.defaultPlaceholder;
                    }
                    this.inputElement.focus();
                } else {
                    [...this.querySelectorAll('lit-select-option')].forEach(a => a.removeAttribute('selected'))
                    this.blur();
                    // @ts-ignore
                    this.inputElement.value = e.detail.text;
                }
                if (a.hasAttribute('selected')) {
                    a.removeAttribute('selected')
                } else {
                    a.setAttribute('selected', '')
                }
                // @ts-ignore
                this.value = e.detail.value;
                this.dispatchEvent(new CustomEvent('change', {detail: e.detail}));//向外层派发change事件，返回当前选中项
            })
        })
    }

    clear() {
        this.inputElement.value = '';
        this.inputElement.placeholder = this.defaultPlaceholder;
    }

    reset() {
        this.querySelectorAll('lit-select-option').forEach(a => {
            [...this.querySelectorAll('lit-select-option')].forEach(a => a.removeAttribute('selected'))
            if (a.getAttribute('value') === this.defaultValue) {
                this.inputElement.value = a.textContent;
                a.setAttribute('selected', '');
            }
        })
    }

    disconnectedCallback() {

    }

    adoptedCallback() {
    }

    attributeChangedCallback(name: any, oldValue: any, newValue: any) {
        if (name === 'value' && this.inputElement) {
            if (newValue) {
                [...this.querySelectorAll('lit-select-option')].forEach(a => {
                    if (a.getAttribute('value') === newValue) {
                        a.setAttribute('selected', '');
                        this.inputElement.value = a.textContent;
                    } else {
                        a.removeAttribute('selected')
                    }
                })
            } else {
                this.clear();
            }
        }
    }

}
