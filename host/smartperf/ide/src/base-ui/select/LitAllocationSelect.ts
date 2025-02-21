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

@element('lit-allocation-select')
export class LitAllocationSelect extends BaseElement {
    private inputElement: HTMLInputElement | null | undefined;
    private inputContent: HTMLDivElement | undefined;
    private options: any;

    static get observedAttributes() {
        return [
            'value','disabled','placeholder'
        ];
    }

    get defaultPlaceholder() {
        return this.getAttribute('placeholder') || '';
    }

    get placeholder() {
        return this.getAttribute('placeholder') || this.defaultPlaceholder;
    }

    set placeholder(value) {
        this.setAttribute('placeholder', value);
    }

    get value() {
        return this.getAttribute('value') || "";
    }

    set value(value: string) {
        this.setAttribute('value', value);
    }

    set processData(value: Array<string>) {
        this.options.innerHTML = '';
        value.forEach(
            item => {
                let option = document.createElement("div");
                option.className = 'option';
                option.innerHTML = item;
                option.style.padding = '8px 10px';
                this.options.appendChild(option);
                this.inputElement?.focus();
            }
        )
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

    get listHeight() {
        return this.getAttribute('list-height') || '256px';
    }

    set listHeight(value) {
        this.setAttribute('list-height', value);
    }

    initElements(): void {
        this.inputContent = this.shadowRoot!.querySelector('.multipleSelect') as HTMLDivElement;
        this.addEventListener('click', () => {
            if (this.options.style.visibility == 'visible') {
                this.options.style.visibility = 'hidden';
                this.options.style.opacity = '0';
            } else {
                this.options.style.visibility = 'visible';
                this.options.style.opacity = '1';
            }
            this.inputContent!.dispatchEvent(new CustomEvent('inputClick', {}));
        })
        this.addEventListener('focusout', (e) => {
            setTimeout(()=>{
                this.options.style.visibility = 'hidden';
                this.options.style.opacity = '0';
            }, 200)
            })
        this.initData();
    }

    initHtml() {
        return `
        <style>
        :host{
            display: inline-flex;
            position: relative;
            overflow: visible;
            cursor: pointer;
            border-radius: 16px;
            outline: none;
            -webkit-user-select:none ;
            -moz-user-select:none;
            user-select:none;
            width: 75%;
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
            z-index: 8999;
            width:100%;
        }
        .multipleSelect{
            position: relative;
            padding: 3px 6px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all .3s;
            outline: none;
            font-size: 1rem;
            z-index: 2999;
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
            transition: all 0.2s;
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
 
        :host([disabled]) {
           pointer-events: none;
           background-color: var(--dark-background1,#f5f5f5);
            cursor: not-allowed;
        }
        
        .multipleRoot input::-webkit-input-placeholder {
                color: var(--dark-color,#aab2bd);
        }
        </style>
        <div class="multipleSelect" tabindex="0">
            <div class="multipleRoot" id="select" style="width:100%">
            <input id="input" placeholder="${this.placeholder}"/>
        </div>
            <lit-icon class="icon" name='down' color="#c3c3c3"></lit-icon>
        </div>
        <div class="body body-bottom">
            <slot></slot>
            <slot name="footer"></slot>
        </div>
        `
    }

    connectedCallback() {
    }

    initData() {
        this.inputElement = this.shadowRoot!.querySelector('input');
        this.options = this.shadowRoot!.querySelector('.body') as HTMLDivElement;
        this.inputElement?.addEventListener('keyup', () => {
            let filter = [...this.shadowRoot!.querySelectorAll<HTMLDivElement>('.option')].filter((a: HTMLDivElement) => {
                if (a.textContent!.indexOf(this.inputElement!.value) <= -1) {
                    a.style.display = "none";
                } else {
                    a.style.display = "block";
                }
            });
            this.value = this.inputElement!.value
            this.inputContent!.dispatchEvent(new CustomEvent('valuable', {}));
        })
        this.shadowRoot?.querySelectorAll('.option').forEach(a => {
            a.addEventListener('click', (e) => {
                a.dispatchEvent(new CustomEvent('onSelected', {
                    detail: {
                        selected: true,
                        text: a.textContent
                    }
                }))
            })
            a.addEventListener('onSelected', (e: any) => {
                this.inputElement!.value = e.detail.text;
                this.value = e.detail.text;
                this.inputContent!.dispatchEvent(new CustomEvent('valuable', {}));
            })
        })
    }

}
