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
import {TabpaneFilesystemCalltree} from "../../../../../../dist/trace/component/trace/sheet/file-system/TabpaneFilesystemCalltree.js";

window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));
describe('TabpaneFilesystemCalltree Test', () => {

    document.body.innerHTML = `<tabpane-filesystem-calltree id="tree"></tabpane-filesystem-calltree>`
    let tabpaneFilesystemCalltree = document.querySelector<TabpaneFilesystemCalltree>('#tree')

    it('TabpaneFilesystemCalltreeTest02', function () {
        tabpaneFilesystemCalltree!.showButtomMenu = jest.fn(()=>'')
        tabpaneFilesystemCalltree.filter = jest.fn(()=>'')
        tabpaneFilesystemCalltree.filter.setAttribute = jest.fn(()=>'')
        expect(tabpaneFilesystemCalltree.showButtomMenu(true)).toBe("")
    });

    it('TabpaneFilesystemCalltreeTest03', function () {
        TabpaneFilesystemCalltree.getParentTree = jest.fn(()=>true);
        let call = {
            id: '1',
            children: [],
        }
        let target = {
            id: '1',
        }
        expect(tabpaneFilesystemCalltree.getParentTree([call],{target},[])).toBeFalsy();

    });

    it('TabpaneFilesystemCalltreeTest04', function () {
        TabpaneFilesystemCalltree.getParentTree = jest.fn(()=>true);
        let call = {
            children: [],
        }
        expect(tabpaneFilesystemCalltree.getParentTree([call],'',[])).not.toBeUndefined();
    });

    it('TabpaneFilesystemCalltreeTest05', function () {
        TabpaneFilesystemCalltree.getChildTree = jest.fn(()=>true);
        let call = {
            id: '1',
            children: [],
        }
        let id = '1';
        expect(tabpaneFilesystemCalltree.getChildTree([call],{id},[])).not.toBeUndefined();
    });

    it('TabpaneFilesystemCalltreeTest06', function () {
        TabpaneFilesystemCalltree.getChildTree = jest.fn(()=>true);
        let call = {
            children: [],
        }
        expect(tabpaneFilesystemCalltree.getChildTree([call],'',[])).not.toBeUndefined();
    });

})