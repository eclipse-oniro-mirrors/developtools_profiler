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
import {TabPaneSystemDetails} from "../../../../../../dist/trace/component/trace/sheet/energy/TabPaneSystemDetails.js"
import "../../../../../../dist/trace/component/trace/sheet/energy/TabPaneSystemDetails.js"

window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));
const sqlit = require("../../../../../../dist/trace/database/SqlLite.js")
jest.mock("../../../../../../dist/trace/database/SqlLite.js");

describe('TabPanePowerBattery Test', () => {
    it('TabPaneSystemDetailsTest01', function () {
        let tabPaneSystemDetails = new TabPaneSystemDetails();
        let MockSystemDetailsData = sqlit.querySystemDetailsData;
        let systemDetails = [
            {
                ts: 1005938319,
                eventName: "WORK_ADD",
                appKey: "UID",
                appValue: "20010016"
            }, {
                ts: 1005938319,
                eventName: "WORK_ADD",
                appKey: "TYPE",
                appValue: "1"
            },{
                ts: 3005933657,
                eventName: "POWER_RUNNINGLOCK",
                appKey: "UID",
                appValue: "1001"
            }, {
                ts: 3005933657,
                eventName: "POWER_RUNNINGLOCK",
                appKey: "TAG",
                appValue: "DUBAI_TAG_RUNNINGLOCK_REMOVE"
            },{
                ts: 3005938319,
                eventName: "WORK_START",
                appKey: "UID",
                appValue: "20010016"
            }, {
                ts: 3005938319,
                eventName: "WORK_START",
                appKey: "TYPE",
                appValue: "1"
            }]
        MockSystemDetailsData.mockResolvedValue(systemDetails)
        let tabPaneSystemDetailsData = {
            cpus: [],
            threadIds: [],
            trackIds: [],
            funTids: [],
            heapIds: [],
            nativeMemory: [],
            cpuAbilityIds: [],
            memoryAbilityIds: [],
            diskAbilityIds: [],
            networkAbilityIds: [],
            leftNs: 0,
            rightNs: 1000,
            hasFps: false,
            statisticsSelectData: undefined,
            perfSampleIds: [],
            perfCpus: [],
            perfProcess: [],
            perfThread: [],
            perfAll: false,
            systemEnergy: [0, 1, 2],
            powerEnergy: [0, 1, 2],
            anomalyEnergy: [0, 1, 2]
        }

        tabPaneSystemDetails.data = tabPaneSystemDetailsData
        expect(tabPaneSystemDetails.data).toBeUndefined()
    })

    it('TabPaneSystemDetailsTest02', function () {
        let tabPaneSystemDetails = new TabPaneSystemDetails();
        let MockSystemDetailsData = sqlit.querySystemDetailsData;
        MockSystemDetailsData.mockResolvedValue([])
        let tabPaneSystemDetailsData = {
            cpus: [],
            threadIds: [],
            trackIds: [],
            funTids: [],
            heapIds: [],
            nativeMemory: [],
            cpuAbilityIds: [],
            memoryAbilityIds: [],
            diskAbilityIds: [],
            networkAbilityIds: [],
            leftNs: 0,
            rightNs: 1000,
            hasFps: false,
            statisticsSelectData: undefined,
            perfSampleIds: [],
            perfCpus: [],
            perfProcess: [],
            perfThread: [],
            perfAll: false,
            systemEnergy: [0, 1, 2],
            powerEnergy: [0, 1, 2],
            anomalyEnergy: [0, 1, 2]
        }

        tabPaneSystemDetails.data = tabPaneSystemDetailsData
        expect(tabPaneSystemDetails.data).toBeUndefined()
    })

    it('TabPaneSystemDetailsTest03', function () {
        let tabPaneSystemDetails = new TabPaneSystemDetails();
        let data = {
            ts: 0,
            eventName: "Event Name",
            type: "type",
            pid: 0,
            uid: 0,
            state: 0,
            workId: "workId",
            name: "name",
            interval: 0,
            level: 0,
            tag: "tag:",
            message: "message",
            log_level: "log_level",
        }

        expect(tabPaneSystemDetails.convertData(data)).toBeUndefined()
    })

    it('TabPaneSystemDetailsTest04', function () {
        let tabPaneSystemDetails = new TabPaneSystemDetails();
        let data = {
            ts: 0,
            eventName: "GNSS_STATE",
            type: "type",
            pid: 0,
            uid: 0,
            state: 0,
            workId: "workId",
            name: "name",
            interval: 0,
            level: 0,
            tag: "tag:",
            message: "message",
            log_level: "log_level",
        }

        expect(tabPaneSystemDetails.convertData(data)).toBeUndefined()
    })

    it('TabPaneSystemDetailsTest05', function () {
        let tabPaneSystemDetails = new TabPaneSystemDetails();
        let data = {
            ts: 0,
            eventName: "POWER_RUNNINGLOCK",
            type: "type",
            pid: 0,
            uid: 0,
            state: 0,
            workId: "workId",
            name: "name",
            interval: 0,
            level: 0,
            tag: "tag:",
            message: "message",
            log_level: "log_level",
        }
        expect(tabPaneSystemDetails.convertData(data)).toBeUndefined()
    })

    it('TabPaneSystemDetailsTest06', function () {
        let tabPaneSystemDetails = new TabPaneSystemDetails();
        let data = {
            ts: 0,
            eventName: "POWER",
            type: "type",
            pid: 0,
            uid: 0,
            state: 0,
            workId: "workId",
            name: "name",
            interval: 0,
            level: 0,
            tag: "tag:",
            message: "message",
            log_level: "log_level",
        }

        expect(tabPaneSystemDetails.convertData(data)).toBeUndefined()
    })
    
    it('TabPaneSystemDetailsTest07', function () {
        let tabPaneSystemDetails = new TabPaneSystemDetails();
        expect(tabPaneSystemDetails.initHtml()).toMatchInlineSnapshot(`
"
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px 0 10px;
        }
        .progress{
            bottom: 33px;
            position: absolute;
            height: 1px;
            left: 0;
            right: 0;
        }
        </style>
        <div style=\\"display: flex;flex-direction: column\\">
            <div style=\\"display: flex;flex-direction: row\\">
                <lit-slicer style=\\"width:100%\\">
                    <div class=\\"box-details\\" style=\\"width: 100%\\">
                        <lit-table id=\\"tb-system-data\\" style=\\"height: auto\\">
                            <lit-table-column width=\\"300px\\" title=\\"\\" data-index=\\"eventName\\" key=\\"eventName\\"  align=\\"flex-start\\" order>
                            </lit-table-column>
                            <lit-table-column width=\\"300px\\" title=\\"\\" data-index=\\"ts\\" key=\\"ts\\"  align=\\"flex-start\\" order>
                            </lit-table-column>
                        </lit-table>
                    </div>
                    <lit-slicer-track ></lit-slicer-track>
                    <lit-table id=\\"tb-system-details-data\\" no-head style=\\"height: auto;border-left: 1px solid var(--dark-border1,#e2e2e2)\\">
                        <lit-table-column width=\\"100px\\" title=\\"\\" data-index=\\"key\\" key=\\"key\\"  align=\\"flex-start\\" >
                        </lit-table-column>
                        <lit-table-column width=\\"1fr\\" title=\\"\\" data-index=\\"value\\" key=\\"value\\"  align=\\"flex-start\\">
                        </lit-table-column>
                    </lit-table>
                </lit-slicer>
            </div>
            <lit-progress-bar class=\\"progress\\"></lit-progress-bar>
        </div>
        "
`);
    });
})