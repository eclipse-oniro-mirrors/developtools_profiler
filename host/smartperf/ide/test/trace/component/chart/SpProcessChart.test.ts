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
import {SpProcessChart} from "../../../../dist/trace/component/chart/SpProcessChart.js";
// @ts-ignore
import {SpSystemTrace} from "../../../../dist/trace/component/SpSystemTrace.js";
import {
    queryProcess,
    queryProcessAsyncFunc,
    queryProcessContentCount, queryProcessMem,
    queryProcessThreads, queryProcessThreadsByTable
} from "../../../../src/trace/database/SqlLite.js";
const sqlit = require("../../../../dist/trace/database/SqlLite.js")
jest.mock("../../../../dist/trace/database/SqlLite.js");

window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));

describe('SpProcessChart Test', ()=> {
    let MockqueryProcessAsyncFunc = sqlit.queryProcessAsyncFunc;
    MockqueryProcessAsyncFunc.mockResolvedValue([
        {
            tid: 1,
            pid: 2,
            threadName: "1",
            track_id: 3,
            startTs: 1111,
            dur: 2000000,
            funName: "func",
            parent_id: 4,
            id: 5,
            cookie: "ff",
            depth: 5,
            argsetid: 6
        }
    ])
    let processContentCount = sqlit.queryProcessContentCount;
    processContentCount.mockResolvedValue([
        {
            pid: 1,
            switch_count: 2,
            thread_count: 3,
            slice_count: 4,
            mem_count: 5
        }
    ])
    let queryProcessThreads = sqlit.queryProcessThreads;
    queryProcessThreads.mockResolvedValue([
        {
            utid: 1,
            hasSched: 0,
            pid: 3,
            tid: 4,
            processName: "process",
            threadName: "thread"
        }
    ])
    let queryProcessThreadsByTable = sqlit.queryProcessThreadsByTable;
    queryProcessThreadsByTable.mockResolvedValue([
        {
            pid: 1,
            tid: 0,
            processName: "process",
            threadName: "thread"
        }
    ])
    let getAsyncEvents = sqlit.getAsyncEvents;
    getAsyncEvents.mockResolvedValue([
        {
            pid: 1,
            startTime: 100000
        }
    ])
    let queryProcessMem = sqlit.queryProcessMem;
    queryProcessMem.mockResolvedValue([
        {
            trackId: 1,
            trackName: "trackName",
            upid: 2,
            pid: 3,
            processName: "processName"
        }
    ])
    let queryEventCountMap = sqlit.queryEventCountMap;
    queryEventCountMap.mockResolvedValue([
        {
            eventName: "eventName",
            count: 1
        }
    ])
    let queryProcess = sqlit.queryProcess;
    queryProcess.mockResolvedValue([
        {
            pid: 1,
            processName: "processName"
        }
    ])

    let queryProcessByTable = sqlit.queryProcessByTable;
    queryProcessByTable.mockResolvedValue([
        {
            pid: 2,
            processName: "processName"
        }
    ])

    let spSystemTrace = new SpSystemTrace();
    let spProcessChart = new SpProcessChart(spSystemTrace);
    it('SpProcessChart01', function () {
        spProcessChart.init()
        expect(spProcessChart).toBeDefined();
    });
})