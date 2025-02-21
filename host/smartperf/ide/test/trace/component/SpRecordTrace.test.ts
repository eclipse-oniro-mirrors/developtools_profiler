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
import {SpRecordTrace} from "../../../dist/trace/component/SpRecordTrace.js"

window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));

describe('SpRecordTrace Test', () => {
    document.body.innerHTML = `
    <sp-application><sp-record-trace id="aaa"></sp-record-trace></sp-application>
   `
    let spRecordTrace = document.querySelector('#aaa') as SpRecordTrace
    it('SpRecordTraceTest01', function () {
        expect(SpRecordTrace.initHtml).not.toBe('')
    });

    it('SpRecordTraceTest02', function () {
        SpRecordTrace.patentNode=jest.fn(()=>true);
        expect(SpRecordTrace.initElements).toBeUndefined()
    });

    it('SpRecordTraceTest04', function () {
        let traceEvents = SpRecordTrace.createTraceEvents = ['Scheduling details', 'CPU Frequency and idle states',
            'High frequency memory', 'Advanced ftrace config', 'Syscalls' , 'Board voltages & frequency'];
        expect(traceEvents[0].indexOf('binder/binder_lock')).toBe(-1)
    });

    it('SpRecordTraceTest05', function () {
        spRecordTrace.spAllocations = jest.fn(()=>undefined)
        spRecordTrace.spAllocations.appProcess = jest.fn(()=>"")
        spRecordTrace.spAllocations.appProcess.indexOf = jest.fn(()=>"")
        spRecordTrace.spAllocations.appProcess.lastIndexOf = jest.fn(()=>1)
        spRecordTrace.spAllocations.appProcess.slice = jest.fn(()=>1)
        expect(spRecordTrace.createNativePluginConfig(1)).toEqual({"configData": {"fileName": "",
                "filterSize": undefined, "fpUnwind": undefined, "mallocFreeMatchingCnt": 1000,
                "mallocFreeMatchingInterval": 1000, "maxStackDepth": undefined, "pid": 1,"processName": "",
                "saveFile": false, "smbPages": undefined, "stringCompressed": true}, "pluginName": "nativehook", "sampleInterval": 1000})
    });

    it('SpRecordTraceTest06', function () {
        expect(spRecordTrace.createFpsPluginConfig()).not.toBeUndefined()
    });
    it('SpRecordTraceTest07', function () {
        expect(spRecordTrace.vs).not.toBeUndefined()
    });
    it('SpRecordTraceTest08', function () {
        spRecordTrace.vs = true
        expect(spRecordTrace.vs).toBeTruthy()
    });

    it('SpRecordTraceTest10', function () {
        let devs = {
            length:1,
        }
        expect(spRecordTrace.compareArray(devs)).toBeTruthy()
    });
    it('SpRecordTraceTest09', function () {
        spRecordTrace.vs = false
        expect(spRecordTrace.vs).toBeFalsy()
    });
    it('SpRecordTraceTest11', function () {
        let devs = {
            length:1,
        }
        expect(spRecordTrace.compareArray(!devs)).toBeTruthy()
    });
    it('SpRecordTraceTest12', function () {
        spRecordTrace.showHint = true
        expect(spRecordTrace.showHint).toBeUndefined()
    });
    it('SpRecordTraceTest13', function () {
        spRecordTrace.showHint = false
        expect(spRecordTrace.showHint).toBeUndefined()
    });
    it('SpRecordTraceTest14', function () {
        let event = {
            isTrusted:true,
            device: {
                serialNumber:"string"
            }
        }
        expect(spRecordTrace.usbDisConnectionListener(event)).toBeUndefined()
    });
    it('SpRecordTraceTest15', function () {
        let traceResult = {
            indexOf:jest.fn(()=>undefined)
        }

        expect(spRecordTrace.isSuccess(traceResult)).toBe(1)
    });
    it('SpRecordTraceTest16', function () {
        expect(spRecordTrace.createSessionRequest()).toStrictEqual({"pluginConfigs": [], "requestId": 1, "sessionConfig": {"buffers":
                    [{"pages": 16384, "policy": 0}], "keepAliveTime": 0, "resultFile": "/data/local/tmp/hiprofiler_data.htrace", "resultMaxSize": 0,
                "sampleDuration": 50000, "sessionMode": 0}})
    });
    it('SpRecordTraceTest17', function () {
        let that = {
            createProcessPlugin:jest.fn(()=>undefined),
            createCpuPlugin:jest.fn(()=>undefined),
            createDiskIOPlugin:jest.fn(()=>undefined),
            createNetworkPlugin:jest.fn(()=>undefined),
        }
        let request = {
            pluginConfigs:{
                push:jest.fn(()=>undefined),
            }
        }
        expect(spRecordTrace.createMonitorPlugin(that, request)).toBeUndefined()
    });
    it('SpRecordTraceTest18', function () {
        expect(spRecordTrace.createNetworkPlugin()).toStrictEqual({"configData": {"testFile": "/data/local/tmp/"},
            "pluginName": "network-plugin", "sampleInterval": 1000})
    });
    it('SpRecordTraceTest19', function () {
        expect(spRecordTrace.createDiskIOPlugin()).toStrictEqual({"configData": {"reportIoStats": "IO_REPORT"},
            "pluginName": "diskio-plugin", "sampleInterval": 1000})
    });
    it('SpRecordTraceTest20', function () {
        expect(spRecordTrace.createCpuPlugin()).toStrictEqual({"configData": {"pid": 0, "reportProcessInfo": true},
            "pluginName": "cpu-plugin", "sampleInterval": 1000})
    });
    it('SpRecordTraceTest21', function () {
        expect(spRecordTrace.createProcessPlugin()).toStrictEqual({"configData": {"report_cpu": true,
                "report_diskio": true, "report_process_tree": true, "report_pss": true}, "pluginName": "process-plugin", "sampleInterval": 1000})
    });
    it('SpRecordTraceTest22', function () {
        let traceConfig = {
            forEach:jest.fn(()=>undefined)
        }
        expect(spRecordTrace.createTraceEvents(traceConfig)).toStrictEqual([])
    });
    it('SpRecordTraceTest23', function () {
        spRecordTrace.spRecordPerf = jest.fn(()=>undefined)
        spRecordTrace.spRecordPerf.getPerfConfig = jest.fn(()=>undefined)
        expect(spRecordTrace.createHiperConfig()).toStrictEqual({"configData": {"isRoot": false,
                "outfileName": "/data/local/tmp/perf.data", "recordArgs": "-f undefined -a  --cpu-limit undefined -e hw-cpu-cycles --call-stack undefined -j undefined"}, "pluginName": "hiperf-plugin", "sampleInterval": NaN})
    });

    it('SpRecordTraceTest24', function () {
        expect(spRecordTrace.isSuccess('Signal')).toBe(2)
    });

    it('SpRecordTraceTest25', function () {
        expect(spRecordTrace.isSuccess('The device is abnormal')).toBe(-1);
    });

    it('SpRecordTraceTest26', function () {
        expect(spRecordTrace.isSuccess('')).toBe(0);
    });

})
