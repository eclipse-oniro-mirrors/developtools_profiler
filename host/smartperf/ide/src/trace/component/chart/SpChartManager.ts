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

import {SpSystemTrace} from "../SpSystemTrace.js";
import {SpHiPerf} from "./SpHiPerf.js";
import {SpCpuChart} from "./SpCpuChart.js";
import {SpFreqChart} from "./SpFreqChart.js";
import {SpFpsChart} from "./SpFpsChart.js";
import {
    getCpuUtilizationRate, queryDataDICT,
    queryTotalTime
} from "../../database/SqlLite.js";
import {info} from "../../../log/Log.js";
import {SpNativeMemoryChart} from "./SpNativeMemoryChart.js";
import {SpAbilityMonitorChart} from "./SpAbilityMonitorChart.js";
import {SpProcessChart} from "./SpProcessChart.js";
import {perfDataQuery} from "./PerfDataQuery.js";
import {SpVirtualMemChart} from "./SpVirtualMemChart.js";
import {SpFileSystemChart} from "./SpFileSystemChart.js";
import {procedurePool} from "../../database/Procedure.js";
import {SpSdkChart} from "./SpSdkChart.js";
import {SpHiSysEventChart} from "./SpHiSysEventChart.js";
import {SmpsChart} from "./SmpsChart.js";

export class SpChartManager {
    private trace: SpSystemTrace;
    public perf: SpHiPerf;
    private cpu: SpCpuChart;
    private freq: SpFreqChart;
    private virtualMemChart:SpVirtualMemChart;
    private fps: SpFpsChart
    private nativeMemory: SpNativeMemoryChart;
    private abilityMonitor: SpAbilityMonitorChart;
    private process: SpProcessChart;
    private fileSystem: SpFileSystemChart;
    private sdkChart: SpSdkChart;
    private hiSyseventChart: SpHiSysEventChart;
    private smpsChart:SmpsChart;

    constructor(trace: SpSystemTrace) {
        this.trace = trace;
        this.perf = new SpHiPerf(trace);
        this.fileSystem = new SpFileSystemChart(trace);
        this.cpu = new SpCpuChart(trace);
        this.freq = new SpFreqChart(trace);
        this.virtualMemChart = new SpVirtualMemChart(trace);
        this.fps = new SpFpsChart(trace);
        this.nativeMemory = new SpNativeMemoryChart(trace);
        this.abilityMonitor = new SpAbilityMonitorChart(trace);
        this.process = new SpProcessChart(trace);
        this.sdkChart = new SpSdkChart(trace);
        this.hiSyseventChart = new SpHiSysEventChart(trace);
        this.smpsChart = new SmpsChart(trace);
    }

    async init(progress:Function){
        progress("load data dict", 50);
        SpSystemTrace.DATA_DICT.clear();
        let dict = await queryDataDICT();
        dict.map((d) => SpSystemTrace.DATA_DICT.set(d['id'], d['data']));
        progress("time range", 65);
        await this.initTotalTime();
        info("timerShaftEL Data initialized")
        progress("cpu", 70);
        await this.cpu.init();
        info("cpu Data initialized")
        progress("process", 73);
        await this.cpu.initProcessThreadStateData(progress);
        info("ProcessThreadState Data initialized")
        progress("cpu rate", 75);
        await this.initCpuRate();
        info("Cpu Rate Data initialized")
        progress("cpu freq", 80);
        await this.freq.init();
        info("Cpu Freq Data initialized")
        await this.virtualMemChart.init();
        progress("fps", 85);
        await this.fps.init();
        info("FPS Data initialized")
        progress("native memory", 86);
        await this.nativeMemory.initNativeMemory()
        progress("native memory", 87);
        await this.nativeMemory.initChart();
        info("Native Memory Data initialized")
        progress("ability monitor", 88);
        await this.abilityMonitor.init();
        progress("hiSysevent", 88.2);
        await this.hiSyseventChart.init();
        info("Perf Files Data initialized")
        progress("vm tracker", 88.4);
        await this.smpsChart.init();
        progress("sdk", 88.6);
        await this.sdkChart.init();
        progress("perf", 88.8);
        await this.perf!.init();
        progress("file system", 89);
        await this.fileSystem!.init();
        info("Ability Monitor Data initialized")
        await perfDataQuery.initPerfCache()
        info("HiPerf Data initialized")
        progress("process", 90);
        await this.process.initAsyncFuncData()
        await this.process.init();
        info("Process Data initialized")
        progress("display", 95);
    }

    initTotalTime = async () => {
        let res = await queryTotalTime();
        if (this.trace.timerShaftEL) {
            this.trace.timerShaftEL.totalNS = res[0].total;
            (window as any).recordStartNS = res[0].recordStartNS;
            (window as any).recordEndNS = res[0].recordEndNS;
            this.trace.timerShaftEL.loadComplete = true;
        }
    }

    initCpuRate = async () => {
        let rates = await getCpuUtilizationRate(0, this.trace.timerShaftEL?.totalNS || 0);
        if (this.trace.timerShaftEL) this.trace.timerShaftEL.cpuUsage = rates;
        info("Cpu UtilizationRate data size is: ", rates.length)
    }

}