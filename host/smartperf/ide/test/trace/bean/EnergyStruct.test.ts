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
import {EnergyAnomalyStruct, EnergySystemStruct, EnergyPowerStruct, EnergyStateStruct, PowerDetailsEnergy, PowerBatteryEnergy, SystemDetailsEnergy} from "../../../dist/trace/bean/EnergyStruct.js";

describe('EnergyStruct Test', ()=> {
    let energyAnomalyStruct = new EnergyAnomalyStruct();
    let energySystemStruct = new EnergySystemStruct();
    let energyPowerStruct = new EnergyPowerStruct();
    let energyStateStruct = new EnergyStateStruct();
    let powerDetailsEnergy = new PowerDetailsEnergy();
    let powerBatteryEnergy = new PowerBatteryEnergy();
    let systemDetailsEnergy = new SystemDetailsEnergy();

    it('energyAnomalyStructTest', function () {
        energyAnomalyStruct = {
            type: 0,
            startNS: 0,
            height: 0,
            eventName: 'eventName'
        };
        expect(energyAnomalyStruct).not.toBeUndefined()
        expect(energyAnomalyStruct).toMatchInlineSnapshot({
  type: expect.any(Number),
  startNS: expect.any(Number),
  height: expect.any(Number),
  eventName: expect.any(String) }, `
Object {
  "eventName": Any<String>,
  "height": Any<Number>,
  "startNS": Any<Number>,
  "type": Any<Number>,
}
`);
    });

    it('energySystemStructTest', function () {
        energySystemStruct = {
            type: 0,
            startNs: 0,
            dur: 0,
            workScheduler: "",
            power: "",
            location: ""
        };
        expect(energySystemStruct).not.toBeUndefined()
        expect(energySystemStruct).toMatchInlineSnapshot({
  type: expect.any(Number),
  startNs: expect.any(Number),
  dur: expect.any(Number),
  workScheduler: expect.any(String),
  power: expect.any(String),
  location: expect.any(String) }, `
Object {
  "dur": Any<Number>,
  "location": Any<String>,
  "power": Any<String>,
  "startNs": Any<Number>,
  "type": Any<Number>,
  "workScheduler": Any<String>,
}
`);
    });

    it('energyPowerStructTest', function () {
        energyPowerStruct = {
            type: 0,
            name: "",
            ts: 0,
            cpu: 0,
            location: 0,
            gpu: 0,
            display:  0,
            camera: 0,
            bluetooth: 0,
            flashlight: 0,
            audio: 0,
            wifiscan: 0
        };
        expect(energyPowerStruct).not.toBeUndefined()
        expect(energyPowerStruct).toMatchInlineSnapshot({
  type: expect.any(Number),
  name: expect.any(String),
  ts: expect.any(Number),
  cpu: expect.any(Number),
  location: expect.any(Number),
  gpu: expect.any(Number),
  display: expect.any(Number),
  camera: expect.any(Number),
  bluetooth: expect.any(Number),
  flashlight: expect.any(Number),
  audio: expect.any(Number),
  wifiscan: expect.any(Number) }, `
Object {
  "audio": Any<Number>,
  "bluetooth": Any<Number>,
  "camera": Any<Number>,
  "cpu": Any<Number>,
  "display": Any<Number>,
  "flashlight": Any<Number>,
  "gpu": Any<Number>,
  "location": Any<Number>,
  "name": Any<String>,
  "ts": Any<Number>,
  "type": Any<Number>,
  "wifiscan": Any<Number>,
}
`);
    });

    it('energyStateStructTest', function () {
        energyStateStruct = {
            type: "",
            startNs: 0,
            dur: 0,
            value: 0
        };
        expect(energyStateStruct).not.toBeUndefined()
        expect(energyStateStruct).toMatchInlineSnapshot({
  type: expect.any(String),
  startNs: expect.any(Number),
  dur: expect.any(Number),
  value: expect.any(Number) }, `
Object {
  "dur": Any<Number>,
  "startNs": Any<Number>,
  "type": Any<String>,
  "value": Any<Number>,
}
`);
    });


    it('powerDetailsEnergyTest', function () {
        powerDetailsEnergy = {
            event: "",
            charge: 0,
            background_time: 0,
            screen_on_time: 0,
            screen_off_time: 0,
            load: "-",
            usage: 0,
            duration: 0,
            camera_id: 0,
            foreground_count: 0,
            background_count: 0,
            screen_on_count: 0,
            screen_off_count: 0,
            count: 0,
            appName: "",
            uid: 0,
            foreground_duration: 0,
            foreground_energy: 0,
            background_duration: 0,
            background_energy: 0,
            screen_on_duration: 0,
            screen_on_energy: 0,
            screen_off_duration: 0,
            screen_off_energy: 0,
            energy: 0,
            energyConsumptionRatio: ""
        };
        expect(powerDetailsEnergy).not.toBeUndefined()
        expect(powerDetailsEnergy).toMatchInlineSnapshot({
  event: expect.any(String),
  charge: expect.any(Number),
  background_time: expect.any(Number),
  screen_on_time: expect.any(Number),
  screen_off_time: expect.any(Number),
  load: expect.any(String),
  usage: expect.any(Number),
  duration: expect.any(Number),
  camera_id: expect.any(Number),
  foreground_count: expect.any(Number),
  background_count: expect.any(Number),
  screen_on_count: expect.any(Number),
  screen_off_count: expect.any(Number),
  count: expect.any(Number),
  appName: expect.any(String),
  uid: expect.any(Number),
  foreground_duration: expect.any(Number),
  foreground_energy: expect.any(Number),
  background_duration: expect.any(Number),
  background_energy: expect.any(Number),
  screen_on_duration: expect.any(Number),
  screen_on_energy: expect.any(Number),
  screen_off_duration: expect.any(Number),
  screen_off_energy: expect.any(Number),
  energy: expect.any(Number),
  energyConsumptionRatio: expect.any(String) }, `
Object {
  "appName": Any<String>,
  "background_count": Any<Number>,
  "background_duration": Any<Number>,
  "background_energy": Any<Number>,
  "background_time": Any<Number>,
  "camera_id": Any<Number>,
  "charge": Any<Number>,
  "count": Any<Number>,
  "duration": Any<Number>,
  "energy": Any<Number>,
  "energyConsumptionRatio": Any<String>,
  "event": Any<String>,
  "foreground_count": Any<Number>,
  "foreground_duration": Any<Number>,
  "foreground_energy": Any<Number>,
  "load": Any<String>,
  "screen_off_count": Any<Number>,
  "screen_off_duration": Any<Number>,
  "screen_off_energy": Any<Number>,
  "screen_off_time": Any<Number>,
  "screen_on_count": Any<Number>,
  "screen_on_duration": Any<Number>,
  "screen_on_energy": Any<Number>,
  "screen_on_time": Any<Number>,
  "uid": Any<Number>,
  "usage": Any<Number>,
}
`);
    });


    it('powerBatteryEnergyTest', function () {
        powerBatteryEnergy = {
            gasGauge: -1,
            charge: -1,
            screen: -1,
            level: -1,
            current: -1,
            capacity: -1,
            appName: "",
            uid: -1
        };
        expect(powerBatteryEnergy).not.toBeUndefined()
        expect(powerBatteryEnergy).toMatchInlineSnapshot({
  gasGauge: expect.any(Number),
  charge: expect.any(Number),
  screen: expect.any(Number),
  level: expect.any(Number),
  current: expect.any(Number),
  capacity: expect.any(Number),
  appName: expect.any(String),
  uid: expect.any(Number) }, `
Object {
  "appName": Any<String>,
  "capacity": Any<Number>,
  "charge": Any<Number>,
  "current": Any<Number>,
  "gasGauge": Any<Number>,
  "level": Any<Number>,
  "screen": Any<Number>,
  "uid": Any<Number>,
}
`);
    });


    it('systemDetailsEnergyTest', function () {
        systemDetailsEnergy = {
            eventName: "",
            type: "",
            pid: -1,
            uid: -1,
            state: -1,
            workId: "",
            name: "",
            interval: -1,
            level: -1,
            tag: "",
            message: "",
            log_level: ""
        };
        expect(systemDetailsEnergy).not.toBeUndefined()
        expect(systemDetailsEnergy).toMatchInlineSnapshot({
  eventName: expect.any(String),
  type: expect.any(String),
  pid: expect.any(Number),
  uid: expect.any(Number),
  state: expect.any(Number),
  workId: expect.any(String),
  name: expect.any(String),
  interval: expect.any(Number),
  level: expect.any(Number),
  tag: expect.any(String),
  message: expect.any(String),
  log_level: expect.any(String) }, `
Object {
  "eventName": Any<String>,
  "interval": Any<Number>,
  "level": Any<Number>,
  "log_level": Any<String>,
  "message": Any<String>,
  "name": Any<String>,
  "pid": Any<Number>,
  "state": Any<Number>,
  "tag": Any<String>,
  "type": Any<String>,
  "uid": Any<Number>,
  "workId": Any<String>,
}
`);
    });

})