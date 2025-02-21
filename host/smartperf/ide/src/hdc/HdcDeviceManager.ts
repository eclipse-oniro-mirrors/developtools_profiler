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

import {HdcClient} from "./hdcclient/HdcClient.js";
import {UsbTransmissionChannel} from "./transmission/UsbTransmissionChannel.js";
import {HDC_DEVICE_FILTERS} from "./common/ConstantType.js";
import {FormatCommand} from "./hdcclient/FormatCommand.js";
import {log} from "../log/Log.js";
import {HdcStream} from "./hdcclient/HdcStream.js";
import {HdcCommand} from "./hdcclient/HdcCommand.js";
import {SpRecordTrace} from "../trace/component/SpRecordTrace.js";

export class HdcDeviceManager {
    private static clientList: Map<string, HdcClient> = new Map();
    private static currentHdcClient: HdcClient;
    private static FILE_RECV_PREFIX_STRING = "hdc file recv -cwd C:\\ "

    /**
     * getDevices
     */
    public static async getDevices(): Promise<USBDevice[]> {
        return navigator.usb.getDevices();
    }

    /**
     * findDevice
     */
    public static findDevice() {
        if (!('usb' in navigator)) {
            throw new Error('WebUSB not supported by the browser (requires HTTPS)');
        }
        return navigator.usb.requestDevice({filters: HDC_DEVICE_FILTERS});
    }

    /**
     * connect by serialNumber
     *
     * @param serialNumber serialNumber
     */
    public static async connect(serialNumber: string): Promise<boolean> {
        let client = this.clientList.get(serialNumber);
        if (client) {
            if (client.usbDevice!.opened) {
                log("device Usb is Open")
                return true;
            } else {
                if (SpRecordTrace.serialNumber == serialNumber) {
                    SpRecordTrace.serialNumber = ''
                }
                log("device Usb not Open")
                return false;
            }
        } else {
            let connectDevice = await this.getDeviceBySerialNumber(serialNumber);
            let usbChannel = await UsbTransmissionChannel.openHdcDevice(connectDevice);
            if (usbChannel) {
                let hdcClient = new HdcClient(usbChannel, connectDevice);
                let connected = await hdcClient.connectDevice();
                if (connected) {
                    this.currentHdcClient = hdcClient;
                    this.clientList.set(serialNumber, hdcClient);
                }
                log("device Usb connected : " + connected)
                return connected
            } else {
                log("device Usb connected failed: ")
                return false;
            }
        }
    }

    public static async getDeviceBySerialNumber(serialNumber: string): Promise<USBDevice> {
        const devices = await navigator.usb.getDevices();
        // @ts-ignore
        return devices.find(dev => dev.serialNumber === serialNumber);
    }

    /**
     * disConnect by serialNumber
     *
     * @param serialNumber
     */
    public static async disConnect(serialNumber: string): Promise<boolean> {
        let hdcClient = this.clientList.get(serialNumber);
        if (hdcClient) {
            await hdcClient.disconnect();
            this.clientList.delete(serialNumber);
            return true;
        } else {
            return true;
        }
    }

    /**
     * Execute shell on the currently connected device and return the result as a string
     *
     * @param cmd cmd
     */
    public static async shellResultAsString(cmd: string, isSkipResult: boolean): Promise<string> {
        if (this.currentHdcClient) {
            let hdcStream = new HdcStream(this.currentHdcClient, false);
            await hdcStream.DoCommand(cmd);
            let result: string = '';
            while (true) {
                let dataMessage = await hdcStream.getMessage();
                if (dataMessage.channelClose || isSkipResult) {
                    result += dataMessage.getDataToString();
                    await hdcStream.DoCommandRemote(new FormatCommand(HdcCommand.CMD_KERNEL_CHANNEL_CLOSE, "0", false));
                    log("result is end, close")
                    break;
                }
                if (dataMessage.usbHead.sessionId == -1) {
                    return Promise.resolve("The device is abnormal");
                }
                result += dataMessage.getDataToString();
            }
            await hdcStream.closeStream();
            await hdcStream.DoCommandRemote(new FormatCommand(HdcCommand.CMD_KERNEL_CHANNEL_CLOSE, "0", false));
            return Promise.resolve(result);
        }
        return Promise.reject("not select device");
    }


    /**
     * Execute shell on the currently connected device and return the result as a string
     *
     * @param cmd cmd
     */
    public static async stopHiprofiler(cmd: string, isSkipResult: boolean): Promise<string> {
        if (this.currentHdcClient) {
            let hdcStream = new HdcStream(this.currentHdcClient, true);
            await hdcStream.DoCommand(cmd);
            let result: string = '';
            while (true) {
                let dataMessage = await hdcStream.getMessage();
                if (dataMessage.channelClose || isSkipResult) {
                    await hdcStream.DoCommandRemote(new FormatCommand(HdcCommand.CMD_KERNEL_CHANNEL_CLOSE, "0", false));
                    log("result is end, close")
                    break;
                }
                result += dataMessage.getDataToString();
            }
            await hdcStream.closeStopStream();
            await hdcStream.DoCommandRemote(new FormatCommand(HdcCommand.CMD_KERNEL_CHANNEL_CLOSE, "0", false));
            return Promise.resolve(result);
        }
        return Promise.reject("not select device");
    }

    /**
     * Execute shell on the currently connected device, the result is returned as Blob
     *
     * @param cmd cmd
     */
    public static async shellResultAsBlob(cmd: string, isSkipResult: boolean): Promise<Blob> {
        if (this.currentHdcClient) {
            let hdcStream = new HdcStream(this.currentHdcClient, false);
            log("cmd is " + cmd);
            await hdcStream.DoCommand(cmd);
            let finalBuffer;
            while (true) {
                let dataMessage = await hdcStream.getMessage();
                if (dataMessage.channelClose || isSkipResult) {
                    log("result is end, close")
                    break;
                }
                let res = dataMessage.getData();
                if (res) {
                    if (!finalBuffer) {
                        finalBuffer = new Uint8Array(res);
                    } else {
                        finalBuffer = HdcDeviceManager.appendBuffer(finalBuffer, new Uint8Array(res));
                    }
                }
            }
            await hdcStream.closeStream();
            if (finalBuffer) {
                return Promise.resolve(new Blob([finalBuffer]));
            }
            return Promise.resolve(new Blob());
        }
        return Promise.reject("not select device");
    }

    /**
     * appendBuffer
     *
     * @param buffer1 firstBuffer
     * @param buffer2 secondBuffer
     * @private
     */
    private static appendBuffer(buffer1: Uint8Array, buffer2: Uint8Array) {
        let tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
        tmp.set(buffer1, 0);
        tmp.set(buffer2, buffer1.byteLength);
        return tmp;
    };

    /**
     * Pull the corresponding file from the device side
     *
     * @param filename filename
     */
    public static async fileRecv(filename: string, callBack: Function): Promise<Blob> {
        let finalBuffer;
        if (this.currentHdcClient) {
            let hdcStream = new HdcStream(this.currentHdcClient, false);
            await hdcStream.DoCommand(HdcDeviceManager.FILE_RECV_PREFIX_STRING + filename + " ./");
            if (!finalBuffer && hdcStream.fileSize > 0) {
                finalBuffer = new Uint8Array(hdcStream.fileSize);
                log("Uint8Array size is " + finalBuffer.byteLength);
            }
            let offset = 0;
            while (true) {
                let dataMessage = await hdcStream.getMessage();
                if (dataMessage.channelClose) {
                    log("result is end, close")
                    break;
                }
                if (dataMessage.commandFlag == HdcCommand.CMD_FILE_FINISH) {
                    await hdcStream.DoCommandRemote(new FormatCommand(HdcCommand.CMD_KERNEL_CHANNEL_CLOSE, "", false));
                    log("CMD_FILE_FINISH is end, close")
                    break;
                }
                let res = dataMessage.getData();
                if (res) {
                    let resRS: ArrayBuffer = res.slice(64);
                    if (finalBuffer) {
                        finalBuffer.set(new Uint8Array(resRS), offset);
                        offset += resRS.byteLength;
                        callBack((offset / hdcStream.fileSize * 100).toFixed(3))
                    }
                }
                if (hdcStream.fileSize != -1 && offset >= hdcStream.fileSize) {
                    callBack(100)
                    await hdcStream.DoCommandRemote(new FormatCommand(HdcCommand.CMD_FILE_FINISH, "", false));
                }
            }
        }
        if (finalBuffer) {
            return Promise.resolve(new Blob([finalBuffer]));
        } else {
            return Promise.resolve(new Blob([]));
        }
    }

}
