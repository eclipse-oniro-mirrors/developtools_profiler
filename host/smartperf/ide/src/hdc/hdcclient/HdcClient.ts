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

import {Serialize} from "../common/Serialize.js";
import {HdcCommand} from "./HdcCommand.js";
import {Utils} from "../common/Utils.js";
import {HANDSHAKE_MESSAGE} from "../common/ConstantType.js";
import {PayloadHead} from "../message/PayloadHead.js";
import {TransmissionInterface} from "../transmission/TransmissionInterface.js";
import {DataProcessing} from "../transmission/DataProcessing.js";
import {DataListener} from "./DataListener.js";
import {DataMessage} from "../message/DataMessage.js";
import {SessionHandShake} from "../message/SessionHandShake.js";
import {AuthType} from "../message/AuthType.js";
import {debug, log} from "../../log/Log.js";
import {HdcStream} from "./HdcStream.js";
import {toHex16} from "../common/BaseConversion.js";

export class HdcClient implements DataListener {
    usbDevice: USBDevice | undefined;
    sessionId: number = 0;
    private transmissionChannel: TransmissionInterface;
    public readDataProcessing: DataProcessing;
    private stream: HdcStream | undefined | null;
    private hdcStopStream: HdcStream | undefined | null;
    private cmdStream: number = -1;
    private stopStream: number = -1;

    constructor(transmissionChannel: TransmissionInterface, usbDevice: USBDevice | undefined) {
        this.transmissionChannel = transmissionChannel;
        this.usbDevice = usbDevice;
        this.readDataProcessing = new DataProcessing(this, transmissionChannel);
    }

    async connectDevice(): Promise<boolean> {
        debug("start Connect Device")
        this.sessionId = Utils.getSessionId();
        log("sessionId is " + this.sessionId)
        // @ts-ignore
        let handShake: SessionHandShake = new SessionHandShake(HANDSHAKE_MESSAGE, AuthType.AUTH_NONE, this.sessionId, this.usbDevice.serialNumber, "");
        let hs = Serialize.serializeSessionHandShake(handShake);
        debug("start Connect hs ", hs)
        let sendResult = await this.readDataProcessing.send(handShake.sessionId, 0, HdcCommand.CMD_KERNEL_HANDSHAKE, hs, hs.length);
        if (sendResult) {
            let handShake = await this.readDataProcessing.readUsbHead();
            let handBody = await this.readDataProcessing.readBody(handShake!.dataSize);
            if (this.sessionId == handShake!.sessionId) {
                debug("handShake: ", handShake);
                let playHeadArray = handBody.buffer.slice(0, PayloadHead.getPayloadHeadLength())
                let resultPayloadHead: PayloadHead = PayloadHead.parsePlayHead(new DataView(playHeadArray));
                debug("resultPayloadHead is ", resultPayloadHead);
                let headSize = resultPayloadHead.headSize;
                let dataSize = resultPayloadHead.dataSize;
                let resPlayProtectBuffer = handBody.buffer.slice(PayloadHead.getPayloadHeadLength(), PayloadHead.getPayloadHeadLength() + headSize);
                debug("PlayProtect is ", resPlayProtectBuffer);
                let resData = handBody.buffer.slice(PayloadHead.getPayloadHeadLength() + headSize, PayloadHead.getPayloadHeadLength() + headSize + dataSize);
                debug("resData is ", resData);
                this.readDataProcessing.startReadData().then(() => {
                });
                return true;
            } else {
                log("session is not eq handShake?.sessionId is : " + handShake?.sessionId + " now session is " + this.sessionId)
                return false;
            }
        } else {
            return false;
        }
    }

    public async disconnect(): Promise<void> {
        await this.transmissionChannel.close();
        this.readDataProcessing.stopReadData();
    }

    public bindStream(channel: number, hdcStream: HdcStream) {
        this.cmdStream = channel;
        this.stream = hdcStream;
    }

    public bindStopStream(channel: number, hdcStopStream: HdcStream) {
        this.stopStream = channel;
        this.hdcStopStream = hdcStopStream;
    }

    public unbindStream(channel: number): boolean {
        this.stream = null;
        return this.stream == null;
    }

    public unbindStopStream(channel: number): boolean {
        this.hdcStopStream = null;
        return this.hdcStopStream == null;
    }

    createDataMessage(data: DataMessage): void {
        if (this.hdcStopStream && data.getChannelId() == this.stopStream) {
            this.hdcStopStream.putMessageInQueue(data);
        }
        if (this.stream && data.getChannelId() == this.cmdStream) {
            this.stream.putMessageInQueue(data);
        }
        if (data.getChannelId() == -1) {
            this.stream?.putMessageInQueue(data);
            this.hdcStopStream?.putMessageInQueue(data);
        }
    }
}

