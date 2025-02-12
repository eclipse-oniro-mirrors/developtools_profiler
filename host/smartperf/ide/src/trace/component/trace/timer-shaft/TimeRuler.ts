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

import {Graph} from "./Graph.js";
import {Rect} from "./Rect.js";
import {ns2s, TimerShaftElement} from "../TimerShaftElement.js";

export class TimeRuler extends Graph {
    totalNS: number
    private stepSmall: number;
    private step: number;
    private stepNS: number;

    constructor(timerShaftEL: TimerShaftElement, frame: Rect, totalNS: number = 10_000_000_000) {
        super(timerShaftEL.canvas, timerShaftEL.ctx!, frame)
        this.totalNS = totalNS;
        this.step = this.frame.width / 10;
        this.stepSmall = this.frame.width / 100;
        this.stepNS = this.totalNS / 10;
    }

    draw() {
        this.step = this.frame.width / 10;
        this.stepSmall = this.frame.width / 100;
        this.stepNS = this.totalNS / 10;
        this.c.clearRect(this.frame.x, this.frame.y, this.frame.width, this.frame.height)
        this.c.beginPath();
        this.c.strokeStyle = "#999"
        this.c.lineWidth = 1;
        for (let i = 0; i <= 10; i++) {
            let x = Math.floor(i * this.step) + this.frame.x;
            this.c.moveTo(x, 0);
            this.c.lineTo(x, this.frame.height);
            if (i == 10) break;
            for (let j = 1; j < 10; j++) {
                this.c.moveTo(x + Math.floor(j * this.stepSmall), 0);
                this.c.lineTo(x + Math.floor(j * this.stepSmall), this.frame.height / 4);
            }
            this.c.fillStyle = '#999'
            this.c.fillText(`${ns2s(i * this.stepNS)}`, x + 5, this.frame.height - 1)
        }
        this.c.stroke();
        this.c.closePath();
    }
}



