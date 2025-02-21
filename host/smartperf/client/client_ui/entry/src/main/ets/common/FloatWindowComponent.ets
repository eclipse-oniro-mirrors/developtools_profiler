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

import {moveFloatWindow,setFloatWindow} from './ui/floatwindow/utils/FloatWindowUtils'





@Component
export struct FloatWindowComponent {
  private settings: RenderingContextSettings = new RenderingContextSettings(true)
  private context: CanvasRenderingContext2D = new CanvasRenderingContext2D(this.settings)
  @State title: string = "SmartPerf"
  private XPoint: number = 5  //x起始坐标
  private YPoint: number = 108   //Y起始坐标
  private XScale: number =8 //刻度
  private YScale: number = 21 //刻度
  private XLength: number = 168 //X轴长度
  private YLength: number = 105  //Y轴长度
  @State data: number[]= [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]   //数据集合
  private MaxDataSize: number= this.XLength / this.XScale  //数据集合的最大长度
  @State NumericalValue: number= 0   //数值
  offsetX: number = -1    //悬浮框移动触摸点 X
  offsetY: number = -1   //悬浮框移动触摸点 X

  MoveWindow(offsetX: number, offsetY: number) {
    moveFloatWindow(this.title,offsetX, offsetY)
  }

  SetWindowPosition(offsetX: number, offsetY: number) {
    setFloatWindow(offsetX, offsetY)
  }
  build() {
    Flex({ direction: FlexDirection.Column, alignItems: ItemAlign.Start, justifyContent: FlexAlign.Center }) {
      Canvas(this.context)
        .width('100%')
        .height('100%')
        .onReady(() => {
          //Y轴
          this.context.clearRect(this.XPoint + 0.5, this.YPoint - this.YLength, this.XLength, this.YLength)
          this.context.beginPath()
          this.context.strokeStyle="#ffffff"
          this.context.moveTo(this.XPoint, this.YPoint - this.YLength)
          this.context.lineTo(this.XPoint, this.YPoint)
          this.context.stroke()
          //X轴
          this.context.beginPath()
          this.context.strokeStyle="#ffffff"
          this.context.moveTo(this.XPoint, this.YPoint)
          this.context.lineTo(this.XPoint + this.XLength, this.YPoint)
          this.context.stroke()
          //K线绘制
          if (this.data.length > 1) {
            for (let i = 1; i < this.data.length; i++) {
              this.context.beginPath()
              this.context.strokeStyle="#ffffff"
              console.log("GestureEvent--------------beginPath:" + this.data[i-1]);
              this.context.moveTo(this.XPoint + (i - 1) * this.XScale, this.YPoint - this.data[i-1])
              this.context.lineTo(this.XPoint + i * this.XScale, this.YPoint - this.data[i])
              this.context.stroke()
            }
          }
        })
    }
    .width('100%')
    .height('100%').margin({  top: 20 }).gesture(
    GestureGroup(GestureMode.Exclusive,
    PanGesture({})
      .onActionStart((event: GestureEvent) => {

      })
      .onActionUpdate((event: GestureEvent) => {
        this.offsetX = event.offsetX
        this.offsetY = event.offsetY

      })
      .onActionEnd(() => {
        this.MoveWindow(this.offsetX, this.offsetY)
        this.SetWindowPosition(this.offsetX, this.offsetY)


      })
    ))
  }
}