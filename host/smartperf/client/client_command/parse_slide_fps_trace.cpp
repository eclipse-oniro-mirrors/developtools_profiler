/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <fstream>
#include <string>
#include <iostream>
#include <regex>
#include "include/parse_slide_fps_trace.h"
#include "include/sp_log.h"

namespace OHOS {
namespace SmartPerf {
double ParseSlideFpsTrace::ParseSlideFpsTraceNoh(std::string file)
{
    double fps = -1.0;
    char realPath[PATH_MAX] = {0x00};
    if ((realpath(file.c_str(), realPath) == nullptr)) {
        std::cout << "" << std::endl;
    }
    infile.open(realPath);
    if (infile.fail()) {
        std::cout << "file open fail:" << file << std::endl;
        LOGE("ParseSlideFpsTrace open file(%s) fialed ", file.c_str());
        return fps;
    }
    fps = SmartPerf::ParseSlideFpsTrace::CalculateTime();
    infile.close();
    return fps;
}

double ParseSlideFpsTrace::CalculateTime()
{
    std::string line;
    int two = 2;
    while (getline(infile, line)) {
        if (line.find("H:touchEventDispatch") != std::string::npos) {
            count++;
            if (count == four) {
                needTime = true;
                frameNow = 0;
                touchTime = std::stod(SmartPerf::ParseSlideFpsTrace::GetLineTime(line));
                swiperFlingFlag = 0;
            }
        } else if (line.find("H:RSMainThread::DoComposition") != std::string::npos) {
            frameNow++;
            doCompositionTime = std::stod(SmartPerf::ParseSlideFpsTrace::GetLineTime(line));
        } else if (line.find("H:WEB_LIST_FLING") != std::string::npos ||
            line.find("H:APP_LIST_FLING,") != std::string::npos) {
            listFlag++;
            if (listFlag == two) {
                completeTime = doCompositionTime;
                frameNum = frameNow;
            }
        }
        AppSwiperScroll(line);
    }
    if (completeTime == 0 || responseTime == 0) {
        return -1;
    } else {
        double fps = (frameNum - 1) / (completeTime - responseTime);
        double flagNum = 120;
        double flagNumb = 121;
        if (fps > flagNum && fps < flagNumb) {
            fps = flagNum;
        }
        return fps;
    }
    return -1.0;
}

void ParseSlideFpsTrace::AppSwiperScroll(std::string line)
{
    if (line.find("H:APP_SWIPER_SCROLL,") != std::string::npos) {
        if (swiperScrollFlag == 0) {
            touchTime = std::stod(SmartPerf::ParseSlideFpsTrace::GetLineTime(line));
            needTime = true;
            swiperScrollFlag = 1;
        }
    }
    if (line.find("H:APP_SWIPER_FLING,") != std::string::npos) {
        if (swiperFlingFlag == 1) {
            completeTime = doCompositionTime;
            frameNum = frameNow;
        }
        swiperFlingFlag++;
    }
    if (touchTime != 0 && (doCompositionTime - touchTime) > completionTime && needTime) {
        frameNow = 1;
        needTime = false;
        responseTime = doCompositionTime;
    }
}

std::string ParseSlideFpsTrace::GetLineTime(std::string lineStr) const
{
    size_t num = 7;
    size_t position1 = lineStr.find("....");
    size_t position2 = lineStr.find(":");
    return lineStr.substr(position1 + num, position2 - position1 - num);
}
std::string ParseSlideFpsTrace::CutString(std::string lineStr, const std::string &start,
    const std::string &end, size_t offset) const
{
    size_t position1 = lineStr.find(start);
    size_t position2 = lineStr.find(end);
    return lineStr.substr(position1 + offset, position2 - position1 - offset);
}
}
}
