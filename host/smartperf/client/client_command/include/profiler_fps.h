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
#ifndef PLUGNFPS_H
#define PLUGNFPS_H
#include <vector>
#include "sp_profiler.h"
#include <queue>
namespace OHOS {
namespace SmartPerf {
struct FpsInfoProfiler {
    int fps;
    std::vector<long long> jitters;
    std::vector<long long> currTimeStamps;
    int curTime;
    long long currTimeDiff;
    long long currTimeDump;
    void Clear()
    {
        fps = 0;
        jitters.clear();
        currTimeDiff = 0;
        currTimeDump = 0;
    }
    bool operator == (const FpsInfoProfiler &other) const
    {
        if (fps != other.fps) {
            return false;
        }
        if (jitters.size() != other.jitters.size()) {
            return false;
        }
        for (size_t i = 0; i < jitters.size(); i++) {
            if (jitters[i] != other.jitters[i]) {
                return false;
            }
        }
        return true;
    }
    FpsInfoProfiler()
    {
        fps = 0;
        curTime = 0;
        currTimeDiff = 0;
        currTimeDump = 0;
    }
};
class ProfilerFPS : public SpProfiler {
public:
    void SetTraceCatch();
    void SetPackageName(std::string pName);
    void GetFPS(std::vector<std::string> v);
    void GetResultFPS(int sectionsNum);
    FpsInfoProfiler GetFpsInfo();
    bool IsForeGround();
    bool IsFindForeGround(std::string line) const;
    void CalcFpsAndJitters();
    FpsInfoProfiler GetSurfaceFrame(std::string name);
    void PrintSections(int msCount, long long currTimeLast, long long currTimeStart, long long currLastTime) const;
    void GetSectionsFps(FpsInfoProfiler &fpsInfoResult, int nums) const;
    void GetSectionsPrint(int printCount, long long msStartTime, int numb, long long harTime) const;
    void GetTimeDiff();
    void GetCurrentTime(int sleepNum);
    void GetOhFps(std::vector<std::string> v);
    std::string GetSurface();
    FpsInfoProfiler fpsInfo;
    FpsInfoProfiler fpsInfoMax;
    FpsInfoProfiler lastFpsInfoResult;
    static ProfilerFPS &GetInstance()
    {
        static ProfilerFPS instance;
        return instance;
    }
    std::map<std::string, std::string> ItemData() override;
private:
    ProfilerFPS() {};
    ProfilerFPS(const ProfilerFPS &);
    ProfilerFPS &operator = (const ProfilerFPS &);

    std::string pkgName;
    int num = 1;
    int number = 2;
    bool refresh = false;
    long long mod = 1e9;
    long long curScreenTimestamp = 0;
    long long prevScreenTimestamp = -1;
    long long prevlastScreenTimestamp = 0;
    int fpsNum = 0;
    bool isFirstResult = false;
    long oneSec = 1000000;
    unsigned long sleepTime = 950000;
    unsigned long sleepNowTime = 10000;
    int ten = 10;
    int four = 4;
    int fifty = 50;
    long long lastCurrTime = 0;
    long long oneThousand = 1000;
    long long msClear = 1000000000;
    long long currRealTime = 0;
    bool isFoundAppName = false;
    bool isFoundBundleName = false;
    int isCatchTrace = 0;
    bool processFlag = false;
    bool ohFlag = false;
};
}
}
#endif