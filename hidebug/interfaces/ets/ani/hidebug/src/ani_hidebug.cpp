/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
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

#include <algorithm>
#include <codecvt>
#include <string>
#include <malloc.h>
#include <parameters.h>
#include "ani_util.h"
#include "application_context.h"
#include "context.h"
#include "directory_ex.h"
#include "error_code.h"
#include "file_ex.h"
#include "hiappevent_util.h"
#include "hidebug_native_interface.h"
#include "hidebug_util.h"
#include "hilog/log.h"
#include "iservice_registry.h"
#include "refbase.h"
#include "heap_helpers.h"
#include "system_ability_definition.h"

using namespace OHOS;
using namespace OHOS::HiviewDFX;

namespace {
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002D0A
#undef LOG_TAG
#define LOG_TAG "HiDebug_ANI"
constexpr int BYTE_2_KB_SHIFT_BITS = 10;
constexpr int MAX_TAGS_ARRAY_LENGTH = 40;

std::map<std::string, uint64_t (*)(ani_vm*)> GetVmGcMap()
{
    return {
                {"ark.gc.gc-count", ark::dfx::GetGCCount},
                {"ark.gc.gc-time", ark::dfx::GetGCDuration},
                {"ark.gc.gc-bytes-allocated", ark::dfx::GetAccumulatedAllocateSize},
                {"ark.gc.gc-bytes-freed", ark::dfx::GetAccumulatedFreeSize},
                {"ark.gc.fullgc-longtime-count", ark::dfx::GetFullGCLongTimeCount}
            };
}

bool GetDumpParam(ani_env *env, ani_array argsAni, std::vector<std::u16string> &args)
{
    ani_size arraySize = 0;
    if (env->Array_GetLength(argsAni, &arraySize) != ANI_OK) {
        HILOG_ERROR(LOG_CORE, "Get input tags size failed.");
        return false;
    }
    for (ani_size i = 0; i < arraySize; i++) {
        ani_ref aniValue = nullptr;
        if (env->Object_CallMethodByName_Ref(argsAni, "$_get", "i:C{std.core.Object}", &aniValue, i) != ANI_OK) {
            HILOG_ERROR(LOG_CORE, "get_element -> Get input args failed.");
            return false;
        }
        std::string strValue;
        if (AniUtil::ParseAniString(env, static_cast<ani_string>(aniValue), strValue) != ANI_OK) {
            HILOG_ERROR(LOG_CORE, "get_value -> Get input args failed.");
            return false;
        }
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> strCnv;
        args.push_back(strCnv.from_bytes(strValue));
    }
    return true;
}

bool GetTraceParam(ani_env *env, ani_array tagsAni, std::vector<uint64_t> &tags)
{
    ani_size arraySize = 0;
    if (env->Array_GetLength(static_cast<ani_array>(tagsAni), &arraySize) != ANI_OK) {
        HILOG_ERROR(LOG_CORE, "Get input tags size failed.");
        return false;
    }
    if (arraySize > static_cast<ani_size>(MAX_TAGS_ARRAY_LENGTH)) {
        HILOG_ERROR(LOG_CORE, "The length of tags array exceeds the limit.");
        return false;
    }
    ani_class longClass {};
    ani_method toLong {};
    ani_status status = env->FindClass("std.core.Long", &longClass);
    if (status != ANI_OK) {
        HILOG_ERROR(LOG_CORE, "Get input tags value failed.");
        return false;
    }
    status = env->Class_FindMethod(longClass, "toLong", ":l", &toLong);
    for (ani_size i = 0; i < arraySize; i++) {
        ani_ref longRef {};
        ani_long longValue {};
        status = env->Array_Get(tagsAni, i, &longRef);
        if (status != ANI_OK) {
            HILOG_ERROR(LOG_CORE, "Array_Get failed, status: %{public}d", status);
            return false;
        }
        status = env->Object_CallMethod_Long(static_cast<ani_object>(longRef), toLong, &longValue);
        if (status != ANI_OK) {
            HILOG_ERROR(LOG_CORE, "Invoke toLong, status: %{public}d", status);
            return false;
        }
        tags.push_back(static_cast<uint64_t>(longValue));
    }
    return true;
}

ani_long GetPss(ani_env *env)
{
    auto nativeMemInfoOption = HidebugNativeInterface::GetInstance().GetAppNativeMemInfo(false);
    return nativeMemInfoOption ? static_cast<ani_long>(nativeMemInfoOption->pss) : 0;
}

ani_long GetSharedDirty(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getSharedDirty");
    auto nativeMemInfoOption = HidebugNativeInterface::GetInstance().GetAppNativeMemInfo(false);
    return nativeMemInfoOption ? static_cast<ani_long>(nativeMemInfoOption->sharedDirty) : 0;
}

ani_long GetPrivateDirty(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getPrivateDirty");
    auto nativeMemInfoOption = HidebugNativeInterface::GetInstance().GetAppNativeMemInfo(false);
    return nativeMemInfoOption ? static_cast<ani_long>(nativeMemInfoOption->privateDirty) : 0;
}

ani_double GetCpuUsage(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getCpuUsage");
    return static_cast<ani_double>(HidebugNativeInterface::GetInstance().GetCpuUsage());
}

ani_long GetNativeHeapSize(ani_env *env)
{
    struct mallinfo mi = mallinfo();
    return static_cast<ani_long>(mi.uordblks + mi.fordblks);
}

ani_long GetNativeHeapAllocatedSize(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getNativeHeapAllocatedSize");
    struct mallinfo mi = mallinfo();
    return static_cast<ani_long>(mi.uordblks);
}

ani_long GetNativeHeapFreeSize(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getNativeHeapFreeSize");
    struct mallinfo mi = mallinfo();
    return static_cast<ani_long>(mi.fordblks);
}

void GetServiceDump(ani_env *env,
    ani_int serviceIdAni, ani_int fdAni, ani_array argsAni)
{
    ApiInvokeRecorder apiInvokeRecorder("getServiceDump");
    int serviceAbilityId = static_cast<int>(serviceIdAni);
    int fd = static_cast<int>(fdAni);
    std::vector<std::u16string> args;
    if (!GetDumpParam(env, argsAni, args)) {
        std::string paramErrorMessage = "The parameter check failed.";
        AniUtil::ThrowErrorMessage(env, paramErrorMessage, ErrorCode::PARAMETER_ERROR);
        return;
    }
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!sam) {
        return;
    }
    sptr<IRemoteObject> sa = sam->CheckSystemAbility(serviceAbilityId);
    if (sa == nullptr) {
        HILOG_ERROR(LOG_CORE, "no this system ability.");
        std::string idErrorMessage = "ServiceId invalid. The system ability does not exist.";
        AniUtil::ThrowErrorMessage(env, idErrorMessage, ErrorCode::SYSTEM_ABILITY_NOT_FOUND);
        return;
    }
    int dumpResult = sa->Dump(fd, args);
    HILOG_INFO(LOG_CORE, "Dump result: %{public}d", dumpResult);
}

ani_long GetVss(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getVss");
    auto vssInfoOption = HidebugNativeInterface::GetInstance().GetVss();
    return vssInfoOption ? static_cast<ani_long>(vssInfoOption.value()) : 0;
}

ani_double GetSystemCpuUsage(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getSystemCpuUsage");
    auto cpuUsageOptional = HidebugNativeInterface::GetInstance().GetSystemCpuUsage();
    if (!cpuUsageOptional) {
        std::string paramErrorMessage = "The status of the system CPU usage is abnormal.";
        AniUtil::ThrowErrorMessage(env, paramErrorMessage, ErrorCode::SYSTEM_STATUS_ABNORMAL);
        return 0;
    }
    return static_cast<ani_double>(cpuUsageOptional.value());
}

ani_object ConvertThreadCpuUsageToEts(ani_env *env, ani_class cls, uint32_t threadIdValue, double cpuUsageValue)
{
    ani_method ctorMethod = nullptr;
    ani_object obj = nullptr;
    if (env->Class_FindMethod(cls, "<ctor>", ":", &ctorMethod) != ANI_OK ||
        env->Object_New(cls, ctorMethod, &obj) != ANI_OK) {
        return AniUtil::CreateUndefined(env);
    }
    env->Object_SetPropertyByName_Long(obj, "threadId", static_cast<ani_long>(threadIdValue));
    AniUtil::SetNamedPropertyNumber(env, obj, "cpuUsage", cpuUsageValue);
    return obj;
}

ani_array ConvertThreadCpuUsageMapToEts(ani_env *env, const std::map<uint32_t, double> &threadMap)
{
    ani_class cls = nullptr;
    ani_size aniSize = static_cast<ani_size>(threadMap.size());
    ani_array result = nullptr;
    ani_ref undefinedRef {};
    if (env->FindClass("@ohos.hidebug.hidebug.ThreadCpuUsageImpl", &cls) != ANI_OK ||
        env->Array_New(aniSize, undefinedRef, &result) != ANI_OK) {
        return result;
    }
    ani_size idx = 0;
    for (const auto& [threadId, cpuUsage] : threadMap) {
        ani_object obj = ConvertThreadCpuUsageToEts(env, cls, threadId, cpuUsage);
        env->Array_Set(result, idx, static_cast<ani_ref>(obj));
        idx++;
    }
    return result;
}

ani_array GetAppThreadCpuUsage(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getAppThreadCpuUsage");
    std::map<uint32_t, double> threadMap = HidebugNativeInterface::GetInstance().GetAppThreadCpuUsage();
    return ConvertThreadCpuUsageMapToEts(env, threadMap);
}

ani_object GetAppNativeMemInfo(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getAppNativeMemInfo");
    auto nativeMemInfoOption = HidebugNativeInterface::GetInstance().GetAppNativeMemInfo();
    if (!nativeMemInfoOption) {
        nativeMemInfoOption.emplace();
    }

    ani_class cls = nullptr;
    ani_method ctorMethod = nullptr;
    ani_object memInfo = nullptr;
    if (env->FindClass("@ohos.hidebug.hidebug.NativeMemInfoAdapter", &cls) != ANI_OK ||
        env->Class_FindMethod(cls, "<ctor>", ":", &ctorMethod) != ANI_OK ||
        env->Object_New(cls, ctorMethod, &memInfo) != ANI_OK) {
        return AniUtil::CreateUndefined(env);
    }
    env->Object_SetPropertyByName_Long(memInfo, "pss",
        static_cast<ani_long>(nativeMemInfoOption->pss));
    env->Object_SetPropertyByName_Long(memInfo, "rss",
        static_cast<ani_long>(nativeMemInfoOption->rss));
    env->Object_SetPropertyByName_Long(memInfo, "sharedDirty",
        static_cast<ani_long>(nativeMemInfoOption->sharedDirty));
    env->Object_SetPropertyByName_Long(memInfo, "privateDirty",
        static_cast<ani_long>(nativeMemInfoOption->privateDirty));
    env->Object_SetPropertyByName_Long(memInfo, "sharedClean",
        static_cast<ani_long>(nativeMemInfoOption->sharedClean));
    env->Object_SetPropertyByName_Long(memInfo, "sharedClean",
        static_cast<ani_long>(nativeMemInfoOption->sharedClean));
    env->Object_SetPropertyByName_Long(memInfo, "privateClean",
        static_cast<ani_long>(nativeMemInfoOption->privateClean));
    env->Object_SetPropertyByName_Long(memInfo, "vss", static_cast<ani_long>(nativeMemInfoOption->vss));
    return memInfo;
}

ani_object GetSystemMemInfo(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getSystemMemInfo");
    auto sysMemOption = HidebugNativeInterface::GetInstance().GetSystemMemInfo();
    if (!sysMemOption) {
        sysMemOption.emplace();
    }

    ani_class cls = nullptr;
    ani_method ctorMethod = nullptr;
    ani_object sysMemInfo = nullptr;
    if (env->FindClass("@ohos.hidebug.hidebug.SystemMemInfoAdapter", &cls) != ANI_OK ||
        env->Class_FindMethod(cls, "<ctor>", ":", &ctorMethod) != ANI_OK ||
        env->Object_New(cls, ctorMethod, &sysMemInfo) != ANI_OK) {
        return AniUtil::CreateUndefined(env);
    }
    env->Object_SetPropertyByName_Long(sysMemInfo, "totalMem", static_cast<ani_long>(sysMemOption->totalMem));
    env->Object_SetPropertyByName_Long(sysMemInfo, "freeMem", static_cast<ani_long>(sysMemOption->freeMem));
    env->Object_SetPropertyByName_Long(sysMemInfo, "availableMem", static_cast<ani_long>(sysMemOption->availableMem));
    return sysMemInfo;
}

ani_string StartAppTraceCapture(ani_env *env,
    ani_array tagsAni, ani_enum_item flagAni, ani_int limitSizeAni)
{
    ApiInvokeRecorder apiInvokeRecorder("startAppTraceCapture");
    ani_string result = nullptr;
    uint32_t traceFlag = 0;
    uint32_t limitSize = static_cast<uint32_t>(limitSizeAni);
    std::vector<uint64_t> tags;
    if (AniUtil::ParseAniEnum(env, flagAni, traceFlag) != ANI_OK || !GetTraceParam(env, tagsAni, tags)) {
        std::string paramErrorMessage = "Invalid argument";
        apiInvokeRecorder.SetErrorCode(ErrorCode::PARAMETER_ERROR);
        AniUtil::ThrowErrorMessage(env, paramErrorMessage, ErrorCode::PARAMETER_ERROR);
        return nullptr;
    }
    uint64_t tag = std::accumulate(tags.begin(), tags.end(), 0ull, [](uint64_t a, uint64_t b) { return a | b; });
    std::string file;
    auto ret = HidebugNativeInterface::GetInstance().StartAppTraceCapture(tag, traceFlag, limitSize, file);
    if (ret == TRACE_SUCCESS) {
        env->String_NewUTF8(file.c_str(), file.size(), &result);
        return result;
    }
    if (ret == TRACE_INVALID_ARGUMENT) {
        std::string errorMessage = "Invalid argument";
        apiInvokeRecorder.SetErrorCode(ErrorCode::PARAMETER_ERROR);
        AniUtil::ThrowErrorMessage(env, errorMessage, ErrorCode::PARAMETER_ERROR);
    }
    if (ret == TRACE_CAPTURED_ALREADY) {
        std::string errorMessage = "Capture trace already enabled.";
        apiInvokeRecorder.SetErrorCode(ErrorCode::HAVA_ALREADY_TRACE);
        AniUtil::ThrowErrorMessage(env, errorMessage, ErrorCode::HAVA_ALREADY_TRACE);
    }
    if (ret == TRACE_NO_PERMISSION) {
        std::string errorMessage = "No write permission on the file.";
        apiInvokeRecorder.SetErrorCode(ErrorCode::WITHOUT_WRITE_PERMISSON);
        AniUtil::ThrowErrorMessage(env, errorMessage, ErrorCode::WITHOUT_WRITE_PERMISSON);
    }
    std::string errorMessage = "Abnormal trace status.";
    apiInvokeRecorder.SetErrorCode(ErrorCode::SYSTEM_STATUS_ABNORMAL);
    AniUtil::ThrowErrorMessage(env, errorMessage, ErrorCode::SYSTEM_STATUS_ABNORMAL);
    return nullptr;
}

void StopAppTraceCapture(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("stopAppTraceCapture");
    auto ret = HidebugNativeInterface::GetInstance().StopAppTraceCapture();
    if (ret == TRACE_ABNORMAL) {
        std::string errorMessage = "The status of the trace is abnormal";
        apiInvokeRecorder.SetErrorCode(ErrorCode::SYSTEM_STATUS_ABNORMAL);
        AniUtil::ThrowErrorMessage(env, errorMessage, ErrorCode::SYSTEM_STATUS_ABNORMAL);
        return;
    }
    if (ret == NO_TRACE_RUNNING) {
        std::string errorMessage = "No capture trace running";
        apiInvokeRecorder.SetErrorCode(ErrorCode::NO_CAPTURE_TRACE_RUNNING);
        AniUtil::ThrowErrorMessage(env, errorMessage, ErrorCode::NO_CAPTURE_TRACE_RUNNING);
        return;
    }
}

ani_int GetGraphicsMemorySync(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getGraphicsMemorySync");
    std::optional<int32_t> result = HidebugNativeInterface::GetInstance().GetGraphicsMemory();
    if (result) {
        return static_cast<ani_int>(result.value());
    }
    constexpr const char* errMsg = "Failed to get the application memory due to a remote exception";
    AniUtil::ThrowErrorMessage(env, errMsg, ErrorCode::SYSTEM_STATUS_ABNORMAL);
    apiInvokeRecorder.SetErrorCode(ErrorCode::SYSTEM_STATUS_ABNORMAL);
    return 0;
}

bool GetTheOnlyStringParam(ani_env *env, ani_string filenameAni, std::string &fileName)
{
    if (AniUtil::ParseAniString(env, filenameAni, fileName) != ANI_OK) {
        HILOG_ERROR(LOG_CORE, "Failed to parse ani_string filename");
        return false;
    }
    size_t bufLen = fileName.size();
    const int bufMax = 128;
    if (bufLen > bufMax || bufLen == 0) {
        HILOG_ERROR(LOG_CORE, "input filename param length is illegal.");
        return false;
    }
    return true;
}

ani_object GetAppVMMemoryInfo(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getAppVMMemoryInfo");
    ani_class cls = nullptr;
    ani_method ctorMethod = nullptr;
    ani_object vMMemoryInfo = nullptr;
    if (env->FindClass("@ohos.hidebug.hidebug.VMMemoryInfoAdapter", &cls) != ANI_OK ||
        env->Class_FindMethod(cls, "<ctor>", ":", &ctorMethod) != ANI_OK ||
        env->Object_New(cls, ctorMethod, &vMMemoryInfo) != ANI_OK) {
        return AniUtil::CreateUndefined(env);
    }
    ani_vm* vm = AniUtil::GetAniVm(env);
    auto totalHeapValue = static_cast<int64_t>(ark::dfx::GetHeapTotalSize(vm) >> BYTE_2_KB_SHIFT_BITS);
    env->Object_SetPropertyByName_Long(vMMemoryInfo, "totalHeap", totalHeapValue);
    auto heapUsedValue = static_cast<int64_t>(ark::dfx::GetHeapUsedSize(vm) >> BYTE_2_KB_SHIFT_BITS);
    env->Object_SetPropertyByName_Long(vMMemoryInfo, "heapUsed", heapUsedValue);
    auto allArraySizeValue = static_cast<int64_t>(ark::dfx::GetArrayBufferSize(vm) >> BYTE_2_KB_SHIFT_BITS);
    env->Object_SetPropertyByName_Long(vMMemoryInfo, "allArraySize", allArraySizeValue);
    return vMMemoryInfo;
}

ani_object GetAppMemoryLimit(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getAppMemoryLimit");
    ani_class cls = nullptr;
    ani_method ctorMethod = nullptr;
    ani_object appMemoryLimit = nullptr;
    if (env->FindClass("@ohos.hidebug.hidebug.MemoryLimitAdapter", &cls) != ANI_OK ||
        env->Class_FindMethod(cls, "<ctor>", ":", &ctorMethod) != ANI_OK ||
        env->Object_New(cls, ctorMethod, &appMemoryLimit) != ANI_OK) {
        return AniUtil::CreateUndefined(env);
    }
    auto memoryLimitOption = HidebugNativeInterface::GetInstance().GetAppMemoryLimit();
    if (!memoryLimitOption) {
        memoryLimitOption.emplace();
    }
    env->Object_SetPropertyByName_Long(appMemoryLimit, "rssLimit", static_cast<ani_long>(memoryLimitOption->rssLimit));
    env->Object_SetPropertyByName_Long(appMemoryLimit, "vssLimit", static_cast<ani_long>(memoryLimitOption->vssLimit));
    ani_vm* vm = AniUtil::GetAniVm(env);
    int64_t vmHeapLimitValue = static_cast<int64_t>(ark::dfx::GetHeapLimitSize(vm) >> BYTE_2_KB_SHIFT_BITS);
    env->Object_SetPropertyByName_Long(appMemoryLimit, "vmHeapLimit", vmHeapLimitValue);
    int64_t vmTotalHeapSizeValue = static_cast<int64_t>(ark::dfx::GetProcessHeapLimitSize(vm) >> BYTE_2_KB_SHIFT_BITS);
    env->Object_SetPropertyByName_Long(appMemoryLimit, "vmTotalHeapSize", vmTotalHeapSizeValue);
    return appMemoryLimit;
}

ani_object GetVMRuntimeStats(ani_env *env)
{
    ApiInvokeRecorder apiInvokeRecorder("getVMRuntimeStats");
    ani_class cls = nullptr;
    ani_method ctorMethod = nullptr;
    ani_object vmRunTimeStats = nullptr;
    if (env->FindClass("escompat.Record", &cls) != ANI_OK ||
        env->Class_FindMethod(cls, "<ctor>", nullptr, &ctorMethod) != ANI_OK ||
        env->Object_New(cls, ctorMethod, &vmRunTimeStats, nullptr) != ANI_OK) {
        HILOG_ERROR(LOG_CORE, "failed to init record.");
        return AniUtil::CreateUndefined(env);
    }
    ani_method setMethod = nullptr;
    if (env->Class_FindMethod(cls, "$_set", nullptr, &setMethod) != ANI_OK) {
        return vmRunTimeStats;
    }
    ani_class longClass = nullptr;
    env->FindClass("std.core.Long", &longClass);
    ani_method longCtor = nullptr;
    env->Class_FindMethod(longClass, "<ctor>", "l:", &longCtor);
    auto vmGcMap = GetVmGcMap();
    ani_vm* vm = AniUtil::GetAniVm(env);
    for (const auto &[k, targetFunction] : vmGcMap) {
        ani_string aniKey = nullptr;
        if (ANI_OK != env->String_NewUTF8(k.c_str(), k.size(), &aniKey)) {
            HILOG_ERROR(LOG_CORE, "create new value string failed");
        }
        ani_object longObject = nullptr;
        env->Object_New(longClass, longCtor, &longObject, static_cast<ani_long>(targetFunction(vm)));
        env->Object_CallMethod_Void(vmRunTimeStats, setMethod, aniKey, longObject);
    }
    return vmRunTimeStats;
}

ani_long GetVMRuntimeStat(ani_env *env, ani_string itemAni)
{
    ApiInvokeRecorder apiInvokeRecorder("getVMRuntimeStat");
    std::string param;
    if (!GetTheOnlyStringParam(env, itemAni, param)) {
        std::string paramErrorMessage = "Invalid parameter, a string parameter required.";
        AniUtil::ThrowErrorMessage(env, paramErrorMessage, ErrorCode::PARAMETER_ERROR);
        apiInvokeRecorder.SetErrorCode(ErrorCode::PARAMETER_ERROR);
        return 0;
    }
    auto vmGcMap = GetVmGcMap();
    auto target = vmGcMap.find(param);
    if (target == vmGcMap.end()) {
        std::string paramErrorMessage = "Invalid parameter, unknown property.";
        AniUtil::ThrowErrorMessage(env, paramErrorMessage, ErrorCode::PARAMETER_ERROR);
        apiInvokeRecorder.SetErrorCode(ErrorCode::PARAMETER_ERROR);
        return 0;
    }
    return static_cast<ani_long>((target->second)(AniUtil::GetAniVm(env)));
}
}
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env = nullptr;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        return ANI_ERROR;
    }
    ani_namespace nameSpace = nullptr;
    if (ANI_OK != env->FindNamespace("@ohos.hidebug.hidebug", &nameSpace)) {
        return ANI_ERROR;
    }
    std::array methods = {
        ani_native_function {"getAppVMMemoryInfoAdapter", ":C{@ohos.hidebug.hidebug.VMMemoryInfoAdapter}",
            reinterpret_cast<void *>(GetAppVMMemoryInfo)},
        ani_native_function {"getMemoryLimitImplAdapter", ":C{@ohos.hidebug.hidebug.MemoryLimitImplAdapter}",
            reinterpret_cast<void *>(GetAppMemoryLimit)},
        ani_native_function {"getVMRuntimeStats", ":C{escompat.Record}", reinterpret_cast<void *>(GetVMRuntimeStats)},
        ani_native_function {"getVMRuntimeStat", "C{std.core.String}:l", reinterpret_cast<void *>(GetVMRuntimeStat)},
        ani_native_function {"getPssAdapter", ":l", reinterpret_cast<void *>(GetPss)},
        ani_native_function {"getSharedDirtyAdapter", ":l", reinterpret_cast<void *>(GetSharedDirty)},
        ani_native_function {"getPrivateDirtyAdapter", ":l", reinterpret_cast<void *>(GetPrivateDirty)},
        ani_native_function {"getCpuUsage", ":d", reinterpret_cast<void *>(GetCpuUsage)},
        ani_native_function {"getServiceDump", "iiC{escompat.Array}:", reinterpret_cast<void *>(GetServiceDump)},
        ani_native_function {"getNativeHeapSizeAdapter", ":l", reinterpret_cast<void *>(GetNativeHeapSize)},
        ani_native_function {"getNativeHeapAllocatedSizeAdapter", ":l",
            reinterpret_cast<void *>(GetNativeHeapAllocatedSize)},
        ani_native_function {"getNativeHeapFreeSizeAdapter", ":l",
            reinterpret_cast<void *>(GetNativeHeapFreeSize)},
        ani_native_function {"getVssAdapter", ":l", reinterpret_cast<void *>(GetVss)},
        ani_native_function {"getAppThreadCpuUsage", ":C{escompat.Array}",
            reinterpret_cast<void *>(GetAppThreadCpuUsage)},
        ani_native_function {"getSystemCpuUsage", ":d", reinterpret_cast<void *>(GetSystemCpuUsage)},
        ani_native_function {"getAppNativeMemInfoAdapter", ":C{@ohos.hidebug.hidebug.NativeMemInfoAdapter}",
            reinterpret_cast<void *>(GetAppNativeMemInfo)},
        ani_native_function {"getSystemMemInfoAdapter", ":C{@ohos.hidebug.hidebug.SystemMemInfoAdapter}",
            reinterpret_cast<void *>(GetSystemMemInfo)},
        ani_native_function {"startAppTraceCapture",
            "C{escompat.Array}C{@ohos.hidebug.hidebug.TraceFlag}i:C{std.core.String}",
            reinterpret_cast<void *>(StartAppTraceCapture)},
        ani_native_function {"stopAppTraceCapture", ":", reinterpret_cast<void *>(StopAppTraceCapture)},
        ani_native_function {"getGraphicsMemorySync", ":i", reinterpret_cast<void *>(GetGraphicsMemorySync)},
    };
    auto retCode = env->Namespace_BindNativeFunctions(nameSpace, methods.data(), methods.size());
    if (ANI_OK != retCode) {
        return retCode;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}
