/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ani_util.h"
#include "hilog/log.h"

namespace OHOS {
namespace HiviewDFX {
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002D0A
#undef LOG_TAG
#define LOG_TAG "HiDebug_ANI_UTIL"

void AniUtil::ThrowErrorMessage(ani_env *env, const std::string &msg, int32_t errCode)
{
    ani_module hiDebugModule = nullptr;
    if (env->FindModule("@ohos.hidebug", &hiDebugModule) != ANI_OK) {
        return;
    }
    ani_function createErrorFn = nullptr;
    if (env->Module_FindFunction(hiDebugModule, "createVoidBusinessError",
        "iC{std.core.String}:C{@ohos.base.BusinessError}", &createErrorFn) != ANI_OK) {
        return;
    }
    ani_int errCodeAni = static_cast<ani_int>(errCode);
    ani_string msgAni = nullptr;
    if (ANI_OK != env->String_NewUTF8(msg.c_str(), msg.size(), &msgAni)) {
        return;
    }
    ani_ref errRef = nullptr;
    if (env->Function_Call_Ref(createErrorFn, &errRef, errCodeAni, msgAni) != ANI_OK) {
        return;
    }
    env->ThrowError(static_cast<ani_error>(errRef));
}

ani_object AniUtil::CreateUndefined(ani_env *env)
{
    ani_ref undefinedRef = nullptr;
    if (env->GetUndefined(&undefinedRef) != ANI_OK) {
        return nullptr;
    }
    return static_cast<ani_object>(undefinedRef);
}

ani_status AniUtil::ParseAniString(ani_env *env, ani_string aniStr, std::string &str)
{
    ani_size srcSize = 0;
    ani_status status = env->String_GetUTF8Size(aniStr, &srcSize);
    if (status != ANI_OK) {
        return status;
    }
    std::vector<char> buffer(srcSize + 1);
    ani_size dstSize = 0;
    status = env->String_GetUTF8SubString(aniStr, 0, srcSize, buffer.data(), buffer.size(), &dstSize);
    if (status != ANI_OK || srcSize != dstSize) {
        return status;
    }
    str.assign(buffer.data(), dstSize);
    return ANI_OK;
}

ani_status AniUtil::ParseAniEnum(ani_env *env, ani_enum_item enumItem, uint32_t &value)
{
    ani_int aniInt = 0;
    ani_status status = env->EnumItem_GetValue_Int(enumItem, &aniInt);
    if (status != ANI_OK) {
        return status;
    }
    value = static_cast<uint32_t>(aniInt);
    return ANI_OK;
}

ani_status AniUtil::SetNamedPropertyNumber(ani_env *env, ani_object object, const std::string& name, double value)
{
    ani_double aniNumber = static_cast<ani_double>(value);
    ani_status status = env->Object_SetPropertyByName_Double(object, name.c_str(), aniNumber);
    return status;
}

ani_vm* AniUtil::GetAniVm(ani_env *env)
{
    ani_vm* vm = nullptr;
    auto status = env->GetVM(&vm);
    if (status != ANI_OK) {
        HILOG_ERROR(LOG_CORE, "Failed get vm for %{public}d.", status);
    }
    return vm;
}
} // namespace HiviewDFX
} // namespace OHOS
