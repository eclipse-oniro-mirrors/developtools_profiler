/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "hisysevent_plugin.h"

#include <fcntl.h>
#include <cinttypes>
#include <csignal>
#include <sstream>
#include <cstdio>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
    constexpr int PIPE_LEN = 2;

    constexpr int READ = 0;
    constexpr int WRITE = 1;
    static pid_t volatile g_child;

    constexpr int MAX_STRING_LEN = 256 * 1024;
    constexpr int MIN_STRING_LEN = 10;
    constexpr int BYTE_BUFFER_SIZE = 1024;

    std::atomic<uint64_t> g_id(1);
}

HisyseventPlugin::HisyseventPlugin():fp_(nullptr, nullptr) {}

HisyseventPlugin::~HisyseventPlugin()
{
    HILOG_INFO(LOG_CORE, "BEGN %s: ready!", __func__);
    std::unique_lock<std::mutex> locker(mutex_);

    if (running_) {
        running_ = false;
        if (workThread_.joinable()) {
            workThread_.join();
        }
    }

    locker.unlock();

    if (fp_ != nullptr) {
        fp_.reset();
    }

    HILOG_INFO(LOG_CORE, "END %s: success!", __func__);
}

int HisyseventPlugin::SetWriter(WriterStruct* writer)
{
    resultWriter_ = writer;

    HILOG_INFO(LOG_CORE, "END %s: success!", __func__);
    return 0;
}

int HisyseventPlugin::Start(const uint8_t* configData, uint32_t configSize)
{
    HILOG_INFO(LOG_CORE, "BEGN %s: ready!", __func__);
    if (configData == nullptr || configSize <= 0) {
        HILOG_ERROR(LOG_CORE, "NOTE %s: param invalid", __func__);
        return -1;
    }

    if (protoConfig_.ParseFromArray(configData, configSize) <= 0) {
        HILOG_ERROR(LOG_CORE, "NOTE HisyseventPlugin: ParseFromArray failed");
        return -1;
    }

    HILOG_DEBUG(LOG_CORE, "NOTE configData ParseFromArray sucessed,sourse data:%s", protoConfig_.msg().c_str());

    if (!InitHisyseventCmd()) {
        HILOG_ERROR(LOG_CORE, "TODO HisyseventPlugin: Init HisyseventCmd failed");
        return -1;
    }

    fp_ = std::unique_ptr<FILE, int (*)(FILE*)>(CustomPopen(&fullCmd_[0], "r"), CustomPclose);
    CHECK_NOTNULL(fp_.get(), -1, "HisyseventPlugin: fullCmd_ Failed, errno(%d)", errno);
    CHECK_NOTNULL(resultWriter_, -1, "HisyseventPlugin: Writer is no set!!");
    CHECK_NOTNULL(resultWriter_->write, -1, "HisyseventPlugin: Writer.write is no set!!");
    CHECK_NOTNULL(resultWriter_->flush, -1, "HisyseventPlugin: Writer.flush is no set!!");

    g_id = 1;
    std::unique_lock<std::mutex> locker(mutex_);
    running_ = true;
    workThread_ = std::thread(&HisyseventPlugin::Run, this);

    HILOG_INFO(LOG_CORE, "END %s: success!", __func__);
    return 0;
}

int HisyseventPlugin::Stop()
{
    HILOG_INFO(LOG_CORE, "BEGN %s: ready!", __func__);
    std::unique_lock<std::mutex> locker(mutex_);
    running_ = false;
    locker.unlock();
    if (workThread_.joinable()) {
        workThread_.join();
    }
    HILOG_INFO(LOG_CORE, "HisyseventPlugin: stop thread success!");

    fp_.reset();

    HILOG_INFO(LOG_CORE, "END %s: success!", __func__);
    return 0;
}

void HisyseventPlugin::Run(void)
{
    HILOG_INFO(LOG_CORE, "BEGN %s: ready!", __func__);
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(MAX_STRING_LEN);

    if (buffer == nullptr) {
        return;
    }

    HILOG_DEBUG(LOG_CORE, "NOTE hisysevent_plugin_result.proto->HisyseventInfo:dataProto;Ready to output the result!");
    HisyseventInfo dataProto;
    fcntl(fileno(fp_.get()), F_SETFL, O_NONBLOCK);

    while (running_) {
        if (fgets(reinterpret_cast<char*>(buffer.get()), MAX_STRING_LEN, fp_.get()) != nullptr) {
            auto cptr = reinterpret_cast<char*>(buffer.get());
            if (!ParseSyseventLineInfo(cptr, strlen(cptr), dataProto))
                continue;
        }

        if (dataProto.ByteSizeLong() >= BYTE_BUFFER_SIZE) {
            // Cmd result resize and SerializeToArray and after save to protoBuffer_ ;write and flush;clear_info
            protoBuffer_.resize(dataProto.ByteSizeLong());
            dataProto.SerializeToArray(protoBuffer_.data(), protoBuffer_.size());

            // SerializeToArray after data=%s",protoBuffer_.data()
            resultWriter_->write(resultWriter_, protoBuffer_.data(), protoBuffer_.size());
            resultWriter_->flush(resultWriter_);
            dataProto.clear_info();
        }
    }

    protoBuffer_.resize(dataProto.ByteSizeLong());
    dataProto.SerializeToArray(protoBuffer_.data(), protoBuffer_.size());
    resultWriter_->write(resultWriter_, protoBuffer_.data(), protoBuffer_.size());
    resultWriter_->flush(resultWriter_);
    dataProto.clear_info();

    HILOG_INFO(LOG_CORE, "END %s: success!", __func__);
}

inline bool HisyseventPlugin::ParseSyseventLineInfo(const char* data, size_t len, HisyseventInfo& dataProto)
{
    if (data == nullptr || len < MIN_STRING_LEN) {
        HILOG_ERROR(LOG_CORE, "NOTE %s: param invalid", __func__);
        return false;
    }

    if (google::protobuf::internal::IsStructurallyValidUTF8(data, strlen(data) - 1)) {
        auto* info = dataProto.add_info();
        info->set_id(g_id);
        info->set_context(data, strlen(data) - 1);  // - \n
        g_id++;
    } else {
        HILOG_ERROR(LOG_CORE, "NOTE HisyseventPlugin: hisysevent context include invalid UTF-8 data");
        return false;
    }

    return true;
}

inline bool HisyseventPlugin::InitHisyseventCmd()
{
    HILOG_INFO(LOG_CORE, "BEGN %s: ready!", __func__);
    if (fullCmd_.size() > 0) {
        HILOG_INFO(LOG_CORE, "fullCmd_ is dirty.Clear().");
        fullCmd_.clear();
    }

    fullCmd_.push_back(const_cast<char *>("hisysevent"));
    fullCmd_.push_back(const_cast<char *>("-rd"));
    fullCmd_.push_back(nullptr);

    HILOG_INFO(LOG_CORE, "END %s: success!", __func__);
    return true;
}

std::string HisyseventPlugin::GetCmdline()
{
    std::string cmdline;
    for (size_t i = 0; i < fullCmd_.size() - 1 ; i++)
        cmdline.append(fullCmd_[i]).append(" ");

    HILOG_INFO(LOG_CORE, "END %s: success!", __func__);
    return cmdline;
}

FILE* HisyseventPlugin::CustomPopen(char* const command[], const char* type)
{
    HILOG_INFO(LOG_CORE, "BEGN %s: ready!", __func__);
    if (command == nullptr || type == nullptr) {
        HILOG_ERROR(LOG_CORE, "HisyseventPlugin:%s param invalid", __func__);
        return nullptr;
    }

    int fd[PIPE_LEN];
    pipe(fd);

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        if (!strncmp(type, "r", strlen(type))) {
            close(fd[READ]);
            dup2(fd[WRITE], 1); // Redirect stdout to pipe
            dup2(fd[WRITE], 2); // 2: Redirect stderr to pipe
        } else {
            close(fd[WRITE]);
            dup2(fd[READ], 0); // Redirect stdin to pipe
        }
        setpgid(pid, pid);
        execvp("hisysevent", &command[0]);
        exit(0);
    } else {
        if (!strncmp(type, "r", strlen(type))) {
            // Close the WRITE end of the pipe since parent's fd is read-only
            close(fd[WRITE]);
        } else {
            // Close the READ end of the pipe since parent's fd is write-only
            close(fd[READ]);
        }
    }

    g_child = pid;

    if (!strncmp(type, "r", strlen(type))) {
        return fdopen(fd[READ], "r");
    }

    HILOG_INFO(LOG_CORE, "END %s: success!", __func__);
    return fdopen(fd[WRITE], "w");
}

int HisyseventPlugin::CustomPclose(FILE* fp)
{
    HILOG_INFO(LOG_CORE, "BEGN %s: ready!", __func__);
    CHECK_NOTNULL(fp, -1, "NOTE %s: fp is null", __func__);

    int stat = 0;
    int ret = fclose(fp);
    CHECK_TRUE(ret == 0, -1, "NOTE %s: fclose failed! errno(%d)", __func__, errno);
    kill(g_child, SIGKILL);
    if (waitpid(g_child, &stat, 0) == -1) {
        if (errno != EINTR) {
            return stat;
        }
    }

    HILOG_INFO(LOG_CORE, "END %s: success!", __func__);
    return stat;
}
