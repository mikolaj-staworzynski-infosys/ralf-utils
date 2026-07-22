/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 Comcast Cable Communications Management, LLC
 *
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

#include "Logging.h"
#include "LogMacros.h"

#if defined(EMSCRIPTEN)
#    include <emscripten/console.h>
#else
#    include <sys/uio.h>
#    include <unistd.h>
#endif

#include <algorithm>
#include <cstdarg>
#include <cstring>
#include <map>

#if defined(LIBRALF_NS)
using namespace LIBRALF_NS;
#endif

#if defined(__FILE_NAME__)
#    define GET_FILENAME(path) (path)
#else
#    if defined(WIN32) || defined(_WIN32)
#        define GET_FILENAME(path) (strrchr(path, '\\') ? strrchr(path, '\\') + 1 : path)
#    else
#        define GET_FILENAME(path) (strrchr(path, '/') ? strrchr(path, '/') + 1 : path)
#    endif
#endif

#if defined(EMSCRIPTEN)

static void logMessage(LogPriority priority, const LogContext &context, const char *message, size_t messageLene)
{
    switch (priority)
    {
        case LogPriority::Debug:
            emscripten_dbg(message);
            break;
        case LogPriority::Info:
            emscripten_console_log(message);
            break;
        case LogPriority::Warning:
            emscripten_console_warn(message);
            break;
        case LogPriority::Error:
        case LogPriority::Fatal:
            emscripten_console_error(message);
            break;
    }
}

LogHandler LIBRALF_NS::emscriptenLogHandler = logMessage;

#else

static void logMessage(LogPriority priority, const LogContext &context, const char *message, size_t messageLen)
{
    int outFd;
    struct iovec iov[3];

    switch (priority)
    {
        case LogPriority::Debug:
            outFd = STDOUT_FILENO;
            iov[0].iov_base = (void *)"Debug: ";
            iov[0].iov_len = 7;
            break;
        case LogPriority::Info:
            outFd = STDOUT_FILENO;
            iov[0].iov_base = (void *)"Info: ";
            iov[0].iov_len = 6;
            break;
        case LogPriority::Warning:
            outFd = STDERR_FILENO;
            iov[0].iov_base = (void *)"Warning: ";
            iov[0].iov_len = 9;
            break;
        case LogPriority::Error:
            outFd = STDERR_FILENO;
            iov[0].iov_base = (void *)"Error: ";
            iov[0].iov_len = 7;
            break;
        case LogPriority::Fatal:
            outFd = STDERR_FILENO;
            iov[0].iov_base = (void *)"Fatal: ";
            iov[0].iov_len = 7;
            break;
    }

    iov[1].iov_base = const_cast<char *>(message);
    iov[1].iov_len = messageLen;

    iov[2].iov_base = (void *)"\n";
    iov[2].iov_len = 1;

    writev(outFd, iov, 3);
}

LogHandler LIBRALF_NS::stdoutLogHandler = logMessage;

#endif

///< The functor to call for handling log messages
static LogHandler g_logHandler =
#if defined(EMSCRIPTEN)
    emscriptenLogHandler;
#else
    stdoutLogHandler;
#endif

void LIBRALF_NS::setLogHandler(LogHandler handler)
{
    g_logHandler = std::move(handler);
}

///< Stores the default minimum log priority
//static LogPriority g_defaultMinLogPrio = LogPriority::Warning;
static LogPriority g_defaultMinLogPrio = LogPriority::Info;

///< Stores the log priority for individual log tags
static std::map<std::string, LogPriority> g_tagMinLogPrio = {};

void LIBRALF_NS::setLogLevel(const char *tag, LogPriority minLogPriority)
{
    if (!tag)
    {
        g_defaultMinLogPrio = minLogPriority;
        g_tagMinLogPrio.clear();
    }
    else
    {
        g_tagMinLogPrio[tag] = minLogPriority;
    }
}

// -------------------------------------------------------------------------
/*!
    \internal

    Returns \c true if the message should be logged given the log \a tag and
    the message \a priority.

 */
static bool shouldLog(LogPriority priority, const char *tag)
{
    if (tag)
    {
        const auto it = g_tagMinLogPrio.find(tag);
        if (it != g_tagMinLogPrio.end())
            return (priority >= it->second);
    }

    return (priority >= g_defaultMinLogPrio);
}

// -------------------------------------------------------------------------
/*!


 */
void vlogPrint(LogPriority priority, const char *tag, const char *file, int line, const char *function,
               const char *format, va_list args)
{
    if (!g_logHandler)
        return;
    if (!shouldLog(priority, tag))
        return;

    char message[1024];
    int len = vsnprintf(message, sizeof(message), format, args);

    g_logHandler(priority, LogContext(tag, GET_FILENAME(file), line, function), message,
                 std::min<int>(len, (sizeof(message) - 1)));
}

// -------------------------------------------------------------------------
/*!


 */
void logPrint(LogPriority priority, const char *tag, const char *file, int line, const char *function,
              const char *format, ...)
{
    std::va_list args;
    va_start(args, format);
    vlogPrint(priority, tag, file, line, function, format, args);
    va_end(args);
}

// -------------------------------------------------------------------------
/*!


 */
void logSysPrint(LogPriority priority, const char *tag, const char *file, int line, const char *function, int error,
                 const char *format, ...)
{
    char message[1024];
    int len;

    std::va_list args;
    va_start(args, format);
    len = vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    if (len < static_cast<int>(sizeof(message)))
    {
        int n = snprintf(message + len, sizeof(message) - len, " (%d - %s)", error, strerror(error));
        if (n > 0)
            len += n;
    }

    if (g_logHandler)
    {
        g_logHandler(priority, LogContext(tag, GET_FILENAME(file), line, function), message,
                     std::min<int>(len, (sizeof(message) - 1)));
    }
}

// -------------------------------------------------------------------------
/*!


 */
void logSysPrint(LogPriority priority, const char *tag, const char *file, int line, const char *function,
                 std::error_code error, const char *format, ...)
{
    char message[1024];
    int len;

    std::va_list args;
    va_start(args, format);
    len = vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    if (len < static_cast<int>(sizeof(message)))
    {
        int n = snprintf(message + len, sizeof(message) - len, " (%d - %s)", error.value(), error.message().c_str());
        if (n > 0)
            len += n;
    }

    if (g_logHandler)
    {
        g_logHandler(priority, LogContext(tag, GET_FILENAME(file), line, function), message,
                     std::min<int>(len, (sizeof(message) - 1)));
    }
}
