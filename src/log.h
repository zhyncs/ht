// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#pragma once

#include <openssl/err.h>
#include <sys/time.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>

#define INFO(fmt, ...)                                                                   \
  do {                                                                                   \
    struct timeval tv;                                                                   \
    memset(&tv, 0, sizeof(timeval));                                                     \
    gettimeofday(&tv, nullptr);                                                          \
    struct tm now_time;                                                                  \
    memset(&now_time, 0, sizeof(tm));                                                    \
    localtime_r(&tv.tv_sec, &now_time);                                                  \
    printf(                                                                              \
        "%02d%02d %s.%.04ld "                                                            \
        "%s:%d %s " fmt "\n",                                                            \
        now_time.tm_mon + 1, now_time.tm_mday, __TIME__, tv.tv_usec, __FILE__, __LINE__, \
        "\033[92mINFO\033[0m", ##__VA_ARGS__);                                           \
  } while (0)

#define ERROR(fmt, ...)                                                                      \
  do {                                                                                       \
    struct timeval tv;                                                                       \
    memset(&tv, 0, sizeof(timeval));                                                         \
    gettimeofday(&tv, nullptr);                                                              \
    struct tm now_time;                                                                      \
    memset(&now_time, 0, sizeof(tm));                                                        \
    localtime_r(&tv.tv_sec, &now_time);                                                      \
    fprintf(stderr,                                                                          \
            "%02d%02d %s.%.04ld "                                                            \
            "%s:%d %s " fmt "\n",                                                            \
            now_time.tm_mon + 1, now_time.tm_mday, __TIME__, tv.tv_usec, __FILE__, __LINE__, \
            "\033[91mERROR\033[0m", ##__VA_ARGS__);                                          \
  } while (0)

#define SysERR(fmt, ...)                                                                     \
  do {                                                                                       \
    struct timeval tv;                                                                       \
    memset(&tv, 0, sizeof(timeval));                                                         \
    gettimeofday(&tv, nullptr);                                                              \
    struct tm now_time;                                                                      \
    memset(&now_time, 0, sizeof(tm));                                                        \
    localtime_r(&tv.tv_sec, &now_time);                                                      \
    fprintf(stderr,                                                                          \
            "%02d%02d %s.%.04ld "                                                            \
            "%s:%d %s " fmt " %s\n",                                                         \
            now_time.tm_mon + 1, now_time.tm_mday, __TIME__, tv.tv_usec, __FILE__, __LINE__, \
            "\033[91mERROR\033[0m", ##__VA_ARGS__, strerror(errno));                         \
  } while (0)

#define EvpERR(fmt, ...)                                                                     \
  do {                                                                                       \
    struct timeval tv;                                                                       \
    memset(&tv, 0, sizeof(timeval));                                                         \
    gettimeofday(&tv, nullptr);                                                              \
    struct tm now_time;                                                                      \
    memset(&now_time, 0, sizeof(tm));                                                        \
    localtime_r(&tv.tv_sec, &now_time);                                                      \
    fprintf(stderr,                                                                          \
            "%02d%02d %s.%.04ld "                                                            \
            "%s:%d %s " fmt " %s\n",                                                         \
            now_time.tm_mon + 1, now_time.tm_mday, __TIME__, tv.tv_usec, __FILE__, __LINE__, \
            "\033[91mERROR\033[0m", ##__VA_ARGS__,                                           \
            ERR_error_string(ERR_peek_last_error(), nullptr));                               \
  } while (0)
