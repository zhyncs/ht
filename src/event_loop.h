// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#pragma once

#include <sys/epoll.h>

#include <array>
#include <memory>
#include <unordered_map>
#include <vector>

#define MAX_EVENTS 2048

class LoopObserver {
 public:
  LoopObserver() = default;
  LoopObserver(const LoopObserver&) = delete;
  LoopObserver& operator=(const LoopObserver&) = delete;
  virtual ~LoopObserver() = default;

  virtual bool handle_event(int fd, unsigned int events) = 0;
  virtual void handle_periodic() = 0;
};

class EventLoop {
 public:
  EventLoop();
  EventLoop(const EventLoop&) = delete;
  EventLoop& operator=(const EventLoop&) = delete;
  ~EventLoop();

  bool poll(int timeout = 0);
  bool run();

  bool add(int fd, unsigned int events, LoopObserver* base);
  bool del(int fd);
  bool mod(int fd, unsigned int events) const;

  void add_periodic(LoopObserver* periodic);
  void del_periodic(LoopObserver* periodic);

 private:
  time_t last_time_ = 0;

  int epoll_fd_ = -1;
  int fired_num_ = -1;
  std::array<struct epoll_event, MAX_EVENTS> events_{};
  std::vector<LoopObserver*> periodics_;
  std::unordered_map<int, LoopObserver*> fd_to_observer_;

  void destroy();
};
