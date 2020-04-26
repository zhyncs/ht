// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#include "event_loop.h"

#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>

#define TIMEOUT_PRECISION 10000

EventLoop::EventLoop() {
  last_time_ = time(nullptr);
  epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
  if (epoll_fd_ < 0) {
    exit(EXIT_FAILURE);
  }
}

EventLoop::~EventLoop() { destroy(); }

bool EventLoop::poll(const int timeout) {
  fired_num_ = epoll_wait(epoll_fd_, events_.data(), MAX_EVENTS, timeout);
  if (fired_num_ < 0) {
    return false;
  }
  return true;
}

bool EventLoop::add(int fd, unsigned int events, LoopObserver* base) {
  if (fd_to_observer_.find(fd) != fd_to_observer_.end()) {
    return false;
  }
  fd_to_observer_[fd] = base;
  struct epoll_event event;
  memset(&event, 0, sizeof(struct epoll_event));
  event.data.fd = fd;
  event.events = events;
  if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &event) < 0) {
    return false;
  }

  return true;
}

bool EventLoop::del(int fd) {
  auto it = fd_to_observer_.find(fd);
  if (it == fd_to_observer_.end()) {
    return false;
  }
  fd_to_observer_.erase(it);
  if (epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr) < 0) {
    return false;
  }

  return true;
}

void EventLoop::add_periodic(LoopObserver* periodic) { periodics_.emplace_back(periodic); }

void EventLoop::del_periodic(LoopObserver* periodic) {
  periodics_.erase(std::remove(periodics_.begin(), periodics_.end(), periodic), periodics_.end());
}

bool EventLoop::mod(int fd, unsigned int events) const {
  struct epoll_event event;
  memset(&event, 0, sizeof(struct epoll_event));
  event.data.fd = fd;
  event.events = events;
  if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &event) < 0) {
    return false;
  }

  return true;
}

bool EventLoop::run() {
  while (true) {
    bool asap = false;
    if (!poll(TIMEOUT_PRECISION)) {
      if (errno == EINTR) {
        asap = true;
      } else {
        exit(EXIT_FAILURE);
      }
    }
    for (size_t i = 0; i < fired_num_; ++i) {
      auto it = fd_to_observer_.find(events_[i].data.fd);
      if (it != fd_to_observer_.end()) {
        if (!it->second->handle_event(events_[i].data.fd, events_[i].events)) {
          if (errno == EINTR) {
            asap = true;
          } else {
            exit(EXIT_FAILURE);
          }
        }
      }
    }
    auto now = time(nullptr);
    if (asap || now - last_time_ >= TIMEOUT_PRECISION / 1000) {
      for (auto& periodic : periodics_) {
        periodic->handle_periodic();
      }
      last_time_ = now;
    }
  }
}

void EventLoop::destroy() {
  if (epoll_fd_ > 0) {
    close(epoll_fd_);
    epoll_fd_ = -1;
  }
}
