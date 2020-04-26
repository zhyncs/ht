// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#pragma once

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "crypto.h"
#include "dns_resolve.h"
#include "event_loop.h"
#include "socket.h"

class TCPRelayHandler;

class TCPRelay : public LoopObserver {
  friend class TCPRelayHandler;

 public:
  TCPRelay() = default;
  TCPRelay(const std::shared_ptr<DNSResolve>& dns_resolver, const char* password);
  TCPRelay(const TCPRelay& relay) = delete;
  TCPRelay& operator=(const TCPRelay& relay) = delete;
  ~TCPRelay() override;
  void add_to_loop(const std::shared_ptr<EventLoop>& loop);
  void remove_handler(TCPRelayHandler* handler);
  void handle_periodic() override;
  bool handle_event(int socket_fd, unsigned int events) override;
  void update_activity(TCPRelayHandler* handler);

 private:
  std::shared_ptr<DNSResolve> dns_resolve_;
  std::shared_ptr<EventLoop> event_loop_;
  Socket server_sock_;
  size_t timeout_offset_ = 0;
  std::vector<TCPRelayHandler*> timeouts_;
  std::unordered_map<TCPRelayHandler*, size_t> handler_to_timeouts_;
  std::unordered_map<int, std::shared_ptr<TCPRelayHandler>> fd_to_handlers_;
  std::string password_;

  void destroy();
  void sweep_timeout();
};
