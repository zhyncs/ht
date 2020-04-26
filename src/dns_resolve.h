// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "cache.h"
#include "event_loop.h"
#include "socket.h"

class DNSResolveHandler {
 public:
  DNSResolveHandler() = default;
  DNSResolveHandler(const DNSResolveHandler&) = delete;
  DNSResolveHandler& operator=(const DNSResolveHandler&) = delete;
  virtual ~DNSResolveHandler() = default;

  virtual bool handle_dns_resolved(const std::string& hostname, const std::string& ip,
                                   const std::string& error) = 0;
};

struct Record;
struct DNSResponse;

class DNSResolve : public LoopObserver {
 public:
  DNSResolve();
  DNSResolve(const DNSResolve&) = delete;
  DNSResolve& operator=(const DNSResolve&) = delete;
  ~DNSResolve() override;

  bool handle_event(int fd, unsigned int events) override;
  void handle_periodic() override;

  bool add_to_loop(const std::shared_ptr<EventLoop>& loop);
  void remove_handler(DNSResolveHandler* handler);
  bool resolve(const std::string& hostname, DNSResolveHandler* handler);

 private:
  Socket sock_;
  Cache cache_;
  std::shared_ptr<EventLoop> loop_;
  std::unordered_map<std::string, std::vector<DNSResolveHandler*>> hostname_to_handlers_;
  std::unordered_map<DNSResolveHandler*, std::string> handler_to_hostname_;

  void call_handler(const std::string& hostname, const std::string& ip = "",
                    const std::string& error = "");
  void handle_data(const std::vector<unsigned char>& data);
  bool send_req(const std::string& hostname);
  void destroy();

  static std::string strip(const std::string& str);
  static std::vector<std::string> split(const std::string& str, char separator);
  static bool build_address(const std::string& address, std::vector<unsigned char>* res);
  static bool build_request(const std::string& address, std::vector<unsigned char>* request);
  static void copy_val_to_vec(uint16_t val, std::vector<unsigned char>* vec, size_t pos);
  static bool is_valid_hostname(const std::string& hostname);
  static int is_ip(const std::string& addr);
  static uint16_t random_id();
  static std::pair<size_t, std::string> parse_name(const std::vector<unsigned char>& data,
                                                   size_t offset);
  static std::string parse_ip(const std::vector<unsigned char>& data, uint16_t addr_type,
                              size_t offset);
  static void parse_record(const std::vector<unsigned char>& data, size_t offset, Record* res,
                           bool question);
  static DNSResponse parse_response(const std::vector<unsigned char>& data);
};
