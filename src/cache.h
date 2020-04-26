// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#pragma once

#include <ctime>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

class Cache {
 public:
  explicit Cache(time_t timeout = 300);
  Cache(const Cache&) = delete;
  Cache& operator=(const Cache&) = delete;
  ~Cache() = default;

  bool contains(const std::string& key) const;
  std::string get(const std::string& domain);
  void set(const std::string& domain, const std::string& ip);
  void sweep();

 private:
  time_t timeout_ = 0;
  std::deque<time_t> last_visit_;
  std::unordered_map<time_t, std::vector<std::string>> time_to_domains_;
  std::unordered_map<std::string, std::string> domain_to_ip_;
  std::unordered_map<std::string, time_t> domain_to_last_time_;
};
