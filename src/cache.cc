// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#include "cache.h"

Cache::Cache(time_t timeout) : timeout_(timeout) {}

bool Cache::contains(const std::string& key) const {
  return domain_to_ip_.find(key) != domain_to_ip_.end();
}

std::string Cache::get(const std::string& domain) {
  time_t now = time(nullptr);
  domain_to_last_time_[domain] = now;
  time_to_domains_[now].emplace_back(domain);
  last_visit_.emplace_back(now);
  return domain_to_ip_[domain];
}

void Cache::set(const std::string& domain, const std::string& ip) {
  time_t now = time(nullptr);
  domain_to_last_time_[domain] = now;
  domain_to_ip_[domain] = ip;
  time_to_domains_[now].emplace_back(domain);
  last_visit_.emplace_back(now);
}

void Cache::sweep() {
  time_t now = time(nullptr);
  while (!last_visit_.empty()) {
    auto least = last_visit_.front();
    if (now - least < timeout_) {
      break;
    }
    last_visit_.pop_front();
    for (const auto& domain : time_to_domains_[least]) {
      if (domain_to_ip_.find(domain) != domain_to_ip_.end()) {
        if (now - domain_to_last_time_[domain] >= timeout_) {
          domain_to_ip_.erase(domain);
          domain_to_last_time_.erase(domain);
        }
      }
    }
    time_to_domains_.erase(least);
  }
}
