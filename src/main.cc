// Copyright (c) 2020 Yineng Zhang <me@zhyncs.com>

#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <memory>

#include "dns_resolve.h"
#include "log.h"
#include "tcp_relay.h"

bool run_server(const char* password);

int main(int argc, char** argv) {
  printf("Version=%s\nUsage: ht -k <password>\n", BUILD_VERSION);
  if (argc != 3) {
    exit(EXIT_FAILURE);
  }
  int opt = getopt(argc, argv, "k:");
  while (opt != -1) {
    switch (opt) {
      case 'k': {
        run_server(optarg);
        break;
      }
      default:
        return -1;
    }
    opt = getopt(argc, argv, "k:");
  }
  return 0;
}

bool run_server(const char* password) {
  INFO("Start server at 0.0.0.0:443");

  auto dns_resolve = std::make_shared<DNSResolve>();
  auto tcp_relay = std::make_shared<TCPRelay>(dns_resolve, password);

  auto server = [&]() {
    auto sig_handler = [](int signum) {
      ERROR("Received signal=%d", signum);
      exit(EXIT_FAILURE);
    };
    struct sigaction sig_action;
    memset(&sig_action, 0, sizeof(struct sigaction));
    sig_action.sa_handler = sig_handler;
    if (sigaction(SIGTERM, &sig_action, nullptr) < 0) {
      ERROR("Fail to handle SIGTERM");
      exit(EXIT_FAILURE);
    }
    if (sigaction(SIGINT, &sig_action, nullptr) < 0) {
      ERROR("Fail to handle SIGINT");
      exit(EXIT_FAILURE);
    }

    auto loop = std::make_shared<EventLoop>();
    dns_resolve->add_to_loop(loop);
    tcp_relay->add_to_loop(loop);
    if (!loop->run()) {
      exit(EXIT_FAILURE);
    }
  };

  server();

  return true;
}
