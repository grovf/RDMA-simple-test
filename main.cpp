#include <arpa/inet.h>
#include <cstdint>
#include <iostream>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <infiniband/verbs.h>

#include "external/popl.hpp"

#define COUNT 16
#define MEM_SIZE COUNT *COUNT

struct TestParameters {
  bool is_initiator;
  std::string dev_name;
  std::uint16_t ib_port;
  std::uint16_t gid;
  std::string local_ip;
  std::string remote_ip;
  std::uint16_t tcp_port;
  std::uint16_t mtu;
};

struct ExchangeInfo {
  std::uint32_t qpn;
  int psn;
  std::uint8_t gid_raw[16];
};

int ip_version(const std::string &server_ip) {
  char buf[16];

  if (inet_pton(AF_INET, server_ip.c_str(), buf))
    return AF_INET;

  if (inet_pton(AF_INET6, server_ip.c_str(), buf))
    return AF_INET6;

  return -EINVAL;
}

static void socket_server_ipv4(int &server_sock, int &sock,
                               const uint16_t &port) {
  sockaddr_in serv_addr{};

  bzero((char *)&serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(port);

  server_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (server_sock < 0) {
    close(server_sock);
    throw std::runtime_error("Error establishing the server socket");
  }

  int enable = 1;
  if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) <
      0)
    throw std::runtime_error("setsockopt(SO_REUSEADDR) failed");

  if (bind(server_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    close(server_sock);
    throw std::runtime_error("Error binding socket to local address");
  }

  listen(server_sock, 1);
  sockaddr_in new_sock_addr{};
  socklen_t new_sock_addr_size = sizeof(new_sock_addr);
  sock = accept(server_sock, (sockaddr *)&new_sock_addr, &new_sock_addr_size);
  if (sock < 0) {
    close(server_sock);
    throw std::runtime_error("Error accepting request from client!");
  }
}

static void socket_server_ipv6(int &server_sock, int &sock,
                               const uint16_t &port) {
  int ret, flag;
  sockaddr_in6 server_addr{}, client_addr{};
  socklen_t client_addr_len;

  server_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if (server_sock < 0)
    throw std::runtime_error("Error establishing the server socket");

  flag = 1;
  if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) <
      0)
    throw std::runtime_error("Error setting socket option!");

  server_addr.sin6_family = AF_INET6;
  server_addr.sin6_addr = in6addr_any;
  server_addr.sin6_port = htons(port);

  if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    close(server_sock);
    throw std::runtime_error("Error binding socket to local address");
  }

  if (listen(server_sock, 1) < 0) {
    close(server_sock);
    throw std::runtime_error("Socket listening error!");
  }

  client_addr_len = sizeof(client_addr);
  sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);
  if (sock < 0) {
    close(server_sock);
    throw std::runtime_error("Error accepting request from client!");
  }
}

static void socket_client_ipv4(int &sock, const std::string &ip,
                               const uint16_t &port) {
  sockaddr_in send_sock_addr{};
  hostent *host = gethostbyname(&ip[0]);

  bzero((char *)&send_sock_addr, sizeof(send_sock_addr));
  send_sock_addr.sin_family = AF_INET;
  send_sock_addr.sin_addr.s_addr =
      inet_addr(inet_ntoa(*(struct in_addr *)*host->h_addr_list));
  send_sock_addr.sin_port = htons(port);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    throw std::runtime_error("Error establishing the socket!");

  if (connect(sock, (sockaddr *)&send_sock_addr, sizeof(send_sock_addr)) < 0)
    throw std::runtime_error("Error connecting to socket!");
}

static void socket_client_ipv6(int &sock, const std::string &ip,
                               const uint16_t &port) {
  sockaddr_in6 server_addr{};

  sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
    throw std::runtime_error("Error establishing the socket!");

  server_addr.sin6_family = AF_INET6;
  inet_pton(AF_INET6, ip.c_str(), &server_addr.sin6_addr);
  server_addr.sin6_port = htons(port);

  if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    close(sock);
    throw std::runtime_error("Error connecting to socket!");
  }
}

static void exchange_info(const std::string &server_ip,
                          const uint16_t &server_port, const bool &is_server,
                          const void *send_data, int send_size, void *recv_data,
                          int recv_size) {
  int server_sock = -1, sock = -1;
  int version = ip_version(server_ip);

  if (version < 0)
    throw std::runtime_error("Invalid ip address");

  if (is_server) {
    if (version == AF_INET)
      socket_server_ipv4(server_sock, sock, server_port);
    else
      socket_server_ipv6(server_sock, sock, server_port);
  } else {
    if (version == AF_INET) {
      socket_client_ipv4(sock, server_ip, server_port);
    } else {
      socket_client_ipv6(sock, server_ip, server_port);
    }
  }

  auto len = write(sock, send_data, send_size);
  if (len != send_size)
    throw std::runtime_error("Socket write error!");

  len = read(sock, recv_data, recv_size);
  if (len != recv_size)
    throw std::runtime_error("Socket read error!");
}

static void validate_mtu(const std::uint16_t &mtu) {
  switch (mtu) {
  case 256:
  case 512:
  case 1024:
  case 2048:
  case 4096:
    break;
  default:
    throw std::runtime_error("Unsupported mtu");
  }
}

static void validate_ip_address(const std::string &ip) {
  if (ip_version(ip) < 0)
    throw std::runtime_error("Invalid ip address");
}

static int parse_arguments(TestParameters *test_param, int argc, char *argv[]) {
  using namespace popl;

  OptionParser op("Allowed options");

  auto help_option = op.add<Switch>("h", "help", "Display help message");
  auto is_initiator =
      op.add<Value<bool>>("I", "is_initiator", "Initiator or target", true);
  auto device_name =
      op.add<Value<std::string>>("N", "device_name", "RDMA device name");
  auto device_port =
      op.add<Value<int>>("P", "device_port", "RDMA device port", 1);
  auto gid = op.add<Value<int>>("G", "gid", "GID index of RDMA device port", 1);
  auto ip_remote =
      op.add<Value<std::string>>("R", "ip_remote", "Remote IP address");
  auto ip_local =
      op.add<Value<std::string>>("L", "ip_local", "Local IP address");
  auto tcp_port = op.add<Value<int>>("V", "tcp_port", "TCP Socket port", 4569);
  auto mtu = op.add<Value<int>>("M", "mtu", "RDMA MTU", 1024);

  op.parse(argc, argv);

  if (help_option->is_set()) {
    std::cout << op << "\n";
    return -1;
  }

  if (!ip_remote->is_set())
    throw std::runtime_error("Remote IP address not set!");

  if (!ip_local->is_set())
    throw std::runtime_error("Local IP address' is not set!");

  if (!device_name->is_set())
    throw std::runtime_error("'dev_name' is not set!");

  validate_mtu(mtu->value());
  validate_ip_address(ip_local->value());
  validate_ip_address(ip_remote->value());

  test_param->is_initiator = is_initiator->value();
  test_param->dev_name = device_name->value();
  test_param->ib_port = device_port->value();
  test_param->gid = gid->value();
  test_param->local_ip = ip_local->value();
  test_param->remote_ip = ip_remote->value();
  test_param->tcp_port = tcp_port->value();
  test_param->mtu = mtu->value();

  return 0;
}

int main(int argc, char *argv[]) {
  ExchangeInfo local{}, remote{};
  TestParameters test_param{};

  if (parse_arguments(&test_param, argc, argv) < 0)
    return 0;

  ibv_context *ib_context = nullptr;
  int num_devices;
  ibv_device **device_list = ibv_get_device_list(&num_devices);

  for (auto i = 0; i < num_devices; i++) {
    if (ibv_get_device_name(device_list[i]) == test_param.dev_name) {
      ib_context = ibv_open_device(device_list[i]);
      break;
    }
  }

  ibv_free_device_list(device_list);
  if (!ib_context)
    throw std::runtime_error("Unable to find the device");

  printf("Context created!\n");

  auto protection_domain = ibv_alloc_pd(ib_context);
  if (!protection_domain)
    throw std::runtime_error("Can't allocate protection domain");

  printf("Protection domain created!\n");

  ibv_cq *completion_queue =
      ibv_create_cq(ib_context, COUNT, nullptr, nullptr, 0);
  if (!completion_queue)
    throw std::runtime_error("Can't create completion queue");

  printf("Completion queue created!\n");

  ibv_qp_init_attr qp_init_attr{};
  qp_init_attr.send_cq = completion_queue;
  qp_init_attr.recv_cq = completion_queue;
  qp_init_attr.cap.max_send_wr = COUNT;
  qp_init_attr.cap.max_recv_wr = COUNT;
  qp_init_attr.cap.max_send_sge = 1;
  qp_init_attr.cap.max_recv_sge = 1;
  qp_init_attr.qp_type = IBV_QPT_RC;

  auto queue_pair = ibv_create_qp(protection_domain, &qp_init_attr);
  if (!queue_pair)
    throw std::runtime_error("Can't create queue pair");

  printf("Queue pair created!\n");

  ibv_qp_attr qp_attr{};
  qp_attr.qp_state = IBV_QPS_INIT;
  qp_attr.pkey_index = 0;
  qp_attr.port_num = test_param.ib_port;
  qp_attr.qp_access_flags = 0;

  if (ibv_modify_qp(queue_pair, &qp_attr,
                    IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
                        IBV_QP_ACCESS_FLAGS))
    throw std::runtime_error("Failed to modify QP");

  printf("QP modified to IBV_QPS_INIT state!\n");

  auto mem = (std::uint8_t *)malloc(sizeof(std::uint8_t) * MEM_SIZE);
  memset(mem, 0, MEM_SIZE);

  ibv_mr *mr = ibv_reg_mr(protection_domain, mem, MEM_SIZE,
                          IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
                              IBV_ACCESS_REMOTE_WRITE);
  if (!mr)
    throw std::runtime_error("Can't register memory region");

  printf("Memory region registered!\n");

  local.qpn = queue_pair->qp_num;
  local.psn = rand() % 0xFFFFFF;

  memset(local.gid_raw, 0, sizeof(*local.gid_raw));
  if (ibv_query_gid(ib_context, test_param.ib_port, test_param.gid,
                    (ibv_gid *)local.gid_raw))
    throw std::runtime_error("Can't get local gid");

  exchange_info(test_param.remote_ip, test_param.tcp_port,
                test_param.is_initiator, &local, sizeof(local), &remote,
                sizeof(remote));

  char gid_str[0x80];
  inet_ntop(AF_INET6, local.gid_raw, gid_str, sizeof(gid_str));
  printf("local QP params: QPN 0x%06x, PSN 0x%06x, GID: %s\n", local.qpn,
         local.psn, gid_str);
  inet_ntop(AF_INET6, remote.gid_raw, gid_str, sizeof(gid_str));
  printf("remote  QP params: QPN 0x%06x, PSN 0x%06x, GID: %s\n", remote.qpn,
         remote.psn, gid_str);

  auto *remote_gid = (ibv_gid *)remote.gid_raw;
  qp_attr = {};
  qp_attr.qp_state = IBV_QPS_RTR;
  qp_attr.path_mtu = IBV_MTU_1024;
  qp_attr.dest_qp_num = remote.qpn;
  qp_attr.rq_psn = remote.psn;
  qp_attr.max_dest_rd_atomic = 1;
  qp_attr.min_rnr_timer = 15;
  qp_attr.ah_attr.port_num = test_param.ib_port;
  qp_attr.ah_attr.grh.hop_limit = 1;
  memcpy(&qp_attr.ah_attr.grh.dgid, remote_gid, 16);
  qp_attr.ah_attr.grh.sgid_index = test_param.gid;
  qp_attr.ah_attr.is_global = 0;
  qp_attr.ah_attr.dlid = 0;
  qp_attr.ah_attr.sl = 0;
  qp_attr.ah_attr.src_path_bits = 0;
  qp_attr.ah_attr.is_global = 1;

  if (ibv_modify_qp(queue_pair, &qp_attr,
                    IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                        IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                        IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER))
    throw std::runtime_error("Failed to modify QP");

  printf("QP modified to IBV_QPS_RTR state!\n");

  qp_attr = {};
  qp_attr.qp_state = IBV_QPS_RTS;
  qp_attr.timeout = 15;
  qp_attr.retry_cnt = 7;
  qp_attr.rnr_retry = 7;
  qp_attr.sq_psn = local.psn;
  qp_attr.max_rd_atomic = 1;

  if (ibv_modify_qp(queue_pair, &qp_attr,
                    IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                        IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
                        IBV_QP_MAX_QP_RD_ATOMIC))
    throw std::runtime_error("Failed to modify QP");

  printf("QP modified to IBV_QPS_RTS!\n");

  auto sg = new ibv_sge[COUNT]();
  int offset = 0;
  for (int i = 0; i < COUNT; ++i) {
    sg[i].addr = (uint64_t)mem + offset;
    sg[i].length = i + 1;
    sg[i].lkey = mr->lkey;
  }

  if (test_param.is_initiator) {
    auto wr = new ibv_send_wr[COUNT]();

    for (int i = 0; i < MEM_SIZE; ++i)
      mem[i] = i + 1;

    for (int i = 0; i < COUNT; ++i) {
      wr[i].wr_id = 100000 + i;
      wr[i].sg_list = &sg[i];
      wr[i].num_sge = 1;
      wr[i].opcode = IBV_WR_SEND;
      wr[i].send_flags = IBV_SEND_SIGNALED;
    }

    struct ibv_send_wr *bad_wr;
    for (int i = 0; i < COUNT; ++i) {
      if (ibv_post_send(queue_pair, &wr[i], &bad_wr))
        throw std::runtime_error("Can't post send request");
    }

    ibv_wc wc{};
    for (int i = 0; i < COUNT; ++i) {
      int ne = 0;
      for (; ne == 0;) {
        ne = ibv_poll_cq(completion_queue, 1, &wc);

        if (ne < 0)
          throw std::runtime_error("Poll CQ failed");
      }

      if (wc.status != IBV_WC_SUCCESS)
        throw std::runtime_error("Fail " + std::to_string(wc.status));

      printf("Transfer %lu has been sent!\n", wc.wr_id);
    }

    delete[] wr;
  } else {
    auto wr = new ibv_recv_wr[COUNT]();

    memset(mem, 0, MEM_SIZE);

    for (int i = 0; i < COUNT; ++i) {
      wr[i].wr_id = 10000 + i;
      wr[i].sg_list = &sg[i];
      wr[i].num_sge = 1;
    }

    ibv_recv_wr *bad_wr;
    for (auto i = 0; i < COUNT; i++) {
      if (ibv_post_recv(queue_pair, &wr[i], &bad_wr))
        throw std::runtime_error("Can't post recv request");
    }

    ibv_wc wc{};
    for (int i = 0; i < COUNT; ++i) {
      int ne = 0;
      for (; ne == 0;) {
        ne = ibv_poll_cq(completion_queue, 1, &wc);

        if (ne < 0)
          throw std::runtime_error("poll CQ failed %d");
      }

      if (wc.status != IBV_WC_SUCCESS)
        throw std::runtime_error("Fail " + std::to_string(wc.status));

      printf("WR %lu received, status=%d, len=%d\n", wc.wr_id, wc.status,
             wc.byte_len);
    }

    delete[] wr;
  }

  delete[] sg;

  if (ibv_dereg_mr(mr))
    throw std::runtime_error("Couldn't deregister MR");

  if (ibv_destroy_qp(queue_pair))
    throw std::runtime_error("Couldn't destroy QP");

  if (ibv_destroy_cq(completion_queue))
    throw std::runtime_error("Couldn't destroy CQ");

  if (ibv_dealloc_pd(protection_domain))
    throw std::runtime_error("Couldn't deallocate PD");

  if (ibv_close_device(ib_context))
    throw std::runtime_error("Couldn't release context");

  return 0;
}