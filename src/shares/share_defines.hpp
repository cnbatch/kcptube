#pragma once

#ifndef _SHARE_DEFINES_
#define _SHARE_DEFINES_

#include <cstdint>
#include <random>
#include <string>
#include <vector>
#include <filesystem>

enum class running_mode { unknow, empty, server, client };
enum class kcp_mode { unknow, regular1, regular2, regular3, regular4, fast1, fast2, fast3, fast4, manual };
enum class encryption_mode { unknow, empty, none, aes_gcm, aes_ocb, chacha20, xchacha20 };

namespace constant_values
{
	constexpr uint16_t timeout_value = 1800;	// second
	constexpr uint16_t dport_refresh_default = 60;
	constexpr uint16_t dport_refresh_minimal = 20;
	constexpr int kcp_send_window = 1024;
	constexpr int kcp_receive_window = 1024;
	constexpr int kcp_mtu = 1420;
	constexpr int checksum_block_size = 2;
};


template<typename T>
T generate_random_number()
{
	thread_local std::random_device rd;
	thread_local std::mt19937 mt(rd());
	thread_local std::uniform_int_distribution<T> uniform_dist(std::numeric_limits<T>::min(), std::numeric_limits<T>::max());
	return uniform_dist(mt);
}

struct user_settings
{
	uint16_t listen_port = 0;
	uint16_t listen_port_start = 0;
	uint16_t listen_port_end = 0;
	uint16_t destination_port = 0;
	uint16_t destination_port_start = 0;
	uint16_t destination_port_end = 0;
	uint16_t dynamic_port_refresh = constant_values::dport_refresh_default;	// seconds
	uint16_t udp_timeout = 0;	 // seconds
	uint16_t keep_alive = 0;	// seconds
	encryption_mode encryption = encryption_mode::empty;
	running_mode mode = running_mode::empty;
	kcp_mode kcp_setting = kcp_mode::unknow;
	int kcp_mtu = -1;
	int kcp_sndwnd = -1;
	int kcp_rcvwnd = -1;
	int kcp_nodelay = -1;
	int kcp_interval = -1;
	int kcp_resend = -1;
	int kcp_nc = -1;
	uint64_t outbound_bandwidth = 0;
	uint64_t inbound_bandwidth = 0;
	bool ipv4_only = false;
	std::string listen_on;
	std::string destination_address;
	std::string encryption_password;
	std::string stun_server;
	std::filesystem::path log_directory;
	std::filesystem::path log_ip_address;
	std::filesystem::path log_messages;
};

user_settings parse_from_args(const std::vector<std::string> &args, std::vector<std::string> &error_msg);
void check_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg);
uint64_t bandwidth_from_string(const std::string &bandwidth);

int64_t calculate_difference(int64_t number1, int64_t number2);

std::string time_to_string();
std::string time_to_string_with_square_brackets();
void print_ip_to_file(const std::string &message, const std::filesystem::path &log_file);
void print_message_to_file(const std::string &message, const std::filesystem::path &log_file);

#endif // !_SHARE_HEADER_
