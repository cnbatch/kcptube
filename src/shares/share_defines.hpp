#pragma once

#ifndef _SHARE_DEFINES_
#define _SHARE_DEFINES_

#include <cstdint>
#include <cstdlib>
#include <atomic>
#include <limits>
#include <random>
#include <set>
#include <map>
#include <string>
#include <string_view>
#include <sstream>
#include <numeric>
#include <memory>
#include <vector>
#include <filesystem>
#ifdef __cpp_lib_format
#include <format>
#endif
#include "../3rd_party/thread_pool.hpp"

constexpr std::string_view app_name = "kcptube";

enum class running_mode { unknow, server, client, relay, relay_ingress, relay_egress };
enum class kcp_mode { unknow, regular1, regular2, regular3, regular4, regular5, fast1, fast2, fast3, fast4, fast5, fast6, manual };
enum class encryption_mode { unknow, empty, none, aes_gcm, aes_ocb, chacha20, xchacha20 };
enum class ip_only_options : uint8_t { not_set = 0, ipv4 = 1, ipv6 = 2 };

namespace constant_values
{
	constexpr uint16_t timeout_value = 180;	// second
	constexpr uint16_t extends_5_seconds = 5;
	constexpr int16_t dport_refresh_default = 60;
	constexpr int16_t dport_refresh_minimal = 20;
	constexpr int kcp_send_window = 1024;
	constexpr int kcp_receive_window = 1024;
	constexpr int packet_length = 1420;
	constexpr int iv_checksum_block_size = 2;
	constexpr int encryption_block_reserve = 48;
	constexpr int packet_layer_header = 4;
	constexpr int packet_layer_data_header = 9;
	constexpr int packet_layer_fec_header = 13;
	constexpr int fec_container_header = 2;
	constexpr int data_layer_header = 1;
	constexpr int mux_data_wrapper_header = 4;
	constexpr int ip_header = 36;
	constexpr int udp_header = 4;
	constexpr int kcp_mtu = packet_length - iv_checksum_block_size;
	constexpr int kcp_mtu_with_fec = kcp_mtu - packet_layer_fec_header;
};

inline constexpr ip_only_options
operator&(ip_only_options option_1, ip_only_options option_2)
{
	return static_cast<ip_only_options>(static_cast<uint8_t>(option_1) & static_cast<uint8_t>(option_2));
}

inline constexpr ip_only_options
operator|(ip_only_options option_1, ip_only_options option_2)
{
	return static_cast<ip_only_options>(static_cast<uint8_t>(option_1) | static_cast<uint8_t>(option_2));
}

inline constexpr ip_only_options
operator^(ip_only_options option_1, ip_only_options option_2)
{
	return static_cast<ip_only_options>(static_cast<uint8_t>(option_1) ^ static_cast<uint8_t>(option_2));
}

inline constexpr ip_only_options
operator~(ip_only_options input_option)
{
	return static_cast<ip_only_options>(~static_cast<int>(input_option));
}

inline ip_only_options &
operator&=(ip_only_options &option_1, ip_only_options option_2)
{
	option_1 = option_1 & option_2;
	return option_1;
}

inline ip_only_options &
operator|=(ip_only_options &option_1, ip_only_options option_2)
{
	option_1 = option_1 | option_2;
	return option_1;
}

inline ip_only_options &
operator^=(ip_only_options &option_1, ip_only_options option_2)
{
	option_1 = option_1 ^ option_2;
	return option_1;
}

template<typename T>
T generate_random_number()
{
	thread_local std::random_device rd;
	thread_local std::mt19937 mt(rd());
	thread_local std::uniform_int_distribution<T> uniform_dist(std::numeric_limits<T>::min(), std::numeric_limits<T>::max());
	T number = uniform_dist(mt);
	return number;
}

template<typename T>
T generate_random_number(T start_num, T end_num)
{
	thread_local std::random_device rd;
	thread_local std::mt19937 mt(rd());
	thread_local std::uniform_int_distribution<T> uniform_dist;
	T number = uniform_dist(mt, decltype(uniform_dist)::param_type(start_num, end_num));
	return number;
}

template<typename T>
T calculate_difference(T number_left, T number_right)
{
	return std::abs(number_left - number_right);
}

struct user_settings
{
	using user_input_address_mapping = std::map<std::pair<std::string, uint16_t>, std::pair<std::string, uint16_t>>;
	int16_t dynamic_port_refresh = -1;	// seconds
	uint16_t udp_timeout = 0;	 // seconds
	uint16_t keep_alive = 0;	// seconds
	uint16_t mux_tunnels = 0;	// client only
	uint8_t fec_data = 0;
	uint8_t fec_redundant = 0;
	encryption_mode encryption = encryption_mode::empty;
	running_mode mode = running_mode::unknow;
	kcp_mode kcp_setting = kcp_mode::unknow;
	int mtu = -1;
	int kcp_mtu = -1;
	int kcp_nodelay = -1;
	int kcp_interval = -1;
	int kcp_resend = -1;
	int kcp_nc = -1;
	uint32_t kcp_sndwnd = 0;
	uint32_t kcp_rcvwnd = 0;
	uint64_t outbound_bandwidth = 0;
	uint64_t inbound_bandwidth = 0;
	ip_only_options ip_version_only = ip_only_options::not_set;
	int fib_ingress = -1;
	int fib_egress = -1;
	bool blast = 1;
	bool ignore_listen_address = false;
	bool ignore_listen_port = false;
	bool ignore_destination_address = false;
	bool ignore_destination_port = false;
	std::vector<std::string> listen_on;
	std::vector<uint16_t> listen_ports;
	std::vector<uint16_t> destination_ports;
	std::vector<std::string> destination_address_list;
	std::string encryption_password;
	std::string stun_server;
	std::filesystem::path log_directory;
	std::filesystem::path log_ip_address;
	std::filesystem::path log_messages;
	std::filesystem::path log_status;
	std::string config_filename;
	std::shared_ptr<user_settings> ingress;
	std::shared_ptr<user_settings> egress;
	std::shared_ptr<user_input_address_mapping> user_input_mappings;
	std::shared_ptr<user_input_address_mapping> user_input_mappings_tcp;
	std::shared_ptr<user_input_address_mapping> user_input_mappings_udp;
};

struct status_records
{
	alignas(64) std::atomic<size_t> ingress_raw_traffic;
	alignas(64) std::atomic<size_t> egress_raw_traffic;
	alignas(64) std::atomic<size_t> ingress_inner_traffic;
	alignas(64) std::atomic<size_t> egress_inner_traffic;
	alignas(64) std::atomic<size_t> fec_recovery_count;
};

#pragma pack (push, 1)
struct fec_container
{
	uint16_t data_length;
	uint8_t data[1];
};
#pragma pack(pop)

struct task_pool_colloector
{
	ttp::task_thread_pool *parallel_encryption_pool;
	ttp::task_thread_pool *parallel_decryption_pool;
	ttp::task_thread_pool *listener_parallels;
	ttp::task_thread_pool *forwarder_parallels;
};

user_settings parse_from_args(const std::vector<std::string> &args, std::vector<std::string> &error_msg);
std::set<uint16_t> port_range_to_vector(const std::string &input_str, std::vector<std::string> &error_msg, const std::string &acting_role);
std::vector<uint16_t> string_to_port_numbers(const std::string& input_str, std::vector<std::string>& error_msg, const std::string& acting_role);
std::vector<std::string> string_to_address_list(const std::string &input_str);
bool is_continuous(const std::vector<uint16_t> &numbers);

std::string time_to_string();
std::string time_to_string_with_square_brackets();
void print_ip_to_file(const std::string &message, const std::filesystem::path &log_file);
void print_message_to_file(const std::string &message, const std::filesystem::path &log_file);
void print_status_to_file(const std::string &message, const std::filesystem::path &log_file);
std::string to_speed_unit(size_t value, size_t duration_seconds);

#endif // !_SHARE_HEADER_
