#pragma once

#ifndef __CONNECTIONS__
#define __CONNECTIONS__

#include <functional>
#include <memory>
#include <map>
#include <array>
#include <atomic>
#include <unordered_set>
#include <unordered_map>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <tuple>
#include <vector>
#include <deque>
#include <asio.hpp>

#include "../shares/share_defines.hpp"
#include "../3rd_party/thread_pool.hpp"
#include "../3rd_party/fecpp.hpp"
#include "stun.hpp"
#include "kcp.hpp"

constexpr size_t gbv_task_count_limit = 8192u;
constexpr int32_t gbv_time_gap_seconds = std::numeric_limits<uint8_t>::max();	//seconds
constexpr int32_t gbv_mux_channels_cleanup = gbv_time_gap_seconds >> 3;	//seconds
constexpr int32_t gbv_keepalive_timeout = gbv_time_gap_seconds >> 3;	//seconds
constexpr uint32_t gbv_mux_min_cache_size = 128u;
constexpr uint32_t gbv_mux_min_cache_available = 16u;
constexpr uint32_t gbv_mux_min_cache_slice = 8u;
constexpr uint32_t gbv_tcp_slice = 2u;
constexpr uint32_t gbv_half_time = 2u;
constexpr uint16_t gbv_fec_waits = 3u;
constexpr size_t gbv_buffer_size = 2048u;
constexpr size_t gbv_buffer_expand_size = 128u;
constexpr size_t gbv_retry_times = 30u;
constexpr size_t gbv_retry_waits = 2u;
constexpr size_t gbv_cleanup_waits = 15;	// second
constexpr size_t gbv_kcp_cleanup_waits = 4;	// second
constexpr size_t gbv_receiver_cleanup_waits = gbv_kcp_cleanup_waits * 2;	// second
constexpr size_t gbv_handshake_timeout = 30;	//seconds
constexpr auto gbv_expring_update_interval = std::chrono::seconds(1);
constexpr auto gbv_keepalive_update_interval = std::chrono::seconds(1);
constexpr auto gbv_stun_resend = std::chrono::seconds(30);
constexpr auto gbv_logging_gap = std::chrono::seconds(60);
const asio::ip::udp::endpoint local_empty_target_v4(asio::ip::make_address_v4("127.0.0.1"), 70);
const asio::ip::udp::endpoint local_empty_target_v6(asio::ip::make_address_v6("::1"), 70);

struct connection_options
{
	ip_only_options ip_version_only = ip_only_options::not_set;
	int fib_ingress = 0;
	int fib_egress = 0;
};

enum class feature : uint8_t
{
	initialise,
	failure,
	disconnect,
	keep_alive,
	test_connection = keep_alive,
	keep_alive_response,
	raw_data,
	mux_transfer,
	mux_cancel,
	pre_connect_custom_address
};

enum class protocol_type : uint8_t { not_care, mux, tcp, udp };

enum class task_type { sequence, direct, in_place };

uint16_t generate_new_port_number(uint16_t start_port_num, uint16_t end_port_num);
uint16_t generate_new_port_number(const std::vector<uint16_t> &port_list);
size_t randomly_pick_index(size_t container_size);

std::string_view feature_to_string(feature ftr);
std::string protocol_type_to_string(protocol_type prtcl);
std::string debug_data_to_string(const uint8_t *data, size_t len);
void debug_print_data(const uint8_t *data, size_t len);
bool empty_mapping_function();

namespace packet
{
#pragma pack (push, 1)
	struct packet_layer
	{
		uint32_t timestamp;
		uint8_t data[1];
	};

	struct packet_layer_data
	{
		uint32_t timestamp;
		uint32_t sn;
		uint8_t sub_sn;
		uint8_t data[1];
	};

	struct packet_layer_fec
	{
		uint32_t timestamp;
		uint32_t sn;
		uint8_t sub_sn;
		uint32_t kcp_conv;
		uint8_t data[1];
	};

	struct data_layer
	{
		feature feature_value : 4;
		protocol_type protocol_value : 4;
		uint8_t data[1];
	};

	struct settings_wrapper
	{
		uint32_t uid;
		uint16_t port_start;	// set 0 for both, if is_continuous() returns false
		uint16_t port_end;
		uint64_t outbound_bandwidth;
		uint64_t inbound_bandwidth;
		uint16_t user_input_port;
		char user_input_ip[1];
	};

	struct mux_data_wrapper
	{
		uint32_t connection_id;
		uint8_t data[1];
	};

	struct pre_connect_custom_address
	{
		uint32_t connection_id;
		uint16_t user_input_port;
		char user_input_ip[1];
	};
#pragma pack(pop)

	constexpr size_t empty_data_size = sizeof(data_layer);

	uint64_t htonll(uint64_t value) noexcept;
	uint64_t ntohll(uint64_t value) noexcept;
	int64_t htonll(int64_t value) noexcept;
	int64_t ntohll(int64_t value) noexcept;
	uint16_t little_endian_to_host(uint16_t value) noexcept;
	uint16_t host_to_little_endian(uint16_t value) noexcept;
	uint32_t little_endian_to_host(uint32_t value) noexcept;
	uint32_t host_to_little_endian(uint32_t value) noexcept;
	uint64_t little_endian_to_host(uint64_t value) noexcept;
	uint64_t host_to_little_endian(uint64_t value) noexcept;
	int16_t little_endian_to_host(int16_t value) noexcept;
	int16_t host_to_little_endian(int16_t value) noexcept;
	int32_t little_endian_to_host(int32_t value) noexcept;
	int32_t host_to_little_endian(int32_t value) noexcept;
	int64_t little_endian_to_host(int64_t value) noexcept;
	int64_t host_to_little_endian(int64_t value) noexcept;

	int64_t right_now();

	std::pair<std::unique_ptr<uint8_t[]>, int> create_packet(const uint8_t *input_data, int data_size);
	std::pair<std::unique_ptr<uint8_t[]>, int> create_fec_data_packet(const uint8_t *input_data, int data_size, uint32_t fec_sn, uint8_t fec_sub_sn);
	std::pair<std::unique_ptr<uint8_t[]>, int> create_fec_redundant_packet(const uint8_t *input_data, int data_size, uint32_t fec_sn, uint8_t fec_sub_sn, uint32_t kcp_conv);
	std::vector<uint8_t> create_inner_packet(feature ftr, protocol_type prtcl, const std::vector<uint8_t> &data);
	std::vector<uint8_t> create_inner_packet(feature ftr, protocol_type prtcl, const uint8_t *input_data, size_t data_size);
	size_t create_inner_packet(feature ftr, protocol_type prtcl, uint8_t *input_data, size_t data_size);

	std::tuple<uint32_t, uint8_t*, size_t> unpack(uint8_t *data, size_t length);
	std::tuple<packet_layer_data, uint8_t*, size_t> unpack_fec(uint8_t *data, size_t length);
	std::tuple<packet_layer_fec, uint8_t*, size_t> unpack_fec_redundant(uint8_t *data, size_t length);
	std::tuple<feature, protocol_type, std::vector<uint8_t>> unpack_inner(const std::vector<uint8_t> &data);
	std::tuple<feature, protocol_type, uint8_t*, size_t> unpack_inner(uint8_t *data, size_t length);

	const settings_wrapper* get_initialise_details_from_unpacked_data(const std::vector<uint8_t> &data);
	const settings_wrapper* get_initialise_details_from_unpacked_data(const uint8_t *data);
	void convert_wrapper_byte_order_ntoh(void *data);
	void convert_wrapper_byte_order_hton(void *data);
	void convert_wrapper_byte_order(const std::vector<uint8_t> &input_data, std::vector<uint8_t> &output_data);
	void convert_wrapper_byte_order(const uint8_t *input_data, uint8_t *output_data, size_t data_size);

	void modify_initialise_details_of_unpacked_data(uint8_t *data, const settings_wrapper &settings);

	std::vector<uint8_t> request_initialise_packet(protocol_type prtcl, uint64_t outbound_bandwidth, uint64_t inbound_bandwidth);
	std::vector<uint8_t> request_initialise_packet(protocol_type prtcl, uint64_t outbound_bandwidth, uint64_t inbound_bandwidth, const std::string &set_address, asio::ip::port_type set_port);

	std::vector<uint8_t> response_initialise_packet(protocol_type prtcl, settings_wrapper settings);

	std::vector<uint8_t> create_test_connection_packet();

	std::vector<uint8_t> inform_disconnect_packet(protocol_type prtcl);

	std::vector<uint8_t> inform_error_packet(protocol_type prtcl, const std::string &error_msg);

	std::vector<uint8_t> create_data_packet(protocol_type prtcl, const std::vector<uint8_t> &custom_data);
	size_t create_data_packet(protocol_type prtcl, uint8_t *custom_data, size_t length);

	std::vector<uint8_t> create_keep_alive_packet(protocol_type prtcl);
	std::vector<uint8_t> create_keep_alive_response_packet(protocol_type prtcl);

	std::vector<uint8_t> create_mux_data_packet(protocol_type prtcl, uint32_t connection_id, const std::vector<uint8_t> &custom_data);
	size_t create_mux_data_packet(protocol_type prtcl, uint32_t connection_id, uint8_t *input_data, size_t data_size);
	std::vector<uint8_t> mux_tell_server_connect_address(protocol_type prtcl, uint32_t connection_id, const std::string &connect_address, asio::ip::port_type connect_port);
	std::tuple<uint32_t, uint8_t*, size_t> extract_mux_data_from_unpacked_data(uint8_t *data, size_t length);
	std::tuple<uint32_t, uint16_t, std::string> extract_mux_pre_connect_from_unpacked_data(uint8_t *data, size_t length);

	std::vector<uint8_t> inform_mux_cancel_packet(protocol_type prtcl, uint32_t connection_id);
	uint32_t extract_mux_cancel_from_unpacked_data(uint8_t *data, size_t length);

	std::string get_error_message_from_unpacked_data(const std::vector<uint8_t> &data);
	std::string get_error_message_from_unpacked_data(uint8_t *data, size_t length);

}	// namespace packet


using asio::ip::tcp;
using asio::ip::udp;

class tcp_session;
class udp_server;

using tcp_callback_t = std::function<void(std::unique_ptr<uint8_t[]>, size_t, std::shared_ptr<tcp_session>)>;
using udp_server_callback_t = std::function<void(std::unique_ptr<uint8_t[]>, size_t, udp::endpoint, udp_server*)>;
using udp_client_callback_t = std::function<void(std::unique_ptr<uint8_t[]>, size_t, udp::endpoint, asio::ip::port_type)>;
using sequence_callback_t = std::function<void(size_t, ttp::task_callback, std::unique_ptr<uint8_t[]>)>;
using diret_callback_t = std::function<void(ttp::task_callback, std::unique_ptr<uint8_t[]>)>;

void empty_tcp_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, std::shared_ptr<tcp_session> tmp2);
void empty_udp_server_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint tmp2, udp_server *tmp3);
void empty_udp_client_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint tmp2, asio::ip::port_type tmp3);
void empty_tcp_disconnect(std::shared_ptr<tcp_session> tmp);
int empty_kcp_output(const char *, int, void *);
void empty_kcp_postupdate(void *);
void empty_task_callback(std::unique_ptr<uint8_t[]> null_data);

class tcp_session : public std::enable_shared_from_this<tcp_session>
{
public:
	tcp_session(asio::io_context &net_io, tcp_callback_t callback_func)
		: network_io(net_io), connection_socket(network_io), task_type_running(task_type::in_place),
		callback(callback_func), callback_for_disconnect(empty_tcp_disconnect),
		last_receive_time(packet::right_now()), last_send_time(packet::right_now()),
		paused(false), stopped(false), session_ending(false) {}

	tcp_session(asio::io_context &net_io, sequence_callback_t task_function, tcp_callback_t callback_func)
		: network_io(net_io), connection_socket(network_io), task_type_running(task_type::sequence), push_task_seq(task_function),
		callback(callback_func), callback_for_disconnect(empty_tcp_disconnect),
		last_receive_time(packet::right_now()), last_send_time(packet::right_now()),
		paused(false), stopped(false), session_ending(false) {}

	tcp_session(asio::io_context &net_io, diret_callback_t task_function,  tcp_callback_t callback_func)
		: network_io(net_io), connection_socket(network_io), task_type_running(task_type::direct), push_task(task_function),
		callback(callback_func), callback_for_disconnect(empty_tcp_disconnect),
		last_receive_time(packet::right_now()), last_send_time(packet::right_now()),
		paused(false), stopped(false), session_ending(false) {}

	void start();

	void session_is_ending(bool set_ending);
	bool session_is_ending();

	void pause(bool set_as_pause);
	void stop();
	bool is_pause() const;
	bool is_stop() const;
	bool is_open() const;

	void disconnect();

	void async_read_data();

	size_t send_data(const std::vector<uint8_t> &buffer_data);
	size_t send_data(const uint8_t *buffer_data, size_t size_in_bytes);
	size_t send_data(const uint8_t *buffer_data, size_t size_in_bytes, asio::error_code &ec);

	void async_send_data(std::unique_ptr<std::vector<uint8_t>> data);
	void async_send_data(std::vector<uint8_t> &&data);
	void async_send_data(std::unique_ptr<uint8_t[]> buffer_data, size_t size_in_bytes);
	void async_send_data(std::unique_ptr<uint8_t[]> buffer_data, uint8_t *start_pos, size_t size_in_bytes);
	void async_send_data(const uint8_t *buffer_data, size_t size_in_bytes);

	void when_disconnect(std::function<void(std::shared_ptr<tcp_session>)> callback_before_disconnect);

	bool replace_callback(tcp_callback_t callback_func);

	tcp::socket& socket();

	int64_t time_gap_of_receive();

	int64_t time_gap_of_send();

private:
	void after_write_completed(const asio::error_code &error, size_t bytes_transferred);

	void after_read_completed(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, size_t bytes_transferred);

	void transfer_data_to_next_function(std::unique_ptr<uint8_t[]> buffer_cache, size_t bytes_transferred);

	asio::io_context &network_io;
	tcp::socket connection_socket;
	tcp_callback_t callback;
	std::function<void(std::shared_ptr<tcp_session>)> callback_for_disconnect;
	alignas(64) std::atomic<int64_t> last_receive_time;
	alignas(64) std::atomic<int64_t> last_send_time;
	alignas(64) std::atomic<bool> paused;
	alignas(64) std::atomic<bool> stopped;
	alignas(64) std::atomic<bool> session_ending;
	task_type task_type_running;
	sequence_callback_t push_task_seq;
	diret_callback_t push_task;
};

class tcp_server
{
public:
	using acceptor_callback_t = std::function<void(std::shared_ptr<tcp_session>)>;
	tcp_server() = delete;

	tcp_server(asio::io_context &io_context, const tcp::endpoint &ep,
		acceptor_callback_t acceptor_callback_func, tcp_callback_t callback_func, connection_options conn_options)
		: internal_io_context(io_context), task_type_running(task_type::in_place), tcp_acceptor(io_context),
		acceptor_callback(acceptor_callback_func), session_callback(callback_func), ip_version_only(conn_options.ip_version_only),
		fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress)
	{
		acceptor_initialise(ep);
		start_accept();
	}

	tcp_server(asio::io_context &io_context, sequence_callback_t task_function, const tcp::endpoint &ep,
		acceptor_callback_t acceptor_callback_func, tcp_callback_t callback_func, connection_options conn_options)
		: internal_io_context(io_context), task_type_running(task_type::sequence), push_task_seq(task_function), tcp_acceptor(io_context),
		acceptor_callback(acceptor_callback_func), session_callback(callback_func), ip_version_only(conn_options.ip_version_only),
		fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress)
	{
		acceptor_initialise(ep);
		start_accept();
	}

	tcp_server(asio::io_context &io_context, diret_callback_t task_function, const tcp::endpoint &ep,
		acceptor_callback_t acceptor_callback_func, tcp_callback_t callback_func, connection_options conn_options)
		: internal_io_context(io_context), task_type_running(task_type::direct), push_task(task_function), tcp_acceptor(io_context),
		acceptor_callback(acceptor_callback_func), session_callback(callback_func), ip_version_only(conn_options.ip_version_only),
		fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress)
	{
		acceptor_initialise(ep);
		start_accept();
	}

private:
	void acceptor_initialise(const tcp::endpoint &ep);
	void start_accept();
	void handle_accept(std::shared_ptr<tcp_session> new_connection, const asio::error_code &error_code);

	asio::io_context &internal_io_context;
	tcp::acceptor tcp_acceptor;
	acceptor_callback_t acceptor_callback;
	tcp_callback_t session_callback;
	task_type task_type_running;
	sequence_callback_t push_task_seq;
	diret_callback_t push_task;
	const ip_only_options ip_version_only;
	int fib_ingress;
	int fib_egress;
	bool paused;
};

class tcp_client
{
public:
	tcp_client() = delete;

	tcp_client(asio::io_context &io_context, tcp_callback_t callback_func, connection_options conn_options)
		: internal_io_context(io_context), resolver(internal_io_context), task_type_running(task_type::in_place), session_callback(callback_func),
		ip_version_only(conn_options.ip_version_only), fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress) {}

	tcp_client(asio::io_context &io_context, sequence_callback_t task_function, tcp_callback_t callback_func, connection_options conn_options)
		: internal_io_context(io_context), resolver(internal_io_context), task_type_running(task_type::sequence), push_task_seq(task_function),
		session_callback(callback_func), ip_version_only(conn_options.ip_version_only), fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress) {}

	tcp_client(asio::io_context &io_context, diret_callback_t task_function, tcp_callback_t callback_func, connection_options conn_options)
		: internal_io_context(io_context), resolver(internal_io_context), task_type_running(task_type::direct), push_task(task_function),
		session_callback(callback_func), ip_version_only(conn_options.ip_version_only), fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress) {}

	std::shared_ptr<tcp_session> connect(asio::error_code &ec);

	bool set_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec);
	bool set_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec);

private:

	asio::io_context &internal_io_context;
	tcp_callback_t session_callback;
	tcp::resolver resolver;
	asio::ip::basic_resolver_results<asio::ip::tcp> remote_endpoints;
	task_type task_type_running;
	sequence_callback_t push_task_seq;
	diret_callback_t push_task;
	const ip_only_options ip_version_only;
	int fib_ingress;
	int fib_egress;
};



class udp_server
{
public:
	udp_server() = delete;

	udp_server(asio::io_context &io_context, const udp::endpoint &ep, udp_server_callback_t callback_func, connection_options conn_options)
		: task_type_running(task_type::in_place), binded_endpoint(ep), resolver(io_context), connection_socket(io_context), callback(callback_func),
		ip_version_only(conn_options.ip_version_only), fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress)
	{
		initialise(ep);
		start_receive();
	}

	udp_server(asio::io_context &io_context, sequence_callback_t task_function,
		const udp::endpoint &ep, udp_server_callback_t callback_func, connection_options conn_options)
		: task_type_running(task_type::sequence), push_task_seq(task_function),
		binded_endpoint(ep), resolver(io_context), connection_socket(io_context), callback(callback_func),
		ip_version_only(conn_options.ip_version_only), fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress)
	{
		initialise(ep);
		start_receive();
	}

	udp_server(asio::io_context &io_context, diret_callback_t task_function,
		const udp::endpoint &ep, udp_server_callback_t callback_func, connection_options conn_options)
		: task_type_running(task_type::direct), push_task(task_function),
		binded_endpoint(ep), resolver(io_context), connection_socket(io_context), callback(callback_func),
		ip_version_only(conn_options.ip_version_only), fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress)
	{
		initialise(ep);
		start_receive();
	}

	void continue_receive();

	void async_send_out(std::unique_ptr<std::vector<uint8_t>> data, const udp::endpoint &client_endpoint);
	void async_send_out(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &client_endpoint);
	void async_send_out(std::unique_ptr<uint8_t[]> data, uint8_t *start_pos, size_t data_size, const udp::endpoint &client_endpoint);
	void async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &client_endpoint);
	udp::resolver& get_resolver() { return resolver; }

private:
	void initialise(const udp::endpoint &ep);
	void start_receive();
	void handle_receive(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred);

	udp::resolver resolver;
	udp::socket connection_socket;
	const udp::endpoint binded_endpoint;
	udp::endpoint incoming_endpoint;
	udp_server_callback_t callback;
	task_type task_type_running;
	sequence_callback_t push_task_seq;
	diret_callback_t push_task;
	const ip_only_options ip_version_only;
	int fib_ingress;
	int fib_egress;
	static inline std::atomic<size_t> task_count{};
};

class udp_client : public std::enable_shared_from_this<udp_client>
{
public:
	udp_client() = delete;

	udp_client(asio::io_context &io_context, udp_client_callback_t callback_func, connection_options conn_options)
		: task_type_running(task_type::in_place), connection_socket(io_context), resolver(io_context),
		callback(callback_func), last_receive_time(packet::right_now()), last_send_time(packet::right_now()),
		paused(false), stopped(false), ip_version_only(conn_options.ip_version_only),
		fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress)
	{
		initialise();
	}

	udp_client(asio::io_context &io_context, sequence_callback_t task_function, udp_client_callback_t callback_func, connection_options conn_options)
		: task_type_running(task_type::sequence), push_task_seq(task_function), connection_socket(io_context), resolver(io_context),
		callback(callback_func), last_receive_time(packet::right_now()), last_send_time(packet::right_now()), paused(false), stopped(false),
		ip_version_only(conn_options.ip_version_only), fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress)
	{
		initialise();
	}

	udp_client(asio::io_context &io_context, diret_callback_t task_function, udp_client_callback_t callback_func, connection_options conn_options)
		: task_type_running(task_type::direct), push_task(task_function), connection_socket(io_context), resolver(io_context),
		callback(callback_func), last_receive_time(packet::right_now()), last_send_time(packet::right_now()), paused(false), stopped(false),
		ip_version_only(conn_options.ip_version_only), fib_ingress(conn_options.fib_ingress), fib_egress(conn_options.fib_egress)
	{
		initialise();
	}

	void pause(bool set_as_pause);
	void stop();
	bool is_pause() const;
	bool is_stop() const;

	udp::resolver::results_type get_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec);
	udp::resolver::results_type get_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec);

	void disconnect();

	void async_receive();

	size_t send_out(const std::vector<uint8_t> &data, const udp::endpoint &peer_endpoint, asio::error_code &ec);
	size_t send_out(const uint8_t *data, size_t size, const udp::endpoint &peer_endpoint, asio::error_code &ec);

	void async_send_out(std::unique_ptr<std::vector<uint8_t>> data, const udp::endpoint &peer_endpoint);
	void async_send_out(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer_endpoint);
	void async_send_out(std::unique_ptr<uint8_t[]> data, uint8_t *start_pos, size_t data_size, const udp::endpoint &peer_endpoint);
	void async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &peer_endpoint);

	int64_t time_gap_of_receive();
	int64_t time_gap_of_send();

protected:
	void initialise();

	void start_receive();

	void handle_receive(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred);

	//ttp::task_thread_pool *task_assigner;
	//ttp::task_group_pool *sequence_task_pool;
	udp::socket connection_socket;
	udp::resolver resolver;
	udp::endpoint incoming_endpoint;
	udp_client_callback_t callback;
	alignas(64) std::atomic<int64_t> last_receive_time;
	alignas(64) std::atomic<int64_t> last_send_time;
	alignas(64) std::atomic<bool> paused;
	alignas(64) std::atomic<bool> stopped;
	task_type task_type_running;
	sequence_callback_t push_task_seq;
	diret_callback_t push_task;
	const ip_only_options ip_version_only;
	int fib_ingress;
	int fib_egress;
	static inline std::atomic<size_t> task_count{};
};

class forwarder : public udp_client
{
public:
	using process_data_t = std::function<void(std::shared_ptr<KCP::KCP>, std::unique_ptr<uint8_t[]>, size_t, udp::endpoint, asio::ip::port_type)>;

	forwarder() = delete;

	forwarder(asio::io_context &io_context, std::shared_ptr<KCP::KCP> input_kcp, process_data_t callback_func, connection_options conn_options) :
		udp_client(io_context,
			std::bind(&forwarder::handle_receive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), conn_options),
		kcp(input_kcp), callback(std::make_shared<process_data_t>(callback_func)) {}

	forwarder(asio::io_context &io_context, sequence_callback_t task_function, std::shared_ptr<KCP::KCP> input_kcp, process_data_t callback_func, connection_options conn_options) :
		udp_client(io_context, task_function, std::bind(&forwarder::handle_receive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), conn_options),
		kcp(input_kcp), callback(std::make_shared<process_data_t>(callback_func)) {}

	forwarder(asio::io_context &io_context, diret_callback_t task_function, std::shared_ptr<KCP::KCP> input_kcp, process_data_t callback_func, connection_options conn_options) :
		udp_client(io_context, task_function, std::bind(&forwarder::handle_receive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), conn_options),
		kcp(input_kcp), callback(std::make_shared<process_data_t>(callback_func)) {}

	void replace_kcp(std::weak_ptr<KCP::KCP> input_kcp)
	{
		kcp = input_kcp;
	}

	void replace_callback(process_data_t callback_func)
	{
		std::atomic_store(&callback, std::make_shared<process_data_t>(callback_func));
	}

	void remove_callback()
	{
		kcp.reset();
		auto empty_callback_func = [](std::shared_ptr<KCP::KCP> kcp, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint ep, asio::ip::port_type num) {};
		std::atomic_store(&callback, std::make_shared<process_data_t>(empty_callback_func));
	}

private:
	void handle_receive(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
	{
		if (paused.load() || stopped.load())
			return;

		std::shared_ptr<KCP::KCP> kcp_ptr = kcp.lock();
		if (kcp_ptr == nullptr)
			return;
		
		std::shared_ptr<process_data_t> cb_ptr = std::atomic_load(&callback);
		(*cb_ptr)(kcp_ptr, std::move(data), data_size, peer, local_port_number);
	}

	std::weak_ptr<KCP::KCP> kcp;
	std::shared_ptr<process_data_t> callback;
};

struct fec_control_data
{
	alignas(64) std::atomic<uint32_t> fec_snd_sn;
	alignas(64) std::atomic<uint32_t> fec_snd_sub_sn;
	std::vector<std::pair<std::unique_ptr<uint8_t[]>, size_t>> fec_snd_cache;
	std::map<uint32_t, std::map<uint16_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>>> fec_rcv_cache;	// uint32_t = snd_sn, uint16_t = sub_sn
	std::unordered_set<uint32_t> fec_rcv_restored;
	fecpp::fec_code fecc;
};

struct encryption_result
{
	std::string error_message;
	std::unique_ptr<uint8_t[]> data;
	size_t data_size;
};

struct decryption_result_listener
{
	std::string error_message;
	std::unique_ptr<uint8_t[]> data;
	size_t data_size;
	udp::endpoint udp_endpoint;
	udp_server *listener;
};

struct decryption_result_forwarder
{
	std::string error_message;
	std::unique_ptr<uint8_t[]> data;
	size_t data_size;
	udp::endpoint udp_endpoint;
	asio::ip::port_type port_number;
};

struct kcp_mappings : public std::enable_shared_from_this<kcp_mappings>
{
	protocol_type connection_protocol;
#ifdef __cpp_lib_atomic_shared_ptr
	alignas(64) std::atomic<std::shared_ptr<udp::endpoint>> ingress_source_endpoint;
	alignas(64) std::atomic<std::shared_ptr<udp::endpoint>> egress_target_endpoint;
	alignas(64) std::atomic<std::shared_ptr<udp::endpoint>> egress_previous_target_endpoint;
#else
	alignas(64) std::shared_ptr<udp::endpoint> ingress_source_endpoint;
	alignas(64) std::shared_ptr<udp::endpoint> egress_target_endpoint;
	alignas(64) std::shared_ptr<udp::endpoint> egress_previous_target_endpoint;
#endif
	alignas(64) std::atomic<size_t> egress_endpoint_index;
	alignas(64) std::shared_ptr<KCP::KCP> ingress_kcp;
	alignas(64) std::shared_ptr<KCP::KCP> egress_kcp;
	alignas(64) std::atomic<udp_server *> ingress_listener;
#ifdef __cpp_lib_atomic_shared_ptr
	alignas(64) std::atomic<std::shared_ptr<forwarder>> egress_forwarder;
#else
	alignas(64) std::shared_ptr<forwarder> egress_forwarder;
#endif
	alignas(64) std::shared_ptr<tcp_session> local_tcp;
	alignas(64) std::shared_ptr<udp_client> local_udp;
	alignas(64) std::atomic<int64_t> handshake_setup_time;
	alignas(64) std::atomic<int64_t> last_data_transfer_time;
	alignas(64) std::atomic<int64_t> hopping_timestamp;
	alignas(64) std::atomic<bool> hopping_available;
	std::weak_ptr<kcp_mappings> hopping_testing_ptr;
	std::shared_ptr<forwarder> hopping_testing_forwarder;
	std::shared_ptr<udp::endpoint> hopping_target_endpoint;
	std::atomic<size_t> hopping_endpoint_index;
	asio::ip::port_type remote_output_port;	// client mode only
	std::string remote_output_address;	// client mode only
	std::function<bool()> mapping_function = empty_mapping_function;	// true: keeps forwarder; false: remove it
	fec_control_data fec_ingress_control;
	fec_control_data fec_egress_control;
	//std::mutex mutex_encryptions_via_listener;
	//std::list<std::future<encryption_result>> encryptions_via_listener;
	//std::mutex mutex_encryptions_via_forwarder;
	//std::list<std::future<encryption_result>> encryptions_via_forwarder;
	//std::mutex mutex_decryptions_from_forwarder;
	//std::list<std::future<decryption_result_forwarder>> decryptions_from_forwarder;
	//std::atomic<int> listener_encryption_task_count;
	//std::atomic<int> forwarder_encryption_task_count;
	//std::atomic<int> forwarder_decryption_task_count;
};

struct mux_records
{
	uint32_t kcp_conv;
	uint32_t connection_id;
	std::shared_ptr<tcp_session> local_tcp;
	std::shared_ptr<udp_client> local_udp;
	udp::endpoint source_endpoint;
	udp_server *listener_ptr;
	std::string custom_output_address;
	alignas(64) std::atomic<int64_t> last_data_transfer_time;
};

struct mux_data_cache
{
	std::unique_ptr<uint8_t[]> data;
	uint8_t *sending_ptr;
	size_t data_size;
};

std::unique_ptr<rfc3489::stun_header> send_stun_3489_request(udp_server &sender, const std::string &stun_host, ip_only_options ip_version_only = ip_only_options::not_set);
std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(udp_server &sender, const std::string &stun_host, ip_only_options ip_version_only = ip_only_options::not_set);
void resend_stun_8489_request(udp_server &sender, const std::string &stun_host, rfc8489::stun_header *header, ip_only_options ip_version_only = ip_only_options::not_set);
template<typename T>
auto split_resolved_addresses(const asio::ip::basic_resolver_results<T> &input_addresses)
{
	std::vector<asio::ip::basic_endpoint<T>> stun_servers_ipv4;
	std::vector<asio::ip::basic_endpoint<T>> stun_servers_ipv6;
	for (auto &target_address : input_addresses)
	{
		auto ep = target_address.endpoint();
		auto ep_address = ep.address();
		if (ep_address.is_v4())
		{
			stun_servers_ipv4.emplace_back(ep);
			continue;
		}

		if (ep_address.is_v6())
		{
			if (ep_address.to_v6().is_v4_mapped())
				stun_servers_ipv4.emplace_back(ep);
			else
				stun_servers_ipv6.emplace_back(target_address.endpoint());
		}
	}

	return std::pair{ stun_servers_ipv4 , stun_servers_ipv6 };
}


#endif // !__CONNECTIONS__
