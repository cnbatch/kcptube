#pragma once

#ifndef __CONNECTIONS__
#define __CONNECTIONS__

#include <functional>
#include <memory>
#include <map>
#include <array>
#include <atomic>
#include <set>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <tuple>
#include <vector>
#include <deque>
#include <asio.hpp>

#include "../shares/share_defines.hpp"
#include "../3rd_party/thread_pool.hpp"
#include "stun.hpp"
#include "kcp.hpp"

constexpr size_t TIME_GAP = std::numeric_limits<uint8_t>::max();	//seconds
constexpr size_t BUFFER_SIZE = 2048u;
constexpr size_t BUFFER_EXPAND_SIZE = 128u;
constexpr size_t RETRY_TIMES = 30u;
constexpr size_t RETRY_WAITS = 2u;
constexpr size_t CLEANUP_WAITS = 15;	// second
constexpr size_t KCP_CLEANUP_WAITS = 4;	// second
constexpr size_t RECEIVER_CLEANUP_WAITS = KCP_CLEANUP_WAITS * 2;	// second
constexpr size_t MUX_CHANNELS_CLEANUP = TIME_GAP >> 3;	//seconds
constexpr size_t HANDSHAKE_TIMEOUT = 30;	//seconds
constexpr size_t KCP_DEFAULT_WINDOW = 32;
constexpr auto EXPRING_UPDATE_INTERVAL = std::chrono::seconds(1);
constexpr auto KEEPALIVE_UPDATE_INTERVAL = std::chrono::seconds(1);
constexpr auto STUN_RESEND = std::chrono::seconds(30);
const asio::ip::udp::endpoint local_empty_target_v4(asio::ip::make_address_v4("127.0.0.1"), 70);
const asio::ip::udp::endpoint local_empty_target_v6(asio::ip::make_address_v6("::1"), 70);

enum class feature : uint8_t
{
	initialise,
	failure,
	disconnect,
	keep_alive,
	raw_data,
	mux_transfer,
	mux_cancel
};

enum class protocol_type : uint8_t { not_care, mux, tcp, udp };

std::string_view feature_to_string(feature ftr);
std::string protocol_type_to_string(protocol_type prtcl);
std::string debug_data_to_string(const uint8_t *data, size_t len);
void debug_print_data(const uint8_t *data, size_t len);
size_t max_capacity_size_by_mtu(size_t mtu_value);

namespace packet
{
#pragma pack (push, 1)
	struct upper_layer
	{
		int64_t timestamp;
		uint8_t feature_value;
		uint8_t protocol_value;
		uint8_t data[1];
	};
	
	struct settings_wrapper
	{
		uint32_t uid;
		uint16_t port_start;
		uint16_t port_end;
	};
	
	struct mux_data_wrapper
	{
		uint32_t connection_id;
		uint8_t data[1];
	};
#pragma pack(pop)

	constexpr size_t empty_data_size = sizeof(upper_layer) + 1;

	int64_t right_now();

	std::vector<uint8_t> create_packet(feature ftr, protocol_type prtcl, const std::vector<uint8_t> &data);
	size_t create_packet(feature ftr, protocol_type prtcl, uint8_t *input_data, size_t data_size);

	std::tuple<int64_t, feature, protocol_type, std::vector<uint8_t>> unpack(const std::vector<uint8_t> &data);
	std::tuple<int64_t, feature, protocol_type, uint8_t*, size_t> unpack(uint8_t *data, size_t length);

	std::tuple<uint32_t, uint16_t, uint16_t> get_initialise_details_from_unpacked_data(const std::vector<uint8_t> &data);
	std::tuple<uint32_t, uint16_t, uint16_t> get_initialise_details_from_unpacked_data(const uint8_t *data);

	void modify_initialise_details_of_unpacked_data(uint8_t *data, uint16_t start_port, uint16_t end_port);

	std::vector<uint8_t> request_initialise_packet(protocol_type prtcl);

	std::vector<uint8_t> response_initialise_packet(protocol_type prtcl, uint32_t uid, uint16_t port_start, uint16_t port_end);

	std::vector<uint8_t> inform_disconnect_packet(protocol_type prtcl);

	std::vector<uint8_t> inform_error_packet(protocol_type prtcl, const std::string &error_msg);

	std::vector<uint8_t> create_data_packet(protocol_type prtcl, const std::vector<uint8_t> &custom_data);
	size_t create_data_packet(protocol_type prtcl, uint8_t *custom_data, size_t length);

	std::vector<uint8_t> create_keep_alive_packet(protocol_type prtcl);

	std::vector<uint8_t> create_mux_data_packet(protocol_type prtcl, uint32_t connection_id, const std::vector<uint8_t> &custom_data);
	size_t create_mux_data_packet(protocol_type prtcl, uint32_t connection_id, uint8_t *input_data, size_t data_size);
	std::tuple<uint32_t, uint8_t*, size_t> extract_mux_data_from_unpacked_data(uint8_t *data, size_t length);

	std::vector<uint8_t> inform_mux_cancel_packet(protocol_type prtcl, uint32_t connection_id);
	uint32_t extract_mux_cancel_from_unpacked_data(uint8_t *data, size_t length);

	std::string get_error_message_from_unpacked_data(const std::vector<uint8_t> &data);
	std::string get_error_message_from_unpacked_data(uint8_t *data, size_t length);

}	// namespace packet


using asio::ip::tcp;
using asio::ip::udp;

class tcp_session;

using tcp_callback_t = std::function<void(std::unique_ptr<uint8_t[]>, size_t, std::shared_ptr<tcp_session>)>;
using udp_callback_t = std::function<void(std::unique_ptr<uint8_t[]>, size_t, udp::endpoint, asio::ip::port_type)>;

void empty_tcp_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, std::shared_ptr<tcp_session> tmp2);
void empty_udp_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint tmp2, asio::ip::port_type tmp3);
void empty_tcp_disconnect(std::shared_ptr<tcp_session> tmp);
int empty_kcp_output(const char *, int, void *);
void empty_task_callback(std::unique_ptr<uint8_t[]> null_data);

class tcp_session : public std::enable_shared_from_this<tcp_session>
{
public:

	tcp_session(asio::io_context &net_io, tcp_callback_t callback_func)
		: network_io(net_io), connection_socket(network_io), task_assigner(nullptr), sequence_task_pool(nullptr), task_limit(0),
		callback(callback_func), callback_for_disconnect(empty_tcp_disconnect),
		last_receive_time(packet::right_now()), last_send_time(packet::right_now()),
		paused(false), stopped(false), session_ending(false) {}
	
	tcp_session(asio::io_context &net_io, ttp::task_group_pool &task_groups, size_t task_count_limit, tcp_callback_t callback_func)
		: network_io(net_io), connection_socket(network_io), task_assigner(nullptr), sequence_task_pool(&task_groups), task_limit(task_count_limit),
		callback(callback_func), callback_for_disconnect(empty_tcp_disconnect),
		last_receive_time(packet::right_now()), last_send_time(packet::right_now()),
		paused(false), stopped(false), session_ending(false) {}
	
	tcp_session(asio::io_context &net_io, ttp::task_thread_pool &task_pool, size_t task_count_limit, tcp_callback_t callback_func)
		: network_io(net_io), connection_socket(network_io), task_assigner(&task_pool), sequence_task_pool(nullptr), task_limit(task_count_limit),
		callback(callback_func), callback_for_disconnect(empty_tcp_disconnect),
		last_receive_time(packet::right_now()), last_send_time(packet::right_now()),
		paused(false), stopped(false), session_ending(false) {}

	void start();

	void session_is_ending(bool set_ending);
	bool session_is_ending();

	void pause(bool set_as_pause);
	void stop();
	bool is_pause();
	bool is_stop();
	bool is_open();

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

	void replace_callback(tcp_callback_t callback_func);

	tcp::socket& socket();

	int64_t time_gap_of_receive();

	int64_t time_gap_of_send();

private:
	void after_write_completed(const asio::error_code &error, size_t bytes_transferred);

	void after_read_completed(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, size_t bytes_transferred);

	void transfer_data_to_next_function(std::unique_ptr<uint8_t[]> buffer_cache, size_t bytes_transferred);

	asio::io_context &network_io;
	ttp::task_thread_pool *task_assigner;
	ttp::task_group_pool *sequence_task_pool;
	tcp::socket connection_socket;
	tcp_callback_t callback;
	std::function<void(std::shared_ptr<tcp_session>)> callback_for_disconnect;
	std::atomic<int64_t> last_receive_time;
	std::atomic<int64_t> last_send_time;
	std::atomic<bool> paused;
	std::atomic<bool> stopped;
	std::atomic<bool> session_ending;
	const size_t task_limit;
};

class tcp_server
{
public:
	using acceptor_callback_t = std::function<void(std::shared_ptr<tcp_session>)>;
	tcp_server() = delete;

	tcp_server(asio::io_context &io_context, const tcp::endpoint &ep,
		acceptor_callback_t acceptor_callback_func, tcp_callback_t callback_func)
		: internal_io_context(io_context), task_assigner(nullptr), sequence_task_pool(nullptr), task_limit(0), tcp_acceptor(io_context),
		acceptor_callback(acceptor_callback_func), session_callback(callback_func)
	{
		acceptor_initialise(ep);
		start_accept();
	}

	tcp_server(asio::io_context &io_context, ttp::task_group_pool &group_pool, size_t task_count_limit, const tcp::endpoint &ep,
		acceptor_callback_t acceptor_callback_func, tcp_callback_t callback_func)
		: internal_io_context(io_context), task_assigner(nullptr), sequence_task_pool(&group_pool), task_limit(task_count_limit), tcp_acceptor(io_context),
		acceptor_callback(acceptor_callback_func), session_callback(callback_func)
	{
		acceptor_initialise(ep);
		start_accept();
	}

	tcp_server(asio::io_context &io_context, ttp::task_thread_pool &task_pool, size_t task_count_limit, const tcp::endpoint &ep,
		acceptor_callback_t acceptor_callback_func, tcp_callback_t callback_func)
		: internal_io_context(io_context), task_assigner(&task_pool), sequence_task_pool(nullptr), task_limit(task_count_limit), tcp_acceptor(io_context),
		acceptor_callback(acceptor_callback_func), session_callback(callback_func)
	{
		acceptor_initialise(ep);
		start_accept();
	}

private:
	void acceptor_initialise(const tcp::endpoint &ep);
	void start_accept();
	void handle_accept(std::shared_ptr<tcp_session> new_connection, const asio::error_code &error_code);

	asio::io_context &internal_io_context;
	ttp::task_thread_pool *task_assigner;
	ttp::task_group_pool *sequence_task_pool;
	tcp::acceptor tcp_acceptor;
	acceptor_callback_t acceptor_callback;
	tcp_callback_t session_callback;
	const size_t task_limit;
	bool paused;
};

class tcp_client
{
public:
	tcp_client() = delete;

	tcp_client(asio::io_context &io_context, tcp_callback_t callback_func, bool v4_only = false)
		: internal_io_context(io_context), resolver(internal_io_context), task_assigner(nullptr), sequence_task_pool(nullptr), task_limit(0), session_callback(callback_func), ipv4_only(v4_only) {}

	tcp_client(asio::io_context &io_context, ttp::task_group_pool &group_pool, size_t task_count_limit, tcp_callback_t callback_func, bool v4_only = false)
		: internal_io_context(io_context), resolver(internal_io_context), task_assigner(nullptr), sequence_task_pool(&group_pool), task_limit(task_count_limit), session_callback(callback_func), ipv4_only(v4_only) {}

	tcp_client(asio::io_context &io_context, ttp::task_thread_pool &task_pool, size_t task_count_limit, tcp_callback_t callback_func, bool v4_only = false)
		: internal_io_context(io_context), resolver(internal_io_context), task_assigner(&task_pool), sequence_task_pool(nullptr), task_limit(task_count_limit), session_callback(callback_func), ipv4_only(v4_only) {}

	std::shared_ptr<tcp_session> connect(asio::error_code &ec);

	bool set_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec);
	bool set_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec);

private:

	asio::io_context &internal_io_context;
	ttp::task_thread_pool *task_assigner;
	ttp::task_group_pool *sequence_task_pool;
	tcp_callback_t session_callback;
	tcp::resolver resolver;
	asio::ip::basic_resolver_results<asio::ip::tcp> remote_endpoints;
	const size_t task_limit;
	const bool ipv4_only;
};



class udp_server
{
public:
	udp_server() = delete;

	udp_server(asio::io_context &io_context, const udp::endpoint &ep, udp_callback_t callback_func)
		: task_assigner(nullptr), sequence_task_pool(nullptr), task_limit(0), port_number(ep.port()), resolver(io_context), connection_socket(io_context), callback(callback_func)
	{
		initialise(ep);
		start_receive();
	}

	udp_server(asio::io_context &io_context, ttp::task_group_pool &group_pool, size_t task_count_limit, const udp::endpoint &ep, udp_callback_t callback_func)
		: task_assigner(nullptr), sequence_task_pool(&group_pool), task_limit(task_count_limit), port_number(ep.port()), resolver(io_context), connection_socket(io_context), callback(callback_func)
	{
		initialise(ep);
		start_receive();
	}

	udp_server(asio::io_context &io_context, ttp::task_thread_pool &task_pool, size_t task_count_limit, const udp::endpoint &ep, udp_callback_t callback_func)
		: task_assigner(&task_pool), sequence_task_pool(nullptr), task_limit(task_count_limit), port_number(ep.port()), resolver(io_context), connection_socket(io_context), callback(callback_func)
	{
		initialise(ep);
		start_receive();
	}

	void continue_receive();

	void async_send_out(std::unique_ptr<std::vector<uint8_t>> data, const udp::endpoint &client_endpoint);
	void async_send_out(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &client_endpoint);
	void async_send_out(std::unique_ptr<uint8_t[]> data, uint8_t *start_pos , size_t data_size, const udp::endpoint &client_endpoint);
	void async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &client_endpoint);
	udp::resolver& get_resolver() { return resolver; }

private:
	void initialise(const udp::endpoint &ep);
	void start_receive();
	void handle_receive(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred);

	asio::ip::port_type get_port_number();

	ttp::task_thread_pool *task_assigner;
	ttp::task_group_pool *sequence_task_pool;
	asio::ip::port_type port_number;
	udp::resolver resolver;
	udp::socket connection_socket;
	udp::endpoint incoming_endpoint;
	udp_callback_t callback;
	const size_t task_limit;
};

class udp_client : public std::enable_shared_from_this<udp_client>
{
public:
	udp_client() = delete;

	udp_client(asio::io_context &io_context, udp_callback_t callback_func, bool v4_only = false)
		: task_assigner(nullptr), sequence_task_pool(nullptr), task_limit(0),
		connection_socket(io_context), resolver(io_context), callback(callback_func),
		last_receive_time(packet::right_now()), last_send_time(packet::right_now()),
		paused(false), stopped(false), ipv4_only(v4_only)
	{
		initialise();
	}

	udp_client(asio::io_context &io_context, ttp::task_group_pool &group_pool, size_t task_count_limit, udp_callback_t callback_func, bool v4_only = false)
		: task_assigner(nullptr), sequence_task_pool(&group_pool), task_limit(task_count_limit),
		connection_socket(io_context), resolver(io_context), callback(callback_func),
		last_receive_time(packet::right_now()), last_send_time(packet::right_now()),
		paused(false), stopped(false), ipv4_only(v4_only)
	{
		initialise();
	}

	udp_client(asio::io_context &io_context, ttp::task_thread_pool &task_pool, size_t task_count_limit, udp_callback_t callback_func, bool v4_only = false)
		: task_assigner(&task_pool), sequence_task_pool(nullptr), task_limit(task_count_limit),
		connection_socket(io_context), resolver(io_context), callback(callback_func),
		last_receive_time(packet::right_now()), last_send_time(packet::right_now()),
		paused(false), stopped(false), ipv4_only(v4_only)
	{
		initialise();
	}

	void pause(bool set_as_pause);
	void stop();
	bool is_pause();
	bool is_stop();

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

	ttp::task_thread_pool *task_assigner;
	ttp::task_group_pool *sequence_task_pool;
	udp::socket connection_socket;
	udp::resolver resolver;
	udp::endpoint incoming_endpoint;
	udp_callback_t callback;
	std::atomic<int64_t> last_receive_time;
	std::atomic<int64_t> last_send_time;
	std::atomic<bool> paused;
	std::atomic<bool> stopped;
	const size_t task_limit;
	const bool ipv4_only;
};

class forwarder : public udp_client
{
public:
	using process_data_t = std::function<void(std::shared_ptr<KCP::KCP>, std::unique_ptr<uint8_t[]>, size_t, udp::endpoint, asio::ip::port_type)>;

	forwarder() = delete;

	forwarder(asio::io_context &io_context, std::shared_ptr<KCP::KCP> input_kcp, process_data_t callback_func, bool v4_only = false) :
		udp_client(io_context,
			std::bind(&forwarder::handle_receive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), v4_only),
		kcp(input_kcp), callback(callback_func) {}

	forwarder(asio::io_context &io_context, ttp::task_group_pool &group_pool, size_t task_count_limit, std::shared_ptr<KCP::KCP> input_kcp, process_data_t callback_func, bool v4_only = false) :
		udp_client(io_context, group_pool, task_count_limit, std::bind(&forwarder::handle_receive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), v4_only),
		kcp(input_kcp), callback(callback_func) {}

	forwarder(asio::io_context &io_context, ttp::task_thread_pool &task_pool, size_t task_count_limit, std::shared_ptr<KCP::KCP> input_kcp, process_data_t callback_func, bool v4_only = false) :
		udp_client(io_context, task_pool, task_count_limit, std::bind(&forwarder::handle_receive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), v4_only),
		kcp(input_kcp), callback(callback_func) {}

	void replace_callback(process_data_t callback_func)
	{
		callback = callback_func;
	}

	void remove_callback()
	{
		kcp.reset();
		callback = [](std::shared_ptr<KCP::KCP> kcp, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint ep, asio::ip::port_type num) {};
	}

private:
	void handle_receive(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
	{
		if (paused.load() || stopped.load())
			return;

		std::shared_ptr<KCP::KCP> kcp_ptr = kcp.lock();
		if (kcp_ptr == nullptr)
			return;
		callback(kcp_ptr, std::move(data), data_size, peer, local_port_number);
	}

	std::weak_ptr<KCP::KCP> kcp;
	process_data_t callback;
};

struct kcp_mappings
{
	protocol_type connection_protocol;
	std::shared_mutex mutex_ingress_endpoint;
	udp::endpoint ingress_source_endpoint;
	std::shared_mutex mutex_egress_endpoint;
	udp::endpoint egress_target_endpoint;
	udp::endpoint egress_previous_target_endpoint;
	std::shared_ptr<KCP::KCP> ingress_kcp;
	std::shared_ptr<KCP::KCP> egress_kcp;
	std::atomic<udp_server *> ingress_listener;
	std::shared_ptr<forwarder> egress_forwarder;
	std::shared_ptr<tcp_session> local_tcp;
	std::shared_ptr<udp_client> local_udp;
	std::atomic<int64_t> changeport_timestamp;
	std::atomic<int64_t> handshake_setup_time;
	std::atomic<int64_t> last_data_transfer_time;
};

struct mux_records
{
	uint32_t kcp_conv;
	uint32_t connection_id;
	std::shared_ptr<tcp_session> local_tcp;
	std::shared_ptr<udp_client> local_udp;
	udp::endpoint source_endpoint;
	std::atomic<int64_t> last_data_transfer_time;
};

struct mux_data_cache
{
	std::unique_ptr<uint8_t[]> data;
	uint8_t *sending_ptr;
	size_t data_size;
};

std::unique_ptr<rfc3489::stun_header> send_stun_3489_request(udp_server &sender, const std::string &stun_host, bool v4_only = false);
std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(udp_server &sender, const std::string &stun_host, bool v4_only = false);
void resend_stun_8489_request(udp_server &sender, const std::string &stun_host, rfc8489::stun_header *header, bool v4_only = false);
uint16_t generate_new_port_number(uint16_t start_port_num, uint16_t end_port_num);


#endif // !__CONNECTIONS__
