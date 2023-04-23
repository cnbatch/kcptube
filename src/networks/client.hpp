#pragma once
#include "connections.hpp"
#include <deque>

#ifndef __CLIENT_HPP__
#define __CLIENT_HPP__

uint16_t generate_new_port_number(uint16_t start_port_num, uint16_t end_port_num);

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

class handshake : public std::enable_shared_from_this<handshake>
{
private:
	asio::io_context &ioc;
	asio::steady_timer timer_data_loop;
	udp::socket udp_socket;
	udp::endpoint remote_server;
	uint16_t destination_port_cache;
	int32_t handshake_timeout;
	int64_t start_time;
	user_settings current_settings;
	std::string destination_address_cache;
	std::atomic<bool> stop;
	std::unique_ptr<KCP::KCP> kcp_ptr;

	void start_receive();
	void handle_receive(std::unique_ptr<uint8_t[]> recv_buffer, const asio::error_code &error, std::size_t bytes_transferred);
	void loop_kcp_update(const asio::error_code &e);
	void cancel_all();

public:
	std::function<void(std::shared_ptr<handshake>, uint32_t, uint16_t, uint16_t)> call_on_success;
	std::function<void(std::shared_ptr<handshake>, const std::string&)> call_on_failure;

	handshake() = delete;
	handshake(const user_settings &settings, asio::io_context &ioctx) :
		ioc(ioctx), timer_data_loop(ioc), udp_socket(ioc), remote_server(), destination_port_cache(0),
		handshake_timeout(30), start_time(0), current_settings(settings),  destination_address_cache{}, stop(false) {}
	~handshake();
	bool send_handshake(protocol_type ptype, const std::string &destination_address, uint16_t destination_port);
	void process_handshake(std::unique_ptr<uint8_t[]> recv_buffer, std::size_t bytes_transferred);
	std::pair<std::string, uint16_t> get_cached_peer();
};


class tcp_to_forwarder
{
	asio::io_context &io_context;
	asio::io_context &network_io;
	user_settings current_settings;
	std::unique_ptr<tcp_server> tcp_access_point;

	std::mutex mutex_id_map_to_forwarder;
	std::map<uint32_t, std::shared_ptr<forwarder>> id_map_to_forwarder;

	std::shared_mutex mutex_id_map_to_session;
	std::map<uint32_t, std::shared_ptr<tcp_session>> id_map_to_session;

	std::map<std::shared_ptr<handshake>, std::shared_ptr<tcp_session>, std::owner_less<>> handshake_map_to_tcp_session;

	std::shared_mutex mutex_kcp_channels;
	std::map<uint32_t, std::pair<std::shared_ptr<KCP::KCP>, std::atomic<uint32_t>>> kcp_channels;

	std::mutex mutex_expiring_kcp;
	std::map<uint32_t, std::pair<std::shared_ptr<KCP::KCP>, int64_t>> expiring_kcpid;
	std::mutex mutex_expiring_forwarders;
	std::map<std::shared_ptr<forwarder>, int64_t, std::owner_less<>> expiring_forwarders;

	std::shared_mutex mutex_udp_target;
	std::unique_ptr<udp::endpoint> udp_target;
	std::unique_ptr<udp::endpoint> previous_udp_target;

	std::shared_mutex mutex_kcp_changeport_timestamp;
	std::map<std::shared_ptr<KCP::KCP>, std::atomic<int64_t>, std::owner_less<>> kcp_changeport_timestamp;

	asio::steady_timer timer_send_data;
	asio::steady_timer timer_find_expires;
	asio::steady_timer timer_expiring_kcp;
	asio::steady_timer timer_change_ports;
	asio::steady_timer timer_keep_alive;
	ttp::task_group_pool &sequence_task_pool_local;
	ttp::task_group_pool &sequence_task_pool_peer;
	const size_t task_limit;

	void tcp_server_accept_incoming(std::shared_ptr<tcp_session> incoming_session);
	void tcp_server_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::shared_ptr<KCP::KCP> kcp_ptr);
	void udp_client_incoming_to_tcp(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_client_incoming_to_tcp_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_client_to_disconnecting_tcp(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	int kcp_sender(const char *buf, int len, void *user);
	udp::endpoint get_remote_address();
	void local_disconnect(std::shared_ptr<KCP::KCP> kcp_ptr, std::shared_ptr<tcp_session> session);
	void process_disconnect(uint32_t conv, tcp_session *session);


	void cleanup_expiring_forwarders();
	void cleanup_expiring_data_connections();
	void loop_update_connections();
	void loop_find_expires();
	void loop_change_new_port();
	void loop_keep_alive();
	void kcp_loop_updates(const asio::error_code &e);
	void expiring_connection_loops(const asio::error_code &e);
	void find_expires(const asio::error_code &e);
	void change_new_port(const asio::error_code & e);
	void time_counting(const asio::error_code &e);
	void keep_alive(const asio::error_code &e);

	void on_handshake_success(std::shared_ptr<handshake> handshake_ptr, uint32_t conv, uint16_t start_port, uint16_t end_port);
	void on_handshake_failure(std::shared_ptr<handshake> handshake_ptr, const std::string &error_message);

	asio::steady_timer timer_speed_count;
	std::atomic<int64_t> input_count;
	std::atomic<int64_t> output_count;
	std::atomic<int64_t> input_count2;
	std::atomic<int64_t> output_count2;

public:
	tcp_to_forwarder() = delete;
	tcp_to_forwarder(const tcp_to_forwarder &) = delete;
	tcp_to_forwarder& operator=(const tcp_to_forwarder &) = delete;

	tcp_to_forwarder(asio::io_context &io_context_ref, asio::io_context &net_io,
		ttp::task_group_pool &seq_task_pool_local, ttp::task_group_pool &seq_task_pool_peer,
		size_t task_count_limit, const user_settings &settings) :
		io_context(io_context_ref),
		network_io(net_io),
		timer_send_data(io_context),
		timer_find_expires(io_context),
		timer_expiring_kcp(io_context),
		timer_change_ports(io_context),
		timer_keep_alive(io_context),
		sequence_task_pool_local(seq_task_pool_local),
		sequence_task_pool_peer(seq_task_pool_peer),
		task_limit(task_count_limit),
		current_settings(settings),
		timer_speed_count(io_context), input_count(0), output_count(0)
	{
	}

	tcp_to_forwarder(tcp_to_forwarder &&existing_client) noexcept :
		io_context(existing_client.io_context),
		network_io(existing_client.network_io),
		timer_send_data(std::move(existing_client.timer_send_data)),
		timer_find_expires(std::move(existing_client.timer_find_expires)),
		timer_expiring_kcp(std::move(existing_client.timer_expiring_kcp)),
		timer_change_ports(std::move(existing_client.timer_change_ports)),
		timer_keep_alive(std::move(existing_client.timer_keep_alive)),
		sequence_task_pool_local(existing_client.sequence_task_pool_local),
		sequence_task_pool_peer(existing_client.sequence_task_pool_peer),
		task_limit(existing_client.task_limit),
		current_settings(std::move(existing_client.current_settings)), timer_speed_count(io_context), input_count(0), output_count(0)
	{
	}

	~tcp_to_forwarder();

	bool start();
};

class udp_to_forwarder
{
	asio::io_context &io_context;
	asio::io_context &network_io;
	user_settings current_settings;
	std::unique_ptr<udp_server> udp_access_point;

	std::mutex mutex_id_map_to_forwarder;
	std::map<uint32_t, std::shared_ptr<forwarder>> id_map_to_forwarder;


	std::shared_mutex mutex_udp_session_map_to_kcp;
	std::map<udp::endpoint, std::shared_ptr<KCP::KCP>> udp_session_map_to_kcp;
	std::shared_mutex mutex_kcp_session_map_to_udp;
	std::map<uint32_t, udp::endpoint> kcp_session_map_to_udp;

	std::mutex mutex_udp_address_map_to_handshake;
	std::map<udp::endpoint, std::shared_ptr<handshake>> udp_address_map_to_handshake;
	std::map<std::shared_ptr<handshake>, udp::endpoint, std::owner_less<>> udp_handshake_map_to_address;
	std::mutex mutex_udp_seesion_caches;
	std::map<std::shared_ptr<handshake>, std::vector<std::vector<uint8_t>>, std::owner_less<>> udp_seesion_caches;

	std::shared_mutex mutex_kcp_channels;
	std::map<uint32_t, std::pair<std::shared_ptr<KCP::KCP>, std::atomic<uint32_t>>> kcp_channels;

	std::mutex mutex_expiring_kcp;
	std::map<uint32_t, std::pair<std::shared_ptr<KCP::KCP>, int64_t>> expiring_kcpid;
	std::mutex mutex_expiring_forwarders;
	std::map<std::shared_ptr<forwarder>, int64_t, std::owner_less<>> expiring_forwarders;

	std::shared_mutex mutex_udp_target;
	std::unique_ptr<udp::endpoint> udp_target;
	std::unique_ptr<udp::endpoint> previous_udp_target;

	std::shared_mutex mutex_kcp_changeport_timestamp;
	std::map<std::shared_ptr<KCP::KCP>, std::atomic<int64_t>, std::owner_less<>> kcp_changeport_timestamp;

	asio::steady_timer timer_send_data;
	asio::steady_timer timer_find_expires;
	asio::steady_timer timer_expiring_kcp;
	asio::steady_timer timer_change_ports;
	asio::steady_timer timer_keep_alive;
	ttp::task_group_pool &sequence_task_pool_local;
	ttp::task_group_pool &sequence_task_pool_peer;
	const size_t task_limit;

	void udp_server_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number);
	void udp_client_incoming_to_udp(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_client_incoming_to_udp_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	int kcp_sender(const char *buf, int len, void *user);
	udp::endpoint get_remote_address();
	void process_disconnect(uint32_t conv);

	void cleanup_expiring_forwarders();
	void cleanup_expiring_data_connections();
	void loop_update_connections();
	void loop_find_expires();
	void loop_change_new_port();
	void loop_keep_alive();
	void kcp_loop_updates(const asio::error_code &e);
	void expiring_kcp_loops(const asio::error_code &e);
	void find_expires(const asio::error_code &e);
	void change_new_port(const asio::error_code &e);
	void keep_alive(const asio::error_code &e);

	void on_handshake_success(std::shared_ptr<handshake> handshake_ptr, uint32_t conv, uint16_t start_port, uint16_t end_port);
	void on_handshake_failure(std::shared_ptr<handshake> handshake_ptr, const std::string &error_message);

public:
	udp_to_forwarder() = delete;
	udp_to_forwarder(const udp_to_forwarder &) = delete;
	udp_to_forwarder& operator=(const udp_to_forwarder &) = delete;

	udp_to_forwarder(asio::io_context &io_context_ref, asio::io_context &net_io,
		ttp::task_group_pool &seq_task_pool_local, ttp::task_group_pool &seq_task_pool_peer,
		size_t task_count_limit, const user_settings &settings) :
		io_context(io_context_ref),
		network_io(net_io),
		timer_send_data(io_context),
		timer_find_expires(io_context), timer_expiring_kcp(io_context),
		timer_change_ports(io_context), timer_keep_alive(io_context),
		sequence_task_pool_local(seq_task_pool_local),
		sequence_task_pool_peer(seq_task_pool_peer),
		task_limit(task_count_limit),
		current_settings(settings) {}

	udp_to_forwarder(udp_to_forwarder &&existing_client) noexcept :
		io_context(existing_client.io_context),
		network_io(existing_client.network_io),
		timer_send_data(std::move(existing_client.timer_send_data)),
		timer_find_expires(std::move(existing_client.timer_find_expires)),
		timer_expiring_kcp(std::move(existing_client.timer_expiring_kcp)),
		timer_change_ports(std::move(existing_client.timer_change_ports)),
		timer_keep_alive(std::move(existing_client.timer_keep_alive)),
		sequence_task_pool_local(existing_client.sequence_task_pool_local),
		sequence_task_pool_peer(existing_client.sequence_task_pool_peer),
		task_limit(existing_client.task_limit),
		current_settings(std::move(existing_client.current_settings)) {}

	~udp_to_forwarder();

	bool start();
};

class client_mode
{
private:
	tcp_to_forwarder tcp_path;
	udp_to_forwarder udp_path;

public:
	client_mode() = delete;
	client_mode(asio::io_context &io_context_ref, asio::io_context &net_io,
		ttp::task_group_pool &seq_task_pool_local, ttp::task_group_pool &seq_task_pool_peer, size_t task_count_limit, const user_settings &settings) :
		tcp_path(io_context_ref, net_io, seq_task_pool_local,  seq_task_pool_peer, task_count_limit, settings),
		udp_path(io_context_ref, net_io, seq_task_pool_local, seq_task_pool_peer, task_count_limit, settings) {}

	bool start()
	{
		return tcp_path.start() && udp_path.start();
	}
};

#endif // !__CLIENT_HPP__
