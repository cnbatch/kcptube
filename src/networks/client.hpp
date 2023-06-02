#pragma once
#include "connections.hpp"
#include "handshake.hpp"

#ifndef __CLIENT_HPP__
#define __CLIENT_HPP__

class tcp_to_forwarder
{
	asio::io_context &io_context;
	asio::io_context &network_io;
	user_settings current_settings;
	std::unique_ptr<tcp_server> tcp_access_point;

	std::mutex mutex_handshake_map_to_tcp_session;
	std::map<std::shared_ptr<handshake>, std::shared_ptr<tcp_session>, std::owner_less<>> handshake_map_to_tcp_session;

	std::shared_mutex mutex_kcp_channels;
	std::map<uint32_t, std::shared_ptr<kcp_mappings>> kcp_channels;

	std::mutex mutex_expiring_kcp;
	std::map<std::shared_ptr<kcp_mappings>, int64_t, std::owner_less<>> expiring_kcp;
	std::mutex mutex_expiring_forwarders;
	std::map<std::shared_ptr<forwarder>, int64_t, std::owner_less<>> expiring_forwarders;

	std::shared_mutex mutex_target_address;
	std::unique_ptr<asio::ip::address> target_address;

	std::shared_mutex mutex_kcp_looping;
	std::map<std::weak_ptr<KCP::KCP>, std::atomic<uint32_t>, std::owner_less<>> kcp_looping;

	std::shared_mutex mutex_kcp_keepalive;
	std::map<std::weak_ptr<KCP::KCP>, std::atomic<int64_t>, std::owner_less<>> kcp_keepalive;

	asio::steady_timer timer_send_data;
	asio::steady_timer timer_find_expires;
	asio::steady_timer timer_expiring_kcp;
	asio::steady_timer timer_keep_alive;
	ttp::task_group_pool &sequence_task_pool_local;
	ttp::task_group_pool &sequence_task_pool_peer;
	const size_t task_limit;

	void tcp_listener_accept_incoming(std::shared_ptr<tcp_session> incoming_session);
	void tcp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::shared_ptr<KCP::KCP> kcp_ptr);
	void udp_forwarder_incoming_to_tcp(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_forwarder_incoming_to_tcp_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_forwarder_to_disconnecting_tcp(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	int kcp_sender(const char *buf, int len, void *user);
	bool save_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);
	bool update_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);
	void local_disconnect(std::shared_ptr<KCP::KCP> kcp_ptr, std::shared_ptr<tcp_session> session);
	void process_disconnect(uint32_t conv, tcp_session *session);
	void change_new_port(kcp_mappings *kcp_mappings_ptr);

	void cleanup_expiring_forwarders();
	void cleanup_expiring_data_connections();
	void loop_update_connections();
	void loop_find_expires();
	void loop_keep_alive();
	void kcp_loop_updates(const asio::error_code &e);
	void expiring_connection_loops(const asio::error_code &e);
	void find_expires(const asio::error_code &e);
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

	std::shared_mutex mutex_udp_local_session_map_to_kcp;
	std::map<udp::endpoint, std::shared_ptr<kcp_mappings>> udp_local_session_map_to_kcp;

	std::mutex mutex_udp_address_map_to_handshake;
	std::map<udp::endpoint, std::shared_ptr<handshake>> udp_address_map_to_handshake;
	std::map<std::shared_ptr<handshake>, udp::endpoint, std::owner_less<>> udp_handshake_map_to_address;
	std::mutex mutex_udp_seesion_caches;
	std::map<std::shared_ptr<handshake>, std::vector<std::vector<uint8_t>>, std::owner_less<>> udp_seesion_caches;

	std::shared_mutex mutex_kcp_channels;
	std::map<uint32_t, std::shared_ptr<kcp_mappings>> kcp_channels;

	std::mutex mutex_expiring_kcp;
	std::map<std::shared_ptr<kcp_mappings>, int64_t, std::owner_less<>> expiring_kcp;
	std::mutex mutex_expiring_forwarders;
	std::map<std::shared_ptr<forwarder>, int64_t, std::owner_less<>> expiring_forwarders;

	std::shared_mutex mutex_target_address;
	std::unique_ptr<asio::ip::address> target_address;

	std::shared_mutex mutex_kcp_looping;
	std::map<std::weak_ptr<KCP::KCP>, std::atomic<uint32_t>, std::owner_less<>> kcp_looping;

	std::shared_mutex mutex_kcp_keepalive;
	std::map<std::weak_ptr<KCP::KCP>, std::atomic<int64_t>, std::owner_less<>> kcp_keepalive;

	asio::steady_timer timer_send_data;
	asio::steady_timer timer_find_expires;
	asio::steady_timer timer_expiring_kcp;
	asio::steady_timer timer_keep_alive;
	ttp::task_group_pool &sequence_task_pool_local;
	ttp::task_group_pool &sequence_task_pool_peer;
	const size_t task_limit;

	void udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number);
	void udp_forwarder_incoming_to_udp(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_forwarder_incoming_to_udp_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	int kcp_sender(const char *buf, int len, void *user);
	bool save_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);
	bool update_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);
	void process_disconnect(uint32_t conv);
	void change_new_port(kcp_mappings *kcp_mappings_ptr);

	void cleanup_expiring_forwarders();
	void cleanup_expiring_data_connections();
	void loop_update_connections();
	void loop_find_expires();
	void loop_keep_alive();
	void kcp_loop_updates(const asio::error_code &e);
	void expiring_kcp_loops(const asio::error_code &e);
	void find_expires(const asio::error_code &e);
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
		timer_find_expires(io_context),
		timer_expiring_kcp(io_context),
		timer_keep_alive(io_context),
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
