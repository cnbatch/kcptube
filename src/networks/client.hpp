#pragma once
#include "connections.hpp"
#include "kcp_updater.hpp"

#ifndef __CLIENT_HPP__
#define __CLIENT_HPP__

class client_mode
{
	asio::io_context &io_context;
	KCP::KCPUpdater &kcp_updater;
	user_settings current_settings;
	std::unique_ptr<tcp_server> tcp_access_point;
	std::unique_ptr<udp_server> udp_access_point;

	std::shared_mutex mutex_handshakes;
	std::map<kcp_mappings*, std::shared_ptr<kcp_mappings>> handshakes;

	std::shared_mutex mutex_udp_local_session_map_to_kcp;
	std::map<udp::endpoint, std::shared_ptr<kcp_mappings>> udp_local_session_map_to_kcp;

	std::mutex mutex_udp_address_map_to_handshake;
	std::map<udp::endpoint, std::shared_ptr<kcp_mappings>> udp_address_map_to_handshake;
	std::mutex mutex_udp_seesion_caches;
	std::map<std::shared_ptr<kcp_mappings>, std::vector<std::vector<uint8_t>>, std::owner_less<>> udp_seesion_caches;

	std::shared_mutex mutex_kcp_channels;
	std::map<uint32_t, std::shared_ptr<kcp_mappings>> kcp_channels;

	std::mutex mutex_expiring_kcp;
	std::map<std::shared_ptr<kcp_mappings>, int64_t, std::owner_less<>> expiring_kcp;
	std::mutex mutex_expiring_handshakes;
	std::map<std::shared_ptr<kcp_mappings>, int64_t, std::owner_less<>> expiring_handshakes;
	std::mutex mutex_expiring_forwarders;
	std::map<std::shared_ptr<forwarder>, int64_t, std::owner_less<>> expiring_forwarders;

	std::shared_mutex mutex_target_address;
	std::unique_ptr<asio::ip::address> target_address;

	std::shared_mutex mutex_kcp_keepalive;
	std::map<std::weak_ptr<KCP::KCP>, std::atomic<int64_t>, std::owner_less<>> kcp_keepalive;

	std::shared_mutex mutex_id_map_to_mux_records;
	std::map<uint64_t, std::shared_ptr<mux_records>> id_map_to_mux_records;	// (KCP conv << 32) + connection uid
	std::shared_mutex mutex_udp_map_to_mux_records;
	std::map<udp::endpoint, std::weak_ptr<mux_records>> udp_map_to_mux_records;

	std::shared_mutex mutex_mux_tcp_cache;
	std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> mux_tcp_cache;
	std::map<std::weak_ptr<KCP::KCP>, uint32_t, std::owner_less<>> mux_tcp_cache_max_size;

	std::shared_mutex mutex_mux_udp_cache;
	std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> mux_udp_cache;
	std::map<std::weak_ptr<KCP::KCP>, uint32_t, std::owner_less<>> mux_udp_cache_max_size;

	asio::steady_timer timer_find_expires;
	asio::steady_timer timer_expiring_kcp;
	asio::steady_timer timer_keep_alive;
	ttp::task_group_pool &sequence_task_pool_local;
	ttp::task_group_pool &sequence_task_pool_peer;
	const size_t task_limit;

	void tcp_listener_accept_incoming(std::shared_ptr<tcp_session> incoming_session);
	void tcp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_ptr_weak);
	void udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number);
	void udp_forwarder_incoming(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_forwarder_incoming_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_forwarder_to_disconnecting_tcp(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);

	void tcp_listener_accept_incoming_mux(std::shared_ptr<tcp_session> incoming_session);
	void tcp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_ptr_weak, std::weak_ptr<mux_records> mux_records_ptr_weak);
	void udp_listener_incoming_mux(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number);

	void mux_transfer_data(protocol_type prtcl, kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> buffer_cache, uint8_t *unbacked_data_ptr, size_t unbacked_data_size);
	void mux_cancel_channel(protocol_type prtcl, kcp_mappings *kcp_mappings_ptr, uint8_t *unbacked_data_ptr, size_t unbacked_data_size);
	void mux_move_cached_to_tunnel();
	std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>> mux_move_cached_to_tunnel(std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> &data_queues, int one_x);
	void refresh_mux_queue(std::weak_ptr<KCP::KCP> kcp_ptr_weak);

	std::shared_ptr<KCP::KCP> pick_one_from_kcp_channels(protocol_type prtcl);
	int kcp_sender(const char *buf, int len, void *user);
	bool get_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);
	bool update_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);
	void local_disconnect(std::shared_ptr<KCP::KCP> kcp_ptr, std::shared_ptr<tcp_session> session);
	void local_disconnect(std::shared_ptr<KCP::KCP> kcp_ptr, std::shared_ptr<tcp_session> session, std::shared_ptr<mux_records> mux_records_ptr);
	void process_disconnect(uint32_t conv);
	void process_disconnect(uint32_t conv, tcp_session *session);
	void change_new_port(kcp_mappings *kcp_mappings_ptr);
	bool handshake_timeout_detection(kcp_mappings *kcp_mappings_ptr);

	void delete_mux_records(uint32_t conv);
	void cleanup_expiring_forwarders();
	void cleanup_expiring_data_connections();
	void cleanup_expiring_handshake_connections();
	void cleanup_expiring_mux_records();
	void loop_find_expires();
	void loop_keep_alive();
	void expiring_connection_loops(const asio::error_code &e);
	void find_expires(const asio::error_code &e);
	void time_counting(const asio::error_code &e);
	void keep_alive(const asio::error_code &e);

	std::shared_ptr<kcp_mappings> create_handshake(std::shared_ptr<tcp_session> local_tcp);
	std::shared_ptr<kcp_mappings> create_handshake(udp::endpoint local_endpoint);
	std::shared_ptr<kcp_mappings> create_handshake(protocol_type prtcl);
	void setup_mux_kcp(std::shared_ptr<KCP::KCP> kcp_ptr);
	void establish_mux_channels(uint16_t counts);
	void on_handshake_success(kcp_mappings *handshake_ptr, uint32_t conv, uint16_t start_port, uint16_t end_port);
	void on_handshake_failure(kcp_mappings *handshake_ptr, const std::string &error_message);
	void handle_handshake(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);

	asio::steady_timer timer_speed_count;
	std::atomic<int64_t> input_count;
	std::atomic<int64_t> output_count;
	std::atomic<int64_t> input_count2;
	std::atomic<int64_t> output_count2;

public:
	client_mode() = delete;
	client_mode(const client_mode &) = delete;
	client_mode& operator=(const client_mode &) = delete;

	client_mode(asio::io_context &io_context_ref, KCP::KCPUpdater &kcp_updater_ref,
		ttp::task_group_pool &seq_task_pool_local, ttp::task_group_pool &seq_task_pool_peer,
		size_t task_count_limit, const user_settings &settings) :
		io_context(io_context_ref),
		kcp_updater(kcp_updater_ref),
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

	client_mode(client_mode &&existing_client) noexcept :
		io_context(existing_client.io_context),
		kcp_updater(existing_client.kcp_updater),
		timer_find_expires(std::move(existing_client.timer_find_expires)),
		timer_expiring_kcp(std::move(existing_client.timer_expiring_kcp)),
		timer_keep_alive(std::move(existing_client.timer_keep_alive)),
		sequence_task_pool_local(existing_client.sequence_task_pool_local),
		sequence_task_pool_peer(existing_client.sequence_task_pool_peer),
		task_limit(existing_client.task_limit),
		current_settings(std::move(existing_client.current_settings)), timer_speed_count(io_context), input_count(0), output_count(0)
	{
	}

	~client_mode();

	bool start();
};

#endif // !__CLIENT_HPP__
