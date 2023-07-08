#pragma once
#include <set>
#include "connections.hpp"
#include "kcp_updater.hpp"

#ifndef __SERVER_HPP__
#define __SERVER_HPP__

class server_mode
{
	asio::io_context &io_context;
	KCP::KCPUpdater &kcp_updater;
	const std::unique_ptr<ttp::task_group_pool> &kcp_data_sender;
	user_settings current_settings;
	std::unique_ptr<rfc8489::stun_header> stun_header;
	std::atomic<uint16_t> external_ipv4_port;
	std::atomic<uint32_t> external_ipv4_address;
	std::atomic<uint16_t> external_ipv6_port;
	std::shared_mutex mutex_ipv6;
	std::array<uint8_t, 16> external_ipv6_address;
	const std::array<uint8_t, 16> zero_value_array;

	std::map<asio::ip::port_type, std::unique_ptr<udp_server>> udp_servers;

	std::shared_mutex mutex_handshake_channels;
	std::map<udp::endpoint, std::shared_ptr<kcp_mappings>> handshake_channels;
	std::shared_mutex mutex_kcp_channels;
	std::map<uint32_t, std::shared_ptr<kcp_mappings>> kcp_channels;

	std::mutex mutex_expiring_kcp;
	std::map<std::shared_ptr<kcp_mappings>, int64_t, std::owner_less<>> expiring_kcp;
	std::mutex mutex_expiring_handshakes;
	std::map<std::weak_ptr<kcp_mappings>, int64_t, std::owner_less<>> expiring_handshakes;

	std::shared_mutex mutex_kcp_keepalive;
	std::map<std::weak_ptr<KCP::KCP>, std::atomic<int64_t>, std::owner_less<>> kcp_keepalive;

	std::shared_mutex mutex_id_map_to_mux_records;
	std::map<uint64_t, std::shared_ptr<mux_records>> id_map_to_mux_records;	// (KCP conv << 32) + connection uid

	std::shared_mutex mutex_expiring_mux_records;
	std::map<uint64_t, std::shared_ptr<mux_records>> expiring_mux_records;	// (KCP conv << 32) + connection uid

	std::shared_mutex mutex_mux_tcp_cache;
	std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> mux_tcp_cache;
	std::map<std::weak_ptr<KCP::KCP>, uint32_t, std::owner_less<>> mux_tcp_cache_max_size;

	std::shared_mutex mutex_mux_udp_cache;
	std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> mux_udp_cache;
	std::map<std::weak_ptr<KCP::KCP>, uint32_t, std::owner_less<>> mux_udp_cache_max_size;

	asio::steady_timer timer_find_expires;
	asio::steady_timer timer_expiring_kcp;
	asio::steady_timer timer_stun;
	asio::steady_timer timer_keep_alive;
	ttp::task_group_pool &sequence_task_pool_local;
	ttp::task_group_pool &sequence_task_pool_peer;
	const size_t task_limit;

	std::unique_ptr<udp::endpoint> udp_target;

	void udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type server_port_number);
	void udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type server_port_number);
	void tcp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_session_weak);
	void udp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, std::weak_ptr<KCP::KCP> kcp_session_weak);
	void tcp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_session_weak, std::weak_ptr<mux_records> mux_records_weak);
	void udp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, std::weak_ptr<KCP::KCP> kcp_session_weak, std::weak_ptr<mux_records> mux_records_weak);

	void udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number);

	void mux_transfer_data(protocol_type prtcl, std::shared_ptr<kcp_mappings> kcp_mappings_ptr, std::unique_ptr<uint8_t[]> buffer_cache, uint8_t *unbacked_data_ptr, size_t unbacked_data_size);
	void mux_cancel_channel(protocol_type prtcl, std::shared_ptr<kcp_mappings> kcp_mappings_ptr, uint8_t *unbacked_data_ptr, size_t unbacked_data_size);

	bool create_new_tcp_connection(std::shared_ptr<KCP::KCP> handshake_kcp, std::shared_ptr<KCP::KCP> data_kcp);
	bool create_new_udp_connection(std::shared_ptr<KCP::KCP> handshake_kcp, std::shared_ptr<KCP::KCP> data_kcp, const udp::endpoint &peer);
	void resume_tcp(kcp_mappings* kcp_mappings_ptr);
	void set_kcp_windows(std::weak_ptr<KCP::KCP> handshake_kcp, std::weak_ptr<KCP::KCP> data_ptr_weak);
	void setup_mux_kcp(std::shared_ptr<KCP::KCP> data_kcp);
	std::shared_ptr<mux_records> create_mux_data_tcp_connection(uint32_t connection_id, std::weak_ptr<KCP::KCP> kcp_session_weak);
	std::shared_ptr<mux_records> create_mux_data_udp_connection(uint32_t connection_id, std::weak_ptr<KCP::KCP> kcp_session_weak);
	void mux_move_cached_to_tunnel(bool skip_kcp_update = false);
	std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>> mux_move_cached_to_tunnel(std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> &data_queues, int one_x);
	void refresh_mux_queue(std::weak_ptr<KCP::KCP> kcp_ptr_weak);

	int kcp_sender(const char *buf, int len, void *user);

	void process_tcp_disconnect(tcp_session *session, std::weak_ptr<KCP::KCP> kcp_ptr_weak);
	void process_tcp_disconnect(tcp_session *session, std::weak_ptr<KCP::KCP> kcp_ptr_weak, std::weak_ptr<mux_records> mux_records_weak);
	bool update_local_udp_target(std::shared_ptr<udp_client> target_connector);
	void save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port);

	uint32_t generate_token_number();
	void delete_mux_records(uint32_t conv);
	void cleanup_expiring_handshake_connections();
	void cleanup_expiring_data_connections();
	void cleanup_expiring_mux_records();
	void loop_find_expires();
	void loop_keep_alive();
	void send_stun_request(const asio::error_code &e);
	void find_expires(const asio::error_code &e);
	void expiring_kcp_loops(const asio::error_code &e);
	void keep_alive(const asio::error_code &e);

public:
	server_mode() = delete;
	server_mode(const server_mode &) = delete;
	server_mode& operator=(const server_mode &) = delete;

	server_mode(asio::io_context &io_context_ref, KCP::KCPUpdater &kcp_updater_ref, const std::unique_ptr<ttp::task_group_pool> &kcp_data_sender_ref,
		ttp::task_group_pool &seq_task_pool_local,ttp::task_group_pool &seq_task_pool_peer, size_t task_count_limit, const user_settings &settings)
		: io_context(io_context_ref), kcp_updater(kcp_updater_ref),
		kcp_data_sender(kcp_data_sender_ref),
		timer_find_expires(io_context), timer_expiring_kcp(io_context),
		timer_stun(io_context), timer_keep_alive(io_context),
		sequence_task_pool_local(seq_task_pool_local),
		sequence_task_pool_peer(seq_task_pool_peer),
		task_limit(task_count_limit),
		external_ipv4_port(0),
		external_ipv4_address(0),
		external_ipv6_port(0),
		external_ipv6_address{},
		zero_value_array{},
		current_settings(settings) {}

	server_mode(server_mode &&existing_server) noexcept
		: io_context(existing_server.io_context),
		kcp_updater(existing_server.kcp_updater),
		kcp_data_sender(existing_server.kcp_data_sender),
		timer_find_expires(std::move(existing_server.timer_find_expires)),
		timer_expiring_kcp(std::move(existing_server.timer_expiring_kcp)),
		timer_stun(std::move(existing_server.timer_stun)),
		timer_keep_alive(std::move(existing_server.timer_keep_alive)),
		sequence_task_pool_local(existing_server.sequence_task_pool_local),
		sequence_task_pool_peer(existing_server.sequence_task_pool_peer),
		task_limit(existing_server.task_limit),
		external_ipv4_port(existing_server.external_ipv4_port.load()),
		external_ipv4_address(existing_server.external_ipv4_address.load()),
		external_ipv6_port(existing_server.external_ipv6_port.load()),
		external_ipv6_address{ existing_server.external_ipv6_address },
		zero_value_array{},
		current_settings(std::move(existing_server.current_settings)) {}

	~server_mode();

	bool start();
};

#endif // !__SERVER_HPP__
