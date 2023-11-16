#pragma once
#include "connections.hpp"
#include "kcp_updater.hpp"
#include "mux_tunnel.hpp"

#ifndef __CLIENT_HPP__
#define __CLIENT_HPP__

class client_mode
{
	friend struct mux_tunnel;
	asio::io_context &io_context;
	KCP::KCPUpdater &kcp_updater;
	const std::unique_ptr<ttp::task_group_pool> &kcp_data_sender;
	user_settings current_settings;
	std::unordered_map<asio::ip::port_type, std::unique_ptr<tcp_server>> tcp_access_points;
	std::unordered_map<asio::ip::port_type, std::unique_ptr<udp_server>> udp_access_points;

	std::shared_mutex mutex_handshakes;
	std::unordered_map<kcp_mappings*, std::shared_ptr<kcp_mappings>> handshakes;

	std::shared_mutex mutex_udp_local_session_map_to_kcp;
	std::map<udp::endpoint, std::shared_ptr<kcp_mappings>> udp_local_session_map_to_kcp;

	std::mutex mutex_udp_address_map_to_handshake;
	std::map<udp::endpoint, std::shared_ptr<kcp_mappings>> udp_address_map_to_handshake;
	std::mutex mutex_udp_seesion_caches;
	std::unordered_map<std::shared_ptr<kcp_mappings>, std::vector<std::vector<uint8_t>>> udp_seesion_caches;

	std::shared_mutex mutex_kcp_channels;
	std::unordered_map<uint32_t, std::shared_ptr<kcp_mappings>> kcp_channels;

	std::mutex mutex_expiring_kcp;
	std::unordered_map<std::shared_ptr<kcp_mappings>, int64_t> expiring_kcp;
	std::mutex mutex_expiring_handshakes;
	std::unordered_map<std::shared_ptr<kcp_mappings>, int64_t> expiring_handshakes;
	std::mutex mutex_expiring_forwarders;
	std::unordered_map<std::shared_ptr<forwarder>, int64_t> expiring_forwarders;

	std::shared_mutex mutex_target_address;
	std::unique_ptr<asio::ip::address> target_address;

	std::shared_mutex mutex_kcp_keepalive;
	std::map<std::weak_ptr<KCP::KCP>, std::atomic<int64_t>, std::owner_less<>> kcp_keepalive;

	std::unique_ptr<mux_tunnel> mux_tunnels;

	asio::steady_timer timer_find_expires;
	asio::steady_timer timer_expiring_kcp;
	asio::steady_timer timer_keep_alive;
	ttp::task_group_pool &sequence_task_pool_local;
	ttp::task_group_pool &sequence_task_pool_peer;
	const size_t task_limit;

	bool start_test_only();
	bool normal_start();
	void multiple_listening_tcp(user_settings::user_input_address_mapping &user_input_mappings, bool mux_enabled);
	void multiple_listening_udp(user_settings::user_input_address_mapping &user_input_mappings, bool mux_enabled);

	void tcp_listener_accept_incoming(std::shared_ptr<tcp_session> incoming_session, const std::string &remote_output_address, asio::ip::port_type remote_output_port);
	void tcp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_ptr_weak);
	void udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, const std::string &remote_output_address, asio::ip::port_type remote_output_port);

	void udp_forwarder_incoming(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_forwarder_incoming_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_forwarder_to_disconnecting_tcp(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);

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

	void cleanup_expiring_forwarders();
	void cleanup_expiring_data_connections();
	void cleanup_expiring_handshake_connections();
	void loop_find_expires();
	void loop_keep_alive();
	void expiring_connection_loops(const asio::error_code &e);
	void find_expires(const asio::error_code &e);
	void keep_alive(const asio::error_code &e);

	std::shared_ptr<kcp_mappings> create_handshake(std::shared_ptr<tcp_session> local_tcp, const std::string &remote_output_address, asio::ip::port_type remote_output_port);
	std::shared_ptr<kcp_mappings> create_handshake(udp::endpoint local_endpoint, const std::string &remote_output_address, asio::ip::port_type remote_output_port);
	std::shared_ptr<kcp_mappings> create_handshake(feature ftr, protocol_type prtcl, const std::string &remote_output_address, asio::ip::port_type remote_output_port);
	void resume_tcp(kcp_mappings *kcp_mappings_ptr);
	void set_kcp_windows(std::weak_ptr<KCP::KCP> handshake_kcp, std::weak_ptr<KCP::KCP> data_ptr_weak);
	void establish_mux_channels(uint16_t counts);
	void on_handshake_success(kcp_mappings *handshake_ptr, const packet::settings_wrapper &basic_settings);
	void on_handshake_failure(kcp_mappings *handshake_ptr, const std::string &error_message);
	void on_handshake_test_success(kcp_mappings *handshake_ptr);
	void handshake_test_failure(kcp_mappings *handshake_ptr);
	void handshake_test_cleanup(kcp_mappings *handshake_ptr);
	void handle_handshake(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);

public:
	client_mode() = delete;
	client_mode(const client_mode &) = delete;
	client_mode& operator=(const client_mode &) = delete;

	client_mode(asio::io_context &io_context_ref, KCP::KCPUpdater &kcp_updater_ref, const std::unique_ptr<ttp::task_group_pool> &kcp_data_sender_ref,
		ttp::task_group_pool &seq_task_pool_local, ttp::task_group_pool &seq_task_pool_peer, size_t task_count_limit, const user_settings &settings) :
		io_context(io_context_ref),
		kcp_updater(kcp_updater_ref),
		kcp_data_sender(kcp_data_sender_ref),
		timer_find_expires(io_context),
		timer_expiring_kcp(io_context),
		timer_keep_alive(io_context),
		sequence_task_pool_local(seq_task_pool_local),
		sequence_task_pool_peer(seq_task_pool_peer),
		task_limit(task_count_limit),
		current_settings(settings) {}

	client_mode(client_mode &&existing_client) noexcept :
		io_context(existing_client.io_context),
		kcp_updater(existing_client.kcp_updater),
		kcp_data_sender(existing_client.kcp_data_sender),
		timer_find_expires(std::move(existing_client.timer_find_expires)),
		timer_expiring_kcp(std::move(existing_client.timer_expiring_kcp)),
		timer_keep_alive(std::move(existing_client.timer_keep_alive)),
		sequence_task_pool_local(existing_client.sequence_task_pool_local),
		sequence_task_pool_peer(existing_client.sequence_task_pool_peer),
		task_limit(existing_client.task_limit),
		current_settings(std::move(existing_client.current_settings)) {}

	~client_mode();

	bool start();
};

#endif // !__CLIENT_HPP__
