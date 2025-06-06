#pragma once
#include <set>
#include "../networks/connections.hpp"
#include "../networks/kcp_updater.hpp"
#include "../networks/mux_tunnel.hpp"

#ifndef __SERVER_HPP__
#define __SERVER_HPP__

class server_mode
{
	friend struct mux_tunnel;
	asio::io_context &io_context;
	KCP::KCPUpdater &kcp_updater;
	user_settings current_settings;
	connection_options conn_options;
	std::unique_ptr<rfc8489::stun_header> stun_header;
	std::atomic<uint16_t> external_ipv4_port;
	std::atomic<uint32_t> external_ipv4_address;
	std::atomic<uint16_t> external_ipv6_port;
	std::shared_mutex mutex_ipv6;
	std::array<uint8_t, 16> external_ipv6_address;
	const std::array<uint8_t, 16> zero_value_array;

	std::vector<std::unique_ptr<udp_server>> udp_servers;

	std::shared_mutex mutex_handshake_channels;
	std::map<udp::endpoint, std::shared_ptr<kcp_mappings>> handshake_channels;
	std::shared_mutex mutex_kcp_channels;
	std::unordered_map<uint32_t, std::shared_ptr<kcp_mappings>> kcp_channels;

	std::mutex mutex_expiring_kcp;
	std::unordered_map<std::shared_ptr<kcp_mappings>, int64_t> expiring_kcp;
	std::mutex mutex_expiring_handshakes;
	std::map<std::weak_ptr<kcp_mappings>, int64_t, std::owner_less<>> expiring_handshakes;

	std::shared_mutex mutex_kcp_keepalive;
	std::map<std::weak_ptr<KCP::KCP>, std::atomic<int64_t>, std::owner_less<>> kcp_keepalive;

	std::mutex mutex_decryptions_from_listener;
	std::list<std::future<decryption_result_listener>> decryptions_from_listener;
	std::atomic<int> listener_decryption_task_count;

	std::unique_ptr<mux_tunnel> mux_tunnels;

	status_records status_counters;

	asio::steady_timer timer_find_expires;
	asio::steady_timer timer_expiring_kcp;
	asio::steady_timer timer_stun;
	asio::steady_timer timer_keep_alive;
	asio::steady_timer timer_status_log;
	//ttp::task_group_pool &sequence_task_pool;
	//ttp::task_thread_pool *parallel_encryption_pool;
	//ttp::task_thread_pool *parallel_decryption_pool;

	std::unique_ptr<udp::endpoint> udp_target;

	void udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, udp_server *listener_ptr);
	void udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, udp_server *listener_ptr);
	//void sequential_extract();
	void tcp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_session_weak);
	void udp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, std::weak_ptr<KCP::KCP> kcp_session_weak);

	void udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, udp_server *listener_ptr);

	bool create_new_tcp_connection(std::shared_ptr<KCP::KCP> handshake_kcp, std::shared_ptr<KCP::KCP> data_kcp, const std::string &user_input_address, asio::ip::port_type user_input_port);
	bool create_new_udp_connection(std::shared_ptr<KCP::KCP> handshake_kcp, std::shared_ptr<KCP::KCP> data_kcp, const udp::endpoint &peer, const std::string &user_input_address, asio::ip::port_type user_input_port);
	void resume_tcp(kcp_mappings* kcp_mappings_ptr);
	void set_kcp_windows(std::weak_ptr<KCP::KCP> handshake_kcp, std::weak_ptr<KCP::KCP> data_ptr_weak);
	std::shared_ptr<mux_records> create_mux_data_tcp_connection(uint32_t connection_id, std::weak_ptr<KCP::KCP> kcp_session_weak, const std::string &user_input_address, asio::ip::port_type user_input_port);
	std::shared_ptr<mux_records> create_mux_data_udp_connection(uint32_t connection_id, std::weak_ptr<KCP::KCP> kcp_session_weak);

	int kcp_sender(const char *buf, int len, void *user);
	//void data_sender(std::shared_ptr<kcp_mappings> kcp_mappings_ptr);
	void data_sender(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> new_buffer, size_t buffer_size);
	//void parallel_encrypt(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size);
	//void parallel_decrypt(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, udp_server *listener_ptr);
	void fec_maker(kcp_mappings *kcp_mappings_ptr, const uint8_t *input_data, int data_size);
	bool fec_find_missings(KCP::KCP *kcp_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count);

	void process_tcp_disconnect(tcp_session *session, std::weak_ptr<KCP::KCP> kcp_ptr_weak, bool inform_peer = true);
	void process_tcp_disconnect(tcp_session *session, std::weak_ptr<KCP::KCP> kcp_ptr_weak, std::weak_ptr<mux_records> mux_records_weak);
	bool update_local_udp_target(std::shared_ptr<udp_client> target_connector);
	void save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port);

	uint32_t generate_token_number();
	void cleanup_expiring_handshake_connections();
	void cleanup_expiring_data_connections();
	void loop_find_expires();
	void loop_keep_alive();
	void send_stun_request(const asio::error_code &e);
	void find_expires(const asio::error_code &e);
	void expiring_kcp_loops(const asio::error_code &e);
	void keep_alive(const asio::error_code &e);
	void log_status(const asio::error_code &e);
	void loop_get_status();

public:
	server_mode() = delete;
	server_mode(const server_mode &) = delete;
	server_mode& operator=(const server_mode &) = delete;

	server_mode(asio::io_context &io_context_ref, KCP::KCPUpdater &kcp_updater_ref, /*ttp::task_group_pool &seq_task_pool, task_pool_colloector &task_pools,*/ const user_settings &settings)
		: io_context(io_context_ref), kcp_updater(kcp_updater_ref),
		timer_find_expires(io_context), timer_expiring_kcp(io_context),
		timer_stun(io_context), timer_keep_alive(io_context),
		timer_status_log(io_context),
		//sequence_task_pool(seq_task_pool),
		//parallel_encryption_pool(task_pools.parallel_encryption_pool),
		//parallel_decryption_pool(task_pools.parallel_decryption_pool),
		external_ipv4_port(0),
		external_ipv4_address(0),
		external_ipv6_port(0),
		external_ipv6_address{},
		zero_value_array{},
		current_settings(settings),
		conn_options{ .ip_version_only = current_settings.ip_version_only,
					  .fib_ingress = current_settings.fib_ingress,
					  .fib_egress = current_settings.fib_egress }
	{}

	server_mode(server_mode &&existing_server) noexcept
		: io_context(existing_server.io_context),
		kcp_updater(existing_server.kcp_updater),
		timer_find_expires(std::move(existing_server.timer_find_expires)),
		timer_expiring_kcp(std::move(existing_server.timer_expiring_kcp)),
		timer_stun(std::move(existing_server.timer_stun)),
		timer_keep_alive(std::move(existing_server.timer_keep_alive)),
		timer_status_log(std::move(existing_server.timer_status_log)),
		//sequence_task_pool(existing_server.sequence_task_pool),
		//parallel_encryption_pool(existing_server.parallel_encryption_pool),
		//parallel_decryption_pool(existing_server.parallel_decryption_pool),
		external_ipv4_port(existing_server.external_ipv4_port.load()),
		external_ipv4_address(existing_server.external_ipv4_address.load()),
		external_ipv6_port(existing_server.external_ipv6_port.load()),
		external_ipv6_address{ existing_server.external_ipv6_address },
		zero_value_array{},
		current_settings(std::move(existing_server.current_settings)),
		conn_options{ .ip_version_only = current_settings.ip_version_only,
					  .fib_ingress = current_settings.fib_ingress,
					  .fib_egress = current_settings.fib_egress }
	{}

	~server_mode();

	bool start();
};

#endif // !__SERVER_HPP__
