#pragma once
#include <set>
#include "../networks/connections.hpp"
#include "../networks/kcp_updater.hpp"

#ifndef __RELAY_HPP__
#define __RELAY_HPP__

class relay_mode
{
	asio::io_context &io_context;
	KCP::KCPUpdater &kcp_updater;
	user_settings current_settings;
	std::unique_ptr<rfc8489::stun_header> stun_header;
	std::atomic<uint16_t> external_ipv4_port;
	std::atomic<uint32_t> external_ipv4_address;
	std::atomic<uint16_t> external_ipv6_port;
	std::shared_mutex mutex_ipv6;
	std::array<uint8_t, 16> external_ipv6_address;
	const std::array<uint8_t, 16> zero_value_array;
#ifdef __cpp_lib_atomic_shared_ptr
	std::atomic<std::shared_ptr<std::vector<uint16_t>>> remote_destination_ports;
#else
	std::shared_ptr<std::vector<uint16_t>> remote_destination_ports;
#endif

	std::vector<std::unique_ptr<udp_server>> udp_servers;

	std::shared_mutex mutex_id_map_to_both_sides;
	std::unordered_map<uint32_t, std::shared_ptr<kcp_mappings>> id_map_to_both_sides;

	std::shared_mutex mutex_handshake_ingress_map_to_channels;
	std::map<udp::endpoint, std::shared_ptr<kcp_mappings>> handshake_ingress_map_to_channels;

	std::mutex mutex_expiring_kcp;
	std::unordered_map<std::shared_ptr<kcp_mappings>, int64_t> expiring_kcp;
	std::mutex mutex_expiring_handshakes;
	std::map<std::weak_ptr<kcp_mappings>, int64_t, std::owner_less<>> expiring_handshakes;

	std::mutex mutex_expiring_forwarders;
	std::unordered_map<std::shared_ptr<forwarder>, int64_t> expiring_forwarders;

	std::shared_mutex mutex_kcp_keepalive_ingress;
	std::map<std::weak_ptr<KCP::KCP>, std::atomic<int64_t>, std::owner_less<>> kcp_keepalive_ingress;
	std::shared_mutex mutex_kcp_keepalive_egress;
	std::map<std::weak_ptr<KCP::KCP>, std::atomic<int64_t>, std::owner_less<>> kcp_keepalive_egress;

	std::mutex mutex_decryptions_from_listener;
	std::list<std::future<decryption_result_listener>> decryptions_from_listener;
	std::atomic<int> listener_decryption_task_count;

	status_records listener_status_counters;
	status_records forwarder_status_counters;

	asio::steady_timer timer_find_expires;
	asio::steady_timer timer_expiring_kcp;
	asio::steady_timer timer_stun;
	asio::steady_timer timer_keep_alive_ingress;
	asio::steady_timer timer_keep_alive_egress;
	asio::steady_timer timer_status_log;
	//ttp::task_group_pool &sequence_task_pool;
	//ttp::task_thread_pool *listener_parallels;
	//ttp::task_thread_pool *forwarder_parallels;

#ifdef __cpp_lib_atomic_shared_ptr
	std::deque<std::atomic<std::shared_ptr<asio::ip::address>>> target_address;
#else
	std::deque<std::shared_ptr<asio::ip::address>> target_address;
#endif

	void udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, udp_server *listener_ptr);
	void udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, udp_server *listener_ptr);
	//void sequential_extract();
	void udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, udp_server *listener_ptr);
	void udp_forwarder_incoming(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_forwarder_incoming_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	//void udp_forwarder_incoming_unpack(std::shared_ptr<KCP::KCP> kcp_ptr);
	void change_new_port(kcp_mappings *kcp_mappings_ptr);
	void test_before_change(kcp_mappings *kcp_mappings_ptr);
	void switch_new_port(kcp_mappings *kcp_mappings_ptr);
	void create_kcp_bidirections(uint32_t new_id, kcp_mappings *handshake_kcp_mappings_ptr);
	std::shared_ptr<kcp_mappings> create_test_handshake();
	void handle_test_handshake(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	bool handshake_timeout_detection(kcp_mappings *kcp_mappings_ptr);
	int kcp_sender_via_listener(const char *buf, int len, void *user);
	int kcp_sender_via_forwarder(const char *buf, int len, void *user);
	std::shared_ptr<KCP::KCP> verify_kcp_conv(std::shared_ptr<KCP::KCP> kcp_ptr, uint32_t conv);
	//void data_sender_via_listener(std::shared_ptr<kcp_mappings> kcp_mappings_ptr);
	void data_sender_via_listener(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> new_buffer, size_t buffer_size);
	//void parallel_encrypt_via_listener(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size);
	//void parallel_decrypt_via_listener(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint& peer, udp_server *listener);
	//void data_sender_via_forwarder(kcp_mappings *kcp_mappings_ptr);
	void data_sender_via_forwarder(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> new_buffer, size_t buffer_size);
	//void parallel_encrypt_via_forwarder(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size);
	//void parallel_decrypt_via_forwarder(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	std::pair<bool, size_t> fec_find_missings(KCP::KCP *kcp_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count);
	void fec_maker_via_listener(kcp_mappings *kcp_mappings_ptr, const uint8_t *input_data, int data_size);
	void fec_maker_via_forwarder(kcp_mappings *kcp_mappings_ptr, const uint8_t *input_data, int data_size);

	void process_disconnect(std::shared_ptr<KCP::KCP> kcp_ptr, const char *buffer, size_t len);
	std::unique_ptr<udp::endpoint> get_udp_target(std::shared_ptr<forwarder> target_connector, size_t index);
	std::unique_ptr<udp::endpoint> update_udp_target(std::shared_ptr<forwarder> target_connector, size_t index);
	void save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port);
	
	void cleanup_expiring_handshake_connections();
	void cleanup_expiring_forwarders();
	void cleanup_expiring_data_connections();
	void loop_find_expires();
	void loop_keep_alive_ingress();
	void loop_keep_alive_egress();
	void send_stun_request(const asio::error_code &e);
	void find_expires(const asio::error_code &e);
	void expiring_kcp_loops(const asio::error_code &e);
	void keep_alive_ingress(const asio::error_code &e);
	void keep_alive_egress(const asio::error_code &e);
	void log_status(const asio::error_code &e);
	void loop_get_status();

public:
	relay_mode() = delete;
	relay_mode(const relay_mode &) = delete;
	relay_mode& operator=(const relay_mode &) = delete;

	relay_mode(asio::io_context &io_context_ref, KCP::KCPUpdater &kcp_updater_ref, /*ttp::task_group_pool &seq_task_pool, task_pool_colloector &task_pools,*/ const user_settings &settings)
		: io_context(io_context_ref), kcp_updater(kcp_updater_ref),
		timer_find_expires(io_context), timer_expiring_kcp(io_context),
		timer_stun(io_context),
		timer_keep_alive_ingress(io_context), timer_keep_alive_egress(io_context),
		timer_status_log(io_context),
		//sequence_task_pool(seq_task_pool),
		//listener_parallels(task_pools.listener_parallels),
		//forwarder_parallels(task_pools.forwarder_parallels),
		external_ipv4_port(0),
		external_ipv4_address(0),
		external_ipv6_port(0),
		external_ipv6_address{},
		zero_value_array{},
		current_settings(settings) {}

	relay_mode(relay_mode &&existing_relay) noexcept
		: io_context(existing_relay.io_context),
		kcp_updater(existing_relay.kcp_updater),
		timer_find_expires(std::move(existing_relay.timer_find_expires)),
		timer_expiring_kcp(std::move(existing_relay.timer_expiring_kcp)),
		timer_stun(std::move(existing_relay.timer_stun)),
		timer_keep_alive_ingress(std::move(existing_relay.timer_keep_alive_ingress)),
		timer_keep_alive_egress(std::move(existing_relay.timer_keep_alive_egress)),
		timer_status_log(std::move(existing_relay.timer_status_log)),
		//sequence_task_pool(existing_relay.sequence_task_pool),
		//listener_parallels(existing_relay.listener_parallels),
		//forwarder_parallels(existing_relay.forwarder_parallels),
		external_ipv4_port(existing_relay.external_ipv4_port.load()),
		external_ipv4_address(existing_relay.external_ipv4_address.load()),
		external_ipv6_port(existing_relay.external_ipv6_port.load()),
		external_ipv6_address{ existing_relay.external_ipv6_address },
		zero_value_array{},
		current_settings(std::move(existing_relay.current_settings)) {}

	~relay_mode();

	bool start();
};






#endif