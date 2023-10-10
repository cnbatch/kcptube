#pragma once
#include <set>
#include "connections.hpp"
#include "kcp_updater.hpp"

#ifndef __RELAY_HPP__
#define __RELAY_HPP__

class relay_mode
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

	std::unordered_map<asio::ip::port_type, std::unique_ptr<udp_server>> udp_servers;

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

	asio::steady_timer timer_find_expires;
	asio::steady_timer timer_expiring_kcp;
	asio::steady_timer timer_stun;
	asio::steady_timer timer_keep_alive_ingress;
	asio::steady_timer timer_keep_alive_egress;
	ttp::task_group_pool &sequence_task_pool_local;
	ttp::task_group_pool &sequence_task_pool_peer;
	const size_t task_limit;

	std::shared_mutex mutex_egress_target_address;
	std::unique_ptr<asio::ip::address> target_address;

	void udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type server_port_number);
	void udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type server_port_number);
	void udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type server_port_number);
	void udp_forwarder_incoming(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_forwarder_incoming_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void change_new_port(kcp_mappings *kcp_mappings_ptr);
	void create_kcp_bidirections(uint32_t new_id, kcp_mappings *handshake_kcp_mappings_ptr);
	int kcp_sender_via_listener(const char *buf, int len, void *user);
	int kcp_sender_via_forwarder(const char *buf, int len, void *user);

	void process_disconnect(std::shared_ptr<KCP::KCP> kcp_ptr, const char *buffer, size_t len);
	bool get_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);
	bool update_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);
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

public:
	relay_mode() = delete;
	relay_mode(const relay_mode &) = delete;
	relay_mode& operator=(const relay_mode &) = delete;

	relay_mode(asio::io_context &io_context_ref, KCP::KCPUpdater &kcp_updater_ref, const std::unique_ptr<ttp::task_group_pool> &kcp_data_sender_ref,
		ttp::task_group_pool &seq_task_pool_local, ttp::task_group_pool &seq_task_pool_peer, size_t task_count_limit, const user_settings &settings)
		: io_context(io_context_ref), kcp_updater(kcp_updater_ref),
		kcp_data_sender(kcp_data_sender_ref),
		timer_find_expires(io_context), timer_expiring_kcp(io_context),
		timer_stun(io_context),
		timer_keep_alive_ingress(io_context),timer_keep_alive_egress(io_context),
		sequence_task_pool_local(seq_task_pool_local),
		sequence_task_pool_peer(seq_task_pool_peer),
		task_limit(task_count_limit),
		external_ipv4_port(0),
		external_ipv4_address(0),
		external_ipv6_port(0),
		external_ipv6_address{},
		zero_value_array{},
		current_settings(settings) {}

	relay_mode(relay_mode &&existing_relay) noexcept
		: io_context(existing_relay.io_context),
		kcp_updater(existing_relay.kcp_updater),
		kcp_data_sender(existing_relay.kcp_data_sender),
		timer_find_expires(std::move(existing_relay.timer_find_expires)),
		timer_expiring_kcp(std::move(existing_relay.timer_expiring_kcp)),
		timer_stun(std::move(existing_relay.timer_stun)),
		timer_keep_alive_ingress(std::move(existing_relay.timer_keep_alive_ingress)),
		timer_keep_alive_egress(std::move(existing_relay.timer_keep_alive_egress)),
		sequence_task_pool_local(existing_relay.sequence_task_pool_local),
		sequence_task_pool_peer(existing_relay.sequence_task_pool_peer),
		task_limit(existing_relay.task_limit),
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