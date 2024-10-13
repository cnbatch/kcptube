#pragma once
#include "../networks/connections.hpp"
#include "../networks/kcp_updater.hpp"

#ifndef __TESTER_HPP__
#define __TESTER_HPP__

class test_mode
{
	friend struct mux_tunnel;
	asio::io_context &io_context;
	KCP::KCPUpdater &kcp_updater;
	user_settings current_settings;
	connection_options conn_options;
	std::vector<uint16_t> destination_ports;

	std::shared_mutex mutex_handshakes;
	std::unordered_map<kcp_mappings*, std::shared_ptr<kcp_mappings>> handshakes;

	std::shared_mutex mutex_target_address;
	std::unique_ptr<asio::ip::address> target_address;

	std::mutex mutex_success_ports;
	std::set<uint16_t> success_ports;

	std::mutex mutex_failure_ports;
	std::set<uint16_t> failure_ports;

	asio::steady_timer timer_find_expires;
	ttp::task_group_pool &sequence_task_pool;

	int kcp_sender(const char *buf, int len, void *user);
	void data_sender(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> new_buffer, size_t buffer_size);

	bool get_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);
	bool update_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);
	bool handshake_timeout_detection(kcp_mappings *kcp_mappings_ptr);

	std::shared_ptr<kcp_mappings> create_handshake(asio::ip::port_type test_port);
	void on_handshake_test_success(kcp_mappings *handshake_ptr);
	void handshake_test_failure(kcp_mappings *handshake_ptr);
	void handshake_test_cleanup(kcp_mappings *handshake_ptr);
	void handle_handshake(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void PrintResults();
	void find_expires(const asio::error_code &e);

public:
	test_mode() = delete;
	test_mode(const test_mode &) = delete;
	test_mode& operator=(const test_mode &) = delete;

	test_mode(asio::io_context &io_context_ref, KCP::KCPUpdater &kcp_updater_ref, ttp::task_group_pool &seq_task_pool, /*size_t task_count_limit,*/ const user_settings &settings) :
		io_context(io_context_ref),
		kcp_updater(kcp_updater_ref),
		timer_find_expires(io_context_ref),
		sequence_task_pool(seq_task_pool),
		current_settings(settings),
		conn_options{ .ip_version_only = current_settings.ip_version_only,
					  .fib_ingress = current_settings.fib_ingress,
					  .fib_egress = current_settings.fib_egress }
	{}

	test_mode(test_mode &&existing_client) noexcept :
		io_context(existing_client.io_context),
		kcp_updater(existing_client.kcp_updater),
		timer_find_expires(std::move(existing_client.timer_find_expires)),
		sequence_task_pool(existing_client.sequence_task_pool),
		current_settings(std::move(existing_client.current_settings)),
		conn_options{ .ip_version_only = current_settings.ip_version_only,
					  .fib_ingress = current_settings.fib_ingress,
					  .fib_egress = current_settings.fib_egress }
	{}

	~test_mode();

	bool start();
};

#endif // !__TESTER_HPP__
