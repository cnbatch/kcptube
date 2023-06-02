#pragma once
#include "connections.hpp"

#ifndef __HANDSHAKE_HPP__
#define __HANDSHAKE_HPP__

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
	std::atomic<bool> finished;
	std::atomic<bool> handshake_resent;
	std::unique_ptr<KCP::KCP> kcp_ptr;

	void start_receive();
	asio::error_code resolve_remote_host(const std::string &destination_address, uint16_t destination_port);
	void handle_receive(std::unique_ptr<uint8_t[]> recv_buffer, const asio::error_code &error, std::size_t bytes_transferred);
	void loop_kcp_update(const asio::error_code &e);
	void cancel_all();

public:
	std::function<void(std::shared_ptr<handshake>, uint32_t, uint16_t, uint16_t)> call_on_success;
	std::function<void(std::shared_ptr<handshake>, const std::string&)> call_on_failure;

	handshake() = delete;
	handshake(const user_settings &settings, asio::io_context &ioctx) :
		ioc(ioctx), timer_data_loop(ioc), udp_socket(ioc), remote_server(), destination_port_cache(0),
		handshake_timeout(30), start_time(0), current_settings(settings), destination_address_cache{},
		stop(false), finished(false), handshake_resent(false) {}
	~handshake();
	bool send_handshake(protocol_type ptype, const std::string &destination_address, uint16_t destination_port);
	void process_handshake(std::unique_ptr<uint8_t[]> recv_buffer, std::size_t bytes_transferred);
	std::pair<std::string, uint16_t> get_cached_peer();
};

#endif