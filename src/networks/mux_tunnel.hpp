#pragma once
#include "connections.hpp"
#include "kcp_updater.hpp"

#ifndef __MUX_TUNNEL_HPP__
#define __MUX_TUNNEL_HPP__

class client_mode;
class server_mode;

struct mux_tunnel
{
	std::shared_mutex mutex_id_map_to_mux_records;
	std::unordered_map<uint64_t, std::shared_ptr<mux_records>> id_map_to_mux_records;	// (KCP conv << 32) + connection uid

	std::shared_mutex mutex_expiring_mux_records;
	std::unordered_map<uint64_t, std::shared_ptr<mux_records>> expiring_mux_records;	// (KCP conv << 32) + connection uid, server only

	std::shared_mutex mutex_udp_map_to_mux_records;
	std::map<udp::endpoint, std::weak_ptr<mux_records>> udp_map_to_mux_records;	// client only

	std::shared_mutex mutex_mux_tcp_cache;
	std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> mux_tcp_cache;
	std::map<std::weak_ptr<KCP::KCP>, uint32_t, std::owner_less<>> mux_tcp_cache_max_size;

	std::shared_mutex mutex_mux_udp_cache;
	std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> mux_udp_cache;
	std::map<std::weak_ptr<KCP::KCP>, uint32_t, std::owner_less<>> mux_udp_cache_max_size;

	client_mode *client_ptr = nullptr;
	server_mode *server_ptr = nullptr;

	mux_tunnel() = delete;
	mux_tunnel(KCP::KCPUpdater &kcp_updater, user_settings &input_settings, void *running_mode_ptr)
		: kcp_updater(kcp_updater), current_settings(input_settings)
	{
		if (input_settings.mode == running_mode::server)
			server_ptr = reinterpret_cast<server_mode*>(running_mode_ptr);
		if (input_settings.mode == running_mode::client)
			client_ptr = reinterpret_cast<client_mode*>(running_mode_ptr);
	}

	// client only
	void tcp_accept_new_income(std::shared_ptr<tcp_session> incoming_session, const std::string &remote_output_address, asio::ip::port_type remote_output_port);
	// client and server
	void read_tcp_data_to_cache(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_session_weak, std::weak_ptr<mux_records> kcp_ptr_weak);
	void client_udp_data_to_cache(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, const std::string &remote_output_address, asio::ip::port_type remote_output_port);
	void server_udp_data_to_cache(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, std::weak_ptr<KCP::KCP> kcp_session_weak, std::weak_ptr<mux_records> mux_records_weak);

	void mux_transfer_data(protocol_type prtcl, kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> buffer_cache, uint8_t *unbacked_data_ptr, size_t unbacked_data_size);
	void mux_cancel_channel(protocol_type prtcl, kcp_mappings *kcp_mappings_ptr, uint8_t *unbacked_data_ptr, size_t unbacked_data_size);
	void mux_pre_connect(protocol_type prtcl, kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> buffer_cache, uint8_t *unbacked_data_ptr, size_t unbacked_data_size);	// server only

	void setup_mux_kcp(std::shared_ptr<KCP::KCP> kcp_ptr);
	void mux_move_cached_to_tunnel(bool skip_kcp_update = false);
	std::list<std::shared_ptr<KCP::KCP>> mux_move_cached_to_tunnel(std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> &data_queues, int one_x);
	void refresh_mux_queue(std::weak_ptr<KCP::KCP> kcp_ptr_weak);
	void delete_mux_records(uint32_t conv);
	void remove_cached_kcp(std::weak_ptr<KCP::KCP> kcp_ptr);
	void cleanup_expiring_mux_records();

private:
	void send_cancel_packet(protocol_type prtcl, uint32_t mux_connection_id, std::shared_ptr<KCP::KCP> kcp_ptr);
	void read_udp_data_to_cache(std::unique_ptr<uint8_t[]> data, size_t data_size, mux_records *mux_records_ptr, std::weak_ptr<KCP::KCP> kcp_ptr);

	KCP::KCPUpdater &kcp_updater;
	user_settings &current_settings;
};

#endif