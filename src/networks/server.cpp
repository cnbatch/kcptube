#include <random>
#include <algorithm>
#include <iostream>
#include <thread>
#include "server.hpp"
#include "../shares/data_operations.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;


uint32_t server_mode::generate_token_number()
{
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<uint32_t> uniform_dist(32, std::numeric_limits<uint32_t>::max() - 1);
	return uniform_dist(mt);
}

server_mode::~server_mode()
{
	timer_find_expires.cancel();
	timer_expiring_kcp.cancel();
	timer_stun.cancel();
	timer_keep_alive.cancel();
}

bool server_mode::start()
{
	printf("start_up() running in server mode\n");

	auto func = std::bind(&server_mode::udp_listener_incoming, this, _1, _2, _3, _4);
	std::set<uint16_t> listen_ports = convert_to_port_list(current_settings);

	udp::endpoint listen_on_ep;
	if (current_settings.ipv4_only)
		listen_on_ep = udp::endpoint(udp::v4(), *listen_ports.begin());
	else
		listen_on_ep = udp::endpoint(udp::v6(), *listen_ports.begin());

	if (!current_settings.listen_on.empty())
	{
		asio::error_code ec;
		asio::ip::address local_address = asio::ip::make_address(current_settings.listen_on, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + "Listen Address incorrect - " + current_settings.listen_on + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			return false;
		}

		if (local_address.is_v4() && !current_settings.ipv4_only)
			listen_on_ep.address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
		else
			listen_on_ep.address(local_address);
	}

	bool running_well = true;
	for (uint16_t port_number : listen_ports)
	{
		listen_on_ep.port(port_number);
		try
		{
			udp_servers.insert({ port_number, std::make_unique<udp_server>(io_context, sequence_task_pool_peer, task_limit, listen_on_ep, func) });
		}
		catch (std::exception &ex)
		{
			std::string error_message = time_to_string_with_square_brackets() + ex.what() + "\tPort Number: " + std::to_string(port_number) + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			running_well = false;
		}
	}

	if (!running_well)
		return running_well;

	try
	{
		timer_find_expires.expires_after(gbv_expring_update_interval);
		timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });

		timer_expiring_kcp.expires_after(gbv_expring_update_interval);
		timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_kcp_loops(e); });

		if (!current_settings.stun_server.empty())
		{
			stun_header = send_stun_8489_request(*udp_servers.begin()->second, current_settings.stun_server, current_settings.ipv4_only);
			timer_stun.expires_after(std::chrono::seconds(1));
			timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
		}

		if (current_settings.keep_alive > 0)
		{
			timer_keep_alive.expires_after(gbv_keepalive_update_interval);
			timer_keep_alive.async_wait([this](const asio::error_code &e) { keep_alive(e); });
		}
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + ex.what() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		running_well = false;
	}

	return running_well;
}

void server_mode::udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type server_port_number)
{
	if (data == nullptr || data_size == 0)
		return;
	uint8_t *data_ptr = data.get();
	if (stun_header != nullptr)
	{
		uint32_t ipv4_address = 0;
		uint16_t ipv4_port = 0;
		std::array<uint8_t, 16> ipv6_address{};
		uint16_t ipv6_port = 0;
		if (rfc8489::unpack_address_port(data_ptr, stun_header->transaction_id_part_1, stun_header->transaction_id_part_2, ipv4_address, ipv4_port, ipv6_address, ipv6_port))
		{
			save_external_ip_address(ipv4_address, ipv4_port, ipv6_address, ipv6_port);
			return;
		}
	}

	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
	if (!error_message.empty())
		return;

	udp_listener_incoming_unpack(std::move(data), plain_size, peer, server_port_number);
}

void server_mode::udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type server_port_number)
{
	if (data == nullptr)
		return;

	uint8_t *data_ptr = data.get();
	uint32_t conv = KCP::KCP::GetConv(data_ptr);
	if (conv == 0)
	{
		udp_listener_incoming_new_connection(std::move(data), plain_size, peer, server_port_number);
		return;
	}

	std::shared_ptr<kcp_mappings> kcp_mappings_ptr = nullptr;
	std::shared_lock locker_kcp_channels{ mutex_kcp_channels };
	if (auto kcp_channel_iter = kcp_channels.find(conv); kcp_channel_iter != kcp_channels.end())
		kcp_mappings_ptr = kcp_channel_iter->second;
	locker_kcp_channels.unlock();

	if (kcp_mappings_ptr == nullptr)
		return;

	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->ingress_kcp;
	if (kcp_ptr->Input((const char *)data_ptr, (long)plain_size) < 0)
		return;

	{
		std::shared_lock shared_lock_ingress{kcp_mappings_ptr->mutex_ingress_endpoint};
		udp::endpoint &ingress_source_endpoint = kcp_mappings_ptr->ingress_source_endpoint;
		if (ingress_source_endpoint != peer)
		{
			shared_lock_ingress.unlock();
			std::unique_lock unique_lock_ingress{kcp_mappings_ptr->mutex_ingress_endpoint};
			if (ingress_source_endpoint != peer)
				ingress_source_endpoint = peer;
		}
	}

	while (true)
	{
		int buffer_size = kcp_ptr->PeekSize();
		if (buffer_size <= 0)
			break;

		std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique<uint8_t[]>(buffer_size);
		uint8_t *buffer_ptr = buffer_cache.get();

		int kcp_data_size = 0;
		if (kcp_data_size = kcp_ptr->Receive((char *)buffer_ptr, buffer_size); kcp_data_size < 0)
			break;

		auto [packet_timestamp, ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack(buffer_ptr, kcp_data_size);
		auto timestamp = packet::right_now();
		if (calculate_difference((int32_t)timestamp, packet_timestamp) > gbv_time_gap_seconds)
			continue;

		kcp_mappings_ptr->ingress_listener.store(udp_servers[server_port_number].get());

		switch (ftr)
		{
		case feature::raw_data:
		{
			if (prtcl == protocol_type::tcp)
			{
				std::shared_ptr<tcp_session> &tcp_channel = kcp_mappings_ptr->local_tcp;
				if (tcp_channel != nullptr)
				{
					tcp_channel->async_send_data(std::move(buffer_cache), unbacked_data_ptr, unbacked_data_size);
				}
			}
			else if (prtcl == protocol_type::udp)
			{
				std::shared_ptr<udp_client> &udp_channel = kcp_mappings_ptr->local_udp;
				udp_channel->async_send_out(std::move(buffer_cache), unbacked_data_ptr, unbacked_data_size, *udp_target);
			}
			break;
		}
		case feature::keep_alive:
		{
			std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_response_packet(prtcl);
			kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());

			uint32_t next_refresh_time = kcp_ptr->Check();
			kcp_updater.submit(kcp_ptr, next_refresh_time);
			break;
		}
		case feature::keep_alive_response:
			kcp_ptr->keep_alive_response_time.store(packet::right_now());
			break;
		case feature::disconnect:
		{
			if (prtcl == protocol_type::tcp)
			{
				std::shared_ptr<tcp_session> &tcp_channel = kcp_mappings_ptr->local_tcp;
				if (tcp_channel != nullptr)
					process_tcp_disconnect(tcp_channel.get(), kcp_ptr);
			}
			if (prtcl == protocol_type::udp)
			{
				std::shared_ptr<udp_client> &udp_channel = kcp_mappings_ptr->local_udp;
				udp_channel->stop();
				udp_channel->disconnect();
			}
			if (prtcl == protocol_type::mux)
			{
				delete_mux_records(conv);
			}

			std::scoped_lock lockers{ mutex_expiring_kcp, mutex_kcp_channels };
			expiring_kcp[kcp_mappings_ptr] = packet::right_now() - current_settings.udp_timeout;
			kcp_channels.erase(conv);
			break;
		}
		case feature::mux_transfer:
		{
			mux_transfer_data(prtcl, kcp_mappings_ptr, std::move(buffer_cache), unbacked_data_ptr, unbacked_data_size);
			break;
		}
		case feature::mux_cancel:
		{
			mux_cancel_channel(prtcl, kcp_mappings_ptr, unbacked_data_ptr, unbacked_data_size);
			break;
		}
		default:
			break;
		}
	}
}

void server_mode::tcp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_session_weak)
{
	if (data == nullptr || incoming_session == nullptr)
		return;

	std::shared_ptr<KCP::KCP> kcp_session = kcp_session_weak.lock();
	if (kcp_session == nullptr)
		return;

	if (!incoming_session->session_is_ending() && !incoming_session->is_pause() &&
		(uint32_t)kcp_session->WaitingForSend() >= kcp_session->GetSendWindowSize())
	{
		incoming_session->pause(true);
	}

	uint8_t *data_ptr = data.get();
	size_t new_data_size = packet::create_data_packet(protocol_type::tcp, data_ptr, data_size);
	kcp_session->Send((const char *)data_ptr, new_data_size);
	uint32_t next_update_time = kcp_session->Check();
	kcp_updater.submit(kcp_session, next_update_time);
}

void server_mode::udp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, std::weak_ptr<KCP::KCP> kcp_session_weak)
{
	if (data == nullptr)
		return;

	std::shared_ptr<KCP::KCP> kcp_session = kcp_session_weak.lock();
	if (kcp_session == nullptr)
		return;

	if ((uint32_t)kcp_session->WaitingForSend() >= kcp_session->GetSendWindowSize())
		return;

	uint8_t *data_ptr = data.get();
	size_t new_data_size = packet::create_data_packet(protocol_type::udp, data_ptr, data_size);

	kcp_session->Send((const char *)data_ptr, new_data_size);
	uint32_t next_update_time = kcp_session->Check();
	kcp_updater.submit(kcp_session, next_update_time);
}

void server_mode::tcp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_session_weak, std::weak_ptr<mux_records> mux_records_weak)
{
	if (data == nullptr || incoming_session == nullptr)
		return;

	std::shared_ptr<KCP::KCP> kcp_session = kcp_session_weak.lock();
	if (kcp_session == nullptr)
		return;

	std::shared_ptr<mux_records> mux_records_ptr = mux_records_weak.lock();
	if (mux_records_ptr == nullptr)
		return;

	std::shared_lock tcp_cache_shared_locker{mutex_mux_tcp_cache};
	auto cache_iter = mux_tcp_cache.find(kcp_session_weak);
	auto size_iter = mux_tcp_cache_max_size.find(kcp_session_weak);
	if (cache_iter == mux_tcp_cache.end() || size_iter == mux_tcp_cache_max_size.end())
		return;
	size_t tcp_cache_size = cache_iter->second.size();
	uint32_t cache_max_size = size_iter->second;
	tcp_cache_shared_locker.unlock();

	if (!incoming_session->session_is_ending() && !incoming_session->is_pause() &&
		tcp_cache_size > cache_max_size)
	{
		incoming_session->pause(true);
	}

	uint32_t connection_id = mux_records_ptr->connection_id;
	uint8_t *data_ptr = data.get();
	size_t new_data_size = packet::create_mux_data_packet(protocol_type::tcp, connection_id, data_ptr, data_size);

	mux_data_cache data_cache = { std::move(data), data_ptr, new_data_size };

	std::unique_lock tcp_cache_locker{mutex_mux_tcp_cache};
	cache_iter = mux_tcp_cache.find(kcp_session_weak);
	if (cache_iter == mux_tcp_cache.end())
		return;
	cache_iter->second.emplace_back(std::move(data_cache));
	tcp_cache_locker.unlock();

	mux_records_ptr->last_data_transfer_time.store(packet::right_now());
	std::unique_ptr<uint8_t[]> empty_ptr;
	auto func = [this, kcp_session_weak](std::unique_ptr<uint8_t[]> data) mutable { refresh_mux_queue(kcp_session_weak); };
	sequence_task_pool_local.push_task((size_t)this, func, std::move(empty_ptr));
}

void server_mode::udp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, std::weak_ptr<KCP::KCP> kcp_session_weak, std::weak_ptr<mux_records> mux_records_weak)
{
	mux_move_cached_to_tunnel();

	if (data == nullptr)
		return;

	std::shared_ptr<KCP::KCP> kcp_session = kcp_session_weak.lock();
	if (kcp_session == nullptr)
		return;

	std::shared_ptr<mux_records> mux_records_ptr = mux_records_weak.lock();
	if (mux_records_ptr == nullptr)
		return;

	std::shared_lock udp_cache_shared_locker{mutex_mux_udp_cache};
	auto cache_iter = mux_udp_cache.find(kcp_session_weak);
	auto size_iter = mux_udp_cache_max_size.find(kcp_session_weak);
	if (cache_iter == mux_udp_cache.end() || size_iter == mux_udp_cache_max_size.end())
		return;
	size_t udp_cache_size = cache_iter->second.size();
	uint32_t cache_max_size = size_iter->second;
	udp_cache_shared_locker.unlock();

	if (udp_cache_size > cache_max_size)
		return;

	uint32_t connection_id = mux_records_ptr->connection_id;
	uint8_t *data_ptr = data.get();
	size_t new_data_size = packet::create_mux_data_packet(protocol_type::udp, connection_id, data_ptr, data_size);

	mux_data_cache data_cache = { std::move(data), data_ptr, new_data_size };

	std::unique_lock udp_cache_locker{mutex_mux_udp_cache};
	cache_iter = mux_udp_cache.find(kcp_session_weak);
	if (cache_iter == mux_udp_cache.end())
		return;
	cache_iter->second.emplace_back(std::move(data_cache));
	udp_cache_locker.unlock();

	mux_records_ptr->last_data_transfer_time.store(packet::right_now());
	mux_move_cached_to_tunnel();
}

void server_mode::udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;
	uint8_t *data_ptr = data.get();
	std::shared_lock shared_locker_handshake_channels{ mutex_handshake_channels, std::defer_lock };
	std::unique_lock unique_locker_handshake_channels{ mutex_handshake_channels, std::defer_lock };
	shared_locker_handshake_channels.lock();
	auto iter = handshake_channels.find(peer);
	if (iter == handshake_channels.end())
	{
		shared_locker_handshake_channels.unlock();
		unique_locker_handshake_channels.lock();
		iter = handshake_channels.find(peer);
		if (iter == handshake_channels.end())
		{
			std::shared_ptr<KCP::KCP> handshake_kcp = std::make_shared<KCP::KCP>();
			std::shared_ptr<kcp_mappings> handshake_kcp_mappings = std::make_shared<kcp_mappings>();
			kcp_mappings *handshake_kcp_mappings_ptr = handshake_kcp_mappings.get();
			handshake_kcp_mappings_ptr->ingress_kcp = handshake_kcp;
			handshake_kcp_mappings_ptr->ingress_source_endpoint = peer;
			handshake_kcp_mappings_ptr->ingress_listener.store(udp_servers[port_number].get());
			handshake_kcp->custom_data.store(handshake_kcp_mappings_ptr);
			handshake_kcp->SetMTU(current_settings.kcp_mtu);
			handshake_kcp->NoDelay(1, 1, 3, 1);
			handshake_kcp->Update();
			handshake_kcp->RxMinRTO() = 10;
			handshake_kcp->SetBandwidth(current_settings.outbound_bandwidth, current_settings.inbound_bandwidth);
			handshake_kcp->SetOutput([this](const char *buf, int len, void *user) -> int
				{
					return kcp_sender(buf, len, user);
				});

			if (handshake_kcp->Input((const char *)data_ptr, (long)data_size) < 0)
				return;

			int buffer_size = handshake_kcp->PeekSize();
			if (buffer_size <= 0)
				return;

			int kcp_data_size = 0;
			if (kcp_data_size = handshake_kcp->Receive((char *)data_ptr, buffer_size); kcp_data_size < 0)
				return;

			auto [packet_timestamp, ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack(data_ptr, kcp_data_size);
			auto timestamp = packet::right_now();
			if (calculate_difference((int32_t)timestamp, packet_timestamp) > gbv_time_gap_seconds)
				return;

			handshake_kcp_mappings_ptr->connection_protocol = prtcl;

			switch (ftr)
			{
			case feature::initialise:
			{
				uint32_t new_id = generate_token_number();
				std::shared_lock locker_kcp_channels{ mutex_kcp_channels };
				while (kcp_channels.find(new_id) != kcp_channels.end())
				{
					new_id = generate_token_number();
				}
				locker_kcp_channels.unlock();

				packet::settings_wrapper basic_settings = packet::get_initialise_details_from_unpacked_data(unbacked_data_ptr);
				uint64_t outbound_bandwidth = current_settings.outbound_bandwidth;
				if (basic_settings.inbound_bandwidth > 0 && outbound_bandwidth > basic_settings.inbound_bandwidth)
					outbound_bandwidth = basic_settings.inbound_bandwidth;

				std::shared_ptr<kcp_mappings> data_kcp_mappings = std::make_shared<kcp_mappings>();
				kcp_mappings *data_kcp_mappings_ptr = data_kcp_mappings.get();
				std::shared_ptr<KCP::KCP> data_kcp = std::make_shared<KCP::KCP>(new_id);
				data_kcp_mappings_ptr->ingress_kcp = data_kcp;
				data_kcp_mappings_ptr->connection_protocol = prtcl;
				data_kcp_mappings_ptr->ingress_listener.store(udp_servers[port_number].get());
				data_kcp->custom_data.store(data_kcp_mappings_ptr);
				data_kcp->keep_alive_send_time.store(timestamp);
				data_kcp->keep_alive_response_time.store(timestamp);
				data_kcp->SetMTU(current_settings.kcp_mtu);
				data_kcp->SetWindowSize(current_settings.kcp_sndwnd, current_settings.kcp_rcvwnd);
				data_kcp->NoDelay(current_settings.kcp_nodelay, current_settings.kcp_interval, current_settings.kcp_resend, current_settings.kcp_nc);
				data_kcp->Update();
				data_kcp->RxMinRTO() = 10;
				data_kcp->SetBandwidth(outbound_bandwidth, current_settings.inbound_bandwidth);

				bool connect_success = false;

				switch (prtcl)
				{
				case protocol_type::mux:
				{
					connect_success = true;
					setup_mux_kcp(data_kcp);
					break;
				}
				case protocol_type::tcp:
				{
					connect_success = create_new_tcp_connection(handshake_kcp, data_kcp);
					break;
				}
				case protocol_type::udp:
				{
					connect_success = create_new_udp_connection(handshake_kcp, data_kcp, peer);
					break;
				}
				default:
					break;
				}

				if (connect_success)
				{
					packet::settings_wrapper basic_settings =
					{
						new_id,
						current_settings.listen_port_start,
						current_settings.listen_port_end,
						current_settings.outbound_bandwidth,
						current_settings.inbound_bandwidth
					};
					std::vector<uint8_t> new_data = packet::response_initialise_packet(prtcl, basic_settings);
					handshake_kcp->Send((const char *)new_data.data(), (long)new_data.size());
					handshake_kcp->Update();
					uint32_t next_update_time = handshake_kcp->Check();
					kcp_updater.submit(handshake_kcp, next_update_time);

					std::scoped_lock lockers{ mutex_expiring_handshakes, mutex_kcp_channels, mutex_kcp_keepalive };
					handshake_channels[peer] = handshake_kcp_mappings;
					expiring_handshakes.insert({ handshake_kcp_mappings, timestamp });

					kcp_channels[new_id] = data_kcp_mappings;
					kcp_keepalive[data_kcp].store(timestamp + current_settings.keep_alive);
				}
				else
				{
					std::scoped_lock lockers{ mutex_expiring_handshakes };
					handshake_channels[peer] = handshake_kcp_mappings;
					expiring_handshakes.insert({ handshake_kcp_mappings, timestamp });
				}
				break;
			}
			case feature::test_connection:
			{
				std::vector<uint8_t> new_data = packet::create_test_connection_packet();
				handshake_kcp->Send((const char *)new_data.data(), (long)new_data.size());
				handshake_kcp->Update();
				uint32_t next_update_time = handshake_kcp->Check();
				kcp_updater.submit(handshake_kcp, next_update_time);

				std::scoped_lock lockers{ mutex_expiring_handshakes };
				handshake_channels[peer] = handshake_kcp_mappings;
				expiring_handshakes.insert({ handshake_kcp_mappings, timestamp });
				break;
			}
			default:
				break;
			}
		}
		unique_locker_handshake_channels.unlock();
	}
	else
	{
		kcp_mappings *kcp_mappings_ptr = iter->second.get();
		std::shared_ptr<KCP::KCP> handshake_kcp = kcp_mappings_ptr->ingress_kcp;
		if (handshake_kcp->Input((const char *)data_ptr, (long)data_size) < 0)
			return;

		shared_locker_handshake_channels.unlock();

		int buffer_size = handshake_kcp->PeekSize();
		if (buffer_size <= 0)
			return;

		int kcp_data_size = 0;
		if (kcp_data_size = handshake_kcp->Receive((char *)data_ptr, buffer_size); kcp_data_size < 0)
			return;

		auto [packet_timestamp, ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack(data_ptr, kcp_data_size);
		auto timestamp = packet::right_now();
		if (calculate_difference((int32_t)timestamp, packet_timestamp) > gbv_time_gap_seconds)
			return;
	}
}

void server_mode::mux_transfer_data(protocol_type prtcl, std::shared_ptr<kcp_mappings> kcp_mappings_ptr, std::unique_ptr<uint8_t[]> buffer_cache, uint8_t *unbacked_data_ptr, size_t unbacked_data_size)
{
	auto [mux_connection_id, mux_data, mux_data_size] = packet::extract_mux_data_from_unpacked_data(unbacked_data_ptr, unbacked_data_size);
	uint64_t complete_connection_id = ((uint64_t)kcp_mappings_ptr->ingress_kcp->GetConv() << 32) + mux_connection_id;
	std::shared_ptr<mux_records> mux_records_ptr = nullptr;

	std::shared_lock locker_expiring_mux_records{mutex_expiring_mux_records};
	if (expiring_mux_records.find(complete_connection_id) != expiring_mux_records.end())
	{
		std::vector<uint8_t> mux_cancel_data = packet::inform_mux_cancel_packet(prtcl, mux_connection_id);
		kcp_mappings_ptr->ingress_kcp->Send((const char *)mux_cancel_data.data(), mux_cancel_data.size());
		uint32_t next_update_time = kcp_mappings_ptr->ingress_kcp->Check();
		kcp_updater.submit(kcp_mappings_ptr->ingress_kcp, next_update_time);
		return;
	}
	locker_expiring_mux_records.unlock();

	{
		std::shared_lock shared_locker_iter_mux_records{mutex_id_map_to_mux_records, std::defer_lock};
		std::unique_lock unique_locker_iter_mux_records{mutex_id_map_to_mux_records, std::defer_lock};
		shared_locker_iter_mux_records.lock();
		auto iter_mux_records = id_map_to_mux_records.find(complete_connection_id);
		if (iter_mux_records == id_map_to_mux_records.end())
		{
			shared_locker_iter_mux_records.unlock();
			unique_locker_iter_mux_records.lock();
			iter_mux_records = id_map_to_mux_records.find(complete_connection_id);
			if (iter_mux_records == id_map_to_mux_records.end())
			{
				if (prtcl == protocol_type::tcp)
					mux_records_ptr = create_mux_data_tcp_connection(mux_connection_id, kcp_mappings_ptr->ingress_kcp);
				if (prtcl == protocol_type::udp)
					mux_records_ptr = create_mux_data_udp_connection(mux_connection_id, kcp_mappings_ptr->ingress_kcp);

				if (mux_records_ptr == nullptr)
				{
					std::vector<uint8_t> mux_cancel_data = packet::inform_mux_cancel_packet(prtcl, mux_connection_id);
					kcp_mappings_ptr->ingress_kcp->Send((const char *)mux_cancel_data.data(), mux_cancel_data.size());
					uint32_t next_update_time = kcp_mappings_ptr->ingress_kcp->Check();
					kcp_updater.submit(kcp_mappings_ptr->ingress_kcp, next_update_time);
					return;
				}

				id_map_to_mux_records[complete_connection_id] = mux_records_ptr;
			}
			else
			{
				mux_records_ptr = iter_mux_records->second;
			}
		}
		else
		{
			mux_records_ptr = iter_mux_records->second;
		}
	}

	if (prtcl == protocol_type::tcp)
	{
		std::shared_ptr<tcp_session> tcp_channel = mux_records_ptr->local_tcp;
		if (tcp_channel != nullptr)
			tcp_channel->async_send_data(std::move(buffer_cache), mux_data, mux_data_size);
		mux_records_ptr->last_data_transfer_time.store(packet::right_now());
	}

	if (prtcl == protocol_type::udp)
	{
		std::shared_ptr<udp_client> udp_channel = mux_records_ptr->local_udp;
		udp_channel->async_send_out(std::move(buffer_cache), mux_data, mux_data_size, *udp_target);
		mux_records_ptr->last_data_transfer_time.store(packet::right_now());
	}
}

void server_mode::mux_cancel_channel(protocol_type prtcl, std::shared_ptr<kcp_mappings> kcp_mappings_ptr, uint8_t *unbacked_data_ptr, size_t unbacked_data_size)
{
	auto [mux_connection_id, mux_data, mux_data_size] = packet::extract_mux_data_from_unpacked_data(unbacked_data_ptr, unbacked_data_size);
	uint64_t complete_connection_id = ((uint64_t)kcp_mappings_ptr->ingress_kcp->GetConv() << 32) + mux_connection_id;
	std::shared_ptr<mux_records> mux_records_ptr = nullptr;

	{
		std::scoped_lock locker{mutex_id_map_to_mux_records, mutex_expiring_mux_records};
		if (expiring_mux_records.find(complete_connection_id) != expiring_mux_records.end())
			return;

		auto iter_mux_records = id_map_to_mux_records.find(complete_connection_id);
		if (iter_mux_records == id_map_to_mux_records.end())
			return;

		mux_records_ptr = iter_mux_records->second;
		id_map_to_mux_records.erase(iter_mux_records);
		expiring_mux_records[complete_connection_id] = mux_records_ptr;
	}

	if (prtcl == protocol_type::tcp)
	{
		std::shared_ptr<tcp_session> session = mux_records_ptr->local_tcp;
		if (session == nullptr)
			return;

		session->when_disconnect(empty_tcp_disconnect);
		session->session_is_ending(true);
		session->pause(false);
		session->stop();
		session->disconnect();
	}

	if (prtcl == protocol_type::udp)
	{
		std::shared_ptr<udp_client> &udp_channel = mux_records_ptr->local_udp;
		udp_channel->stop();
		udp_channel->disconnect();
	}
}

bool server_mode::create_new_tcp_connection(std::shared_ptr<KCP::KCP> handshake_kcp, std::shared_ptr<KCP::KCP> data_kcp)
{
	bool connect_success = false;
	std::weak_ptr<KCP::KCP> weak_data_kcp = data_kcp;
	auto callback_function = [weak_data_kcp, this](std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> target_session)
	{
		tcp_connector_incoming(std::move(data), data_size, target_session, weak_data_kcp);
	};
	tcp_client target_connector(io_context, callback_function, current_settings.ipv4_only);
	std::string &destination_address = current_settings.destination_address;
	uint16_t destination_port = current_settings.destination_port;
	asio::error_code ec;
	if (target_connector.set_remote_hostname(destination_address, destination_port, ec) && ec)
	{
		std::string error_message = time_to_string_with_square_brackets() + ec.message() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message + "\n", current_settings.log_messages);
		return false;
	}

	std::shared_ptr<tcp_session> local_session = target_connector.connect(ec);
	if (!ec)
	{
		connect_success = true;
		local_session->when_disconnect([weak_data_kcp, this](std::shared_ptr<tcp_session> session) { process_tcp_disconnect(session.get(), weak_data_kcp); });
		std::weak_ptr weak_session = local_session;
		data_kcp->SetOutput([this](const char *buf, int len, void *user) -> int
			{
				int ret = kcp_sender(buf, len, user);
				kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;
				std::shared_ptr data_kcp = kcp_mappings_ptr->ingress_kcp;
				std::shared_ptr session = kcp_mappings_ptr->local_tcp;
				if (data_kcp != nullptr && session != nullptr && session->is_pause() &&
					(uint32_t)data_kcp->WaitingForSend() < data_kcp->GetSendWindowSize())
					session->pause(false);
				return ret;
			});

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings*)data_kcp->custom_data.load();
		kcp_mappings_ptr->local_tcp = local_session;
		local_session->async_read_data();
	}
	else
	{
		connect_success = false;
		std::vector<uint8_t> data = packet::inform_error_packet(protocol_type::tcp, ec.message());
		handshake_kcp->Send((const char *)data.data(), data.size());
		handshake_kcp->Update();
		uint32_t next_update_time = handshake_kcp->Check();
		kcp_updater.submit(handshake_kcp, next_update_time);
	}

	return connect_success;
}

bool server_mode::create_new_udp_connection(std::shared_ptr<KCP::KCP> handshake_kcp, std::shared_ptr<KCP::KCP> data_kcp, const udp::endpoint &peer)
{
	bool connect_success = false;
	std::weak_ptr<KCP::KCP> weak_data_kcp = data_kcp;

	udp_callback_t udp_func_ap = [weak_data_kcp, this](std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
	{
		udp_connector_incoming(std::move(data), data_size, peer, port_number, weak_data_kcp);
	};

	std::shared_ptr<udp_client> target_connector = nullptr;
	for (int i = 0; i < gbv_retry_times; i++)
	{
		try
		{
			target_connector = std::make_shared<udp_client>(io_context, sequence_task_pool_local, task_limit, udp_func_ap, current_settings.ipv4_only);
		}
		catch (...)
		{
			continue;
		}
		break;
	}

	if (target_connector == nullptr)
		return false;

	asio::error_code ec;
	if (current_settings.ipv4_only)
		target_connector->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		target_connector->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);

	if (ec)
	{
		std::vector<uint8_t> data = packet::inform_error_packet(protocol_type::udp, ec.message());
		handshake_kcp->Send((const char *)data.data(), data.size());
		handshake_kcp->Update();
		uint32_t next_update_time = handshake_kcp->Check();
		kcp_updater.submit(handshake_kcp, next_update_time);
		return false;
	}

	data_kcp->SetOutput([this](const char *buf, int len, void *user) -> int
		{
			return kcp_sender(buf, len, user);
		});

	if (udp_target != nullptr || update_local_udp_target(target_connector))
	{
		target_connector->async_receive();
		kcp_mappings *kcp_mappings_ptr = (kcp_mappings*)data_kcp->custom_data.load();
		kcp_mappings_ptr->ingress_source_endpoint = peer;
		kcp_mappings_ptr->local_udp = target_connector;
		data_kcp->Flush();
		connect_success = true;
	}

	return connect_success;
}

void server_mode::setup_mux_kcp(std::shared_ptr<KCP::KCP> data_kcp)
{
	data_kcp->SetOutput([this](const char *buf, int len, void *user) -> int
		{
			int ret = kcp_sender(buf, len, user);
			std::weak_ptr data_kcp = ((kcp_mappings *)user)->ingress_kcp;
			std::unique_ptr<uint8_t[]> empty_ptr;
			auto func = [this, data_kcp](std::unique_ptr<uint8_t[]> data) mutable {refresh_mux_queue(data_kcp); };
			sequence_task_pool_peer.push_task((size_t)user, func, std::move(empty_ptr));
			return ret;
		});

	std::scoped_lock lockers{ mutex_mux_tcp_cache, mutex_mux_udp_cache};
	mux_tcp_cache[data_kcp].clear();
	mux_udp_cache[data_kcp].clear();
	mux_tcp_cache_max_size[data_kcp] = data_kcp->GetSendWindowSize();
	mux_udp_cache_max_size[data_kcp] = data_kcp->GetSendWindowSize();
}

std::shared_ptr<mux_records> server_mode::create_mux_data_tcp_connection(uint32_t connection_id, std::weak_ptr<KCP::KCP> kcp_session_weak)
{
	std::shared_ptr<mux_records> mux_records_ptr = std::make_shared<mux_records>();
	std::weak_ptr<mux_records> mux_records_ptr_weak = mux_records_ptr;
	auto callback_function = [this, kcp_session_weak, mux_records_ptr_weak](std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> target_session)
	{
		tcp_connector_incoming(std::move(data), data_size, target_session, kcp_session_weak, mux_records_ptr_weak);
	};
	tcp_client target_connector(io_context, callback_function, current_settings.ipv4_only);
	std::string &destination_address = current_settings.destination_address;
	uint16_t destination_port = current_settings.destination_port;
	asio::error_code ec;
	if (target_connector.set_remote_hostname(destination_address, destination_port, ec) && ec)
	{
		std::string error_message = time_to_string_with_square_brackets() + ec.message() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message + "\n", current_settings.log_messages);
		return nullptr;
	}

	std::shared_ptr<tcp_session> local_session = target_connector.connect(ec);
	if (ec)
	{
		return nullptr;
	}

	mux_records_ptr->local_tcp = local_session;
	mux_records_ptr->connection_id = connection_id;
	local_session->when_disconnect([this, kcp_session_weak, mux_records_ptr_weak](std::shared_ptr<tcp_session> session)
		{ process_tcp_disconnect(session.get(), kcp_session_weak, mux_records_ptr_weak); });
	local_session->async_read_data();

	return mux_records_ptr;
}

std::shared_ptr<mux_records> server_mode::create_mux_data_udp_connection(uint32_t connection_id, std::weak_ptr<KCP::KCP> kcp_session_weak)
{
	std::shared_ptr<mux_records> mux_records_ptr = std::make_shared<mux_records>();
	std::weak_ptr<mux_records> mux_records_ptr_weak = mux_records_ptr;

	udp_callback_t udp_func_ap = [this, kcp_session_weak, mux_records_ptr_weak](std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
	{
		udp_connector_incoming(std::move(data), data_size, peer, port_number, kcp_session_weak, mux_records_ptr_weak);
	};

	std::shared_ptr<udp_client> target_connector = nullptr;
	for (int i = 0; i < gbv_retry_times; i++)
	{
		try
		{
			target_connector = std::make_shared<udp_client>(io_context, sequence_task_pool_local, task_limit, udp_func_ap, current_settings.ipv4_only);
		}
		catch (...)
		{
			continue;
		}
		break;
	}

	if (target_connector == nullptr)
		return nullptr;

	asio::error_code ec;
	if (current_settings.ipv4_only)
		target_connector->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		target_connector->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);

	if (ec)
	{
		return nullptr;
	}

	if (udp_target != nullptr || update_local_udp_target(target_connector))
		target_connector->async_receive();
	else
		return nullptr;

	mux_records_ptr->local_udp = target_connector;
	mux_records_ptr->connection_id = connection_id;

	return mux_records_ptr;
}

void server_mode::mux_move_cached_to_tunnel()
{
	std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>> kcp_ptr_list;
	{
		std::scoped_lock cache_lockers{mutex_mux_tcp_cache, mutex_mux_udp_cache};
		std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>> kcp_ptr_udp = mux_move_cached_to_tunnel(mux_udp_cache, 2);
		std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>> kcp_ptr_tcp = mux_move_cached_to_tunnel(mux_tcp_cache, 2);

		kcp_ptr_list.insert(kcp_ptr_tcp.begin(), kcp_ptr_tcp.end());
		kcp_ptr_list.insert(kcp_ptr_udp.begin(), kcp_ptr_udp.end());
	}

	for (std::shared_ptr<KCP::KCP> kcp_ptr : kcp_ptr_list)
	{
		uint32_t next_update_time = kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_update_time);
	}
}

std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>>
server_mode::mux_move_cached_to_tunnel(std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> &data_queues, int one_x)
{
	std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>> kcp_ptr_list;
	if (one_x <= 0)
		one_x = 1;

	for (auto &[kcp_ptr_weak, data_cache] : data_queues)
	{
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
		if (kcp_ptr == nullptr)
			continue;

		int available_spaces = (int)((int64_t)kcp_ptr->GetSendWindowSize() - kcp_ptr->WaitingForSend());
		if (available_spaces <= 0)
			continue;

		available_spaces = available_spaces / one_x + 1;
		size_t pickup_size = data_cache.size();
		if (pickup_size > available_spaces)
			pickup_size = (size_t)available_spaces;

		for (size_t i = 0; i < pickup_size; i++)
		{
			mux_data_cache cached_data = std::move(data_cache.front());
			kcp_ptr->Send((const char *)cached_data.sending_ptr, cached_data.data_size);
			data_cache.pop_front();
		}

		kcp_ptr_list.insert(kcp_ptr);
	}

	return kcp_ptr_list;
}

void server_mode::refresh_mux_queue(std::weak_ptr<KCP::KCP> kcp_ptr_weak)
{
	mux_move_cached_to_tunnel();
	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
	if (kcp_ptr == nullptr)
		return;

	std::shared_lock tcp_cache_shared_locker{mutex_mux_tcp_cache};
	auto cache_iter = mux_tcp_cache.find(kcp_ptr_weak);
	auto size_iter = mux_tcp_cache_max_size.find(kcp_ptr_weak);
	if (cache_iter == mux_tcp_cache.end() || size_iter == mux_tcp_cache_max_size.end())
		return;
	size_t tcp_cache_size = cache_iter->second.size();
	uint32_t cache_max_size = size_iter->second;
	tcp_cache_shared_locker.unlock();

	if (tcp_cache_size > cache_max_size)
		return;

	std::shared_lock locker{mutex_id_map_to_mux_records};
	for (auto &[connection_id, record_ptr] : id_map_to_mux_records)
	{
		std::shared_ptr session = record_ptr->local_tcp;
		if (session != nullptr && session->is_pause())
		{
			session->pause(false);
		}
	}
	locker.unlock();
}

int server_mode::kcp_sender(const char *buf, int len, void *user)
{
	if (user == nullptr)
		return 0;
	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;
	std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(len + gbv_buffer_expand_size);
	std::copy_n((const uint8_t *)buf, len, new_buffer.get());
	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, new_buffer.get(), len);
	if (!error_message.empty() || cipher_size == 0)
		return 0;

	std::shared_lock shared_lock_ingress{kcp_mappings_ptr->mutex_ingress_endpoint};
	udp::endpoint ingress_source_endpoint = kcp_mappings_ptr->ingress_source_endpoint;
	shared_lock_ingress.unlock();
	kcp_mappings_ptr->ingress_listener.load()->async_send_out(std::move(new_buffer), cipher_size, ingress_source_endpoint);
	return 0;
}

void server_mode::process_tcp_disconnect(tcp_session *session, std::weak_ptr<KCP::KCP> kcp_ptr_weak)
{
	if (session == nullptr)
		return;

	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
	if (kcp_ptr == nullptr)
		return;

	uint32_t conv = kcp_ptr->GetConv();
	std::shared_ptr<kcp_mappings> kcp_mappings_ptr = nullptr;
	std::scoped_lock lockers{ mutex_kcp_channels, mutex_expiring_kcp, mutex_kcp_keepalive };
	if (kcp_channels.find(conv) == kcp_channels.end())
		return;

	kcp_mappings_ptr = kcp_channels[conv];
	if (expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
	{
		session->when_disconnect(empty_tcp_disconnect);
		session->session_is_ending(true);
		session->pause(false);
		session->stop();
		session->disconnect();
		std::vector<uint8_t> data = packet::inform_disconnect_packet(protocol_type::tcp);
		kcp_ptr->Send((const char *)data.data(), data.size());
		uint32_t next_update_time = kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_update_time);
		expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() });
		kcp_channels.erase(conv);
	}

	if (auto iter = kcp_keepalive.find(kcp_ptr); iter != kcp_keepalive.end())
		kcp_keepalive.erase(iter);
}

void server_mode::process_tcp_disconnect(tcp_session *session, std::weak_ptr<KCP::KCP> kcp_ptr_weak, std::weak_ptr<mux_records> mux_records_weak)
{
	if (session == nullptr)
		return;

	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
	if (kcp_ptr == nullptr)
		return;

	std::shared_ptr<mux_records> mux_records_ptr = mux_records_weak.lock();
	if (mux_records_ptr == nullptr)
		return;

	uint32_t mux_connection_id = mux_records_ptr->connection_id;
	uint64_t complete_connection_id = ((uint64_t)kcp_ptr->GetConv() << 32) + mux_connection_id;
	std::vector<uint8_t> mux_cancel_data = packet::inform_mux_cancel_packet(protocol_type::tcp, mux_connection_id);

	std::unique_lock locker{mutex_mux_tcp_cache};
	if (auto iter = mux_tcp_cache.find(kcp_ptr); iter != mux_tcp_cache.end())
	{
		std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(mux_cancel_data.size());
		uint8_t *data_ptr = data.get();
		std::copy(mux_cancel_data.begin(), mux_cancel_data.end(), data_ptr);
		mux_data_cache data_cache = { std::move(data), data_ptr, mux_cancel_data.size() };
		iter->second.emplace_back(std::move(data_cache));
	}
	locker.unlock();

	std::unique_ptr<uint8_t[]> empty_ptr;
	auto func = [this, kcp_ptr_weak](std::unique_ptr<uint8_t[]> data) mutable { refresh_mux_queue(kcp_ptr_weak); };
	sequence_task_pool_local.push_task((size_t)this, func, std::move(empty_ptr));

	session->when_disconnect(empty_tcp_disconnect);
	session->session_is_ending(true);
	session->pause(false);
	session->stop();
	session->disconnect();

	std::scoped_lock lockers{mutex_id_map_to_mux_records, mutex_expiring_mux_records};
	id_map_to_mux_records.erase(complete_connection_id);
	expiring_mux_records.erase(complete_connection_id);
}

bool server_mode::update_local_udp_target(std::shared_ptr<udp_client> target_connector)
{
	bool connect_success = false;
	asio::error_code ec;
	for (int i = 0; i <= gbv_retry_times; ++i)
	{
		const std::string &destination_address = current_settings.destination_address;
		uint16_t destination_port = current_settings.destination_port;
		udp::resolver::results_type udp_endpoints = target_connector->get_remote_hostname(destination_address, destination_port, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + ec.message() + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			std::this_thread::sleep_for(std::chrono::seconds(gbv_retry_waits));
		}
		else if (udp_endpoints.size() == 0)
		{
			std::string error_message = time_to_string_with_square_brackets() + "destination address not found\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			std::this_thread::sleep_for(std::chrono::seconds(gbv_retry_waits));
		}
		else
		{
			udp_target = std::make_unique<udp::endpoint>(*udp_endpoints.begin());
			connect_success = true;
			break;
		}
	}
	return connect_success;
}

void server_mode::save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port)
{
	std::string v4_info;
	std::string v6_info;

	if (ipv4_address != 0 && ipv4_port != 0 && (external_ipv4_address.load() != ipv4_address || external_ipv4_port.load() != ipv4_port))
	{
		external_ipv4_address.store(ipv4_address);
		external_ipv4_port.store(ipv4_port);
		std::stringstream ss;
		ss << "External IPv4 Address: " << asio::ip::make_address_v4(ipv4_address) << "\n";
		ss << "External IPv4 Port: " << ipv4_port << "\n";
		if (!current_settings.log_ip_address.empty())
			v4_info = ss.str();
	}

	std::shared_lock locker(mutex_ipv6);
	if (ipv6_address != zero_value_array && ipv6_port != 0 && (external_ipv6_address != ipv6_address || external_ipv6_port != ipv6_port))
	{
		locker.unlock();
		std::unique_lock lock_ipv6(mutex_ipv6);
		external_ipv6_address = ipv6_address;
		lock_ipv6.unlock();
		external_ipv6_port.store(ipv6_port);
		std::stringstream ss;
		ss << "External IPv6 Address: " << asio::ip::make_address_v6(ipv6_address) << "\n";
		ss << "External IPv6 Port: " << ipv6_port << "\n";
		if (!current_settings.log_ip_address.empty())
			v6_info = ss.str();
	}

	if (!current_settings.log_ip_address.empty())
	{
		std::string message = "Update Time: " + time_to_string() + "\n" + v4_info + v6_info;
		print_ip_to_file(message, current_settings.log_ip_address);
		std::cout << message;
	}
}

void server_mode::delete_mux_records(uint32_t conv)
{
	std::scoped_lock locker{mutex_id_map_to_mux_records, mutex_expiring_mux_records};
	for (auto iter = id_map_to_mux_records.begin(), next_iter = iter; iter != id_map_to_mux_records.end(); iter = next_iter)
	{
		++next_iter;
		uint64_t connection_id = iter->first;
		uint32_t kcp_conv = connection_id >> 32;
		if (kcp_conv != conv)
			continue;

		std::shared_ptr<mux_records> mux_records_ptr = iter->second;

		if (mux_records_ptr->local_tcp != nullptr)
		{
			mux_records_ptr->local_tcp->when_disconnect(empty_tcp_disconnect);
			mux_records_ptr->local_tcp->stop();
			mux_records_ptr->local_tcp->disconnect();
			mux_records_ptr->local_tcp = nullptr;
		}

		if (mux_records_ptr->local_udp != nullptr)
		{
			mux_records_ptr->local_udp->stop();
			mux_records_ptr->local_udp->disconnect();
			mux_records_ptr->local_udp = nullptr;
		}

		id_map_to_mux_records.erase(iter);
	}

	for (auto iter = expiring_mux_records.begin(), next_iter = iter; iter != expiring_mux_records.end(); iter = next_iter)
	{
		++next_iter;
		uint64_t connection_id = iter->first;
		std::shared_ptr<mux_records> mux_records_ptr = iter->second;
		if (mux_records_ptr->local_tcp != nullptr)
		{
			mux_records_ptr->local_tcp->when_disconnect(empty_tcp_disconnect);
			mux_records_ptr->local_tcp->stop();
			mux_records_ptr->local_tcp->disconnect();
			mux_records_ptr->local_tcp = nullptr;
		}

		if (mux_records_ptr->local_udp != nullptr)
		{
			mux_records_ptr->local_udp->stop();
			mux_records_ptr->local_udp->disconnect();
			mux_records_ptr->local_udp = nullptr;
		}

		expiring_mux_records.erase(iter);
	}
}

void server_mode::cleanup_expiring_handshake_connections()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock locker{ mutex_expiring_handshakes, mutex_handshake_channels };
	for (auto iter = expiring_handshakes.begin(), next_iter = iter; iter != expiring_handshakes.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = iter->first.lock();
		if (kcp_mappings_ptr == nullptr)
		{
			expiring_handshakes.erase(iter);
			continue;
		}

		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->ingress_kcp;
		int64_t expire_time = iter->second;
		if (calculate_difference(time_right_now, expire_time) < gbv_kcp_cleanup_waits)
		{
			continue;
		}

		kcp_updater.remove(kcp_ptr);

		std::shared_lock locker_endpoint{kcp_mappings_ptr->mutex_ingress_endpoint};
		udp::endpoint ep = kcp_mappings_ptr->ingress_source_endpoint;
		locker_endpoint.unlock();
		handshake_channels.erase(ep);
		expiring_handshakes.erase(iter);
	}
}

void server_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock lockers{ mutex_expiring_kcp };
	for (auto iter = expiring_kcp.begin(), next_iter = iter; iter != expiring_kcp.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = iter->first;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->ingress_kcp;
		int64_t expire_time = iter->second;
		uint32_t conv = kcp_ptr->GetConv();

		if (calculate_difference(time_right_now, expire_time) < gbv_kcp_cleanup_waits)
		{
			continue;
		}

		switch (kcp_mappings_ptr->connection_protocol)
		{
		case protocol_type::tcp:
		{
			std::shared_ptr<tcp_session> &current_session = kcp_mappings_ptr->local_tcp;
			if (current_session != nullptr)
			{
				current_session->when_disconnect(empty_tcp_disconnect);
				current_session->disconnect();
				current_session->stop();
				current_session = nullptr;
			}
			break;
		}
		case protocol_type::udp:
		{
			std::shared_ptr<udp_client> current_session = kcp_mappings_ptr->local_udp;
			if (current_session != nullptr)
			{
				current_session->stop();
				current_session->disconnect();
			}
			break;
		}
		default:
			break;
		}

		kcp_updater.remove(kcp_ptr);
		expiring_kcp.erase(iter);
	}
}

void server_mode::cleanup_expiring_mux_records()
{
	auto time_right_now = packet::right_now();
	std::map<uint32_t, std::vector<std::vector<uint8_t>>> waiting_for_inform;	// kcp_conv, inform_data

	{
		std::scoped_lock lockers{ mutex_id_map_to_mux_records, mutex_expiring_mux_records };
		for (auto iter = id_map_to_mux_records.begin(), next_iter = iter; iter != id_map_to_mux_records.end(); iter = next_iter)
		{
			++next_iter;
			uint64_t connection_id = iter->first;
			std::shared_ptr<mux_records> mux_records_ptr = iter->second;
			std::shared_ptr<tcp_session> local_tcp = mux_records_ptr->local_tcp;
			std::shared_ptr<udp_client> local_udp = mux_records_ptr->local_udp;

			if (local_tcp != nullptr && !local_tcp->is_stop())
				continue;

			if (local_udp != nullptr)
			{
				if (calculate_difference(mux_records_ptr->last_data_transfer_time.load(), time_right_now) < current_settings.udp_timeout)
					continue;

				local_udp->stop();
				local_udp->disconnect();

				std::vector<uint8_t> data = packet::inform_mux_cancel_packet(protocol_type::udp, mux_records_ptr->connection_id);
				waiting_for_inform[mux_records_ptr->kcp_conv].emplace_back(std::move(data));
			}

			id_map_to_mux_records.erase(iter);
			expiring_mux_records[connection_id] = mux_records_ptr;
		}
	}

	for (auto &[kcp_conv, data_list] : waiting_for_inform)
	{
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = nullptr;
		std::shared_lock locker{mutex_kcp_channels};
		auto iter = kcp_channels.find(kcp_conv);
		if (iter == kcp_channels.end())
			continue;
		kcp_mappings_ptr = iter->second;
		locker.unlock();
		for (std::vector<uint8_t> &data : data_list)
		{
			kcp_mappings_ptr->ingress_kcp->Send((const char *)data.data(), data.size());
		}
		uint32_t next_update_time = kcp_mappings_ptr->ingress_kcp->Check();
		kcp_updater.submit(kcp_mappings_ptr->ingress_kcp, next_update_time);
	}

	std::unique_lock locker_expireing_mux_records{ mutex_expiring_mux_records };
	for (auto iter = expiring_mux_records.begin(), next_iter = iter; iter != expiring_mux_records.end(); iter = next_iter)
	{
		++next_iter;
		uint64_t connection_id = iter->first;
		std::shared_ptr<mux_records> mux_records_ptr = iter->second;

		if (calculate_difference(mux_records_ptr->last_data_transfer_time.load(), time_right_now) < gbv_cleanup_waits)
			continue;

		expiring_mux_records.erase(iter);
	}
	locker_expireing_mux_records.unlock();
}

void server_mode::loop_find_expires()
{
	std::scoped_lock lockers{ mutex_kcp_channels, mutex_expiring_kcp };
	for (auto iter = kcp_channels.begin(), next_iter = iter; iter != kcp_channels.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t conv = iter->first;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = iter->second;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->ingress_kcp;
		int32_t timeout_seconds = gbv_keepalive_timeout + current_settings.keep_alive;
		bool keep_alive_timed_out = current_settings.keep_alive > 0 &&
			calculate_difference(kcp_ptr->keep_alive_response_time.load(), kcp_ptr->keep_alive_send_time.load()) > timeout_seconds;

		bool do_erase = false;
		bool normal_delete = false;

		protocol_type ptype = kcp_mappings_ptr->connection_protocol;

		if (ptype == protocol_type::tcp)
		{
			std::shared_ptr<tcp_session> &local_session = kcp_mappings_ptr->local_tcp;
			if (local_session == nullptr || keep_alive_timed_out)
			{
				auto error_packet = packet::inform_error_packet(protocol_type::tcp, "TCP Session Closed");
				kcp_ptr->Send((char *)error_packet.data(), error_packet.size());

				uint32_t next_refresh_time = kcp_ptr->Check();
				kcp_updater.submit(kcp_ptr, next_refresh_time);
				do_erase = true;
				normal_delete = true;
			}
		}

		if (ptype == protocol_type::udp)
		{
			std::shared_ptr<udp_client> local_session = kcp_mappings_ptr->local_udp;
			do_erase = (local_session->time_gap_of_receive() > current_settings.udp_timeout &&
			            local_session->time_gap_of_send() > current_settings.udp_timeout) || keep_alive_timed_out;
		}

		if (ptype == protocol_type::mux)
		{
			if (calculate_difference(kcp_ptr->LastInputTime(), packet::right_now()) > gbv_mux_channels_cleanup || keep_alive_timed_out)
			{
				do_erase = true;
				kcp_ptr->SetOutput(empty_kcp_output);
				delete_mux_records(kcp_ptr->GetConv());
				std::scoped_lock mux_locks{mutex_mux_tcp_cache, mutex_mux_udp_cache};
				mux_tcp_cache.erase(kcp_ptr);
				mux_tcp_cache_max_size.erase(kcp_ptr);
				mux_udp_cache.erase(kcp_ptr);
				mux_udp_cache_max_size.erase(kcp_ptr);
			}
			else
			{
				uint32_t cache_max_size = std::max(kcp_ptr->GetSendWindowSize() / 8, 32u);
				std::scoped_lock mux_locks{mutex_mux_tcp_cache, mutex_mux_udp_cache};
				if (auto iter = mux_tcp_cache_max_size.find(kcp_ptr); iter != mux_tcp_cache_max_size.end())
					iter->second = cache_max_size;

				if (auto iter = mux_udp_cache_max_size.find(kcp_ptr); iter != mux_udp_cache_max_size.end())
					iter->second = cache_max_size;
			}
		}

		if (do_erase)
		{
			kcp_channels.erase(conv);

			if (expiring_kcp.find(kcp_mappings_ptr) != expiring_kcp.end())
				continue;

			if (normal_delete)
				expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() });
			else
				expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() - current_settings.udp_timeout });
		}
		else
		{
			uint32_t next_refresh_time = kcp_ptr->Check();
			kcp_updater.submit(kcp_ptr, next_refresh_time);
		}
	}
}

void server_mode::loop_keep_alive()
{
	std::shared_lock locker_kcp_looping{ mutex_kcp_keepalive };
	for (auto &[kcp_ptr_weak, timestamp] : kcp_keepalive)
	{
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
		if (kcp_ptr == nullptr)
			continue;

		if (timestamp.load() > packet::right_now())
			continue;
		timestamp += current_settings.keep_alive;

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->custom_data.load();
		protocol_type ptype = kcp_mappings_ptr->connection_protocol;
		std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_packet(ptype);
		kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());

		uint32_t next_refresh_time = kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_refresh_time);
		kcp_ptr->keep_alive_send_time.store(packet::right_now());
	}
}

void server_mode::send_stun_request(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (current_settings.stun_server.empty())
		return;

	resend_stun_8489_request(*udp_servers.begin()->second, current_settings.stun_server, stun_header.get(), current_settings.ipv4_only);

	timer_stun.expires_after(gbv_stun_resend);
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}

void server_mode::find_expires(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_find_expires();

	timer_find_expires.expires_after(gbv_expring_update_interval);
	timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });
}

void server_mode::expiring_kcp_loops(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	cleanup_expiring_handshake_connections();
	cleanup_expiring_data_connections();
	cleanup_expiring_mux_records();

	timer_expiring_kcp.expires_after(gbv_expring_update_interval);
	timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_kcp_loops(e); });
}

void server_mode::keep_alive(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive();

	timer_keep_alive.expires_after(gbv_keepalive_update_interval);
	timer_keep_alive.async_wait([this](const asio::error_code& e) { keep_alive(e); });
}
