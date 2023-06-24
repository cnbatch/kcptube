#include <iostream>
#include <limits>
#include <random>
#include <thread>
#include "client.hpp"
#include "../shares/data_operations.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;


client_mode::~client_mode()
{
	timer_expiring_kcp.cancel();
	timer_find_expires.cancel();
	timer_keep_alive.cancel();
}

bool client_mode::start()
{
	printf("start_up() running in client mode\n");

	uint16_t port_number = current_settings.listen_port;
	if (port_number == 0)
		return false;

	tcp::endpoint listen_on_tcp;
	udp::endpoint listen_on_udp;
	if (current_settings.ipv4_only)
	{
		listen_on_tcp = tcp::endpoint(tcp::v4(), port_number);
		listen_on_udp = udp::endpoint(udp::v4(), port_number);
	}
	else
	{
		listen_on_tcp = tcp::endpoint(tcp::v6(), port_number);
		listen_on_udp = udp::endpoint(udp::v6(), port_number);
	}

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
		{
			listen_on_tcp.address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
			listen_on_udp.address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
		}
		else
		{
			listen_on_tcp.address(local_address);
			listen_on_udp.address(local_address);
		}
	}

	try
	{
		if (current_settings.mux_tunnels == 0)
		{
			tcp_server::acceptor_callback_t tcp_func_acceptor = std::bind(&client_mode::tcp_listener_accept_incoming, this, _1);
			tcp_access_point = std::make_unique<tcp_server>(io_context, listen_on_tcp, tcp_func_acceptor, empty_tcp_callback);

			udp_callback_t udp_func_ap = std::bind(&client_mode::udp_listener_incoming, this, _1, _2, _3, _4);
			udp_access_point = std::make_unique<udp_server>(io_context, sequence_task_pool_local, task_limit, listen_on_udp, udp_func_ap);
		}
		else
		{
			tcp_server::acceptor_callback_t tcp_func_acceptor = std::bind(&client_mode::tcp_listener_accept_incoming_mux, this, _1);
			tcp_access_point = std::make_unique<tcp_server>(io_context, listen_on_tcp, tcp_func_acceptor, empty_tcp_callback);

			udp_callback_t udp_func_ap = std::bind(&client_mode::udp_listener_incoming_mux, this, _1, _2, _3, _4);
			udp_access_point = std::make_unique<udp_server>(io_context, sequence_task_pool_local, task_limit, listen_on_udp, udp_func_ap);

			establish_mux_channels(current_settings.mux_tunnels);
		}

		timer_expiring_kcp.expires_after(EXPRING_UPDATE_INTERVAL);
		timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_connection_loops(e); });

		timer_find_expires.expires_after(EXPRING_UPDATE_INTERVAL);
		timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });

		if (current_settings.keep_alive > 0)
		{
			timer_keep_alive.expires_after(KEEPALIVE_UPDATE_INTERVAL);
			timer_keep_alive.async_wait([this](const asio::error_code& e) { keep_alive(e); });
		}
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + ex.what() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		return false;
	}

	return true;
}

void client_mode::tcp_listener_accept_incoming(std::shared_ptr<tcp_session> incoming_session)
{
	if (!incoming_session->is_open())
		return;

	std::shared_ptr<kcp_mappings> hs = create_handshake(incoming_session);
	if (hs == nullptr)
	{
		std::string error_message = time_to_string_with_square_brackets() + "establish handshake failed\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);

		incoming_session->when_disconnect(empty_tcp_disconnect);
		incoming_session->disconnect();
		return;
	}

	hs->egress_kcp->Update();
	uint32_t next_update_time = hs->egress_kcp->Check();
	kcp_updater.submit(hs->egress_kcp, next_update_time);

	std::unique_lock lock_handshake{ mutex_handshakes };
	handshakes[hs.get()] = hs;
}

void client_mode::tcp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_ptr_weak)
{
	if (data == nullptr || incoming_session == nullptr || data_size == 0)
		return;

	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
	if (kcp_ptr == nullptr)
		return;

	if (!incoming_session->session_is_ending() && !incoming_session->is_pause() &&
		kcp_ptr->WaitingForSend() >= kcp_ptr->GetSendWindowSize())
	{
		incoming_session->pause(true);
	}

	uint8_t *data_ptr = data.get();

	size_t new_data_size = packet::create_data_packet(protocol_type::tcp, data_ptr, data_size);
	kcp_ptr->Send((const char *)data_ptr, new_data_size);
	uint32_t next_refresh_time = kcp_ptr->Check();
	kcp_updater.submit(kcp_ptr, next_refresh_time);

	input_count += data_size;
}

void client_mode::udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	if (data == nullptr || data_size == 0)
		return;

	uint8_t *data_ptr = data.get();
	std::shared_ptr<KCP::KCP> kcp_session = nullptr;

	{
		std::shared_lock shared_locker_udp_session_map_to_kcp{ mutex_udp_local_session_map_to_kcp, std::defer_lock };
		std::unique_lock unique_locker_udp_session_map_to_kcp{ mutex_udp_local_session_map_to_kcp, std::defer_lock };
		shared_locker_udp_session_map_to_kcp.lock();
		auto iter = udp_local_session_map_to_kcp.find(peer);
		if (iter == udp_local_session_map_to_kcp.end())
		{
			shared_locker_udp_session_map_to_kcp.unlock();
			unique_locker_udp_session_map_to_kcp.lock();
			iter = udp_local_session_map_to_kcp.find(peer);
			if (iter == udp_local_session_map_to_kcp.end())
			{
				std::unique_lock locker_udp_session_map_to_handshake{ mutex_udp_address_map_to_handshake };
				auto handshake_iter = udp_address_map_to_handshake.find(peer);
				if (handshake_iter != udp_address_map_to_handshake.end())
				{
					std::shared_ptr<kcp_mappings> hs = handshake_iter->second;
					std::unique_lock locker_udp_seesion_caches{ mutex_udp_seesion_caches };
					udp_seesion_caches[hs].emplace_back(std::vector<uint8_t>(data_ptr, data_ptr + data_size));
					return;
				}

				std::shared_ptr<kcp_mappings> hs = create_handshake(peer);
				if (hs == nullptr)
				{
					std::string error_message = time_to_string_with_square_brackets() + "establish handshake failed\n";
					std::cerr << error_message;
					print_message_to_file(error_message, current_settings.log_messages);
					return;
				}

				hs->egress_kcp->Update();
				uint32_t next_update_time = hs->egress_kcp->Check();
				kcp_updater.submit(hs->egress_kcp, next_update_time);

				udp_address_map_to_handshake[peer] = hs;

				std::unique_lock locker_udp_seesion_caches{ mutex_udp_seesion_caches };
				udp_seesion_caches[hs].emplace_back(std::vector<uint8_t>(data_ptr, data_ptr + data_size));
				return;
			}
			else
			{
				kcp_session = iter->second->egress_kcp;
			}
		}
		else
		{
			kcp_session = iter->second->egress_kcp;
		}
	}

	if (kcp_session->WaitingForSend() >= kcp_session->GetSendWindowSize())
		return;

	size_t new_data_size = packet::create_data_packet(protocol_type::udp, data_ptr, data_size);

	kcp_session->Send((const char *)data_ptr, new_data_size);
	uint32_t next_refresh_time = kcp_session->Check();
	kcp_updater.submit(kcp_session, next_refresh_time);

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_session->custom_data.load();
	kcp_mappings_ptr->last_data_transfer_time.store(packet::right_now());
}

void client_mode::udp_forwarder_incoming(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (kcp_ptr == nullptr || data == nullptr || data_size == 0)
		return;

	uint8_t *data_ptr = data.get();
	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
	if (!error_message.empty())
	{
		std::cerr << error_message << "\n";
		return;
	}

	udp_forwarder_incoming_unpack(kcp_ptr, std::move(data), plain_size, peer, local_port_number);
	input_count2 += data_size;
}

void client_mode::udp_forwarder_incoming_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	uint8_t *data_ptr = data.get();
	uint32_t conv = KCP::KCP::GetConv(data_ptr);
	if (kcp_ptr->GetConv() != conv)
	{
		std::stringstream ss;
		ss << peer;
		std::string error_message = time_to_string_with_square_brackets() +
			"KCP conv is not the same as record : conv = " + std::to_string(conv) +
			", local kcp : " + std::to_string(kcp_ptr->GetConv()) + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		return;
	}

	if (kcp_ptr->Input((const char *)data_ptr, (long)plain_size) < 0)
		return;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->custom_data.load();
	if (kcp_mappings_ptr == nullptr)
		return;

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
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			continue;

		tcp_session *tcp_channel = kcp_mappings_ptr->local_tcp.get();

		switch (ftr)
		{
		case feature::initialise:
		{
			std::string error_message = time_to_string_with_square_brackets() + "incorrect 'initialise' packet received\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			break;
		}
		case feature::failure:
		{
			std::string error_message = time_to_string_with_square_brackets() + "failure, error message: " + reinterpret_cast<char*>(unbacked_data_ptr) + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
		}
		[[fallthrough]];
		case feature::disconnect:
		{
			if (prtcl == protocol_type::tcp)
				process_disconnect(conv, tcp_channel);

			if (prtcl == protocol_type::udp)
				process_disconnect(conv);

			if (kcp_mappings_ptr->connection_protocol == protocol_type::mux)
			{
				process_disconnect(conv);
				delete_mux_records(conv);
			}

			break;
		}
		case feature::keep_alive:
			break;
		case feature::raw_data:
		{
			if (prtcl != kcp_mappings_ptr->connection_protocol)
				continue;

			if (prtcl == protocol_type::tcp)
			{
				tcp_channel->async_send_data(std::move(buffer_cache), unbacked_data_ptr, unbacked_data_size);
				output_count += unbacked_data_size;
			}

			if (prtcl == protocol_type::udp)
			{
				udp::endpoint &udp_endpoint = kcp_mappings_ptr->ingress_source_endpoint;
				udp_access_point->async_send_out(std::move(buffer_cache), unbacked_data_ptr, unbacked_data_size, udp_endpoint);
				kcp_mappings_ptr->last_data_transfer_time.store(packet::right_now());
			}

			std::shared_lock share_locker_egress{ kcp_mappings_ptr->mutex_egress_endpoint };
			if (kcp_mappings_ptr->egress_target_endpoint != peer && kcp_mappings_ptr->egress_previous_target_endpoint != peer)
			{
				share_locker_egress.unlock();

				std::scoped_lock lockers{ kcp_mappings_ptr->mutex_egress_endpoint, mutex_target_address };
				kcp_mappings_ptr->egress_previous_target_endpoint = kcp_mappings_ptr->egress_target_endpoint;
				kcp_mappings_ptr->egress_target_endpoint = peer;
				*target_address = peer.address();
			}
			break;
		}
		case feature::mux_transfer:
			mux_transfer_data(prtcl, kcp_mappings_ptr, std::move(buffer_cache), unbacked_data_ptr, unbacked_data_size);
			break;
		case feature::mux_cancel:
			mux_cancel_channel(prtcl, kcp_mappings_ptr, unbacked_data_ptr, unbacked_data_size);
			break;
		default:
			break;
		}
	}
}

void client_mode::udp_forwarder_to_disconnecting_tcp(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (data_size == 0 || kcp_ptr == nullptr)
		return;

	uint8_t *data_ptr = data.get();
	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
	if (!error_message.empty())
		return;

	uint32_t conv = KCP::KCP::GetConv(data_ptr);
	if (kcp_ptr->GetConv() != conv)
	{
		std::stringstream ss;
		ss << peer;
		std::string error_message = time_to_string_with_square_brackets() +
			"kcp conv is not the same as record : conv = " + std::to_string(conv) +
			", local kcp_ptr : " + std::to_string(kcp_ptr->GetConv()) + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		return;
	}
	if (kcp_ptr->Input((const char *)data_ptr, (long)plain_size) < 0)
		return;

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

		auto [packet_timestamp, ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack(buffer_ptr, buffer_size);
		if (prtcl != protocol_type::tcp)
		{
			// error
			continue;
		}

		auto timestamp = packet::right_now();
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			continue;


		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->custom_data.load();
		tcp_session *tcp_channel = kcp_mappings_ptr->local_tcp.get();

		switch (ftr)
		{
		case feature::initialise:
		{
			std::string error_message = time_to_string_with_square_brackets() + "incorrect 'initialise' packet received\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			break;
		}
		case feature::failure:
		{
			std::string error_message = time_to_string_with_square_brackets() + "failure, error message: " + reinterpret_cast<char*>(unbacked_data_ptr) + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
		}
		[[fallthrough]];
		case feature::disconnect:
		{
			break;
		}
		case feature::keep_alive:
			break;
		case feature::raw_data:
		{
			if (tcp_channel->is_open())
				tcp_channel->async_send_data(std::move(buffer_cache), unbacked_data_ptr, unbacked_data_size);
			break;
		}
		case feature::mux_transfer:
			mux_transfer_data(prtcl, kcp_mappings_ptr, std::move(buffer_cache), unbacked_data_ptr, unbacked_data_size);
			break;
		case feature::mux_cancel:
			mux_cancel_channel(prtcl, kcp_mappings_ptr, unbacked_data_ptr, unbacked_data_size);
			break;
		default:
			break;
		}
	}
	input_count2 += data_size;
}

void client_mode::tcp_listener_accept_incoming_mux(std::shared_ptr<tcp_session> incoming_session)
{
	if (!incoming_session->is_open())
		return;

	std::shared_ptr<KCP::KCP> kcp_ptr = pick_one_from_kcp_channels();
	if (kcp_ptr == nullptr)
	{
		incoming_session->when_disconnect(empty_tcp_disconnect);
		incoming_session->disconnect();
		return;
	}
	uint32_t conv = kcp_ptr->GetConv();

	uint32_t new_id = generate_random_number<uint32_t>();
	uint64_t complete_connection_id = ((uint64_t)conv << 32) + new_id;
	std::shared_lock locker_id_map_to_mux_records{ mutex_id_map_to_mux_records };
	while (id_map_to_mux_records.find(complete_connection_id) != id_map_to_mux_records.end())
	{
		new_id = generate_random_number<uint32_t>();
		complete_connection_id = ((uint64_t)conv << 32) + new_id;
	}
	locker_id_map_to_mux_records.unlock();

	std::shared_ptr<mux_records> mux_records_ptr = std::make_shared<mux_records>();
	mux_records_ptr->kcp_conv = conv;
	mux_records_ptr->connection_id = new_id;
	mux_records_ptr->local_tcp = incoming_session;

	std::weak_ptr<KCP::KCP> kcp_ptr_weak = kcp_ptr;
	std::weak_ptr<mux_records> mux_records_ptr_weak = mux_records_ptr;
	incoming_session->replace_callback([this, kcp_ptr_weak, mux_records_ptr_weak](std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session) mutable
		{
			tcp_listener_incoming(std::move(data), data_size, incoming_session, kcp_ptr_weak, mux_records_ptr_weak);
		});
	incoming_session->when_disconnect([this, kcp_ptr, mux_records_ptr](std::shared_ptr<tcp_session> session) { local_disconnect(kcp_ptr, session, mux_records_ptr); });
	incoming_session->async_read_data();

	std::scoped_lock locks{ mutex_id_map_to_mux_records };
	id_map_to_mux_records[complete_connection_id] = mux_records_ptr;
}

void client_mode::tcp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_ptr_weak, std::weak_ptr<mux_records> mux_records_ptr_weak)
{
	mux_move_cached_to_tunnel();

	if (data == nullptr || incoming_session == nullptr || data_size == 0)
		return;

	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
	if (kcp_ptr == nullptr)
		return;

	std::shared_ptr<mux_records> mux_records_ptr = mux_records_ptr_weak.lock();
	if (mux_records_ptr == nullptr)
		return;

	std::shared_lock tcp_cache_shared_locker{mutex_mux_tcp_cache};
	auto cache_iter = mux_tcp_cache.find(kcp_ptr_weak);
	auto size_iter = mux_tcp_cache_max_size.find(kcp_ptr_weak);
	if (cache_iter == mux_tcp_cache.end() || size_iter == mux_tcp_cache_max_size.end())
		return;
	size_t tcp_cache_size = cache_iter->second.size();
	int cahce_max_size = size_iter->second;
	tcp_cache_shared_locker.unlock();

	if (!incoming_session->session_is_ending() && !incoming_session->is_pause() &&
		tcp_cache_size > cahce_max_size)
	{
		incoming_session->pause(true);
	}

	uint32_t connection_id = mux_records_ptr->connection_id;
	uint8_t *data_ptr = data.get();
	size_t new_data_size = packet::create_mux_data_packet(protocol_type::tcp, connection_id, data_ptr, data_size);

	mux_data_cache data_cache = { std::move(data), data_ptr, new_data_size };

	std::unique_lock tcp_cache_locker{mutex_mux_tcp_cache};
	cache_iter = mux_tcp_cache.find(kcp_ptr_weak);
	if (cache_iter == mux_tcp_cache.end())
		return;
	cache_iter->second.emplace_back(std::move(data_cache));
	tcp_cache_locker.unlock();

	mux_records_ptr->last_data_transfer_time.store(packet::right_now());
	mux_move_cached_to_tunnel();
}

void client_mode::udp_listener_incoming_mux(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	mux_move_cached_to_tunnel();
	std::shared_ptr<mux_records> mux_records_ptr = nullptr;
	std::shared_ptr<KCP::KCP> kcp_ptr = nullptr;

	if (mux_records_ptr == nullptr)
	{
		std::shared_lock shared_locker_udp_map_to_mux_records{mutex_udp_map_to_mux_records};
		if (udp_map_to_mux_records.find(peer) == udp_map_to_mux_records.end())
		{
			shared_locker_udp_map_to_mux_records.unlock();
			std::scoped_lock lockers{mutex_udp_map_to_mux_records, mutex_id_map_to_mux_records};
			if (udp_map_to_mux_records.find(peer) == udp_map_to_mux_records.end())
			{
				kcp_ptr = pick_one_from_kcp_channels();
				if (kcp_ptr == nullptr)
					return;

				uint32_t conv = kcp_ptr->GetConv();
				uint32_t new_id = generate_random_number<uint32_t>();
				uint64_t complete_connection_id = ((uint64_t)conv << 32) + new_id;
				while (id_map_to_mux_records.find(complete_connection_id) != id_map_to_mux_records.end())
				{
					new_id = generate_random_number<uint32_t>();
					complete_connection_id = ((uint64_t)conv << 32) + new_id;
				}

				mux_records_ptr = std::make_shared<mux_records>();
				mux_records_ptr->kcp_conv = conv;
				mux_records_ptr->connection_id = new_id;
				mux_records_ptr->source_endpoint = peer;

				id_map_to_mux_records[complete_connection_id] = mux_records_ptr;
				udp_map_to_mux_records[peer] = mux_records_ptr;
			}
			else
			{
				mux_records_ptr = udp_map_to_mux_records[peer].lock();
			}
		}
		else
		{
			mux_records_ptr = udp_map_to_mux_records[peer].lock();
		}
	}

	if (mux_records_ptr == nullptr)
		return;

	if (kcp_ptr == nullptr)
	{
		uint32_t kcp_conv = mux_records_ptr->kcp_conv;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = nullptr;
		std::shared_lock locker_kcp_channels{mutex_kcp_channels};
		if (auto iter = kcp_channels.find(kcp_conv); iter != kcp_channels.end())
			kcp_mappings_ptr = iter->second;
		else
			return;
		locker_kcp_channels.unlock();

		if (kcp_mappings_ptr == nullptr)
			return;

		kcp_ptr = kcp_mappings_ptr->egress_kcp;
		if (kcp_ptr == nullptr)
			return;
	}

	std::shared_lock udp_cache_shared_locker{mutex_mux_udp_cache};
	auto cache_iter = mux_udp_cache.find(kcp_ptr);
	auto size_iter = mux_udp_cache_max_size.find(kcp_ptr);
	if (cache_iter == mux_udp_cache.end() || size_iter == mux_udp_cache_max_size.end())
		return;
	size_t udp_cache_size = cache_iter->second.size();
	int cahce_max_size = size_iter->second;
	udp_cache_shared_locker.unlock();

	if (udp_cache_size > cahce_max_size)
		return;

	uint32_t connection_id = mux_records_ptr->connection_id;
	uint8_t *data_ptr = data.get();
	size_t new_data_size = packet::create_mux_data_packet(protocol_type::udp, connection_id, data_ptr, data_size);

	mux_data_cache data_cache = { std::move(data), data_ptr, new_data_size };

	std::unique_lock udp_cache_locker{mutex_mux_udp_cache};
	cache_iter = mux_udp_cache.find(kcp_ptr);
	if (cache_iter == mux_udp_cache.end())
		return;
	cache_iter->second.emplace_back(std::move(data_cache));
	udp_cache_locker.unlock();

	mux_records_ptr->last_data_transfer_time.store(packet::right_now());
	mux_move_cached_to_tunnel();
}

void client_mode::mux_transfer_data(protocol_type prtcl, kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> buffer_cache, uint8_t *unbacked_data_ptr, size_t unbacked_data_size)
{
	auto [mux_connection_id, mux_data, mux_data_size] = packet::extract_mux_data_from_unpacked_data(unbacked_data_ptr, unbacked_data_size);
	uint64_t complete_connection_id = ((uint64_t)kcp_mappings_ptr->egress_kcp->GetConv() << 32) + mux_connection_id;
	std::shared_ptr<mux_records> mux_records_ptr = nullptr;

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
				unique_locker_iter_mux_records.unlock();
				std::vector<uint8_t> data = packet::inform_mux_cancel_packet(prtcl, mux_connection_id);
				kcp_mappings_ptr->egress_kcp->Send((const char *)data.data(), data.size());
				uint32_t next_update_time = kcp_mappings_ptr->egress_kcp->Check();
				kcp_updater.submit(kcp_mappings_ptr->egress_kcp, next_update_time);
				return;
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
		udp::endpoint udp_client_ep = mux_records_ptr->source_endpoint;
		udp_access_point->async_send_out(std::move(buffer_cache), mux_data, mux_data_size, udp_client_ep);
		mux_records_ptr->last_data_transfer_time.store(packet::right_now());
	}
}

void client_mode::mux_cancel_channel(protocol_type prtcl, kcp_mappings *kcp_mappings_ptr, uint8_t *unbacked_data_ptr, size_t unbacked_data_size)
{
	auto [mux_connection_id, mux_data, mux_data_size] = packet::extract_mux_data_from_unpacked_data(unbacked_data_ptr, unbacked_data_size);
	uint64_t complete_connection_id = ((uint64_t)kcp_mappings_ptr->egress_kcp->GetConv() << 32) + mux_connection_id;
	std::shared_ptr<mux_records> mux_records_ptr = nullptr;

	{
		std::scoped_lock locker{mutex_id_map_to_mux_records, mutex_udp_map_to_mux_records};

		auto iter_mux_records = id_map_to_mux_records.find(complete_connection_id);
		if (iter_mux_records == id_map_to_mux_records.end())
			return;

		mux_records_ptr = iter_mux_records->second;
		id_map_to_mux_records.erase(iter_mux_records);
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
		udp_map_to_mux_records.erase(mux_records_ptr->source_endpoint);
	}
}

void client_mode::mux_move_cached_to_tunnel()
{
	std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>> kcp_ptr_list;
	std::unique_lock udp_cache_locker{mutex_mux_udp_cache};
	std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>> kcp_ptr_udp = mux_move_cached_to_tunnel(mux_udp_cache, 2);
	udp_cache_locker.unlock();

	std::unique_lock tcp_cache_locker{mutex_mux_tcp_cache};
	std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>> kcp_ptr_tcp = mux_move_cached_to_tunnel(mux_tcp_cache, 1);
	tcp_cache_locker.unlock();

	kcp_ptr_list.insert(kcp_ptr_tcp.begin(), kcp_ptr_tcp.end());
	kcp_ptr_list.insert(kcp_ptr_udp.begin(), kcp_ptr_udp.end());

	for (std::shared_ptr<KCP::KCP> kcp_ptr : kcp_ptr_list)
	{
		uint32_t next_update_time = kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_update_time);
	}
}

std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>>
client_mode::mux_move_cached_to_tunnel(std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> &data_queues, int one_x)
{
	std::set<std::shared_ptr<KCP::KCP>, std::owner_less<>> kcp_ptr_list;
	if (one_x <= 0)
		one_x = 1;

	for (auto &[kcp_ptr_weak, data_cache] : data_queues)
	{
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
		if (kcp_ptr == nullptr)
			continue;

		kcp_ptr_list.insert(kcp_ptr);

		//if (kcp_ptr->WaitingForSend() > kcp_ptr->GetSendWindowSize())
		//	continue;

		size_t pickup_size = data_cache.size();
		//size_t snd_wnd = (size_t)kcp_ptr->GetSendWindowSize() / one_x;
		//if (pickup_size > snd_wnd)
		//	pickup_size = (size_t)snd_wnd;
		int available_spaces = kcp_ptr->GetSendWindowSize() - kcp_ptr->WaitingForSend();
		if (available_spaces <= 0)
			continue;

		available_spaces = available_spaces / one_x + 1;
		if (pickup_size > available_spaces)
			pickup_size = (size_t)available_spaces;

		for (size_t i = 0; i < pickup_size; i++)
		{
			mux_data_cache cached_data = std::move(data_cache.front());
			kcp_ptr->Send((const char *)cached_data.sending_ptr, cached_data.data_size);
			data_cache.pop_front();
		}
	}

	return kcp_ptr_list;
}

void client_mode::refresh_mux_queue(std::weak_ptr<KCP::KCP> kcp_ptr_weak)
{
	mux_move_cached_to_tunnel();
	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
	if (kcp_ptr == nullptr)
		return;
	std::unique_lock tcp_cache_locker{mutex_mux_tcp_cache};
	size_t tcp_cache_size = mux_tcp_cache[kcp_ptr_weak].size();
	tcp_cache_locker.unlock();

	size_t snd_wnd = (size_t)kcp_ptr->GetSendWindowSize() / 4;
	if (snd_wnd < KCP_DEFAULT_WINDOW)
		snd_wnd = KCP_DEFAULT_WINDOW;

	std::shared_lock locker{mutex_id_map_to_mux_records};
	for (auto &[connection_id, record_ptr] : id_map_to_mux_records)
	{
		std::shared_ptr session = record_ptr->local_tcp;
		if (session != nullptr && session->is_pause() && tcp_cache_size < snd_wnd)
		{
			session->pause(false);
		}
	}
	locker.unlock();
}

std::shared_ptr<KCP::KCP> client_mode::pick_one_from_kcp_channels()
{
	std::shared_ptr<KCP::KCP> kcp_ptr = nullptr;
	std::shared_lock locker_kcp_channels{mutex_kcp_channels};
	if (kcp_channels.empty())
	{
		kcp_ptr = nullptr;
	}
	else if (kcp_channels.size() == 1)
	{
		kcp_ptr = kcp_channels.begin()->second->egress_kcp;
	}
	else
	{
		int index = generate_random_number<int>(0, (uint16_t)kcp_channels.size() - 1);
		auto iter = kcp_channels.begin();
		std::advance(iter, index);
		kcp_ptr = iter->second->egress_kcp;
	}
	locker_kcp_channels.unlock();

	return kcp_ptr;
}

int client_mode::kcp_sender(const char *buf, int len, void *user)
{
	std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(len + BUFFER_EXPAND_SIZE);
	uint8_t *new_buffer_ptr = new_buffer.get();
	std::copy_n((const uint8_t *)buf, len, new_buffer_ptr);
	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, new_buffer_ptr, len);
	if (!error_message.empty() || cipher_size == 0 || user == nullptr)
		return 0;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;
	kcp_mappings_ptr->egress_forwarder->async_send_out(std::move(new_buffer), cipher_size, kcp_mappings_ptr->egress_target_endpoint);
	change_new_port(kcp_mappings_ptr);
	output_count2 += cipher_size;
	return 0;
}

bool client_mode::get_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target)
{
	if (target_address != nullptr)
	{
		uint16_t destination_port = current_settings.destination_port;
		if (destination_port == 0)
			destination_port = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

		udp_target = udp::endpoint(*target_address, destination_port);
		return true;
	}

	return update_udp_target(target_connector, udp_target);
}

bool client_mode::update_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target)
{
	uint16_t destination_port = current_settings.destination_port;
	if (destination_port == 0)
		destination_port = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

	bool connect_success = false;
	asio::error_code ec;
	for (int i = 0; i <= RETRY_TIMES; ++i)
	{
		const std::string &destination_address = current_settings.destination_address;
		udp::resolver::results_type udp_endpoints = target_connector->get_remote_hostname(destination_address, destination_port, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + ec.message() + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
		}
		else if (udp_endpoints.size() == 0)
		{
			std::string error_message = time_to_string_with_square_brackets() + "destination address not found\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
		}
		else
		{
			std::scoped_lock locker{ mutex_target_address };
			udp_target = *udp_endpoints.begin();
			target_address = std::make_unique<asio::ip::address>(udp_target.address());
			connect_success = true;
			break;
		}
	}

	return connect_success;
}

void client_mode::local_disconnect(std::shared_ptr<KCP::KCP> kcp_ptr, std::shared_ptr<tcp_session> session)
{
	uint32_t conv = kcp_ptr->GetConv();
	auto udp_func = std::bind(&client_mode::udp_forwarder_to_disconnecting_tcp, this, _1, _2, _3, _4, _5);

	std::scoped_lock lockers{ mutex_kcp_channels };
	auto kcp_channel_iter = kcp_channels.find(conv);
	if (kcp_channel_iter == kcp_channels.end())
		return;

	std::shared_ptr<kcp_mappings> kcp_mappings_ptr = kcp_channel_iter->second;

	if (std::scoped_lock locker_expiring_kcp{ mutex_expiring_kcp }; expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
		expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() });

	if (std::scoped_lock locker_kcp_keepalive{mutex_kcp_keepalive}; kcp_keepalive.find(kcp_ptr) != kcp_keepalive.end())
		kcp_keepalive.erase(kcp_ptr);

	kcp_mappings_ptr->changeport_timestamp.store(LLONG_MAX);
	kcp_mappings_ptr->egress_forwarder->replace_callback(udp_func);

	std::vector<uint8_t> data = packet::inform_disconnect_packet(protocol_type::tcp);
	kcp_ptr->Send((const char *)data.data(), data.size());
	uint32_t next_update_time = kcp_ptr->Check();
	kcp_updater.submit(kcp_ptr, next_update_time);

	session->when_disconnect(empty_tcp_disconnect);
	session->session_is_ending(true);
	session->pause(false);
	session->stop();

	kcp_channels.erase(kcp_channel_iter);
}

void client_mode::local_disconnect(std::shared_ptr<KCP::KCP> kcp_ptr, std::shared_ptr<tcp_session> session, std::shared_ptr<mux_records> mux_records_ptr)
{
	uint32_t connection_id = mux_records_ptr->connection_id;
	uint64_t complete_connection_id = ((uint64_t)mux_records_ptr->kcp_conv << 32) + connection_id;
	std::vector<uint8_t> mux_cancel_data = packet::inform_mux_cancel_packet(protocol_type::tcp, connection_id);

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

	//kcp_ptr->Send((const char *)mux_cancel_data.data(), mux_cancel_data.size());
	//uint32_t next_update_time = kcp_ptr->Check();
	//kcp_updater.submit(kcp_ptr, next_update_time);

	session->when_disconnect(empty_tcp_disconnect);
	session->session_is_ending(true);
	session->pause(false);
	session->stop();

	std::scoped_lock lockers{mutex_id_map_to_mux_records};
	id_map_to_mux_records.erase(complete_connection_id);
}

void client_mode::process_disconnect(uint32_t conv)
{
	std::scoped_lock lockers{ mutex_kcp_channels };
	auto kcp_channel_iter = kcp_channels.find(conv);
	if (kcp_channel_iter == kcp_channels.end())
		return;

	std::shared_ptr<kcp_mappings> kcp_mappings_ptr = kcp_channel_iter->second;
	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;

	if (std::scoped_lock locker_expiring_kcp{ mutex_expiring_kcp }; expiring_kcp.find(kcp_ptr) == expiring_kcp.end())
		expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() });

	if (std::scoped_lock locker_kcp_keepalive{mutex_kcp_keepalive}; kcp_keepalive.find(kcp_ptr) != kcp_keepalive.end())
		kcp_keepalive.erase(kcp_ptr);

	kcp_channels.erase(kcp_channel_iter);
}

void client_mode::process_disconnect(uint32_t conv, tcp_session *session)
{
	auto udp_func = std::bind(&client_mode::udp_forwarder_to_disconnecting_tcp, this, _1, _2, _3, _4, _5);

	std::scoped_lock lockers{ mutex_kcp_channels, mutex_expiring_kcp };
	auto kcp_channel_iter = kcp_channels.find(conv);
	if (kcp_channel_iter == kcp_channels.end())
		return;

	std::shared_ptr<kcp_mappings> kcp_mappings_ptr = kcp_channel_iter->second;
	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;

	if (expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
		expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() });

	if (std::scoped_lock locker_kcp_keepalive{mutex_kcp_keepalive}; kcp_keepalive.find(kcp_ptr) != kcp_keepalive.end())
		kcp_keepalive.erase(kcp_ptr);

	kcp_mappings_ptr->egress_forwarder->replace_callback(udp_func);

	session->when_disconnect(empty_tcp_disconnect);
	session->session_is_ending(true);
	session->pause(false);
	session->stop();
	session->disconnect();

	kcp_channels.erase(kcp_channel_iter);
}

void client_mode::change_new_port(kcp_mappings *kcp_mappings_ptr)
{
	if (kcp_mappings_ptr->changeport_timestamp.load() > packet::right_now())
		return;
	kcp_mappings_ptr->changeport_timestamp += current_settings.dynamic_port_refresh;

	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;

	auto udp_func = std::bind(&client_mode::udp_forwarder_incoming, this, _1, _2, _3, _4, _5);
	std::shared_ptr<forwarder> udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, kcp_ptr, udp_func, current_settings.ipv4_only);
	if (udp_forwarder == nullptr)
		return;

	uint16_t destination_port_start = current_settings.destination_port_start;
	uint16_t destination_port_end = current_settings.destination_port_end;
	if (destination_port_start != destination_port_end)
	{
		uint16_t new_port_numer = generate_new_port_number(destination_port_start, destination_port_end);
		std::shared_lock locker{ mutex_target_address };
		asio::ip::address temp_address = *target_address;
		locker.unlock();
		std::scoped_lock locker_egress{kcp_mappings_ptr->mutex_egress_endpoint};
		kcp_mappings_ptr->egress_target_endpoint.address(temp_address);
		kcp_mappings_ptr->egress_target_endpoint.port(new_port_numer);
	}

	asio::error_code ec;
	if (current_settings.ipv4_only)
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);

	if (ec)
		return;

	udp_forwarder->async_receive();

	std::shared_ptr<forwarder> old_forwarder = kcp_mappings_ptr->egress_forwarder;
	kcp_mappings_ptr->egress_forwarder = udp_forwarder;

	std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
	expiring_forwarders.insert({ old_forwarder, packet::right_now() });
}

bool client_mode::handshake_timeout_detection(kcp_mappings *kcp_mappings_ptr)
{
	if (kcp_mappings_ptr == nullptr)
		return true;

	int64_t right_now = packet::right_now();
	int64_t time_diff = calculate_difference(kcp_mappings_ptr->handshake_setup_time.load(), right_now);
	if (time_diff < HANDSHAKE_TIMEOUT)
		return false;

	protocol_type connection_protocol = kcp_mappings_ptr->connection_protocol;
	std::shared_ptr<kcp_mappings> new_kcp_mappings_ptr;
	if (connection_protocol == protocol_type::tcp)
		new_kcp_mappings_ptr = create_handshake(kcp_mappings_ptr->local_tcp);
	if (connection_protocol == protocol_type::udp)
		new_kcp_mappings_ptr = create_handshake(kcp_mappings_ptr->ingress_source_endpoint);
	if (connection_protocol == protocol_type::mux)
		new_kcp_mappings_ptr = create_handshake(protocol_type::mux);

	std::shared_ptr<kcp_mappings> old_kcp_mappings_ptr = nullptr;
	std::unique_lock locker{mutex_handshakes};
	if (auto iter = handshakes.find(kcp_mappings_ptr); iter != handshakes.end())
	{
		old_kcp_mappings_ptr = iter->second;
		handshakes.erase(iter);
	}
	handshakes[new_kcp_mappings_ptr.get()] = new_kcp_mappings_ptr;
	locker.unlock();

	kcp_mappings_ptr->egress_kcp->custom_data.store(nullptr);
	kcp_updater.remove(kcp_mappings_ptr->egress_kcp);
	uint32_t next_update_time = new_kcp_mappings_ptr->egress_kcp->Check();
	kcp_updater.submit(new_kcp_mappings_ptr->egress_kcp, next_update_time);
	return true;
}

void client_mode::delete_mux_records(uint32_t conv)
{
	std::scoped_lock locker{mutex_id_map_to_mux_records, mutex_udp_map_to_mux_records};
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

		id_map_to_mux_records.erase(iter);
	}

	for (auto iter = udp_map_to_mux_records.begin(), next_iter = iter; iter != udp_map_to_mux_records.end(); iter = next_iter)
	{
		++next_iter;
		std::weak_ptr mux_records_ptr_weak = iter->second;
		if (mux_records_ptr_weak.expired())
			udp_map_to_mux_records.erase(iter);
	}
}

void client_mode::cleanup_expiring_forwarders()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock lockers{ mutex_expiring_forwarders };
	for (auto iter = expiring_forwarders.begin(), next_iter = iter; iter != expiring_forwarders.end(); iter = next_iter)
	{
		++next_iter;
		auto &[udp_forwrder, expire_time] = *iter;
		int64_t time_elapsed = calculate_difference(time_right_now, expire_time);

		if (time_elapsed <= RECEIVER_CLEANUP_WAITS / 2)
			continue;

		if (time_elapsed < RECEIVER_CLEANUP_WAITS)
		{
			udp_forwrder->remove_callback();
			udp_forwrder->stop();
			continue;
		}

		udp_forwrder->disconnect();
		expiring_forwarders.erase(iter);
	}
}

void client_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock locker{ mutex_expiring_kcp };
	for (auto iter = expiring_kcp.begin(), next_iter = iter; iter != expiring_kcp.end(); iter = next_iter)
	{
		++next_iter;
		auto &[kcp_mappings_ptr, expire_time] = *iter;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;

		if (calculate_difference(time_right_now, expire_time) < KCP_CLEANUP_WAITS)
			continue;

		kcp_ptr->SetOutput(empty_kcp_output);

		{
			std::scoped_lock locker_expiring_forwarders{ mutex_expiring_forwarders };
			std::shared_ptr<forwarder> forwarder_ptr = kcp_mappings_ptr->egress_forwarder;
			forwarder_ptr->remove_callback();
			forwarder_ptr->stop();
			if (expiring_forwarders.find(forwarder_ptr) == expiring_forwarders.end())
				expiring_forwarders.insert({ forwarder_ptr, packet::right_now() });
		}

		if (kcp_mappings_ptr->connection_protocol == protocol_type::tcp)
		{
			tcp_session *tcp_channel = kcp_mappings_ptr->local_tcp.get();
			tcp_channel->when_disconnect(empty_tcp_disconnect);
			tcp_channel->stop();
		}

		if (kcp_mappings_ptr->connection_protocol == protocol_type::udp)
		{
			udp::endpoint &udp_endpoint = kcp_mappings_ptr->ingress_source_endpoint;
			std::scoped_lock locker_udp_session_map_to_kcp {mutex_udp_local_session_map_to_kcp};
			udp_local_session_map_to_kcp.erase(udp_endpoint);
		}

		kcp_updater.remove(kcp_mappings_ptr->egress_kcp);
		expiring_kcp.erase(iter);
	}
}

void client_mode::cleanup_expiring_handshake_connections()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock locker{ mutex_expiring_handshakes };
	for (auto iter = expiring_handshakes.begin(), next_iter = iter; iter != expiring_handshakes.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = iter->first;
		if (kcp_mappings_ptr == nullptr)
		{
			expiring_handshakes.erase(iter);
			continue;
		}

		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;
		int64_t expire_time = iter->second;
		if (calculate_difference(time_right_now, expire_time) < KCP_CLEANUP_WAITS)
			continue;

		if (kcp_mappings_ptr->egress_forwarder != nullptr)
		{
			kcp_mappings_ptr->egress_forwarder->remove_callback();
			kcp_mappings_ptr->egress_forwarder->stop();
			kcp_mappings_ptr->egress_forwarder->disconnect();
		}

		kcp_updater.remove(kcp_ptr);
		expiring_handshakes.erase(iter);
	}
}

void client_mode::cleanup_expiring_mux_records()
{
	auto time_right_now = packet::right_now();
	std::map<uint32_t, std::vector<std::vector<uint8_t>>> waiting_for_inform;	// kcp_conv, inform_data

	{
		std::scoped_lock lockers{ mutex_id_map_to_mux_records, mutex_udp_map_to_mux_records};
		for (auto iter = id_map_to_mux_records.begin(), next_iter = iter; iter != id_map_to_mux_records.end(); iter = next_iter)
		{
			++next_iter;
			uint64_t connection_id = iter->first;
			std::shared_ptr<mux_records> mux_records_ptr = iter->second;
			udp::endpoint local_udp_ep = mux_records_ptr->source_endpoint;
			std::shared_ptr<tcp_session> local_tcp = mux_records_ptr->local_tcp;
			std::shared_ptr<udp_client> local_udp = mux_records_ptr->local_udp;

			if (local_tcp != nullptr && !local_tcp->is_stop())
				continue;

			if (calculate_difference(mux_records_ptr->last_data_transfer_time.load(), time_right_now) < current_settings.udp_timeout)
				continue;

			if (udp_map_to_mux_records.find(local_udp_ep) != udp_map_to_mux_records.end())
			{
				udp_map_to_mux_records.erase(local_udp_ep);

				std::vector<uint8_t> data = packet::inform_mux_cancel_packet(protocol_type::udp, mux_records_ptr->connection_id);
				waiting_for_inform[mux_records_ptr->kcp_conv].emplace_back(std::move(data));
			}

			id_map_to_mux_records.erase(iter);
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
			kcp_mappings_ptr->egress_kcp->Send((const char *)data.data(), data.size());
		}
		uint32_t next_update_time = kcp_mappings_ptr->egress_kcp->Check();
		kcp_updater.submit(kcp_mappings_ptr->egress_kcp, next_update_time);
	}
}

void client_mode::loop_find_expires()
{
	auto time_right_now = packet::right_now();

	std::unique_lock locker_expiring_kcp{mutex_expiring_kcp, std::defer_lock };
	std::unique_lock locker_kcp_keepalive{mutex_kcp_keepalive, std::defer_lock };
	std::scoped_lock locker{ mutex_kcp_channels };
	uint32_t max_window_size = (uint32_t)(max_capacity_size_by_mtu(current_settings.kcp_mtu) / (kcp_channels.size() * 2 + 1));
	for (auto iter = kcp_channels.begin(), next_iter = iter; iter != kcp_channels.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t conv = iter->first;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = iter->second;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;
		kcp_ptr->SetMaxWindowSize(max_window_size);

		if (kcp_mappings_ptr->connection_protocol == protocol_type::tcp)
		{
			tcp_session *tcp_channel = kcp_mappings_ptr->local_tcp.get();
			if (tcp_channel->is_stop() || !tcp_channel->is_open())
			{
				locker_expiring_kcp.lock();
				if (expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
				{
					tcp_channel->when_disconnect(empty_tcp_disconnect);
					tcp_channel->disconnect();
					tcp_channel->stop();
					expiring_kcp.insert({ kcp_mappings_ptr, time_right_now });
				}
				locker_expiring_kcp.unlock();

				locker_kcp_keepalive.lock();
				if (kcp_keepalive.find(kcp_ptr) != kcp_keepalive.end())
					kcp_keepalive.erase(kcp_ptr);
				locker_kcp_keepalive.unlock();

				kcp_channels.erase(iter);
				kcp_ptr->SetOutput(empty_kcp_output);
			}
		}

		if (kcp_mappings_ptr->connection_protocol == protocol_type::udp)
		{
			if (calculate_difference(time_right_now, kcp_mappings_ptr->last_data_transfer_time.load()) > current_settings.udp_timeout)
			{
				locker_expiring_kcp.lock();
				if (expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
					expiring_kcp.insert({ kcp_mappings_ptr, time_right_now });
				locker_expiring_kcp.unlock();

				locker_kcp_keepalive.lock();
				if (kcp_keepalive.find(kcp_ptr) != kcp_keepalive.end())
					kcp_keepalive.erase(kcp_ptr);
				locker_kcp_keepalive.unlock();

				kcp_channels.erase(iter);
				kcp_ptr->SetOutput(empty_kcp_output);
			}
		}

		if (kcp_mappings_ptr->connection_protocol == protocol_type::mux)
		{
			if (calculate_difference(kcp_ptr->LastInputTime(), packet::right_now()) > MUX_CHANNELS_CLEANUP)
			{
				locker_expiring_kcp.lock();
				if (expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
					expiring_kcp.insert({ kcp_mappings_ptr, time_right_now });
				locker_expiring_kcp.unlock();

				kcp_channels.erase(iter);
				kcp_ptr->SetOutput(empty_kcp_output);

				delete_mux_records(conv);
				establish_mux_channels(1);

				std::scoped_lock mux_locks{mutex_mux_tcp_cache, mutex_mux_udp_cache};
				mux_tcp_cache.erase(kcp_ptr);
				mux_tcp_cache_max_size.erase(kcp_ptr);
				mux_udp_cache.erase(kcp_ptr);
				mux_udp_cache_max_size.erase(kcp_ptr);
			}
			else
			{
				int snd_wnd = kcp_ptr->GetSendWindowSize();
				std::scoped_lock mux_locks{mutex_mux_tcp_cache, mutex_mux_udp_cache};
				if (auto iter = mux_tcp_cache_max_size.find(kcp_ptr); iter != mux_tcp_cache_max_size.end())
					iter->second = snd_wnd;

				if (auto iter = mux_udp_cache_max_size.find(kcp_ptr); iter != mux_tcp_cache_max_size.end())
					iter->second = snd_wnd;
			}
		}
	}
}

void client_mode::loop_keep_alive()
{
	std::shared_lock locker_kcp_keepalive{ mutex_kcp_keepalive };
	for (auto iter = kcp_keepalive.begin(), next_iter = iter; iter != kcp_keepalive.end(); iter = next_iter)
	{
		++next_iter;
		std::weak_ptr kcp_ptr_weak = iter->first;
		std::atomic<int64_t> &timestamp = iter->second;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
		if (kcp_ptr == nullptr)
			continue;

		if (timestamp.load() > packet::right_now())
			continue;
		timestamp += current_settings.keep_alive;

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->custom_data.load();
		std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_packet(kcp_mappings_ptr->connection_protocol);
		kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());

		uint32_t next_refresh_time = kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_refresh_time);
	}
}

void client_mode::expiring_connection_loops(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	cleanup_expiring_forwarders();
	cleanup_expiring_data_connections();
	cleanup_expiring_handshake_connections();
	cleanup_expiring_mux_records();

	timer_expiring_kcp.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_connection_loops(e); });
}

void client_mode::find_expires(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_find_expires();

	timer_find_expires.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });
}

void client_mode::time_counting(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	int64_t input_speed = input_count.load();
	int64_t output_speed = output_count.load();

	int64_t input_speed2 = input_count2.load();
	int64_t output_speed2 = output_count2.load();

	std::cout << "Client -> Here speed: " << input_speed / 1024 << " KB/s\t Here -> Client Speed: " << output_speed / 1024 << " KB/s\t";
	std::cout << "Server -> Here speed: " << input_speed2 / 1024 << " KB/s\t Here -> Server Speed: " << output_speed2 / 1024 << " KB/s\n";

	input_count.store(0);
	output_count.store(0);

	input_count2.store(0);
	output_count2.store(0);

	timer_speed_count.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_speed_count.async_wait([this](const asio::error_code &e) { time_counting(e); });
}

void client_mode::keep_alive(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_keep_alive();

	timer_keep_alive.expires_after(KEEPALIVE_UPDATE_INTERVAL);
	timer_keep_alive.async_wait([this](const asio::error_code& e) { keep_alive(e); });
}

std::shared_ptr<kcp_mappings> client_mode::create_handshake(std::shared_ptr<tcp_session> local_tcp)
{
	std::shared_ptr<kcp_mappings> handshake_kcp_mappings = create_handshake(protocol_type::tcp);
	if (handshake_kcp_mappings != nullptr)
		handshake_kcp_mappings->local_tcp = local_tcp;
	return handshake_kcp_mappings;
}

std::shared_ptr<kcp_mappings> client_mode::create_handshake(udp::endpoint local_endpoint)
{
	std::shared_ptr<kcp_mappings> handshake_kcp_mappings = create_handshake(protocol_type::udp);
	if (handshake_kcp_mappings != nullptr)
		handshake_kcp_mappings->ingress_source_endpoint = local_endpoint;
	return handshake_kcp_mappings;
}

std::shared_ptr<kcp_mappings> client_mode::create_handshake(protocol_type prtcl)
{
	std::shared_ptr<KCP::KCP> handshake_kcp = std::make_shared<KCP::KCP>();
	std::shared_ptr<kcp_mappings> handshake_kcp_mappings = std::make_shared<kcp_mappings>();
	handshake_kcp->custom_data.store(handshake_kcp_mappings.get());
	handshake_kcp_mappings->egress_kcp = handshake_kcp;
	handshake_kcp_mappings->connection_protocol = prtcl;
	handshake_kcp_mappings->changeport_timestamp.store(LLONG_MAX);
	handshake_kcp_mappings->handshake_setup_time.store(packet::right_now());

	auto udp_func = std::bind(&client_mode::handle_handshake, this, _1, _2, _3, _4, _5);
	auto udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, handshake_kcp, udp_func, current_settings.ipv4_only);
	if (udp_forwarder == nullptr)
		return nullptr;

	bool success = get_udp_target(udp_forwarder, handshake_kcp_mappings->egress_target_endpoint);
	if (!success)
		return nullptr;
	handshake_kcp_mappings->egress_forwarder = udp_forwarder;

	handshake_kcp->SetMTU(current_settings.kcp_mtu);
	handshake_kcp->NoDelay(1, 1, 3, 1);
	handshake_kcp->Update();
	handshake_kcp->RxMinRTO() = 10;
	handshake_kcp->SetBandwidth(current_settings.outbound_bandwidth, current_settings.inbound_bandwidth);
	handshake_kcp->SetOutput([this](const char *buf, int len, void *user) -> int
		{
			if (handshake_timeout_detection((kcp_mappings *)user))
				return 0;
			return kcp_sender(buf, len, user);
		});

	asio::error_code ec;
	if (current_settings.ipv4_only)
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);
	udp_forwarder->async_receive();

	std::vector<uint8_t> handshake_data = packet::request_initialise_packet(handshake_kcp_mappings->connection_protocol);
	if (handshake_kcp->Send((const char *)handshake_data.data(), handshake_data.size()) < 0)
		return nullptr;

	handshake_kcp->Update();

	return handshake_kcp_mappings;
}

void client_mode::setup_mux_kcp(std::shared_ptr<KCP::KCP> kcp_ptr)
{
	kcp_ptr->SetOutput([this](const char *buf, int len, void *user) -> int
		{
			std::weak_ptr data_kcp = ((kcp_mappings *)user)->egress_kcp;
			std::unique_ptr<uint8_t[]> empty_ptr;
			auto func = [this, data_kcp](std::unique_ptr<uint8_t[]> data) mutable {refresh_mux_queue(data_kcp); };
			sequence_task_pool_local.push_task((size_t)this, func, std::move(empty_ptr));
			int ret = kcp_sender(buf, len, user);
			empty_ptr = nullptr;
			sequence_task_pool_local.push_task((size_t)this, func, std::move(empty_ptr));
			return ret;
		});

	std::scoped_lock lockers{ mutex_mux_tcp_cache, mutex_mux_udp_cache};
	mux_tcp_cache[kcp_ptr].clear();
	mux_udp_cache[kcp_ptr].clear();
	mux_tcp_cache_max_size[kcp_ptr] = kcp_ptr->GetSendWindowSize();
	mux_udp_cache_max_size[kcp_ptr] = kcp_ptr->GetSendWindowSize();
}

void client_mode::establish_mux_channels(uint16_t counts)
{
	for (int i = 0; i < counts; i++)
	{
		std::shared_ptr<kcp_mappings> hs = create_handshake(protocol_type::mux);
		if (hs == nullptr)
		{
			std::string error_message = time_to_string_with_square_brackets() + "establish handshake failed\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			return;
		}

		hs->egress_kcp->Update();
		uint32_t next_update_time = hs->egress_kcp->Check();
		kcp_updater.submit(hs->egress_kcp, next_update_time);

		std::scoped_lock locker{mutex_handshakes};
		handshakes[hs.get()] = hs;
	}
}

void client_mode::on_handshake_success(kcp_mappings *handshake_ptr, uint32_t conv, uint16_t start_port, uint16_t end_port)
{
	if (start_port != 0 && end_port != 0)
	{
		current_settings.destination_port_start = start_port;
		current_settings.destination_port_end = end_port;
	}

	protocol_type ptrcl = handshake_ptr->connection_protocol;
	std::shared_ptr<kcp_mappings> kcp_mappings_ptr = std::make_shared<kcp_mappings>();
	std::shared_ptr<KCP::KCP> kcp_ptr = std::make_shared<KCP::KCP>(conv);
	kcp_mappings_ptr->connection_protocol = ptrcl;

	auto udp_func = std::bind(&client_mode::udp_forwarder_incoming, this, _1, _2, _3, _4, _5);
	std::shared_ptr<forwarder> udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, kcp_ptr, udp_func, current_settings.ipv4_only);
	if (udp_forwarder == nullptr)
		return;

	asio::error_code ec;
	if (current_settings.ipv4_only)
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);

	if (ec)
		return;
	udp_forwarder->async_receive();

	kcp_ptr->custom_data.store(kcp_mappings_ptr.get());
	kcp_ptr->SetMTU(current_settings.kcp_mtu);
	kcp_ptr->SetWindowSize(current_settings.kcp_sndwnd, current_settings.kcp_rcvwnd);
	kcp_ptr->NoDelay(current_settings.kcp_nodelay, current_settings.kcp_interval, current_settings.kcp_resend, current_settings.kcp_nc);
	kcp_ptr->RxMinRTO() = 10;
	kcp_ptr->SetBandwidth(current_settings.outbound_bandwidth, current_settings.inbound_bandwidth);

	kcp_mappings_ptr->egress_kcp = kcp_ptr;
	kcp_mappings_ptr->egress_forwarder = udp_forwarder;

	bool success = get_udp_target(udp_forwarder, kcp_mappings_ptr->egress_target_endpoint);
	if (!success)
		return;
	kcp_mappings_ptr->egress_previous_target_endpoint = kcp_mappings_ptr->egress_target_endpoint;

	if (current_settings.dynamic_port_refresh == 0)
		kcp_mappings_ptr->changeport_timestamp.store(LLONG_MAX);
	else
		kcp_mappings_ptr->changeport_timestamp.store(packet::right_now() + current_settings.dynamic_port_refresh);

	if (current_settings.keep_alive > 0)
	{
		std::scoped_lock locker { mutex_kcp_keepalive };
		kcp_keepalive[kcp_ptr].store(packet::right_now() + current_settings.keep_alive);
	}


	if (ptrcl == protocol_type::tcp)
	{
		std::shared_ptr<tcp_session> incoming_session = handshake_ptr->local_tcp;
		{
			std::scoped_lock lock_handshake{ mutex_handshakes, mutex_expiring_handshakes };
			std::shared_ptr<kcp_mappings> handshake_mappings_ptr = handshakes[handshake_ptr];
			handshakes.erase(handshake_ptr);
			expiring_handshakes.insert({ handshake_mappings_ptr, packet::right_now() });
		}

		kcp_mappings_ptr->local_tcp = incoming_session;
		kcp_ptr->SetOutput([this](const char *buf, int len, void *user) -> int
			{
				int ret = kcp_sender(buf, len, user);
				kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;
				if (kcp_mappings_ptr->local_tcp->is_pause() &&
					kcp_mappings_ptr->egress_kcp->WaitingForSend() < kcp_mappings_ptr->egress_kcp->GetSendWindowSize())
					kcp_mappings_ptr->local_tcp->pause(false);
				return ret;
			});

		std::weak_ptr<KCP::KCP> kcp_ptr_weak = kcp_ptr;
		incoming_session->replace_callback([this, kcp_ptr_weak](std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session) mutable
			{
				tcp_listener_incoming(std::move(data), data_size, incoming_session, kcp_ptr_weak);
			});
		incoming_session->when_disconnect([kcp_ptr, this](std::shared_ptr<tcp_session> session) { local_disconnect(kcp_ptr, session); });
		incoming_session->async_read_data();
	}

	if (ptrcl == protocol_type::udp)
	{
		std::scoped_lock handshake_lockers{ mutex_udp_address_map_to_handshake, mutex_expiring_handshakes, mutex_udp_seesion_caches, mutex_udp_local_session_map_to_kcp };
		udp::endpoint local_peer = handshake_ptr->ingress_source_endpoint;
		std::shared_ptr<kcp_mappings> handshake_mappings_ptr = udp_address_map_to_handshake[local_peer];
		expiring_handshakes.insert({ handshake_mappings_ptr, packet::right_now() });

		kcp_mappings_ptr->ingress_source_endpoint = local_peer;
		kcp_ptr->SetOutput([this](const char *buf, int len, void *user) -> int
			{
				return kcp_sender(buf, len, user);
			});

		for (auto &data : udp_seesion_caches[handshake_mappings_ptr])
		{
			std::vector<uint8_t> new_data = packet::create_data_packet(protocol_type::udp, data);
			kcp_ptr->Send((const char *)new_data.data(), new_data.size());
		}

		udp_address_map_to_handshake.erase(local_peer);
		udp_seesion_caches.erase(handshake_mappings_ptr);
		udp_local_session_map_to_kcp[local_peer] = kcp_mappings_ptr;
		kcp_mappings_ptr->last_data_transfer_time.store(packet::right_now());
	}

	if (ptrcl == protocol_type::mux)
	{
		std::scoped_lock handshake_lockers{mutex_handshakes, mutex_expiring_handshakes};
		std::shared_ptr<kcp_mappings> handshake_mappings_ptr = handshakes[handshake_ptr];
		handshakes.erase(handshake_ptr);
		expiring_handshakes.insert({ handshake_mappings_ptr, packet::right_now() });
		setup_mux_kcp(kcp_ptr);
	}

	kcp_ptr->Update();
	uint32_t next_update_time = kcp_ptr->Check();
	kcp_updater.submit(kcp_ptr, next_update_time);

	std::scoped_lock lockers{ mutex_kcp_channels };
	kcp_channels[conv] = kcp_mappings_ptr;
}

void client_mode::on_handshake_failure(kcp_mappings *handshake_ptr, const std::string &error_message)
{
	std::cerr << error_message << "\n";
	print_message_to_file(error_message + "\n", current_settings.log_messages);

	if (handshake_ptr->connection_protocol == protocol_type::tcp)
	{
		std::shared_ptr<tcp_session> incoming_session = handshake_ptr->local_tcp;

		{
			std::scoped_lock lock_handshake{ mutex_handshakes, mutex_expiring_handshakes };
			auto session_iter = handshakes.find(handshake_ptr);
			if (session_iter == handshakes.end())
				return;
			handshakes.erase(session_iter);
			expiring_handshakes.insert({ session_iter->second, packet::right_now() });
		}

		incoming_session->when_disconnect(empty_tcp_disconnect);
		incoming_session->disconnect();
	}

	if (handshake_ptr->connection_protocol == protocol_type::udp)
	{
		std::scoped_lock lockers{ mutex_udp_address_map_to_handshake, mutex_expiring_handshakes, mutex_udp_seesion_caches };
		udp::endpoint local_peer = handshake_ptr->ingress_source_endpoint;
		auto iter = udp_address_map_to_handshake.find(local_peer);
		if (iter == udp_address_map_to_handshake.end())
			return;
		std::shared_ptr<kcp_mappings> handshake_mappings_ptr = iter->second;
		expiring_handshakes.insert({ handshake_mappings_ptr, packet::right_now() });
		udp_address_map_to_handshake.erase(iter);
		udp_seesion_caches.erase(handshake_mappings_ptr);
	}

	if (handshake_ptr->connection_protocol == protocol_type::mux)
	{
		std::scoped_lock lock_handshake{ mutex_handshakes, mutex_expiring_handshakes };
		auto session_iter = handshakes.find(handshake_ptr);
		if (session_iter == handshakes.end())
			return;
		handshakes.erase(session_iter);
		expiring_handshakes.insert({ session_iter->second, packet::right_now() });
		establish_mux_channels(1);
	}
}

void client_mode::handle_handshake(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (data == nullptr || data_size == 0 || kcp_ptr == nullptr)
		return;

	uint8_t *data_ptr = data.get();
	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);

	if (!error_message.empty())
	{
		std::cerr << error_message << "\n";
		return;
	}

	if (kcp_ptr->Input((const char *)data_ptr, (long)plain_size) < 0)
		return;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->custom_data.load();
	if (kcp_mappings_ptr == nullptr)
		return;

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
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			continue;

		switch (ftr)
		{
		case feature::initialise:
		{
			auto [conv, start_port, end_port] = packet::get_initialise_details_from_unpacked_data(unbacked_data_ptr);
			on_handshake_success(kcp_mappings_ptr, conv, start_port, end_port);
			break;
		}
		case feature::failure:
		{
			error_message = packet::get_error_message_from_unpacked_data(unbacked_data_ptr, unbacked_data_size);
			on_handshake_failure(kcp_mappings_ptr, error_message);
			break;
		}
		default:
			break;
		}
	}
}
