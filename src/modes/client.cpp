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
	timer_status_log.cancel();
}

bool client_mode::start()
{
	std::cout << app_name << " is running in client mode\n";

	uint16_t port_number = current_settings.listen_port;
	if (port_number == 0 && !current_settings.ignore_listen_port && !current_settings.ignore_listen_address)
		return false;

	tcp::endpoint listen_on_tcp;
	udp::endpoint listen_on_udp;
	if (current_settings.ip_version_only == ip_only_options::ipv4)
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

		if (local_address.is_v4() && current_settings.ip_version_only == ip_only_options::not_set)
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
			if (current_settings.ignore_listen_port || current_settings.ignore_listen_address)
			{
				if (current_settings.user_input_mappings != nullptr)
				{
					multiple_listening_tcp(*current_settings.user_input_mappings, false);
					multiple_listening_udp(*current_settings.user_input_mappings, false);
				}
				if (current_settings.user_input_mappings_tcp != nullptr)
					multiple_listening_tcp(*current_settings.user_input_mappings_tcp, false);

				if (current_settings.user_input_mappings_udp != nullptr)
					multiple_listening_udp(*current_settings.user_input_mappings_udp, false);
			}
			else
			{
				tcp_server::acceptor_callback_t tcp_func_acceptor = std::bind(&client_mode::tcp_listener_accept_incoming, this, _1, "", 0);
				udp_callback_t udp_func_ap = std::bind(&client_mode::udp_listener_incoming, this, _1, _2, _3, _4, "", 0);
				auto tcp_access_point = std::make_unique<tcp_server>(io_context, listen_on_tcp, tcp_func_acceptor, empty_tcp_callback);
				auto udp_access_point = std::make_unique<udp_server>(io_context, sequence_task_pool_local, task_limit, listen_on_udp, udp_func_ap);
				tcp_access_points.insert({ port_number, std::move(tcp_access_point) });
				udp_access_points.insert({ port_number, std::move(udp_access_point) });
			}
		}
		else
		{
			mux_tunnels = std::make_unique<mux_tunnel>(kcp_updater, current_settings, this);
			tcp_server::acceptor_callback_t tcp_func_acceptor = std::bind(&mux_tunnel::tcp_accept_new_income, mux_tunnels.get(), _1, "", 0);
			udp_callback_t udp_func_ap = std::bind(&mux_tunnel::client_udp_data_to_cache, mux_tunnels.get(), _1, _2, _3, _4, "", 0);
			if (current_settings.ignore_listen_port || current_settings.ignore_listen_address)
			{
				if (current_settings.user_input_mappings != nullptr)
				{
					multiple_listening_tcp(*current_settings.user_input_mappings, true);
					multiple_listening_udp(*current_settings.user_input_mappings, true);
				}
				if (current_settings.user_input_mappings_tcp != nullptr)
					multiple_listening_tcp(*current_settings.user_input_mappings_tcp, true);

				if (current_settings.user_input_mappings_udp != nullptr)
					multiple_listening_udp(*current_settings.user_input_mappings_udp, true);
			}
			else
			{
				auto tcp_access_point = std::make_unique<tcp_server>(io_context, listen_on_tcp, tcp_func_acceptor, empty_tcp_callback);
				auto udp_access_point = std::make_unique<udp_server>(io_context, sequence_task_pool_local, task_limit, listen_on_udp, udp_func_ap);
				tcp_access_points.insert({ port_number, std::move(tcp_access_point) });
				udp_access_points.insert({ port_number, std::move(udp_access_point) });
			}
			establish_mux_channels(current_settings.mux_tunnels);
		}

		timer_expiring_kcp.expires_after(gbv_expring_update_interval);
		timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_connection_loops(e); });

		timer_find_expires.expires_after(gbv_expring_update_interval);
		timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });

		if (current_settings.keep_alive > 0)
		{
			timer_keep_alive.expires_after(gbv_keepalive_update_interval);
			timer_keep_alive.async_wait([this](const asio::error_code& e) { keep_alive(e); });
		}

		if (!current_settings.log_status.empty())
		{
			timer_status_log.expires_after(gbv_logging_gap);
			timer_status_log.async_wait([this](const asio::error_code& e) { log_status(e); });
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

void client_mode::multiple_listening_tcp(user_settings::user_input_address_mapping &user_input_mappings, bool mux_enabled)
{
	for (auto &[listen_local, destination] : user_input_mappings)
	{
		tcp::endpoint listen_on_tcp;
		if (current_settings.ip_version_only == ip_only_options::ipv4)
			listen_on_tcp = tcp::endpoint(tcp::v4(), 0);
		else
			listen_on_tcp = tcp::endpoint(tcp::v6(), 0);
		
		std::string local_address = listen_local.first;
		asio::ip::port_type local_port = listen_local.second;
		std::string remote_address = destination.first;
		asio::ip::port_type remote_port = destination.second;

		if (!local_address.empty())
		{
			asio::ip::address input_address = asio::ip::address::from_string(local_address);
			if (current_settings.ip_version_only == ip_only_options::ipv4 && !input_address.is_v4())
			{
				std::string error_message = time_to_string_with_square_brackets() + "ipv4_only is set, ignoring IPv6 address" + local_address + "\n";
				std::cerr << error_message;
				print_message_to_file(error_message, current_settings.log_messages);
				continue;
			}
			listen_on_tcp.address(input_address);
		}
		listen_on_tcp.port(local_port);

		tcp_server::acceptor_callback_t tcp_func_acceptor;
		if (mux_enabled)
			tcp_func_acceptor = std::bind(&mux_tunnel::tcp_accept_new_income, mux_tunnels.get(), _1, remote_address, remote_port);
		else
			tcp_func_acceptor = std::bind(&client_mode::tcp_listener_accept_incoming, this, _1, remote_address, remote_port);

		auto tcp_access_point = std::make_unique<tcp_server>(io_context, listen_on_tcp, tcp_func_acceptor, empty_tcp_callback);
		tcp_access_points.insert({ local_port, std::move(tcp_access_point) });
	}
}

void client_mode::multiple_listening_udp(user_settings::user_input_address_mapping &user_input_mappings, bool mux_enabled)
{
	for (auto &[listen_local, destination] : user_input_mappings)
	{
		udp::endpoint listen_on_udp;
		if (current_settings.ip_version_only == ip_only_options::ipv4)
			listen_on_udp = udp::endpoint(udp::v4(), 0);
		else
			listen_on_udp = udp::endpoint(udp::v6(), 0);

		std::string local_address = listen_local.first;
		asio::ip::port_type local_port = listen_local.second;
		std::string remote_address = destination.first;
		asio::ip::port_type remote_port = destination.second;

		if (!local_address.empty())
		{
			asio::ip::address input_address = asio::ip::address::from_string(local_address);
			if (current_settings.ip_version_only == ip_only_options::ipv4 && !input_address.is_v4())
			{
				std::string error_message = time_to_string_with_square_brackets() + "ipv4_only is set, ignoring IPv6 address" + local_address + "\n";
				std::cerr << error_message;
				print_message_to_file(error_message, current_settings.log_messages);
				continue;
			}
			listen_on_udp.address(input_address);
		}
		listen_on_udp.port(local_port);

		udp_callback_t udp_func_ap;
		if (mux_enabled)
			udp_func_ap = std::bind(&mux_tunnel::client_udp_data_to_cache, mux_tunnels.get(), _1, _2, _3, _4, remote_address, remote_port);
		else
			udp_func_ap = std::bind(&client_mode::udp_listener_incoming, this, _1, _2, _3, _4, remote_address, remote_port);

		auto udp_access_point = std::make_unique<udp_server>(io_context, sequence_task_pool_local, task_limit, listen_on_udp, udp_func_ap);
		udp_access_points.insert({ local_port, std::move(udp_access_point) });
	}
}

void client_mode::tcp_listener_accept_incoming(std::shared_ptr<tcp_session> incoming_session, const std::string &remote_output_address, asio::ip::port_type remote_output_port)
{
	if (!incoming_session->is_open())
		return;

	std::shared_ptr<kcp_mappings> hs = create_handshake(incoming_session, remote_output_address, remote_output_port);
	if (hs == nullptr)
	{
		std::string error_message = time_to_string_with_square_brackets() + "establish handshake failed\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);

		incoming_session->session_is_ending(true);
		incoming_session->disconnect();
		return;
	}

	hs->egress_kcp->Update();
	uint32_t next_update_time = hs->egress_kcp->Refresh();
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

	if (!incoming_session->session_is_ending() && !incoming_session->is_pause() && kcp_ptr->WaitQueueIsFull())
	{
		incoming_session->pause(true);
	}

	uint8_t *data_ptr = data.get();

	size_t new_data_size = packet::create_data_packet(protocol_type::tcp, data_ptr, data_size);
	kcp_ptr->Send((const char *)data_ptr, new_data_size);
	uint32_t next_update_time = current_settings.blast ? kcp_ptr->Refresh() : kcp_ptr->Check();
	kcp_updater.submit(kcp_ptr, next_update_time);

	status_counters.egress_inner_traffic += data_size;
}

void client_mode::udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, const std::string &remote_output_address, asio::ip::port_type remote_output_port)
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
					status_counters.egress_inner_traffic += data_size;
					return;
				}

				std::shared_ptr<kcp_mappings> hs = create_handshake(peer, remote_output_address, remote_output_port);
				if (hs == nullptr)
				{
					std::string error_message = time_to_string_with_square_brackets() + "establish handshake failed\n";
					std::cerr << error_message;
					print_message_to_file(error_message, current_settings.log_messages);
					return;
				}

				hs->ingress_listen_port = port_number;
				hs->egress_kcp->Update();
				uint32_t next_update_time = hs->egress_kcp->Check();
				kcp_updater.submit(hs->egress_kcp, next_update_time);

				udp_address_map_to_handshake[peer] = hs;

				std::unique_lock locker_udp_seesion_caches{ mutex_udp_seesion_caches };
				udp_seesion_caches[hs].emplace_back(std::vector<uint8_t>(data_ptr, data_ptr + data_size));
				status_counters.egress_inner_traffic += data_size;
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

	if (kcp_session->WaitQueueIsFull())
		return;

	size_t new_data_size = packet::create_data_packet(protocol_type::udp, data_ptr, data_size);

	kcp_session->Send((const char *)data_ptr, new_data_size);
	uint32_t next_update_time = current_settings.blast ? kcp_session->Refresh() : kcp_session->Check();
	kcp_updater.submit(kcp_session, next_update_time);

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_session->GetUserData();
	if (kcp_mappings_ptr != nullptr)
		kcp_mappings_ptr->last_data_transfer_time.store(packet::right_now());

	status_counters.egress_inner_traffic += data_size;
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

	status_counters.ingress_raw_traffic += plain_size;

	udp_forwarder_incoming_unpack(kcp_ptr, std::move(data), plain_size, peer, local_port_number);
}

void client_mode::udp_forwarder_incoming_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (plain_size == 0)
		return;
	auto [packet_timestamp, data_ptr, packet_data_size] = packet::unpack(data.get(), plain_size);
	if (packet_data_size == 0)
		return;
	auto timestamp = packet::right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > gbv_time_gap_seconds)
		return;

	uint32_t conv = 0;
	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		auto [unpacked_data_ptr, unpacked_data_size] = fec_unpack(kcp_ptr, data.get(), plain_size, peer);
		if (unpacked_data_ptr == nullptr)
			return;
		data_ptr = unpacked_data_ptr;
		packet_data_size = unpacked_data_size;
		conv = kcp_ptr->GetConv();
	}
	else
	{
		conv = KCP::KCP::GetConv(data_ptr);
		kcp_ptr = verify_kcp_conv(kcp_ptr, conv, peer);
	}

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
	if (kcp_mappings_ptr == nullptr)
		return;

	if (data_ptr != nullptr && packet_data_size != 0)
		kcp_ptr->Input((const char *)data_ptr, (long)packet_data_size);

	resume_tcp(kcp_mappings_ptr);

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

		auto [ftr, prtcl, unpacked_data_ptr, unpacked_data_size] = packet::unpack_inner(buffer_ptr, kcp_data_size);

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
			std::string error_message = time_to_string_with_square_brackets() + "failure, error message: " + reinterpret_cast<char*>(unpacked_data_ptr) + "\n";
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
				mux_tunnels->delete_mux_records(conv);
			}

			break;
		}
		case feature::keep_alive:
		{
			std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_response_packet(prtcl);
			kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());

			uint32_t next_update_time = kcp_ptr->Check();
			kcp_updater.submit(kcp_ptr, next_update_time);
			break;
		}
		case feature::keep_alive_response:
			kcp_ptr->keep_alive_response_time.store(packet::right_now());
			break;
		case feature::raw_data:
		{
			if (prtcl != kcp_mappings_ptr->connection_protocol)
				break;

			if (prtcl == protocol_type::tcp)
			{
				tcp_channel->async_send_data(std::move(buffer_cache), unpacked_data_ptr, unpacked_data_size);
			}

			if (prtcl == protocol_type::udp)
			{
				std::shared_ptr<udp::endpoint> udp_endpoint = kcp_mappings_ptr->ingress_source_endpoint;
				asio::ip::port_type output_port = kcp_mappings_ptr->ingress_listen_port;
				udp_access_points[output_port]->async_send_out(std::move(buffer_cache), unpacked_data_ptr, unpacked_data_size, *udp_endpoint);
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
			mux_tunnels->transfer_data(prtcl, kcp_mappings_ptr, std::move(buffer_cache), unpacked_data_ptr, unpacked_data_size);
			break;
		case feature::mux_cancel:
			mux_tunnels->delete_channel(prtcl, kcp_mappings_ptr, unpacked_data_ptr, unpacked_data_size);
			break;
		default:
			break;
		}
		status_counters.ingress_inner_traffic += unpacked_data_size;
	}
}

void client_mode::udp_forwarder_to_disconnecting_tcp(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (data_size == 0 || kcp_ptr == nullptr)
		return;

	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data.get(), (int)data_size);
	if (!error_message.empty())
		return;

	auto [packet_timestamp, data_ptr, packet_data_size] = packet::unpack(data.get(), plain_size);
	if (packet_data_size == 0)
		return;
	auto timestamp = packet::right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > gbv_time_gap_seconds)
		return;

	status_counters.ingress_raw_traffic += plain_size;

	uint32_t conv = 0;
	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		auto [unpacked_data_ptr, unpacked_data_size] = fec_unpack(kcp_ptr, data.get(), plain_size, peer);
		if (unpacked_data_ptr == nullptr)
			return;
		data_ptr = unpacked_data_ptr;
		packet_data_size = unpacked_data_size;
		conv = kcp_ptr->GetConv();
	}
	else
	{
		conv = KCP::KCP::GetConv(data_ptr);
		kcp_ptr = verify_kcp_conv(kcp_ptr, conv, peer);
	}

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
	if (kcp_mappings_ptr == nullptr)
		return;

	if (data_ptr != nullptr && packet_data_size != 0)
		kcp_ptr->Input((const char *)data_ptr, (long)packet_data_size);

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

		auto [ftr, prtcl, unpacked_data_ptr, unpacked_data_size] = packet::unpack_inner(buffer_ptr, buffer_size);
		if (prtcl != protocol_type::tcp)
		{
			// error
			continue;
		}

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
		if (kcp_mappings_ptr == nullptr)
			return;
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
			std::string error_message = time_to_string_with_square_brackets() + "failure, error message: " + reinterpret_cast<char*>(unpacked_data_ptr) + "\n";
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
				tcp_channel->async_send_data(std::move(buffer_cache), unpacked_data_ptr, unpacked_data_size);
			break;
		}
		case feature::mux_transfer:
			mux_tunnels->transfer_data(prtcl, kcp_mappings_ptr, std::move(buffer_cache), unpacked_data_ptr, unpacked_data_size);
			break;
		case feature::mux_cancel:
			mux_tunnels->delete_channel(prtcl, kcp_mappings_ptr, unpacked_data_ptr, unpacked_data_size);
			break;
		default:
			break;
		}
		status_counters.ingress_inner_traffic += unpacked_data_size;
	}
}

std::shared_ptr<KCP::KCP> client_mode::pick_one_from_kcp_channels(protocol_type prtcl)
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
	else if (kcp_channels.size() == 2)
	{
		if (prtcl == protocol_type::tcp)
		{
			kcp_ptr = kcp_channels.begin()->second->egress_kcp;
		}
		if (prtcl == protocol_type::udp)
		{
			auto iter = kcp_channels.begin();
			std::advance(iter, 1);
			kcp_ptr = iter->second->egress_kcp;
		}
	}
	else
	{
		std::map<int64_t, uint32_t> peaks_of_recv, peaks_of_sent;	// peak value, kcp conv
		std::map<uint32_t, int32_t> recv_peaks_by_index, sent_peaks_by_index;	// kcp conv, peak-sorted index
		for (auto iter = kcp_channels.begin(); iter != kcp_channels.end(); ++iter)
		{
			int64_t recv_peak_value = iter->second->egress_kcp->ReceivedDataAveragePeak();
			int64_t sent_peak_value = iter->second->egress_kcp->SentDataAveragePeak();
			peaks_of_recv[recv_peak_value] = iter->first;
			peaks_of_sent[sent_peak_value] = iter->first;
		}

		int32_t index = 0;
		for (auto [peak_value, conv] : peaks_of_recv)
			recv_peaks_by_index[conv] = index++;

		index = 0;
		for (auto [peak_value, conv] : peaks_of_sent)
			sent_peaks_by_index[conv] = index++;

		recv_peaks_by_index.rbegin()->second = -1;
		sent_peaks_by_index.rbegin()->second = -1;

		std::multimap<int32_t, uint32_t> index_sum_of_conv;	// index_sum, kcp conv
		for (auto &[conv, mappings] : kcp_channels)
		{
			if (recv_peaks_by_index[conv] < 0 || sent_peaks_by_index[conv] < 0)
				continue;
			int32_t index_sum = recv_peaks_by_index[conv] + sent_peaks_by_index[conv];
			index_sum_of_conv.insert({ index_sum, conv });
		}

		auto conv = index_sum_of_conv.begin()->second;
		kcp_ptr = kcp_channels[conv]->egress_kcp;
	}
	locker_kcp_channels.unlock();

	return kcp_ptr;
}

std::shared_ptr<KCP::KCP> client_mode::verify_kcp_conv(std::shared_ptr<KCP::KCP> kcp_ptr, uint32_t conv, const udp::endpoint &peer)
{
	if (kcp_ptr->GetConv() != conv)
	{
		std::shared_lock locker_kcp_channels{ mutex_kcp_channels };
		auto iter = kcp_channels.find(conv);
		if (iter == kcp_channels.end())
		{
			locker_kcp_channels.unlock();
			std::stringstream ss;
			ss << peer;
			std::string error_message = time_to_string_with_square_brackets() +
				"KCP conv is not the same as record : conv = " + std::to_string(conv) +
				", local kcp : " + std::to_string(kcp_ptr->GetConv()) + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			return kcp_ptr;
		}
		kcp_ptr = iter->second->egress_kcp;
	}
	return kcp_ptr;
}

int client_mode::kcp_sender(const char *buf, int len, void *user)
{
	if (user == nullptr)
		return 0;
	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;

	if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
	{
		int buffer_size = 0;
		std::unique_ptr<uint8_t[]> new_buffer = packet::create_packet((const uint8_t *)buf, len, buffer_size);
		data_sender(kcp_mappings_ptr, std::move(new_buffer), buffer_size);
	}
	else
	{
		fec_maker(kcp_mappings_ptr, (const uint8_t *)buf, len);
	}
	return 0;
}

void client_mode::data_sender(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> new_buffer, size_t buffer_size)
{
	if (kcp_data_sender != nullptr)
	{
		auto func = [this, kcp_mappings_ptr, buffer_size](std::unique_ptr<uint8_t[]> new_buffer)
			{
				auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, new_buffer.get(), (int)buffer_size);
				if (kcp_mappings_ptr->egress_forwarder == nullptr || !error_message.empty() || cipher_size == 0)
					return;
				kcp_mappings_ptr->egress_forwarder->async_send_out(std::move(new_buffer), cipher_size, kcp_mappings_ptr->egress_target_endpoint);
				change_new_port(kcp_mappings_ptr);
				status_counters.egress_raw_traffic += cipher_size;
			};
		kcp_data_sender->push_task((size_t)kcp_mappings_ptr, func, std::move(new_buffer));
		return;
	}

	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, new_buffer.get(), (int)buffer_size);
	if (kcp_mappings_ptr->egress_forwarder == nullptr || !error_message.empty() || cipher_size == 0)
		return;
	kcp_mappings_ptr->egress_forwarder->async_send_out(std::move(new_buffer), cipher_size, kcp_mappings_ptr->egress_target_endpoint);
	change_new_port(kcp_mappings_ptr);
	status_counters.egress_raw_traffic += cipher_size;
}

void client_mode::fec_maker(kcp_mappings *kcp_mappings_ptr, const uint8_t *input_data, int data_size)
{
	fec_control_data &fec_controllor = kcp_mappings_ptr->fec_egress_control;

	int conv = kcp_mappings_ptr->egress_kcp->GetConv();
	int fec_data_buffer_size = 0;
	std::unique_ptr<uint8_t[]> fec_data_buffer = packet::create_fec_data_packet(input_data, data_size, fec_data_buffer_size,
		fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
	data_sender(kcp_mappings_ptr, std::move(fec_data_buffer), fec_data_buffer_size);

	if (conv == 0)
	{
		fec_controllor.fec_snd_sub_sn.store(0);
		return;
	}

	fec_controllor.fec_snd_cache.emplace_back(clone_into_pair(input_data, data_size));

	if (fec_controllor.fec_snd_cache.size() == current_settings.fec_data)
	{
		auto [array_data, fec_align_length, total_size] = compact_into_container(fec_controllor.fec_snd_cache);
		auto redundants = fec_controllor.fecc.encode(array_data.get(), total_size, fec_align_length);
		for (auto &data_ptr : redundants)
		{
			int fec_redundant_buffer_size = 0;
			auto fec_redundant_buffer = packet::create_fec_redundant_packet(data_ptr.get(), (int)fec_align_length,
				fec_redundant_buffer_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++, conv);
			data_sender(kcp_mappings_ptr, std::move(fec_redundant_buffer), fec_redundant_buffer_size);
		}
		fec_controllor.fec_snd_cache.clear();
		fec_controllor.fec_snd_sub_sn.store(0);
		fec_controllor.fec_snd_sn++;
	}
}

std::tuple<uint8_t*, size_t> client_mode::fec_unpack(std::shared_ptr<KCP::KCP> &kcp_ptr, uint8_t *original_data_ptr, size_t plain_size, const udp::endpoint &peer)
{
	uint8_t *data_ptr = nullptr;
	size_t packet_data_size = 0;
	auto [packet_header, kcp_data_ptr, kcp_data_size] = packet::unpack_fec(original_data_ptr, plain_size);
	uint32_t fec_sn = packet_header.sn;
	uint8_t fec_sub_sn = packet_header.sub_sn;
	kcp_mappings *kcp_mappings_ptr = nullptr;
	std::pair<std::unique_ptr<uint8_t[]>, size_t> original_data;
	if (fec_sub_sn >= current_settings.fec_data)
	{
		auto [packet_header_redundant, redundant_data_ptr, redundant_data_size] = packet::unpack_fec_redundant(original_data_ptr, plain_size);
		kcp_ptr = verify_kcp_conv(kcp_ptr, packet_header_redundant.kcp_conv, peer);
		kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
		if (kcp_mappings_ptr == nullptr)
			return { nullptr, 0 };
		original_data.first = std::make_unique<uint8_t[]>(redundant_data_size);
		original_data.second = redundant_data_size;
		std::copy_n(redundant_data_ptr, redundant_data_size, original_data.first.get());
		kcp_mappings_ptr->fec_egress_control.fec_rcv_cache[packet_header_redundant.sn][packet_header_redundant.sub_sn] = std::move(original_data);
		if (!fec_find_missings(kcp_ptr.get(), kcp_mappings_ptr->fec_egress_control, fec_sn, current_settings.fec_data))
			return  { nullptr, 0 };
		packet_data_size = 0;
	}
	else
	{
		data_ptr = kcp_data_ptr;
		packet_data_size = kcp_data_size;
		original_data.first = std::make_unique<uint8_t[]>(kcp_data_size);
		original_data.second = kcp_data_size;
		std::copy_n(kcp_data_ptr, kcp_data_size, original_data.first.get());

		uint32_t conv = KCP::KCP::GetConv(data_ptr);
		kcp_ptr = verify_kcp_conv(kcp_ptr, conv, peer);
		kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
		if (kcp_mappings_ptr == nullptr)
			return  { nullptr, 0 };
		kcp_mappings_ptr->fec_egress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
		fec_find_missings(kcp_ptr.get(), kcp_mappings_ptr->fec_egress_control, fec_sn, current_settings.fec_data);
	}
	return { data_ptr, packet_data_size };
}

bool client_mode::fec_find_missings(KCP::KCP *kcp_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count)
{
	bool recovered = false;
	for (auto iter = fec_controllor.fec_rcv_cache.begin(), next_iter = iter; iter != fec_controllor.fec_rcv_cache.end(); iter = next_iter)
	{
		++next_iter;
		auto sn = iter->first;
		auto &mapped_data = iter->second;
		if (mapped_data.size() < max_fec_data_count)
		{
			if (fec_sn - sn > gbv_fec_waits)
			{
				fec_controllor.fec_rcv_cache.erase(iter);
				if (auto rcv_sn_iter = fec_controllor.fec_rcv_restored.find(sn);
					rcv_sn_iter != fec_controllor.fec_rcv_restored.end())
					fec_controllor.fec_rcv_restored.erase(rcv_sn_iter);
			}
			continue;
		}
		if (auto rcv_sn_iter = fec_controllor.fec_rcv_restored.find(sn); rcv_sn_iter != fec_controllor.fec_rcv_restored.end())
		{
			if (fec_sn - sn > gbv_fec_waits)
			{
				fec_controllor.fec_rcv_cache.erase(iter);
				fec_controllor.fec_rcv_restored.erase(rcv_sn_iter);
			}
			continue;
		}
		auto [recv_data, fec_align_length] = compact_into_container(mapped_data, max_fec_data_count);
		auto array_data = mapped_pair_to_mapped_pointer(recv_data);
		auto restored_data = fec_controllor.fecc.decode(array_data, fec_align_length);

		for (auto &[i, data] : restored_data)
		{
			auto [missed_data_ptr, missed_data_size] = extract_from_container(data);
			kcp_ptr->Input((const char *)missed_data_ptr, (long)missed_data_size);
			status_counters.fec_recovery_count++;
		}

		fec_controllor.fec_rcv_restored.insert(sn);
		recovered = true;
	}
	return recovered;
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
	for (int i = 0; i <= gbv_retry_times; ++i)
	{
		const std::string &destination_address = current_settings.destination_address;
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

	std::unique_lock locker_kcp_channels{ mutex_kcp_channels };
	auto kcp_channel_iter = kcp_channels.find(conv);
	if (kcp_channel_iter == kcp_channels.end())
		return;

	std::shared_ptr<kcp_mappings> kcp_mappings_ptr = kcp_channel_iter->second;
	locker_kcp_channels.unlock();

	if (std::scoped_lock locker_expiring_kcp{ mutex_expiring_kcp }; expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
		expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() + gbv_keepalive_timeout });

	if (std::scoped_lock locker_kcp_keepalive{mutex_kcp_keepalive}; kcp_keepalive.find(kcp_ptr) != kcp_keepalive.end())
		kcp_keepalive.erase(kcp_ptr);

	kcp_mappings_ptr->changeport_timestamp.store(LLONG_MAX);
	kcp_mappings_ptr->egress_forwarder->replace_callback(udp_func);

	std::vector<uint8_t> data = packet::inform_disconnect_packet(protocol_type::tcp);
	kcp_ptr->Send((const char *)data.data(), data.size());
	uint32_t next_update_time = kcp_ptr->Check();
	kcp_updater.submit(kcp_ptr, next_update_time);

	session->session_is_ending(true);
	session->pause(false);
	session->stop();
}

void client_mode::local_disconnect(std::shared_ptr<KCP::KCP> kcp_ptr, std::shared_ptr<tcp_session> session, std::shared_ptr<mux_records> mux_records_ptr)
{
	uint32_t connection_id = mux_records_ptr->connection_id;
	uint64_t complete_connection_id = ((uint64_t)mux_records_ptr->kcp_conv << 32) + connection_id;
	std::vector<uint8_t> mux_cancel_data = packet::inform_mux_cancel_packet(protocol_type::tcp, connection_id);

	std::unique_lock locker{ mux_tunnels->mutex_mux_tcp_cache};
	if (auto iter = mux_tunnels->mux_tcp_cache.find(kcp_ptr); iter != mux_tunnels->mux_tcp_cache.end())
	{
		std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(mux_cancel_data.size());
		uint8_t *data_ptr = data.get();
		std::copy(mux_cancel_data.begin(), mux_cancel_data.end(), data_ptr);
		mux_data_cache data_cache = { std::move(data), data_ptr, mux_cancel_data.size() };
		iter->second.emplace_back(std::move(data_cache));
	}
	locker.unlock();
	mux_tunnels->move_cached_data_to_tunnel();

	std::scoped_lock lockers{ mux_tunnels->mutex_id_map_to_mux_records };
	mux_tunnels->id_map_to_mux_records.erase(complete_connection_id);
	session->session_is_ending(true);
	session->pause(false);
	session->stop();
	mux_records_ptr->local_tcp.reset();
}

void client_mode::process_disconnect(uint32_t conv)
{
	std::unique_lock locker_kcp_channels{ mutex_kcp_channels };
	auto kcp_channel_iter = kcp_channels.find(conv);
	if (kcp_channel_iter == kcp_channels.end())
		return;
	std::shared_ptr<kcp_mappings> kcp_mappings_ptr = kcp_channel_iter->second;
	locker_kcp_channels.unlock();
	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;

	if (std::scoped_lock locker_expiring_kcp{ mutex_expiring_kcp }; expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
		expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() + gbv_keepalive_timeout });

	if (std::scoped_lock locker_kcp_keepalive{mutex_kcp_keepalive}; kcp_keepalive.find(kcp_ptr) != kcp_keepalive.end())
		kcp_keepalive.erase(kcp_ptr);
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

	session->session_is_ending(true);
	session->pause(false);
	session->stop();
}

void client_mode::change_new_port(kcp_mappings *kcp_mappings_ptr)
{
	if (kcp_mappings_ptr->changeport_timestamp.load() > packet::right_now())
		return;
	kcp_mappings_ptr->changeport_timestamp.store(LLONG_MAX);

	if (kcp_mappings_ptr->changeport_available.load())
		switch_new_port(kcp_mappings_ptr);
	else if (kcp_mappings_ptr->changeport_testing_ptr.expired())
		test_before_change(kcp_mappings_ptr);
}

void client_mode::test_before_change(kcp_mappings *kcp_mappings_ptr)
{
	std::shared_ptr<kcp_mappings> hs = create_handshake(feature::test_connection, protocol_type::not_care, "", 0);
	if (hs == nullptr)
	{
		kcp_mappings_ptr->changeport_timestamp.store(packet::right_now() + current_settings.dynamic_port_refresh);
		return;
	}

	hs->egress_kcp->Update();
	uint32_t next_update_time = hs->egress_kcp->Refresh();
	kcp_updater.submit(hs->egress_kcp, next_update_time);

	kcp_mappings *handshake_ptr = hs.get();
	kcp_mappings_ptr->changeport_testing_ptr = hs;
	std::weak_ptr<kcp_mappings> kcp_mappings_weak = kcp_mappings_ptr->self_share();
	hs->changeport_testing_ptr = kcp_mappings_weak;
	hs->mapping_function = [handshake_ptr]()
		{
			std::shared_ptr<kcp_mappings> kcp_mappings_ptr = handshake_ptr->changeport_testing_ptr.lock();
			if (kcp_mappings_ptr == nullptr) return;
			kcp_mappings_ptr->changeport_available.store(true);
			kcp_mappings_ptr->changeport_timestamp.store(packet::right_now());
		};

	std::unique_lock lock_handshake{ mutex_handshakes };
	handshakes[hs.get()] = hs;
	lock_handshake.unlock();
}

void client_mode::switch_new_port(kcp_mappings *kcp_mappings_ptr)
{
	kcp_mappings_ptr->changeport_timestamp.store(packet::right_now() + current_settings.dynamic_port_refresh);

	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;
	if (kcp_ptr == nullptr || kcp_ptr->GetConv() == 0)
		return;

	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	try
	{
		auto udp_func = std::bind(&client_mode::udp_forwarder_incoming, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, kcp_ptr, udp_func, current_settings.ip_version_only);
		if (udp_forwarder == nullptr)
			return;
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + "Cannnot switch to new port now. Error: " + ex.what() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		return;
	}

	uint16_t destination_port_start = current_settings.destination_port_start;
	uint16_t destination_port_end = current_settings.destination_port_end;
	if (destination_port_start != destination_port_end)
	{
		std::shared_ptr<kcp_mappings> changeport_testing_ptr = kcp_mappings_ptr->changeport_testing_ptr.lock();
		uint16_t new_port_numer = 0;
		if (changeport_testing_ptr == nullptr)
			new_port_numer = generate_new_port_number(destination_port_start, destination_port_end);
		else
			new_port_numer = changeport_testing_ptr->egress_target_endpoint.port();
		kcp_mappings_ptr->changeport_available.store(false);
		kcp_mappings_ptr->changeport_testing_ptr.reset();
		std::shared_lock locker{ mutex_target_address };
		asio::ip::address temp_address = *target_address;
		locker.unlock();
		std::scoped_lock locker_egress{ kcp_mappings_ptr->mutex_egress_endpoint };
		kcp_mappings_ptr->egress_target_endpoint.address(temp_address);
		kcp_mappings_ptr->egress_target_endpoint.port(new_port_numer);
	}

	asio::error_code ec;
	if (current_settings.ip_version_only == ip_only_options::ipv4)
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
	if (time_diff < gbv_handshake_timeout)
		return false;

	std::shared_ptr<kcp_mappings> new_kcp_mappings_ptr;
	switch (kcp_mappings_ptr->connection_protocol)
	{
	case protocol_type::not_care:
	{
		new_kcp_mappings_ptr = create_handshake(feature::test_connection, protocol_type::not_care, "", 0);
		if (std::shared_ptr<kcp_mappings> main_kcp_mappings_ptr = kcp_mappings_ptr->changeport_testing_ptr.lock();
			main_kcp_mappings_ptr == nullptr)
			break;
		else
			main_kcp_mappings_ptr->changeport_testing_ptr = new_kcp_mappings_ptr;
		new_kcp_mappings_ptr->changeport_testing_ptr = kcp_mappings_ptr->changeport_testing_ptr;
		kcp_mappings *new_kcp_mapping_raw = new_kcp_mappings_ptr.get();
		new_kcp_mappings_ptr->mapping_function = [new_kcp_mapping_raw]()
			{
				std::shared_ptr<kcp_mappings> kcp_mappings_ptr = new_kcp_mapping_raw->changeport_testing_ptr.lock();
				if (kcp_mappings_ptr == nullptr) return;
				kcp_mappings_ptr->changeport_available.store(true);
				kcp_mappings_ptr->changeport_timestamp.store(packet::right_now());
			};
		kcp_mappings_ptr->mapping_function = []() {};
		break;
	}
	case protocol_type::mux:
		new_kcp_mappings_ptr = create_handshake(feature::initialise, protocol_type::mux, kcp_mappings_ptr->remote_output_address, kcp_mappings_ptr->remote_output_port);
		break;
	case protocol_type::tcp:
		new_kcp_mappings_ptr = create_handshake(kcp_mappings_ptr->local_tcp, kcp_mappings_ptr->remote_output_address, kcp_mappings_ptr->remote_output_port);
		break;
	case protocol_type::udp:
		new_kcp_mappings_ptr = create_handshake(*kcp_mappings_ptr->ingress_source_endpoint, kcp_mappings_ptr->remote_output_address, kcp_mappings_ptr->remote_output_port);
		break;
	default:
		break;
	}

	new_kcp_mappings_ptr->ingress_source_endpoint = kcp_mappings_ptr->ingress_source_endpoint;
	new_kcp_mappings_ptr->ingress_listen_port = kcp_mappings_ptr->ingress_listen_port;

	if (kcp_mappings_ptr->connection_protocol == protocol_type::udp)
	{
		auto func = [this, kcp_mappings_ptr, new_kcp_mappings_ptr]() mutable
			{
				std::shared_ptr<kcp_mappings> old_kcp_mappings_ptr = nullptr;
				{
					std::scoped_lock lockers{ mutex_udp_address_map_to_handshake, mutex_expiring_handshakes, mutex_udp_seesion_caches };
					std::shared_ptr<udp::endpoint> local_peer = new_kcp_mappings_ptr->ingress_source_endpoint;
					auto iter = udp_address_map_to_handshake.find(*local_peer);
					if (iter == udp_address_map_to_handshake.end())
						return;
					old_kcp_mappings_ptr = iter->second;
					iter->second = new_kcp_mappings_ptr;
					udp_seesion_caches[new_kcp_mappings_ptr] = std::move(udp_seesion_caches[old_kcp_mappings_ptr]);
					udp_seesion_caches.erase(old_kcp_mappings_ptr);
				}

				kcp_mappings_ptr->egress_kcp->SetUserData(nullptr);
				kcp_updater.remove(kcp_mappings_ptr->egress_kcp);
				uint32_t next_update_time = new_kcp_mappings_ptr->egress_kcp->Check();
				kcp_updater.submit(new_kcp_mappings_ptr->egress_kcp, next_update_time);
			};
		sequence_task_pool_local.push_task((size_t)kcp_mappings_ptr, func);
	}
	else
	{
		auto func = [this, kcp_mappings_ptr, new_kcp_mappings_ptr]() mutable
			{
				std::shared_ptr<kcp_mappings> old_kcp_mappings_ptr = nullptr;
				std::unique_lock locker{ mutex_handshakes };
				if (auto iter = handshakes.find(kcp_mappings_ptr); iter != handshakes.end())
				{
					old_kcp_mappings_ptr = iter->second;
					handshakes.erase(iter);
				}
				handshakes[new_kcp_mappings_ptr.get()] = new_kcp_mappings_ptr;
				locker.unlock();

				kcp_mappings_ptr->egress_kcp->SetUserData(nullptr);
				kcp_updater.remove(kcp_mappings_ptr->egress_kcp);
				uint32_t next_update_time = new_kcp_mappings_ptr->egress_kcp->Check();
				kcp_updater.submit(new_kcp_mappings_ptr->egress_kcp, next_update_time);
			};
		sequence_task_pool_local.push_task((size_t)kcp_mappings_ptr, func);
	}
	return true;
}

void client_mode::cleanup_expiring_forwarders()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock lockers{ mutex_expiring_forwarders };
	for (auto iter = expiring_forwarders.begin(), next_iter = iter; iter != expiring_forwarders.end(); iter = next_iter)
	{
		++next_iter;
		auto &[udp_forwrder, expire_time] = *iter;
		int64_t time_elapsed = time_right_now - expire_time;

		if (time_elapsed > gbv_receiver_cleanup_waits / 2 &&
			udp_forwrder != nullptr)
			udp_forwrder->stop();

		if (time_elapsed <= gbv_receiver_cleanup_waits)
			continue;

		expiring_forwarders.erase(iter);
	}
}

void client_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = packet::right_now();
	std::vector<std::shared_ptr<forwarder>> old_forwarders;

	std::scoped_lock locker{ mutex_expiring_kcp, mutex_kcp_channels };
	for (auto iter = expiring_kcp.begin(), next_iter = iter; iter != expiring_kcp.end(); iter = next_iter)
	{
		++next_iter;
		auto &[kcp_mappings_ptr, expire_time] = *iter;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;
		uint32_t conv = kcp_ptr->GetConv();

		if (time_right_now - expire_time < gbv_kcp_cleanup_waits)
			continue;

		kcp_ptr->SetOutput(empty_kcp_output);
		kcp_ptr->SetPostUpdate(empty_kcp_postupdate);
		kcp_ptr->SetUserData(nullptr);

		old_forwarders.push_back(kcp_mappings_ptr->egress_forwarder);
		kcp_mappings_ptr->egress_forwarder->stop();

		if (kcp_mappings_ptr->connection_protocol == protocol_type::tcp)
		{
			tcp_session *tcp_channel = kcp_mappings_ptr->local_tcp.get();
			if (tcp_channel != nullptr)
			{
				tcp_channel->session_is_ending(true);
				tcp_channel->stop();
				kcp_mappings_ptr->local_tcp.reset();
			}
		}

		if (kcp_mappings_ptr->connection_protocol == protocol_type::udp)
		{
			std::scoped_lock locker_udp_session_map_to_kcp {mutex_udp_local_session_map_to_kcp};
			udp_local_session_map_to_kcp.erase(*kcp_mappings_ptr->ingress_source_endpoint);
		}
		
		kcp_updater.remove(kcp_ptr);
		expiring_kcp.erase(iter);

		if (auto kcp_iter = kcp_channels.find(conv); kcp_iter != kcp_channels.end())
			kcp_channels.erase(kcp_iter);
	}

	if (!old_forwarders.empty())
	{
		std::scoped_lock locker_expiring_forwarders{ mutex_expiring_forwarders };
		for (std::shared_ptr<forwarder> forwarder_ptr : old_forwarders)
			expiring_forwarders[forwarder_ptr] = packet::right_now();
	}
}

void client_mode::cleanup_expiring_handshake_connections()
{
	auto time_right_now = packet::right_now();

	std::unique_lock locker_expiring_handshakes{ mutex_expiring_handshakes };
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
		if (time_right_now - expire_time < gbv_kcp_cleanup_waits)
			continue;

		kcp_mappings_ptr->mapping_function();
		if (kcp_mappings_ptr->egress_forwarder != nullptr)
		{
			kcp_mappings_ptr->egress_forwarder->remove_callback();
			kcp_mappings_ptr->egress_forwarder->stop();
		}
		
		kcp_updater.remove(kcp_mappings_ptr->egress_kcp);
		expiring_handshakes.erase(iter);
	}
	locker_expiring_handshakes.unlock();

	std::shared_lock locker_handshake{ mutex_handshakes };
	for (auto iter = handshakes.begin(); iter != handshakes.end(); ++iter)
	{
		kcp_mappings *kcp_mappings_raw_ptr = iter->first;
		handshake_timeout_detection(kcp_mappings_raw_ptr);
	}	
	locker_handshake.unlock();

	std::unique_lock locker_udp_handshake{ mutex_udp_address_map_to_handshake };
	for (auto iter = udp_address_map_to_handshake.begin(); iter != udp_address_map_to_handshake.end(); ++iter)
	{
		kcp_mappings *kcp_mappings_raw_ptr = iter->second.get();
		handshake_timeout_detection(kcp_mappings_raw_ptr);
	}	
	locker_udp_handshake.unlock();
}

void client_mode::loop_find_expires()
{
	auto time_right_now = packet::right_now();

	std::unique_lock locker_expiring_kcp{mutex_expiring_kcp, std::defer_lock };
	std::unique_lock locker_kcp_keepalive{mutex_kcp_keepalive, std::defer_lock };
	std::scoped_lock locker{ mutex_kcp_channels };
	for (auto iter = kcp_channels.begin(), next_iter = iter; iter != kcp_channels.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t conv = iter->first;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = iter->second;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->egress_kcp;
		int64_t kcp_last_activity_gap = calculate_difference(kcp_ptr->LastInputTime(), packet::right_now());
		int64_t kcp_keep_alive_gap = calculate_difference(kcp_ptr->keep_alive_response_time.load(), kcp_ptr->keep_alive_send_time.load());
		int32_t timeout_seconds = gbv_keepalive_timeout + current_settings.keep_alive;
		bool keep_alive_timed_out = current_settings.keep_alive > 0 && std::min(kcp_last_activity_gap, kcp_keep_alive_gap) > timeout_seconds;

		if (std::shared_ptr<kcp_mappings> hs = kcp_mappings_ptr->changeport_testing_ptr.lock(); hs != nullptr)
		{
			kcp_mappings_ptr->changeport_testing_ptr.reset();
			std::scoped_lock lock_handshake{ mutex_handshakes, mutex_expiring_forwarders };
			auto session_iter = handshakes.find(hs.get());
			if (session_iter != handshakes.end())
			{
				expiring_forwarders[hs->egress_forwarder] = packet::right_now();
				hs->egress_forwarder->stop();
				hs->egress_forwarder = nullptr;
				handshakes.erase(session_iter);
			}
		}

		if (kcp_mappings_ptr->connection_protocol == protocol_type::tcp)
		{
			tcp_session *tcp_channel = kcp_mappings_ptr->local_tcp.get();
			if (tcp_channel->is_stop() || !tcp_channel->is_open() || keep_alive_timed_out)
			{
				locker_expiring_kcp.lock();
				if (expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
				{
					tcp_channel->session_is_ending(true);
					tcp_channel->stop();
					kcp_mappings_ptr->egress_forwarder->stop();
					expiring_kcp.insert({ kcp_mappings_ptr, time_right_now });
				}
				locker_expiring_kcp.unlock();

				locker_kcp_keepalive.lock();
				if (kcp_keepalive.find(kcp_ptr) != kcp_keepalive.end())
					kcp_keepalive.erase(kcp_ptr);
				locker_kcp_keepalive.unlock();

				kcp_channels.erase(iter);
				kcp_ptr->SetOutput(empty_kcp_output);
				kcp_ptr->SetPostUpdate(empty_kcp_postupdate);
				kcp_ptr->SetUserData(nullptr);
			}
		}

		if (kcp_mappings_ptr->connection_protocol == protocol_type::udp)
		{
			if (calculate_difference(kcp_mappings_ptr->last_data_transfer_time.load(), time_right_now) > current_settings.udp_timeout || keep_alive_timed_out)
			{
				kcp_mappings_ptr->egress_forwarder->stop();

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
				kcp_ptr->SetPostUpdate(empty_kcp_postupdate);
				kcp_ptr->SetUserData(nullptr);
			}
		}

		if (kcp_mappings_ptr->connection_protocol == protocol_type::mux)
		{
			if (calculate_difference(kcp_ptr->LastInputTime(), time_right_now) > gbv_mux_channels_cleanup || keep_alive_timed_out)
			{
				kcp_mappings_ptr->egress_forwarder->stop();

				locker_expiring_kcp.lock();
				if (expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
					expiring_kcp.insert({ kcp_mappings_ptr, time_right_now });
				locker_expiring_kcp.unlock();

				kcp_channels.erase(iter);
				kcp_ptr->SetOutput(empty_kcp_output);
				kcp_ptr->SetPostUpdate(empty_kcp_postupdate);
				kcp_ptr->SetUserData(nullptr);

				mux_tunnels->delete_mux_records(conv);
				establish_mux_channels(1);
				mux_tunnels->remove_cached_kcp(kcp_ptr);
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

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
		if (kcp_mappings_ptr == nullptr)
			continue;
		std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_packet(kcp_mappings_ptr->connection_protocol);
		kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());

		uint32_t next_update_time = kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_update_time);
		kcp_ptr->keep_alive_send_time.store(packet::right_now());
	}
}

void client_mode::expiring_connection_loops(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	cleanup_expiring_forwarders();
	cleanup_expiring_data_connections();
	cleanup_expiring_handshake_connections();
	if (mux_tunnels != nullptr)
		mux_tunnels->cleanup_expiring_mux_records();

	timer_expiring_kcp.expires_after(gbv_expring_update_interval);
	timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_connection_loops(e); });
}

void client_mode::find_expires(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_find_expires();

	timer_find_expires.expires_after(gbv_expring_update_interval);
	timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });
}

void client_mode::keep_alive(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_keep_alive();

	timer_keep_alive.expires_after(gbv_keepalive_update_interval);
	timer_keep_alive.async_wait([this](const asio::error_code& e) { keep_alive(e); });
}

void client_mode::log_status(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;
	
	loop_get_status();

	timer_status_log.expires_after(gbv_logging_gap);
	timer_status_log.async_wait([this](const asio::error_code& e) { log_status(e); });
}

void client_mode::loop_get_status()
{
	std::string output_text = time_to_string_with_square_brackets() + "Summary of " + current_settings.config_filename + "\n";
	constexpr auto duration_seconds = gbv_logging_gap.count();
	auto forwarder_receives_raw = to_speed_unit(status_counters.ingress_raw_traffic.exchange(0) / duration_seconds);
	auto forwarder_receives_inner = to_speed_unit(status_counters.ingress_inner_traffic.exchange(0) / duration_seconds);
	auto forwarder_send_inner = to_speed_unit(status_counters.egress_inner_traffic.exchange(0) / duration_seconds);
	auto forwarder_send_raw = to_speed_unit(status_counters.egress_raw_traffic.exchange(0) / duration_seconds);
	auto forwarder_fec_recovery = status_counters.fec_recovery_count.exchange(0);

#ifdef __cpp_lib_format
	output_text += std::format("receive (raw): {}, receive (inner): {}, send (inner): {}, send (raw): {}, fec recover: {}\n",
		forwarder_receives_raw, forwarder_receives_inner, forwarder_send_inner, forwarder_send_raw, forwarder_fec_recovery);
#else
	std::ostringstream oss;
	oss << "receive (raw): " << forwarder_receives_raw << ", receive (inner): " << forwarder_receives_inner <<
		", send (inner): " << forwarder_send_inner << ", send (raw): " << forwarder_send_raw << ", fec recover: " << forwarder_fec_recovery << "\n";
	output_text += oss.str();
#endif

	std::shared_lock locker{ mutex_kcp_channels };
	for (auto &[conv, kcp_mappings_pr] : kcp_channels)
	{
#ifdef __cpp_lib_format
		output_text += std::format("KCP#{} average latency: {} ms\n", conv, kcp_mappings_pr->egress_kcp->GetRxSRTT());
#else
		oss.clear();
		oss << "KCP#" << conv << " average latency: " << kcp_mappings_pr->egress_kcp->GetRxSRTT() << " ms\n";
		output_text += oss.str();
#endif
	}
	locker.unlock();

	if (mux_tunnels != nullptr)
	{
		auto mux_tcp_recv_traffic = to_speed_unit(mux_tunnels->tcp_recv_traffic.exchange(0) / duration_seconds);
		auto mux_tcp_send_traffic = to_speed_unit(mux_tunnels->tcp_send_traffic.exchange(0) / duration_seconds);
		auto mux_udp_recv_traffic = to_speed_unit(mux_tunnels->udp_recv_traffic.exchange(0) / duration_seconds);
		auto mux_udp_send_traffic = to_speed_unit(mux_tunnels->udp_send_traffic.exchange(0) / duration_seconds);
#ifdef __cpp_lib_format
		output_text += std::format("mux_tunnels:\treceive (tcp): {}, receive (udp): {}, send (tcp): {}, send (udp): {}\n",
			mux_tcp_recv_traffic, mux_tcp_send_traffic, mux_udp_recv_traffic, mux_udp_send_traffic);
#else
		oss.clear();
		oss << "mux_tunnels:\treceive (tcp): " << mux_tcp_recv_traffic << ", receive (udp): " << mux_tcp_send_traffic <<
			", send (tcp): " << mux_udp_recv_traffic << ", send (udp): " << mux_udp_send_traffic << "\n";
		output_text += oss.str();
#endif
	}

	output_text += "\n";

	if (!current_settings.log_status.empty())
		print_status_to_file(output_text, current_settings.log_status);
	std::cout << output_text << std::endl;
}

std::shared_ptr<kcp_mappings> client_mode::create_handshake(std::shared_ptr<tcp_session> local_tcp, const std::string &remote_output_address, asio::ip::port_type remote_output_port)
{
	std::shared_ptr<kcp_mappings> handshake_kcp_mappings = create_handshake(feature::initialise, protocol_type::tcp, remote_output_address, remote_output_port);
	if (handshake_kcp_mappings != nullptr)
		handshake_kcp_mappings->local_tcp = local_tcp;
	return handshake_kcp_mappings;
}

std::shared_ptr<kcp_mappings> client_mode::create_handshake(udp::endpoint local_endpoint, const std::string &remote_output_address, asio::ip::port_type remote_output_port)
{
	std::shared_ptr<kcp_mappings> handshake_kcp_mappings = create_handshake(feature::initialise, protocol_type::udp, remote_output_address, remote_output_port);
	if (handshake_kcp_mappings != nullptr)
		handshake_kcp_mappings->ingress_source_endpoint = std::make_shared<udp::endpoint>(local_endpoint);
	return handshake_kcp_mappings;
}

std::shared_ptr<kcp_mappings> client_mode::create_handshake(feature ftr, protocol_type prtcl, const std::string &remote_output_address, asio::ip::port_type remote_output_port)
{
	std::shared_ptr<KCP::KCP> handshake_kcp = std::make_shared<KCP::KCP>();
	std::shared_ptr<kcp_mappings> handshake_kcp_mappings = std::make_shared<kcp_mappings>();
	handshake_kcp->SetUserData(handshake_kcp_mappings.get());
	handshake_kcp_mappings->egress_kcp = handshake_kcp;
	handshake_kcp_mappings->connection_protocol = prtcl;
	handshake_kcp_mappings->changeport_timestamp.store(LLONG_MAX);
	handshake_kcp_mappings->handshake_setup_time.store(packet::right_now());
	handshake_kcp_mappings->remote_output_address = remote_output_address;
	handshake_kcp_mappings->remote_output_port = remote_output_port;

	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	try
	{
		auto udp_func = std::bind(&client_mode::handle_handshake, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, handshake_kcp, udp_func, current_settings.ip_version_only);
		if (udp_forwarder == nullptr)
			return nullptr;
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + "Cannnot create handshake connection. Error: " + ex.what() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		return nullptr;
	}

	bool success = get_udp_target(udp_forwarder, handshake_kcp_mappings->egress_target_endpoint);
	if (!success)
		return nullptr;
	handshake_kcp_mappings->egress_forwarder = udp_forwarder;
	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		size_t K = current_settings.fec_data;
		size_t N = K + current_settings.fec_redundant;
		handshake_kcp_mappings->fec_egress_control.fecc.reset_martix(K, N);
	}

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
	if (current_settings.ip_version_only == ip_only_options::ipv4)
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);
	udp_forwarder->async_receive();

	std::vector<uint8_t> handshake_data;
	if (ftr == feature::initialise)
	{
		if (current_settings.ignore_listen_address || current_settings.ignore_listen_port)
			handshake_data = packet::request_initialise_packet(handshake_kcp_mappings->connection_protocol,
			                                                   current_settings.outbound_bandwidth, current_settings.inbound_bandwidth,
			                                                   remote_output_address, remote_output_port);
		else
			handshake_data = packet::request_initialise_packet(handshake_kcp_mappings->connection_protocol,
			                                                   current_settings.outbound_bandwidth, current_settings.inbound_bandwidth);
	}
	if (ftr == feature::test_connection)
		handshake_data = packet::create_test_connection_packet();
	if (handshake_kcp->Send((const char *)handshake_data.data(), handshake_data.size()) < 0)
		return nullptr;

	handshake_kcp->Update();

	return handshake_kcp_mappings;
}

void client_mode::resume_tcp(kcp_mappings *kcp_mappings_ptr)
{
	if (kcp_mappings_ptr->local_tcp == nullptr)
		return;

	if (kcp_data_sender != nullptr)
	{
		kcp_data_sender->push_task((size_t)kcp_mappings_ptr, [kcp_mappings_ptr]()
			{
				if (kcp_mappings_ptr->local_tcp == nullptr)
					return;
				if (kcp_mappings_ptr->local_tcp->is_pause() && kcp_mappings_ptr->egress_kcp->WaitQueueBelowHalfCapacity())
					kcp_mappings_ptr->local_tcp->pause(false);
			});
		return;
	}

	if (kcp_mappings_ptr->local_tcp->is_pause() && kcp_mappings_ptr->egress_kcp->WaitQueueBelowHalfCapacity())
		kcp_mappings_ptr->local_tcp->pause(false);
}

void client_mode::set_kcp_windows(std::weak_ptr<KCP::KCP> handshake_kcp, std::weak_ptr<KCP::KCP> data_ptr_weak)
{
	std::shared_ptr handshake_kcp_ptr = handshake_kcp.lock();
	if (handshake_kcp_ptr == nullptr)
		return;

	std::shared_ptr data_kcp_ptr = data_ptr_weak.lock();
	if (data_kcp_ptr == nullptr)
		return;

	data_kcp_ptr->ResetWindowValues(handshake_kcp_ptr->GetRxSRTT());

	if (mux_tunnels != nullptr)
	{
		std::scoped_lock mux_locks{ mux_tunnels->mutex_mux_tcp_cache, mux_tunnels->mutex_mux_udp_cache };
		if (auto iter = mux_tunnels->mux_tcp_cache_max_size.find(data_ptr_weak); iter != mux_tunnels->mux_tcp_cache_max_size.end())
			iter->second = data_kcp_ptr->GetSendWindowSize();
		if (auto iter = mux_tunnels->mux_udp_cache_max_size.find(data_ptr_weak); iter != mux_tunnels->mux_udp_cache_max_size.end())
			iter->second = data_kcp_ptr->GetSendWindowSize();
	}
}

void client_mode::establish_mux_channels(uint16_t counts)
{
	for (int i = 0; i < counts; i++)
	{
		std::shared_ptr<kcp_mappings> hs = create_handshake(feature::initialise, protocol_type::mux, "", 0);
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

		std::scoped_lock locker{ mutex_handshakes };
		handshakes[hs.get()] = hs;
	}
}

void client_mode::on_handshake_success(kcp_mappings *handshake_ptr, const packet::settings_wrapper &basic_settings)
{
	auto timestamp = packet::right_now();
	uint64_t outbound_bandwidth = current_settings.outbound_bandwidth;
	if (basic_settings.inbound_bandwidth > 0 && outbound_bandwidth > basic_settings.inbound_bandwidth)
		outbound_bandwidth = basic_settings.inbound_bandwidth;

	if (basic_settings.port_start != 0 && basic_settings.port_end != 0)
	{
		current_settings.destination_port_start = basic_settings.port_start;
		current_settings.destination_port_end = basic_settings.port_end;
	}

	protocol_type ptrcl = handshake_ptr->connection_protocol;
	std::shared_ptr<kcp_mappings> kcp_mappings_ptr = std::make_shared<kcp_mappings>();
	std::shared_ptr<KCP::KCP> kcp_ptr = std::make_shared<KCP::KCP>(basic_settings.uid);
	kcp_mappings_ptr->connection_protocol = ptrcl;

	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	try
	{
		auto udp_func = std::bind(&client_mode::udp_forwarder_incoming, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, kcp_ptr, udp_func, current_settings.ip_version_only);
		if (udp_forwarder == nullptr)
			return;
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + "Cannnot create new connection of UDP. Error: " + ex.what() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		return;
	}

	asio::error_code ec;
	if (current_settings.ip_version_only == ip_only_options::ipv4)
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);

	if (ec)
		return;
	udp_forwarder->async_receive();

	kcp_ptr->SetUserData(kcp_mappings_ptr.get());
	kcp_ptr->keep_alive_send_time.store(timestamp);
	kcp_ptr->keep_alive_response_time.store(timestamp);
	kcp_ptr->SetMTU(current_settings.kcp_mtu);
	kcp_ptr->SetWindowSize(current_settings.kcp_sndwnd, current_settings.kcp_rcvwnd);
	kcp_ptr->NoDelay(current_settings.kcp_nodelay, current_settings.kcp_interval, current_settings.kcp_resend, current_settings.kcp_nc);
	kcp_ptr->RxMinRTO() = 10;
	kcp_ptr->SetBandwidth(outbound_bandwidth, current_settings.inbound_bandwidth);
	std::weak_ptr handshake_kcp_weak = handshake_ptr->egress_kcp;
	std::weak_ptr data_ptr_weak = kcp_ptr;
	handshake_ptr->mapping_function = [this, handshake_kcp_weak, data_ptr_weak]() { set_kcp_windows(handshake_kcp_weak, data_ptr_weak); };

	kcp_mappings_ptr->egress_kcp = kcp_ptr;
	kcp_mappings_ptr->egress_forwarder = udp_forwarder;
	kcp_mappings_ptr->egress_target_endpoint = handshake_ptr->egress_target_endpoint;
	kcp_mappings_ptr->egress_previous_target_endpoint = kcp_mappings_ptr->egress_target_endpoint;

	if (current_settings.dynamic_port_refresh == 0)
		kcp_mappings_ptr->changeport_timestamp.store(LLONG_MAX);
	else
		kcp_mappings_ptr->changeport_timestamp.store(timestamp + current_settings.dynamic_port_refresh);

	if (current_settings.keep_alive > 0)
	{
		std::scoped_lock locker { mutex_kcp_keepalive };
		kcp_keepalive[kcp_ptr].store(timestamp);
	}

	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		size_t K = current_settings.fec_data;
		size_t N = K + current_settings.fec_redundant;
		kcp_mappings_ptr->fec_egress_control.fecc.reset_martix(K, N);
	}

	if (ptrcl == protocol_type::tcp)
	{
		std::shared_ptr<tcp_session> incoming_session = handshake_ptr->local_tcp;
		{
			std::scoped_lock lock_handshake{ mutex_handshakes, mutex_expiring_handshakes };
			std::shared_ptr<kcp_mappings> handshake_mappings_ptr = handshakes[handshake_ptr];
			handshakes.erase(handshake_ptr);
			expiring_handshakes.insert({ handshake_mappings_ptr, timestamp });
		}

		kcp_mappings_ptr->local_tcp = incoming_session;
		kcp_ptr->SetOutput([this](const char *buf, int len, void *user) -> int { return kcp_sender(buf, len, user); });
		kcp_ptr->SetPostUpdate([this](void *user) { resume_tcp((kcp_mappings *)user); });

		std::weak_ptr<KCP::KCP> kcp_ptr_weak = kcp_ptr;
		bool replaced = incoming_session->replace_callback([this, kcp_ptr_weak](std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session) mutable
			{
				tcp_listener_incoming(std::move(data), data_size, incoming_session, kcp_ptr_weak);
			});
		if (!replaced)
			return;
		incoming_session->when_disconnect([kcp_ptr, this](std::shared_ptr<tcp_session> session) { local_disconnect(kcp_ptr, session); });
		incoming_session->async_read_data();
	}

	if (ptrcl == protocol_type::udp)
	{
		std::scoped_lock handshake_lockers{ mutex_udp_address_map_to_handshake, mutex_expiring_handshakes, mutex_udp_seesion_caches, mutex_udp_local_session_map_to_kcp };
		udp::endpoint local_peer = *handshake_ptr->ingress_source_endpoint;
		std::shared_ptr<kcp_mappings> handshake_mappings_ptr = udp_address_map_to_handshake[local_peer];
		expiring_handshakes.insert({ handshake_mappings_ptr, timestamp });

		kcp_mappings_ptr->ingress_source_endpoint = handshake_ptr->ingress_source_endpoint;
		kcp_mappings_ptr->ingress_listen_port = handshake_ptr->ingress_listen_port;
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
		kcp_mappings_ptr->last_data_transfer_time.store(timestamp);
	}

	if (ptrcl == protocol_type::mux)
	{
		kcp_mappings_ptr->ingress_listen_port = handshake_ptr->ingress_listen_port;
		std::scoped_lock handshake_lockers{mutex_handshakes, mutex_expiring_handshakes};
		std::shared_ptr<kcp_mappings> handshake_mappings_ptr = handshakes[handshake_ptr];
		handshakes.erase(handshake_ptr);
		expiring_handshakes.insert({ handshake_mappings_ptr, timestamp });
		mux_tunnels->setup_mux_kcp(kcp_ptr);
	}

	kcp_ptr->Update();
	uint32_t next_update_time = kcp_ptr->Check();
	kcp_updater.submit(kcp_ptr, next_update_time);

	std::scoped_lock lockers{ mutex_kcp_channels };
	kcp_channels[basic_settings.uid] = kcp_mappings_ptr;
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
			if (session_iter->second != nullptr)
				expiring_handshakes.insert({ session_iter->second, packet::right_now() });
			handshakes.erase(session_iter);
		}
		if (incoming_session != nullptr)
		{
			incoming_session->session_is_ending(true);
			incoming_session->disconnect();
		}
	}

	if (handshake_ptr->connection_protocol == protocol_type::udp)
	{
		std::scoped_lock lockers{ mutex_udp_address_map_to_handshake, mutex_expiring_handshakes, mutex_udp_seesion_caches };
		std::shared_ptr<udp::endpoint> local_peer = handshake_ptr->ingress_source_endpoint;
		auto iter = udp_address_map_to_handshake.find(*local_peer);
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
		expiring_handshakes.insert({ session_iter->second, packet::right_now() });
		handshakes.erase(session_iter);
		establish_mux_channels(1);
	}
}

void client_mode::on_handshake_test_success(kcp_mappings *handshake_ptr)
{
	std::scoped_lock lock_handshake{ mutex_handshakes, mutex_expiring_forwarders };
	handshake_ptr->mapping_function();
	auto session_iter = handshakes.find(handshake_ptr);
	if (session_iter == handshakes.end())
		return;
	expiring_forwarders[handshake_ptr->egress_forwarder] = packet::right_now();
	handshake_ptr->egress_forwarder->stop();
	handshake_ptr->egress_forwarder = nullptr;
	handshakes.erase(session_iter);
}

void client_mode::handle_handshake(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (data == nullptr || data_size == 0 || kcp_ptr == nullptr)
		return;

	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data.get(), (int)data_size);

	if (!error_message.empty())
	{
		std::cerr << error_message << "\n";
		print_message_to_file(error_message, current_settings.log_messages);
		return;
	}

	auto [packet_timestamp, data_ptr, packet_data_size] = packet::unpack(data.get(), plain_size);
	if (packet_data_size == 0)
		return;
	auto timestamp = packet::right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > gbv_time_gap_seconds)
		return;

	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		auto [packet_header, kcp_data_ptr, kcp_data_size] = packet::unpack_fec(data.get(), plain_size);
		data_ptr = kcp_data_ptr;
		packet_data_size = kcp_data_size;
	}

	if (kcp_ptr->Input((const char *)data_ptr, (long)packet_data_size) < 0)
		return;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
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

		auto [ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack_inner(buffer_ptr, kcp_data_size);
		switch (ftr)
		{
		case feature::initialise:
		{
			std::unique_ptr<uint8_t[]> settings_data_ptr = std::make_unique<uint8_t[]>(unbacked_data_size);
			packet::convert_wrapper_byte_order(unbacked_data_ptr, settings_data_ptr.get(), unbacked_data_size);
			const packet::settings_wrapper *basic_settings = packet::get_initialise_details_from_unpacked_data(settings_data_ptr.get());
			if (basic_settings->inbound_bandwidth > 0 && current_settings.outbound_bandwidth > basic_settings->inbound_bandwidth)
				current_settings.outbound_bandwidth = basic_settings->inbound_bandwidth;
			on_handshake_success(kcp_mappings_ptr, *basic_settings);
			break;
		}
		case feature::test_connection:
		{
			on_handshake_test_success(kcp_mappings_ptr);
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
