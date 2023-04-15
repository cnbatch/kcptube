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
	timer_send_data.cancel();
	timer_find_expires.cancel();
	timer_expiring_kcp.cancel();
	timer_stun.cancel();
	timer_keep_alive.cancel();
}

bool server_mode::start()
{
	printf("start_up() running in server mode\n");

	auto func = std::bind(&server_mode::udp_server_incoming, this, _1, _2, _3, _4);
	std::set<uint16_t> listen_ports;
	if (current_settings.listen_port != 0)
		listen_ports.insert(current_settings.listen_port);

	for (uint16_t port_number = current_settings.listen_port_start; port_number <= current_settings.listen_port_end; ++port_number)
	{
		if (port_number != 0)
			listen_ports.insert(port_number);
	}

	udp::endpoint listen_on_ep(udp::v6(), *listen_ports.begin());
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

		if (local_address.is_v4())
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
			udp_servers.insert({ port_number, std::make_unique<udp_server>(network_io, sequence_task_pool_peer, task_limit, listen_on_ep, func) });
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
		timer_send_data.expires_after(KCP_UPDATE_INTERVAL);
		timer_send_data.async_wait([this](const asio::error_code &e) { kcp_loop_updates(e); });

		timer_find_expires.expires_after(KCP_UPDATE_INTERVAL);
		timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });

		timer_expiring_kcp.expires_after(FINDER_EXPIRES_INTERVAL);
		timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_kcp_loops(e); });

		if (!current_settings.stun_server.empty())
		{
			stun_header = send_stun_8489_request(*udp_servers.begin()->second, current_settings.stun_server);
			timer_stun.expires_after(std::chrono::seconds(1));
			timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
		}

		if (current_settings.keep_alive > 0)
		{
			timer_keep_alive.expires_after(seconds{ current_settings.keep_alive });
			timer_keep_alive.async_wait([this](const asio::error_code &e) { keep_alive(e); });
		}

		//timer_speed_count.expires_after(CHANGEPORT_UPDATE_INTERVAL);
		//timer_speed_count.async_wait([this](const asio::error_code &e) { time_counting(e); });
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

void server_mode::udp_server_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	if (data == nullptr || data_size == 0)
		return;
	input_count_before_kcp += data_size;
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

	udp_server_incoming_unpack(std::move(data), plain_size, peer, port_number);

	input_count2 += data_size;
}

void server_mode::udp_server_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	if (data == nullptr)
		return;
	
	uint8_t *data_ptr = data.get();
	uint32_t conv = KCP::KCP::GetConv(data_ptr);
	if (conv == 0)
	{
		udp_server_incoming_new_connection(std::move(data), plain_size, peer, port_number);
		return;
	}

	std::shared_lock locker_kcp_channels{ mutex_kcp_channels };
	auto kcp_channel_iter = kcp_channels.find(conv);
	if (kcp_channel_iter == kcp_channels.end())
	{
		return;
	}

	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_channel_iter->second;
	locker_kcp_channels.unlock();
	if (kcp_ptr->Input((const char *)data_ptr, (long)plain_size) < 0)
		return;

	{
		std::shared_lock shared_locker_kcp_session_map_to_source_udp{ mutex_kcp_session_map_to_source_udp };
		if (auto kcp_iter = kcp_session_map_to_source_udp.find(kcp_ptr); kcp_iter != kcp_session_map_to_source_udp.end())
		{
			if (kcp_iter->second != peer)
			{
				shared_locker_kcp_session_map_to_source_udp.unlock();
				std::unique_lock unique_locker_kcp_session_map_to_source_udp{ mutex_kcp_session_map_to_source_udp };
				if (kcp_iter->second != peer)
					kcp_iter->second = peer;
			}
		}
		else
			return;
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
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			continue;

		kcp_ptr->ReplaceUserPtr(udp_servers[port_number].get());

		switch (ftr)
		{
		case feature::data:
		{
			if (prtcl == protocol_type::tcp)
			{
				std::shared_ptr<tcp_session> tcp_channel;
				std::shared_lock locker{ mutex_kcp_session_map_to_tcp };
				if (auto session_iter = kcp_session_map_to_tcp.find(kcp_ptr); session_iter != kcp_session_map_to_tcp.end())
					tcp_channel = session_iter->second;
				else
					break;
				locker.unlock();
				tcp_channel->async_send_data(std::move(buffer_cache), unbacked_data_ptr, unbacked_data_size);
				output_count += unbacked_data_size;
			}
			else if (prtcl == protocol_type::udp)
			{
				std::shared_ptr<udp_client> udp_channel;
				std::shared_lock locker{ mutex_kcp_session_map_to_target_udp };
				if (auto channel_iter = kcp_session_map_to_target_udp.find(kcp_ptr); channel_iter != kcp_session_map_to_target_udp.end())
					udp_channel = channel_iter->second;
				else
					break;
				locker.unlock();
				if (udp_channel == nullptr)
					continue;

				udp_channel->async_send_out(std::move(buffer_cache), unbacked_data_ptr, unbacked_data_size, *udp_target);
				output_count += unbacked_data_size;
			}
			break;
		}
		case feature::keep_alive:
			break;
		case feature::disconnect:
		{
			if (prtcl == protocol_type::tcp)
			{
				std::shared_ptr<tcp_session> tcp_channel;
				std::shared_lock locker{ mutex_kcp_session_map_to_tcp };
				if (auto session_iter = kcp_session_map_to_tcp.find(kcp_ptr); session_iter != kcp_session_map_to_tcp.end())
					tcp_channel = session_iter->second;
				else
					break;
				locker.unlock();
				if (unbacked_data_size > 0)
				{
					asio::error_code ec;
					tcp_channel->send_data(unbacked_data_ptr, unbacked_data_size, ec);
				}
				//tcp_channel->disconnect();
				process_tcp_disconnect(tcp_channel.get(), kcp_ptr);
			}
			else if (prtcl == protocol_type::udp)
			{
				asio::error_code ec;
				std::shared_ptr<udp_client> udp_channel;
				std::shared_lock locker{ mutex_kcp_session_map_to_target_udp };
				if (auto channel_iter = kcp_session_map_to_target_udp.find(kcp_ptr); channel_iter != kcp_session_map_to_target_udp.end())
					udp_channel = channel_iter->second;
				else
					break;
				locker.unlock();
				if (unbacked_data_size > 0)
					udp_channel->send_out(unbacked_data_ptr, unbacked_data_size, *udp_target, ec);
				udp_channel->stop();
			}

			std::scoped_lock lockers{ mutex_expiring_kcp, mutex_kcp_looping };
			expiring_kcp[kcp_ptr] = packet::right_now() - current_settings.udp_timeout;
			kcp_looping.erase(kcp_ptr);
			break;
		}
		default:
			break;
		}
	}
}

void server_mode::tcp_client_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::shared_ptr<KCP::KCP> kcp_session)
{
	if (data == nullptr || incoming_session == nullptr)
		return;
	uint8_t *data_ptr = data.get();
	size_t new_data_size = packet::create_data_packet(protocol_type::tcp, data_ptr, data_size);
	kcp_session->Send((const char *)data_ptr, new_data_size);
	kcp_session->Update(time_now_for_kcp());
	//kcp_session->Flush();
	std::shared_lock locker_kcp_looping{ mutex_kcp_looping };
	if (auto iter = kcp_looping.find(kcp_session); iter != kcp_looping.end())
		iter->second.store(kcp_session->Check(time_now_for_kcp()));
	locker_kcp_looping.unlock();
	if (!incoming_session->session_is_ending() && !incoming_session->is_pause() &&
		kcp_session->WaitingForSend() >= kcp_session->GetSendWindowSize()/* * 16*/)
	{
		incoming_session->pause(true);
	}
	input_count += data_size;
}

void server_mode::udp_client_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, std::shared_ptr<KCP::KCP> kcp_session)
{
	if (data == nullptr)
		return;

	uint8_t *data_ptr = data.get();
	size_t new_data_size = packet::create_data_packet(protocol_type::udp, data_ptr, data_size);

	kcp_session->Send((const char *)data_ptr, new_data_size);
	kcp_session->Update(time_now_for_kcp());

	std::shared_lock locker_kcp_looping{ mutex_kcp_looping };
	if (kcp_looping.find(kcp_session) != kcp_looping.end())
		kcp_looping[kcp_session].store(kcp_session->Check(time_now_for_kcp()));
	locker_kcp_looping.unlock();
	input_count += data_size;
}

void server_mode::udp_server_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
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
			std::shared_ptr<KCP::KCP> handshake_kcp = std::make_shared<KCP::KCP>(0, nullptr);
			handshake_kcp->SetMTU(current_settings.kcp_mtu);
			handshake_kcp->NoDelay(0, 10, 0, 1);
			handshake_kcp->Update(time_now_for_kcp());
			handshake_kcp->RxMinRTO() = 10;
			handshake_kcp->SetOutput([this, port_number, peer](const char *buf, int len, void *user) -> int
				{
					std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(len + BUFFER_EXPAND_SIZE);
					uint8_t *new_buffer_ptr = new_buffer.get();
					std::copy_n((uint8_t *)buf, len, new_buffer_ptr);
					auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, new_buffer_ptr, len);
					if (!error_message.empty() || cipher_size == 0)
						return 0;

					udp_servers[port_number]->async_send_out(std::move(new_buffer), cipher_size, peer);
					return 0;
				});

			if (handshake_kcp->Input((const char *)data_ptr, (long)data_size) < 0)
			{
				return;
			}

			int buffer_size = handshake_kcp->PeekSize();
			if (buffer_size <= 0)
				return;

			int kcp_data_size = 0;
			if (kcp_data_size = handshake_kcp->Receive((char *)data_ptr, buffer_size); kcp_data_size < 0)
				return;

			auto [packet_timestamp, ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack(data_ptr, kcp_data_size);
			auto timestamp = packet::right_now();
			if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
				return;

			switch (ftr)
			{
			case feature::initialise:
			{
				uint32_t new_id = generate_token_number();
				std::shared_lock locker_uid_to_protocal_type{ mutex_uid_to_protocal_type };
				while (uid_to_protocal_type.find(new_id) != uid_to_protocal_type.end())
				{
					new_id = generate_token_number();
				}
				locker_uid_to_protocal_type.unlock();

				uint8_t protocal_number = (uint8_t)prtcl;
				uint16_t dynamic_port_start = current_settings.listen_port_start;
				uint16_t dynamic_port_end = current_settings.listen_port_end;

				std::shared_ptr<KCP::KCP> data_kcp = std::make_shared<KCP::KCP>(new_id, nullptr);
				std::unique_lock locker_kcp_session_map_to_source_udp{ mutex_kcp_session_map_to_source_udp, std::defer_lock };
				std::lock(locker_kcp_session_map_to_source_udp, locker_uid_to_protocal_type);
				kcp_session_map_to_source_udp[data_kcp] = peer;
				uid_to_protocal_type[new_id] = prtcl;
				locker_kcp_session_map_to_source_udp.unlock();
				locker_uid_to_protocal_type.unlock();
				data_kcp->ReplaceUserPtr(udp_servers[port_number].get());
				data_kcp->SetMTU(current_settings.kcp_mtu);
				data_kcp->SetWindowSize(current_settings.kcp_sndwnd, current_settings.kcp_rcvwnd);
				data_kcp->NoDelay(current_settings.kcp_nodelay, current_settings.kcp_interval, current_settings.kcp_resend, current_settings.kcp_nc);
				data_kcp->Update(time_now_for_kcp());
				data_kcp->RxMinRTO() = 10;

				bool connect_success = false;

				switch (prtcl)
				{
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
					std::vector<uint8_t> new_data = packet::response_initialise_packet(prtcl, new_id, dynamic_port_start, dynamic_port_end);
					handshake_kcp->Send((const char *)new_data.data(), (long)new_data.size());
					handshake_kcp->Flush();

					std::scoped_lock lockers{ mutex_expiring_handshakes, mutex_kcp_channels, mutex_kcp_session_map_to_source_udp, mutex_uid_to_protocal_type, mutex_kcp_looping };
					handshake_channels.insert({ peer, handshake_kcp });
					expiring_handshakes.insert({ handshake_kcp, packet::right_now() });
					kcp_channels.insert({ new_id, data_kcp });
					kcp_session_map_to_source_udp[data_kcp] = peer;
					uid_to_protocal_type[new_id] = prtcl;
					kcp_looping[data_kcp].store(0);
				}
				else
				{
					std::scoped_lock lockers{ mutex_expiring_handshakes };
					handshake_channels.insert({ peer, handshake_kcp });
					expiring_handshakes.insert({ handshake_kcp, packet::right_now() });
				}
				break;
			}
			default:
				break;
			}
		}
		unique_locker_handshake_channels.unlock();
		shared_locker_handshake_channels.lock();
	}
	else
	{
		std::shared_ptr<KCP::KCP> handshake_kcp = iter->second;
		if (handshake_kcp->Input((const char *)data_ptr, (long)data_size) < 0)
			return;
		
		shared_locker_handshake_channels.unlock();

		handshake_kcp->Flush();
		//std::vector<char> std_buffer;
		//if (handshake_kcp->Receive(std_buffer) < 0 || std_buffer.size() == 0)
		//	return;
		int buffer_size = handshake_kcp->PeekSize();
		if (buffer_size <= 0)
			return;

		int kcp_data_size = 0;
		if (kcp_data_size = handshake_kcp->Receive((char *)data_ptr, buffer_size); kcp_data_size < 0)
			return;

		auto [packet_timestamp, ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack(data_ptr, kcp_data_size);
		auto timestamp = packet::right_now();
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			return;

		handshake_kcp->Flush();
	}
	input_count2 += data_size;
}

bool server_mode::create_new_tcp_connection(std::shared_ptr<KCP::KCP> handshake_kcp, std::shared_ptr<KCP::KCP> data_kcp)
{
	bool connect_success = false;
	auto callback_function = [data_kcp, this](std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> target_session)
	{
		tcp_client_incoming(std::move(data), data_size, target_session, data_kcp);
	};
	tcp_client target_connector(io_context, callback_function);
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
		local_session->when_disconnect([data_kcp, this](std::shared_ptr<tcp_session> session) { process_tcp_disconnect(session.get(), data_kcp); });
		data_kcp->SetOutput([this, data_kcp, session = local_session.get()](const char *buf, int len, void *user) -> int
			{
				return kcp_sender(data_kcp, session, buf, len, user);
			});

		{
			std::scoped_lock lockers{ mutex_tcp_session_map_to_kcp , mutex_kcp_session_map_to_tcp };
			tcp_session_map_to_kcp.insert({ local_session, data_kcp });
			kcp_session_map_to_tcp.insert({ data_kcp, local_session });
		}
		local_session->async_read_data();
	}
	else
	{
		connect_success = false;
		std::vector<uint8_t> data = packet::inform_error_packet(protocol_type::tcp, ec.message());
		handshake_kcp->Send((const char *)data.data(), data.size());
		handshake_kcp->Update(time_now_for_kcp());
		std::lock_guard locker{ mutex_expiring_kcp };
		expiring_kcp.insert({ data_kcp, packet::right_now() });
	}

	return connect_success;
}

bool server_mode::create_new_udp_connection(std::shared_ptr<KCP::KCP> handshake_kcp, std::shared_ptr<KCP::KCP> data_kcp, const udp::endpoint &peer)
{
	bool connect_success = false;

	asio::error_code ec;
	udp_callback_t udp_func_ap = [data_kcp, this](std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
	{
		udp_client_incoming(std::move(data), data_size, peer, port_number, data_kcp);
	};
	std::shared_ptr<udp_client> target_connector = std::make_shared<udp_client>(network_io, sequence_task_pool_local, task_limit, udp_func_ap);
	target_connector->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target, ec);
	if (ec)
		return false;

	data_kcp->SetOutput([this, data_kcp](const char *buf, int len, void *user) -> int
		{
			return kcp_sender(data_kcp, nullptr, buf, len, user);
		});

	if (udp_target != nullptr || update_local_udp_target(target_connector))
	{
		target_connector->async_receive();
		std::unique_lock locker{ mutex_kcp_session_map_to_target_udp };
		kcp_session_map_to_target_udp.insert({ data_kcp, target_connector });
		locker.unlock();
		data_kcp->Flush();
		return true;
	}

	if (ec)
	{
		connect_success = false;
		std::vector<uint8_t> data = packet::inform_error_packet(protocol_type::tcp, ec.message());
		handshake_kcp->Send((const char *)data.data(), data.size());
		handshake_kcp->Update(time_now_for_kcp());
		std::lock_guard locker{ mutex_expiring_kcp };
		expiring_kcp.insert({ data_kcp, packet::right_now() });
	}

	return connect_success;
}

int server_mode::kcp_sender(std::shared_ptr<KCP::KCP> data_kcp, tcp_session *session, const char *buf, int len, void *user)
{
	std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(len + BUFFER_EXPAND_SIZE);
	uint8_t *new_buffer_ptr = new_buffer.get();
	std::copy_n((const uint8_t *)buf, len, new_buffer_ptr);
	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, new_buffer_ptr, len);
	if (!error_message.empty() || cipher_size == 0)
		return 0;

	((udp_server *)user)->async_send_out(std::move(new_buffer), cipher_size, get_remote_address(data_kcp));
	if (session != nullptr && session->is_pause() && data_kcp->WaitingForSend() < data_kcp->GetSendWindowSize())
		session->pause(false);
	output_count2 += cipher_size;
	return 0;
}

void server_mode::process_tcp_disconnect(tcp_session *session, std::shared_ptr<KCP::KCP> kcp_ptr)
{
	if (session == nullptr)
		return;

	std::scoped_lock lockers{ mutex_expiring_kcp, mutex_kcp_looping };
	if (expiring_kcp.find(kcp_ptr) == expiring_kcp.end())
	{
		session->when_disconnect(empty_tcp_disconnect);
		session->session_is_ending(true);
		session->pause(false);
		session->stop();
		session->disconnect();
		std::vector<uint8_t> data = packet::inform_disconnect_packet(protocol_type::tcp);
		kcp_ptr->Send((const char *)data.data(), data.size());
		kcp_ptr->Update(time_now_for_kcp());
		kcp_ptr->Flush();
		expiring_kcp.insert({ kcp_ptr, packet::right_now() - (CLEANUP_WAITS - 1) });
	}
	if (auto iter = kcp_looping.find(kcp_ptr); iter != kcp_looping.end())
	{
		kcp_looping.erase(iter);
	}
}

udp::endpoint server_mode::get_remote_address(std::shared_ptr<KCP::KCP> kcp_ptr)
{
	udp::endpoint ep;
	std::shared_lock locker_kcp_session_map_to_source_udp{ mutex_kcp_session_map_to_source_udp };
	ep = kcp_session_map_to_source_udp[kcp_ptr];
	locker_kcp_session_map_to_source_udp.unlock();

	return ep;
}

bool server_mode::update_local_udp_target(std::shared_ptr<udp_client> target_connector)
{
	bool connect_success = false;
	asio::error_code ec;
	for (int i = 0; i <= RETRY_TIMES; ++i)
	{
		const std::string &destination_address = current_settings.destination_address;
		uint16_t destination_port = current_settings.destination_port;
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

void server_mode::cleanup_expiring_handshake_connections()
{
	auto time_right_now = packet::right_now();

	std::lock_guard locker{ mutex_expiring_handshakes };
	for (auto iter = expiring_handshakes.begin(), next_iter = iter; iter != expiring_handshakes.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<KCP::KCP> kcp_ptr = iter->first;
		int64_t expire_time = iter->second;
		if (calculate_difference(time_right_now, expire_time) < CLEANUP_WAITS || kcp_ptr->WaitingForSend() > 0)
		{
			kcp_ptr->Update(time_now_for_kcp());
			continue;
		}
		expiring_handshakes.erase(iter);
	}
}

void server_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock lockers{ mutex_expiring_kcp, mutex_kcp_looping };
	for (auto iter = expiring_kcp.begin(), next_iter = iter; iter != expiring_kcp.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<KCP::KCP> kcp_ptr = iter->first;
		int64_t expire_time = iter->second;
		uint32_t conv = kcp_ptr->GetConv();
		if (calculate_difference(time_right_now, expire_time) < CLEANUP_WAITS || kcp_ptr->WaitingForSend() > 0)
		{
			kcp_ptr->Update(time_now_for_kcp());
			continue;
		}

		std::unique_lock locker_kcp_channels{ mutex_kcp_channels };
		kcp_channels.erase(conv);
		locker_kcp_channels.unlock();

		std::unique_lock locker_protocal_type_of_kcp{ mutex_uid_to_protocal_type };
		switch (uid_to_protocal_type[conv])
		{
		case protocol_type::tcp:
		{
			std::scoped_lock switch_lockers{ mutex_kcp_session_map_to_tcp, mutex_tcp_session_map_to_kcp };
			std::shared_ptr<tcp_session> current_session = kcp_session_map_to_tcp[kcp_ptr];

			if (auto loop_iter = kcp_looping.find(kcp_ptr); loop_iter != kcp_looping.end())
				kcp_looping.erase(loop_iter);

			if (current_session != nullptr)
			{
				current_session->when_disconnect(empty_tcp_disconnect);
				current_session->disconnect();
				current_session->stop();
				tcp_session_map_to_kcp.erase(current_session);
				current_session = nullptr;
			}
			else
			{
				for (auto map_iter = tcp_session_map_to_kcp.begin(); map_iter != tcp_session_map_to_kcp.end(); ++map_iter)
				{
					if (map_iter->second == kcp_ptr)
					{
						tcp_session_map_to_kcp.erase(map_iter);
						break;
					}
				}
			}
			kcp_session_map_to_tcp.erase(kcp_ptr);
			break;
		}
		case protocol_type::udp:
		{
			if (auto loop_iter = kcp_looping.find(kcp_ptr); loop_iter != kcp_looping.end())
				kcp_looping.erase(loop_iter);

			{
				std::scoped_lock switch_lockers{ mutex_kcp_session_map_to_target_udp };
				if (auto session_iter = kcp_session_map_to_target_udp.find(kcp_ptr); session_iter != kcp_session_map_to_target_udp.end())
				{
					session_iter->second->stop();
					kcp_session_map_to_target_udp.erase(session_iter);
				}
			}
			break;
		}
		default:
			break;
		}

		kcp_ptr->SetOutput(empty_kcp_output);
		uid_to_protocal_type.erase(conv);
		locker_protocal_type_of_kcp.unlock();

		std::unique_lock locker_kcp_session_map_to_source_udp{ mutex_kcp_session_map_to_source_udp };
		kcp_session_map_to_source_udp.erase(kcp_ptr);
		locker_kcp_session_map_to_source_udp.unlock();

		expiring_kcp.erase(iter);
	}
}

void server_mode::loop_update_connections()
{
	std::shared_lock locker_kcp_looping{ mutex_kcp_looping };
	for (auto iter = kcp_looping.begin(); iter != kcp_looping.end(); ++iter)
	{
		std::shared_ptr<KCP::KCP> kcp_ptr = iter->first;
		uint32_t conv = kcp_ptr->GetConv();
		std::atomic<uint32_t> &kcp_update_time = iter->second;

		if (uint32_t kcp_refresh_time = time_now_for_kcp(); kcp_refresh_time >= kcp_update_time.load())
		{
			kcp_ptr->Update(kcp_refresh_time);
			uint32_t next_refresh_time = kcp_ptr->Check(kcp_refresh_time);
			kcp_update_time.store(next_refresh_time);
		}
	}
}

void server_mode::loop_find_expires()
{
	std::scoped_lock lockers{ mutex_kcp_looping, mutex_expiring_kcp };
	for (auto iter = kcp_looping.begin(), next_iter = iter; iter != kcp_looping.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<KCP::KCP> kcp_ptr = iter->first;
		uint32_t conv = kcp_ptr->GetConv();
		std::atomic<uint32_t> &kcp_update_time = iter->second;

		bool do_erase = false;
		bool normal_delete = false;

		std::shared_lock locker_uid_to_protocal_type{ mutex_uid_to_protocal_type };
		protocol_type ptype = uid_to_protocal_type[conv];
		locker_uid_to_protocal_type.unlock();

		if (ptype == protocol_type::tcp)
		{
			std::shared_lock locker_kcp_session_map_to_tcp{ mutex_kcp_session_map_to_tcp };
			std::shared_ptr<tcp_session> local_session = kcp_session_map_to_tcp[kcp_ptr];
			if (local_session == nullptr)
			{
				auto error_packet = packet::inform_error_packet(protocol_type::tcp, "TCP Session Closed");
				kcp_ptr->Send((char *)error_packet.data(), error_packet.size());
				kcp_ptr->Update(time_now_for_kcp());
				kcp_ptr->Flush();
				uint32_t next_refresh_time = kcp_ptr->Check(time_now_for_kcp());
				kcp_update_time.store(next_refresh_time);
				do_erase = true;
				normal_delete = true;
			}
		}

		if (ptype == protocol_type::udp)
		{
			std::shared_lock locker_kcp_session_map_to_tcp{ mutex_kcp_session_map_to_target_udp };
			std::shared_ptr<udp_client> local_session = kcp_session_map_to_target_udp[kcp_ptr];
			locker_kcp_session_map_to_tcp.unlock();
			do_erase = local_session->time_gap_of_receive() > current_settings.udp_timeout &&
			           local_session->time_gap_of_send() > current_settings.udp_timeout;
		}

		if (do_erase)
		{
			kcp_ptr->SetOutput(empty_kcp_output);
			kcp_looping.erase(iter);

			if (expiring_kcp.find(kcp_ptr) != expiring_kcp.end())
				continue;

			if (normal_delete)
				expiring_kcp.insert({ kcp_ptr, packet::right_now() });
			else
				expiring_kcp.insert({ kcp_ptr, packet::right_now() - current_settings.udp_timeout });
		}
		else
		{
			if (uint32_t kcp_refresh_time = time_now_for_kcp(); kcp_refresh_time >= kcp_update_time.load())
			{
				kcp_ptr->Update(kcp_refresh_time);
				uint32_t next_refresh_time = kcp_ptr->Check(kcp_refresh_time);
				kcp_update_time.store(next_refresh_time);
			}
		}
	}
}

void server_mode::loop_keep_alive()
{
	std::shared_lock locker_kcp_looping{ mutex_kcp_looping };
	std::shared_lock locker_uid_to_protocal_type{ mutex_uid_to_protocal_type };
	for (auto &[kcp_ptr, kcp_update_time] : kcp_looping)
	{
		uint32_t conv = kcp_ptr->GetConv();
		protocol_type ptype = uid_to_protocal_type[conv];
		std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_packet(ptype);
		kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());
		uint32_t next_refresh_time = kcp_ptr->Check(time_now_for_kcp());
		kcp_update_time.store(next_refresh_time);
	}
}

void server_mode::send_stun_request(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (current_settings.stun_server.empty())
		return;

	resend_stun_8489_request(*udp_servers.begin()->second, current_settings.stun_server, stun_header.get());

	timer_stun.expires_after(STUN_RESEND);
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}

void server_mode::kcp_loop_updates(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_update_connections();

	timer_send_data.expires_after(KCP_UPDATE_INTERVAL);
	timer_send_data.async_wait([this](const asio::error_code &e) { kcp_loop_updates(e); });
}

void server_mode::find_expires(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_find_expires();

	timer_find_expires.expires_after(FINDER_EXPIRES_INTERVAL);
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

	timer_expiring_kcp.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_kcp_loops(e); });
}

void server_mode::time_counting(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	int64_t input_speed = input_count.load();
	int64_t output_speed = output_count.load();

	int64_t input_speed2 = input_count2.load();
	int64_t output_speed2 = output_count2.load();

	std::cout << "Local -> Here speed: " << input_speed / 1024 << " KB/s\t Here -> Local Speed: " << output_speed / 1024 << " KB/s\t";
	std::cout << "Peer -> Here speed: " << input_speed2 / 1024 << " KB/s\t Here -> Peer Speed: " << output_speed2 / 1024 << " KB/s\n";
	std::cout << "Peer -> Here speed (before KCP): " << input_count_before_kcp.load() / 1024 << " KB/s\n";

	input_count.store(0);
	output_count.store(0);

	input_count2.store(0);
	output_count2.store(0);

	input_count_before_kcp.store(0);

	timer_speed_count.expires_after(CHANGEPORT_UPDATE_INTERVAL);
	timer_speed_count.async_wait([this](const asio::error_code &e) { time_counting(e); });
}

void server_mode::keep_alive(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive();

	timer_keep_alive.expires_after(seconds{ current_settings.keep_alive });
	timer_keep_alive.async_wait([this](const asio::error_code& e) { keep_alive(e); });
}