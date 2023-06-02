#include <climits>
#include "relay.hpp"
#include "../shares/data_operations.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;

relay_mode::~relay_mode()
{
}

bool relay_mode::start()
{
	printf("start_up() running in relay mode\n");

	auto func = std::bind(&relay_mode::udp_listener_incoming, this, _1, _2, _3, _4);

	std::set<uint16_t> listen_ports = convert_to_port_list(*current_settings.ingress);

	bool ipv4_only = current_settings.ingress->ipv4_only;
	udp::endpoint listen_on_ep;
	if (ipv4_only)
		listen_on_ep = udp::endpoint(udp::v4(), *listen_ports.begin());
	else
		listen_on_ep = udp::endpoint(udp::v6(), *listen_ports.begin());

	std::string listen_on = current_settings.ingress->listen_on;
	if (!listen_on.empty())
	{
		asio::error_code ec;
		asio::ip::address local_address = asio::ip::make_address(listen_on, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + "Listen Address incorrect - " + listen_on + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			return false;
		}

		if (local_address.is_v4() && !ipv4_only)
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

		if (!current_settings.ingress->stun_server.empty())
		{
			stun_header = send_stun_8489_request(*udp_servers.begin()->second, current_settings.ingress->stun_server, ipv4_only);
			timer_stun.expires_after(std::chrono::seconds(1));
			timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
		}

		if (current_settings.ingress->keep_alive > 0)
		{
			timer_keep_alive_ingress.expires_after(KEEPALIVE_UPDATE_INTERVAL);
			timer_keep_alive_ingress.async_wait([this](const asio::error_code &e) { keep_alive_ingress(e); });
		}

		if (current_settings.egress->keep_alive > 0)
		{
			timer_keep_alive_egress.expires_after(KEEPALIVE_UPDATE_INTERVAL);
			timer_keep_alive_egress.async_wait([this](const asio::error_code &e) { keep_alive_egress(e); });
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

void relay_mode::udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
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

	auto [error_message, plain_size] = decrypt_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, data_ptr, (int)data_size);
	if (!error_message.empty())
		return;

	udp_listener_incoming_unpack(std::move(data), plain_size, peer, port_number);
}

void relay_mode::udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	if (data == nullptr)
		return;

	uint8_t *data_ptr = data.get();
	uint32_t conv = KCP::KCP::GetConv(data_ptr);
	if (conv == 0)
	{
		udp_listener_incoming_new_connection(std::move(data), plain_size, peer, port_number);
		return;
	}

	std::shared_ptr<kcp_mappings> kcp_mappings_ptr;
	std::shared_lock locker_id_map_to_both_sides{ mutex_id_map_to_both_sides };
	if (auto kcp_channels_iter = id_map_to_both_sides.find(conv); kcp_channels_iter == id_map_to_both_sides.end())
		return;
	else
		kcp_mappings_ptr = kcp_channels_iter->second;
	locker_id_map_to_both_sides.unlock();

	std::shared_ptr<KCP::KCP> kcp_ptr_ingress = kcp_mappings_ptr->ingress_kcp;
	std::shared_ptr<KCP::KCP> kcp_ptr_egress = kcp_mappings_ptr->egress_kcp;
	std::shared_ptr<forwarder> forwarder_ptr_egress = kcp_mappings_ptr->egress_forwarder;

	if (kcp_ptr_ingress->Input((const char *)data_ptr, (long)plain_size) < 0)
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
		int buffer_size = kcp_ptr_ingress->PeekSize();
		if (buffer_size <= 0)
			break;

		std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique<uint8_t[]>(buffer_size);
		uint8_t *buffer_ptr = buffer_cache.get();

		int kcp_data_size = 0;
		if (kcp_data_size = kcp_ptr_ingress->Receive((char *)buffer_ptr, buffer_size); kcp_data_size < 0)
			break;

		auto [packet_timestamp, ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack(buffer_ptr, kcp_data_size);
		auto timestamp = packet::right_now();
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			continue;

		kcp_mappings_ptr->ingress_listener.store(udp_servers[port_number].get());

		switch (ftr)
		{
		case feature::data:
		{
			kcp_ptr_egress->Send((const char *)buffer_ptr, kcp_data_size);

			std::shared_lock lock_kcp_looping{ mutex_kcp_looping };
			kcp_looping[kcp_mappings_ptr->ingress_kcp].store(kcp_mappings_ptr->ingress_kcp->Check(time_now_for_kcp()));
			kcp_looping[kcp_mappings_ptr->egress_kcp].store(kcp_mappings_ptr->egress_kcp->Check(time_now_for_kcp()));
			lock_kcp_looping.unlock();
			break;
		}
		case feature::keep_alive:
			break;
		case feature::failure:
			[[fallthrough]];
		case feature::disconnect:
		{
			process_disconnect(kcp_ptr_egress, (const char *)buffer_ptr, kcp_data_size);
			break;
		}
		default:
			break;
		}
	}
}

void relay_mode::udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	uint8_t *data_ptr = data.get();
	std::shared_lock shared_locker_handshake_channels{ mutex_handshake_ingress_map_to_egress, std::defer_lock };
	std::unique_lock unique_locker_handshake_channels{ mutex_handshake_ingress_map_to_egress, std::defer_lock };
	shared_locker_handshake_channels.lock();
	auto iter = handshake_ingress_map_to_channels.find(peer);
	if (iter == handshake_ingress_map_to_channels.end())
	{
		shared_locker_handshake_channels.unlock();
		unique_locker_handshake_channels.lock();
		iter = handshake_ingress_map_to_channels.find(peer);
		if (iter == handshake_ingress_map_to_channels.end())
		{
			asio::error_code ec;

			handshake_ingress_map_to_channels[peer] = std::make_unique<kcp_mappings>();
			kcp_mappings *handshake_kcp_mappings = handshake_ingress_map_to_channels[peer].get();
			handshake_kcp_mappings->ingress_source_endpoint = peer;
			handshake_kcp_mappings->ingress_listener.store(udp_servers[port_number].get());

			std::shared_ptr<KCP::KCP> handshake_kcp_ingress = std::make_shared<KCP::KCP>(0, nullptr);
			handshake_kcp_ingress->SetMTU(current_settings.ingress->kcp_mtu);
			handshake_kcp_ingress->NoDelay(0, 2, 0, 1);
			handshake_kcp_ingress->Update(time_now_for_kcp());
			handshake_kcp_ingress->RxMinRTO() = 10;
			handshake_kcp_ingress->SetBandwidth(current_settings.ingress->outbound_bandwidth, current_settings.ingress->inbound_bandwidth);
			handshake_kcp_ingress->SetOutput([this](const char *buf, int len, void *user) -> int
				{
					return kcp_sender_via_listener(buf, len, user);
				});

			if (handshake_kcp_ingress->Input((const char *)data_ptr, (long)data_size) < 0)
			{
				return;
			}

			int buffer_size = handshake_kcp_ingress->PeekSize();
			if (buffer_size <= 0)
				return;

			int kcp_data_size = 0;
			if (kcp_data_size = handshake_kcp_ingress->Receive((char *)data_ptr, buffer_size); kcp_data_size < 0)
				return;

			auto [packet_timestamp, ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack(data_ptr, kcp_data_size);
			auto timestamp = packet::right_now();
			if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
				return;

			switch (ftr)
			{
			case feature::initialise:
			{
				handshake_kcp_mappings->ingress_kcp = handshake_kcp_ingress;
				handshake_kcp_mappings->connection_protocol = prtcl;
				handshake_kcp_ingress->custom_data.store(handshake_kcp_mappings);

				std::shared_ptr<KCP::KCP> handshake_kcp_egress = std::make_shared<KCP::KCP>(0, nullptr);
				auto udp_func = std::bind(&relay_mode::udp_forwarder_incoming, this, _1, _2, _3, _4, _5);
				auto udp_forwarder = std::make_shared<forwarder>(network_io, sequence_task_pool_peer, task_limit, handshake_kcp_egress, udp_func, current_settings.egress->ipv4_only);
				if (udp_forwarder == nullptr)
				{
					expiring_handshakes.insert({ handshake_kcp_ingress, packet::right_now() });
					return;
				}
				handshake_kcp_mappings->egress_kcp = handshake_kcp_egress;
				handshake_kcp_mappings->egress_forwarder = udp_forwarder;
				handshake_kcp_mappings->changeport_timestamp.store(LLONG_MAX);
				handshake_kcp_egress->custom_data.store(handshake_kcp_mappings);

				handshake_kcp_egress->SetMTU(current_settings.egress->kcp_mtu);
				handshake_kcp_egress->NoDelay(0, 2, 0, 1);
				handshake_kcp_egress->RxMinRTO() = 10;
				handshake_kcp_egress->SetBandwidth(current_settings.egress->outbound_bandwidth, current_settings.egress->inbound_bandwidth);
				handshake_kcp_egress->Update(time_now_for_kcp());
				handshake_kcp_egress->SetOutput([this](const char *buf, int len, void *user) -> int
					{
						return kcp_sender_via_forwarder(buf, len, user);
					});

				bool connect_success = save_udp_target(udp_forwarder, handshake_kcp_mappings->egress_target_endpoint);
				if (current_settings.egress->ipv4_only)
					udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v4, ec);
				else
					udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v6, ec);

				udp_forwarder->async_receive();

				if (!connect_success || ec)
				{
					std::vector<uint8_t> data = packet::inform_error_packet(protocol_type::udp, ec.message());
					handshake_kcp_ingress->Send((const char *)data.data(), data.size());
					std::lock_guard locker{ mutex_expiring_handshakes };
					expiring_handshakes.insert({ handshake_kcp_ingress, packet::right_now() });
					return;
				}

				handshake_kcp_egress->Send((const char *)data_ptr, kcp_data_size);
				std::lock_guard locker{ mutex_expiring_handshakes };
				int64_t right_now = packet::right_now();
				expiring_handshakes.insert({ handshake_kcp_ingress, right_now });
				expiring_handshakes.insert({ handshake_kcp_egress, right_now });

				break;
			}
			default:
				break;
			}
		}
		//unique_locker_handshake_channels.unlock();
		//shared_locker_handshake_channels.lock();
	}
	else
	{
		std::shared_ptr<KCP::KCP> handshake_kcp_ingress = iter->second->ingress_kcp;
		std::shared_ptr<KCP::KCP> handshake_kcp_egress = iter->second->egress_kcp;
		if (handshake_kcp_ingress->Input((const char *)data_ptr, (long)data_size) < 0)
			return;

		shared_locker_handshake_channels.unlock();

		int buffer_size = handshake_kcp_ingress->PeekSize();
		if (buffer_size <= 0)
			return;

		int kcp_data_size = 0;
		if (kcp_data_size = handshake_kcp_ingress->Receive((char *)data_ptr, buffer_size); kcp_data_size < 0)
			return;

		auto [packet_timestamp, ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack(data_ptr, kcp_data_size);
		auto timestamp = packet::right_now();
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			return;
		handshake_kcp_egress->Send((const char *)data_ptr, kcp_data_size);
	}
}

void relay_mode::udp_forwarder_incoming(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (data == nullptr || data_size == 0 || kcp_ptr == nullptr)
		return;

	uint8_t *data_ptr = data.get();
	auto [error_message, plain_size] = decrypt_data(current_settings.egress->encryption_password, current_settings.egress->encryption, data_ptr, (int)data_size);

	if (!error_message.empty())
		return;

	udp_forwarder_incoming_unpack(kcp_ptr, std::move(data), plain_size, peer, local_port_number);
}

void relay_mode::udp_forwarder_incoming_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	uint8_t *data_ptr = data.get();
	uint32_t conv = KCP::KCP::GetConv(data_ptr);
	if (kcp_ptr->GetConv() != conv)
	{
		std::string error_message = time_to_string_with_square_brackets() +
			"UDP<->KCP, conv is not the same as record : conv = " + std::to_string(conv) +
			", local kcp : " + std::to_string(kcp_ptr->GetConv()) + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		return;
	}

	if (kcp_ptr->Input((const char *)data_ptr, (long)plain_size) < 0)
		return;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->custom_data.load();

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
			if (conv == 0)
			{
				auto [conv_id, start_port, end_port] = packet::get_initialise_details_from_unpacked_data(unbacked_data_ptr);
				if (start_port != 0 && end_port != 0)
				{
					if (current_settings.egress->destination_port_start != start_port)
						current_settings.egress->destination_port_start = start_port;

					if (current_settings.egress->destination_port_end != end_port)
						current_settings.egress->destination_port_end = end_port;
				}

				uint16_t dynamic_port_start = current_settings.ingress->destination_port_start;
				uint16_t dynamic_port_end = current_settings.ingress->destination_port_end;
				packet::modify_initialise_details_of_unpacked_data(unbacked_data_ptr, dynamic_port_start, dynamic_port_end);

				create_kcp_bidirections(conv_id, kcp_mappings_ptr);
			}

			kcp_mappings_ptr->ingress_kcp->Send((const char *)buffer_ptr, kcp_data_size);

			uint32_t next_refresh_time = kcp_ptr->Check(time_now_for_kcp());
			std::shared_lock locker_kcp_looping{ mutex_kcp_looping };
			if (auto iter = kcp_looping.find(kcp_mappings_ptr->ingress_kcp); iter != kcp_looping.end())
				iter->second.store(next_refresh_time);
			locker_kcp_looping.unlock();
			break;
		}
		case feature::failure:
		[[fallthrough]];
		case feature::disconnect:
		{
			process_disconnect(kcp_mappings_ptr->ingress_kcp, (const char *)buffer_ptr, kcp_data_size);
			break;
		}
		case feature::keep_alive:
			break;
		case feature::data:
		{
			kcp_mappings_ptr->ingress_kcp->Send((const char *)buffer_ptr, kcp_data_size);

			std::shared_lock lock_kcp_looping{ mutex_kcp_looping };
			kcp_looping[kcp_mappings_ptr->ingress_kcp].store(kcp_mappings_ptr->ingress_kcp->Check(time_now_for_kcp()));
			kcp_looping[kcp_mappings_ptr->egress_kcp].store(kcp_mappings_ptr->egress_kcp->Check(time_now_for_kcp()));
			lock_kcp_looping.unlock();

			std::shared_lock share_locker_egress{ kcp_mappings_ptr->mutex_egress_endpoint };
			if (kcp_mappings_ptr->egress_target_endpoint != peer && kcp_mappings_ptr->egress_previous_target_endpoint != peer)
			{
				share_locker_egress.unlock();
				std::scoped_lock lockers{ kcp_mappings_ptr->mutex_egress_endpoint, mutex_egress_target_address };
				kcp_mappings_ptr->egress_previous_target_endpoint = kcp_mappings_ptr->egress_target_endpoint;
				kcp_mappings_ptr->egress_target_endpoint = peer;
				*target_address = peer.address();
			}
			break;
		}
		default:
			break;
		}
	}
}

void relay_mode::change_new_port(kcp_mappings *kcp_mappings_ptr)
{
	auto timestamp = packet::right_now();
	if (kcp_mappings_ptr->changeport_timestamp.load() > timestamp)
		return;
	kcp_mappings_ptr->changeport_timestamp += current_settings.egress->dynamic_port_refresh;

	std::shared_ptr<KCP::KCP> kcp_ptr_egress = kcp_mappings_ptr->egress_kcp;

	auto udp_func = std::bind(&relay_mode::udp_forwarder_incoming, this, _1, _2, _3, _4, _5);
	auto udp_forwarder = std::make_shared<forwarder>(network_io, sequence_task_pool_peer, task_limit, kcp_ptr_egress, udp_func, current_settings.egress->ipv4_only);
	if (udp_forwarder == nullptr)
		return;

	uint16_t destination_port_start = current_settings.egress->destination_port_start;
	uint16_t destination_port_end = current_settings.egress->destination_port_end;
	if (destination_port_start != destination_port_end)
	{
		uint16_t new_port_numer = generate_new_port_number(destination_port_start, destination_port_end);
		std::shared_lock locker{ mutex_egress_target_address };
		asio::ip::address temp_address = *target_address;
		locker.unlock();
		std::scoped_lock locker_egress{kcp_mappings_ptr->mutex_egress_endpoint};
		kcp_mappings_ptr->egress_target_endpoint.address(temp_address);
		kcp_mappings_ptr->egress_target_endpoint.port(new_port_numer);
	}

	asio::error_code ec;
	if (current_settings.egress->ipv4_only)
		udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v6, ec);

	if (ec)
		return;

	udp_forwarder->async_receive();

	std::shared_ptr<forwarder> old_forwarder = kcp_mappings_ptr->egress_forwarder;
	kcp_mappings_ptr->egress_forwarder = udp_forwarder;

	std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
	expiring_forwarders.insert({ old_forwarder, timestamp });
}

void relay_mode::create_kcp_bidirections(uint32_t new_id, kcp_mappings *handshake_kcp_mappings_ptr)
{
	asio::error_code ec;
	auto timestamp = packet::right_now();

	std::unique_lock locker_id_map_to_both_sides{ mutex_id_map_to_both_sides };
	id_map_to_both_sides[new_id] = std::make_shared<kcp_mappings>();
	kcp_mappings *kcp_mappings_ptr = id_map_to_both_sides[new_id].get();
	locker_id_map_to_both_sides.unlock();
	kcp_mappings_ptr->connection_protocol = handshake_kcp_mappings_ptr->connection_protocol;

	std::shared_ptr<KCP::KCP> kcp_ptr_ingress = std::make_shared<KCP::KCP>(new_id, nullptr);
	kcp_ptr_ingress->SetMTU(current_settings.ingress->kcp_mtu);
	kcp_ptr_ingress->SetWindowSize(current_settings.ingress->kcp_sndwnd, current_settings.ingress->kcp_rcvwnd);
	kcp_ptr_ingress->NoDelay(current_settings.ingress->kcp_nodelay, current_settings.ingress->kcp_interval, current_settings.ingress->kcp_resend, current_settings.ingress->kcp_nc);
	kcp_ptr_ingress->Update(time_now_for_kcp());
	kcp_ptr_ingress->RxMinRTO() = 10;
	kcp_ptr_ingress->SetBandwidth(current_settings.ingress->outbound_bandwidth, current_settings.ingress->inbound_bandwidth);
	kcp_ptr_ingress->SetOutput([this](const char *buf, int len, void *user) -> int
		{
			return kcp_sender_via_listener(buf, len, user);
		});
	kcp_ptr_ingress->custom_data.store(kcp_mappings_ptr);

	std::shared_ptr<KCP::KCP> kcp_ptr_egress = std::make_shared<KCP::KCP>(new_id, nullptr);
	auto udp_func = std::bind(&relay_mode::udp_forwarder_incoming, this, _1, _2, _3, _4, _5);
	auto udp_forwarder = std::make_shared<forwarder>(network_io, sequence_task_pool_peer, task_limit, kcp_ptr_egress, udp_func, current_settings.egress->ipv4_only);
	if (udp_forwarder == nullptr)
		return;

	if (current_settings.egress->ipv4_only)
		udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v6, ec);

	if (ec)
		return;

	udp_forwarder->async_receive();
	bool connect_success = save_udp_target(udp_forwarder, kcp_mappings_ptr->egress_target_endpoint);
	if (!connect_success)
		return;

	kcp_ptr_egress->SetMTU(current_settings.egress->kcp_mtu);
	kcp_ptr_egress->SetWindowSize(current_settings.egress->kcp_sndwnd, current_settings.egress->kcp_rcvwnd);
	kcp_ptr_egress->NoDelay(current_settings.egress->kcp_nodelay, current_settings.egress->kcp_interval, current_settings.egress->kcp_resend, current_settings.egress->kcp_nc);
	kcp_ptr_egress->RxMinRTO() = 10;
	kcp_ptr_egress->SetBandwidth(current_settings.egress->outbound_bandwidth, current_settings.egress->inbound_bandwidth);
	std::weak_ptr weak_kcp_ptr_egress = kcp_ptr_egress;
	kcp_ptr_egress->SetOutput([this](const char *buf, int len, void *user) -> int
		{
			return kcp_sender_via_forwarder(buf, len, user);
		});
	kcp_ptr_egress->Update(time_now_for_kcp());
	kcp_ptr_egress->custom_data.store(kcp_mappings_ptr);

	kcp_mappings_ptr->ingress_kcp = kcp_ptr_ingress;
	kcp_mappings_ptr->ingress_listener.store(handshake_kcp_mappings_ptr->ingress_listener.load());
	kcp_mappings_ptr->egress_kcp = kcp_ptr_egress;
	kcp_mappings_ptr->egress_forwarder = udp_forwarder;
	if (current_settings.egress->dynamic_port_refresh == 0)
		kcp_mappings_ptr->changeport_timestamp.store(LLONG_MAX);
	else
		kcp_mappings_ptr->changeport_timestamp.store(timestamp + current_settings.egress->dynamic_port_refresh);

	std::unique_lock lock_kcp_looping{ mutex_kcp_looping };
	kcp_looping[kcp_ptr_ingress].store(kcp_ptr_ingress->Check(time_now_for_kcp()));
	kcp_looping[kcp_ptr_egress].store(kcp_ptr_egress->Check(time_now_for_kcp()));
	lock_kcp_looping.unlock();

	if (current_settings.ingress->keep_alive > 0)
	{
		std::scoped_lock locker { mutex_kcp_keepalive_ingress };
		kcp_keepalive_ingress[kcp_ptr_ingress].store(timestamp + current_settings.ingress->keep_alive);
	}

	if (current_settings.egress->keep_alive > 0)
	{
		std::scoped_lock locker { mutex_kcp_keepalive_egress };
		kcp_keepalive_egress[kcp_ptr_egress].store(timestamp + current_settings.egress->keep_alive);
	}
}

std::unique_ptr<uint8_t[]> relay_mode::kcp_sender_prepare(const char *buf, int len, const std::string &encryption_password, encryption_mode encryption, size_t &new_data_size)
{
	std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(len + BUFFER_EXPAND_SIZE);
	uint8_t *new_buffer_ptr = new_buffer.get();
	std::copy_n((const uint8_t *)buf, len, new_buffer_ptr);
	auto [error_message, cipher_size] = encrypt_data(encryption_password, encryption, new_buffer_ptr, len);
	if (!error_message.empty() || cipher_size == 0)
		return nullptr;

	new_data_size = cipher_size;
	return new_buffer;
}

//int relay_mode::kcp_sender(udp::endpoint peer, const char *buf, int len, void *user)
//{
//
//}

int relay_mode::kcp_sender_via_listener(const char *buf, int len, void *user)
{
	size_t cipher_size = 0;
	std::unique_ptr<uint8_t[]> new_buffer = kcp_sender_prepare(buf, len, current_settings.ingress->encryption_password, current_settings.ingress->encryption, cipher_size);
	if (new_buffer == nullptr)
		return 0;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;
	std::shared_lock shared_lock_ingress{kcp_mappings_ptr->mutex_ingress_endpoint};
	udp::endpoint ingress_source_endpoint = kcp_mappings_ptr->ingress_source_endpoint;
	shared_lock_ingress.unlock();
	kcp_mappings_ptr->ingress_listener.load()->async_send_out(std::move(new_buffer), cipher_size, ingress_source_endpoint);
	//((udp_server *)user)->async_send_out(std::move(new_buffer), cipher_size, peer);
	change_new_port(kcp_mappings_ptr);
	return 0;
}

int relay_mode::kcp_sender_via_forwarder(const char *buf, int len, void *user)
{
	size_t cipher_size = 0;
	std::unique_ptr<uint8_t[]> new_buffer = kcp_sender_prepare(buf, len, current_settings.egress->encryption_password, current_settings.egress->encryption, cipher_size);
	if (new_buffer == nullptr)
		return 0;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;
	kcp_mappings_ptr->egress_forwarder->async_send_out(std::move(new_buffer), cipher_size, kcp_mappings_ptr->egress_target_endpoint);
	//((forwarder *)user)->async_send_out(std::move(new_buffer), cipher_size, peer);
	change_new_port(kcp_mappings_ptr);
	return 0;
}

void relay_mode::process_disconnect(std::shared_ptr<KCP::KCP> kcp_ptr, const char *buffer, size_t len)
{
	kcp_ptr->Send(buffer, len);

	std::shared_lock lock_kcp_looping{ mutex_kcp_looping };
	if (auto iter = kcp_looping.find(kcp_ptr); iter != kcp_looping.end())
		iter->second.store(kcp_ptr->Check(time_now_for_kcp()));
	lock_kcp_looping.unlock();

	std::scoped_lock lockers{ mutex_id_map_to_both_sides };
	if (auto kcp_channels_iter = id_map_to_both_sides.find(kcp_ptr->GetConv());
		kcp_channels_iter != id_map_to_both_sides.end())
	{
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr_original = kcp_channels_iter->second;
		id_map_to_both_sides.erase(kcp_channels_iter);
		if (std::scoped_lock lockers{ mutex_expiring_kcp };
			expiring_kcp.find(kcp_mappings_ptr_original) == expiring_kcp.end())
			expiring_kcp[kcp_mappings_ptr_original] = packet::right_now();
	}
}

bool relay_mode::save_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target)
{
	if (target_address != nullptr)
	{
		uint16_t destination_port = current_settings.egress->destination_port;
		if (destination_port == 0)
			destination_port = generate_new_port_number(current_settings.egress->destination_port_start, current_settings.egress->destination_port_end);

		udp_target = udp::endpoint(*target_address, destination_port);
		return true;
	}

	return update_udp_target(target_connector, udp_target);
}

bool relay_mode::update_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target)
{
	uint16_t destination_port = current_settings.egress->destination_port;
	if (destination_port == 0)
		destination_port = generate_new_port_number(current_settings.egress->destination_port_start, current_settings.egress->destination_port_end);

	bool connect_success = false;
	asio::error_code ec;
	for (int i = 0; i <= RETRY_TIMES; ++i)
	{
		const std::string &destination_address = current_settings.egress->destination_address;

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
			std::scoped_lock locker{ mutex_egress_target_address };
			udp_target = *udp_endpoints.begin();
			target_address = std::make_unique<asio::ip::address>(udp_target.address());
			connect_success = true;
			break;
		}
	}
	return connect_success;
}

void relay_mode::save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16>& ipv6_address, uint16_t ipv6_port)
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

void relay_mode::cleanup_expiring_handshake_connections()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock locker{ mutex_expiring_handshakes, mutex_handshake_ingress_map_to_egress };
	for (auto iter = expiring_handshakes.begin(), next_iter = iter; iter != expiring_handshakes.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<KCP::KCP> kcp_ptr = iter->first.lock();
		if (kcp_ptr == nullptr)
		{
			expiring_handshakes.erase(iter);
			continue;
		}

		int64_t expire_time = iter->second;
		if (calculate_difference(time_right_now, expire_time) < CLEANUP_WAITS)
		{
			kcp_ptr->Update(time_now_for_kcp());
			continue;
		}
		expiring_handshakes.erase(iter);

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->custom_data.load();
		handshake_ingress_map_to_channels.erase(kcp_mappings_ptr->ingress_source_endpoint);
	}
}

void relay_mode::cleanup_expiring_forwarders()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock lockers{ mutex_expiring_forwarders };
	for (auto iter = expiring_forwarders.begin(), next_iter = iter; iter != expiring_forwarders.end(); iter = next_iter)
	{
		++next_iter;
		auto &[udp_forwrder, expire_time] = *iter;
		int64_t time_elapsed = calculate_difference(time_right_now, expire_time);

		if (time_elapsed <= CLEANUP_WAITS / 2)
			continue;

		if (time_elapsed > CLEANUP_WAITS / 2 && time_elapsed < CLEANUP_WAITS)
		{
			udp_forwrder->remove_callback();
			udp_forwrder->stop();
			continue;
		}

		udp_forwrder->disconnect();
		expiring_forwarders.erase(iter);
	}
}

void relay_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = packet::right_now();
	auto kcp_right_now = time_now_for_kcp();

	std::scoped_lock locker{ mutex_expiring_kcp };
	for (auto iter = expiring_kcp.begin(), next_iter = iter; iter != expiring_kcp.end(); iter = next_iter)
	{
		++next_iter;
		auto &[kcp_mappings_ptr, expire_time] = *iter;
		std::shared_ptr<KCP::KCP> ingress_kcp_ptr = kcp_mappings_ptr->ingress_kcp;
		std::shared_ptr<KCP::KCP> egress_kcp_ptr = kcp_mappings_ptr->ingress_kcp;

		if (calculate_difference(time_right_now, expire_time) < CLEANUP_WAITS)
		{
			ingress_kcp_ptr->Update(kcp_right_now);
			egress_kcp_ptr->Update(kcp_right_now);
			continue;
		}

		ingress_kcp_ptr->SetOutput(empty_kcp_output);
		egress_kcp_ptr->SetOutput(empty_kcp_output);

		{
			std::scoped_lock locker_expiring_forwarders{ mutex_expiring_forwarders };
			std::shared_ptr<forwarder> forwarder_ptr = kcp_mappings_ptr->egress_forwarder;
			forwarder_ptr->remove_callback();
			forwarder_ptr->stop();
			if (expiring_forwarders.find(forwarder_ptr) == expiring_forwarders.end())
				expiring_forwarders.insert({ forwarder_ptr, packet::right_now() });
		}

		expiring_kcp.erase(iter);
	}
}

void relay_mode::loop_update_connections()
{
	bool self_cleanup = false;
	std::shared_lock locker{ mutex_kcp_looping };
	for (auto iter = kcp_looping.begin(), next_iter = iter; iter != kcp_looping.end(); iter = next_iter)
	{
		++next_iter;
		auto &[kcp_ptr_weak, kcp_update_time] = *iter;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
		if (kcp_ptr == nullptr)
		{
			self_cleanup = true;
			continue;
		}

		if (uint32_t kcp_refresh_time = time_now_for_kcp(); kcp_refresh_time >= kcp_update_time.load())
		{
			kcp_ptr->Update(kcp_refresh_time);
			uint32_t next_refresh_time = kcp_ptr->Check(kcp_refresh_time);
			kcp_update_time.store(next_refresh_time);
		}
	}
	locker.unlock();

	if (!self_cleanup)
		return;

	std::scoped_lock locker_kcp_looping{ mutex_kcp_looping };
	for (auto iter = kcp_looping.begin(), next_iter = iter; iter != kcp_looping.end(); iter = next_iter)
	{
		++next_iter;
		auto &[kcp_ptr_weak, kcp_update_time] = *iter;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
		if (kcp_ptr == nullptr)
			kcp_looping.erase(iter);
	}
}

void relay_mode::loop_find_expires()
{
	std::scoped_lock locker{ mutex_id_map_to_both_sides };
	for (auto iter = id_map_to_both_sides.begin(), next_iter = iter; iter != id_map_to_both_sides.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t conv = iter->first;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = iter->second;
		std::shared_ptr<KCP::KCP> kcp_ptr_ingress = kcp_mappings_ptr->ingress_kcp;
		std::shared_ptr<KCP::KCP> kcp_ptr_egress = kcp_mappings_ptr->egress_kcp;

		if (kcp_ptr_ingress->SecondsSinceLastSendTime() > current_settings.egress->udp_timeout &&
			kcp_ptr_egress->SecondsSinceLastSendTime() > current_settings.egress->udp_timeout)
		{
			if (std::scoped_lock locker_expiring_kcp{ mutex_expiring_kcp }; expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
				expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() });

			if (std::scoped_lock locker_kcp_keepalive{mutex_kcp_keepalive_ingress}; kcp_keepalive_ingress.find(kcp_ptr_ingress) != kcp_keepalive_ingress.end())
				kcp_keepalive_ingress.erase(kcp_ptr_ingress);

			if (std::scoped_lock locker_kcp_keepalive{mutex_kcp_keepalive_egress}; kcp_keepalive_egress.find(kcp_ptr_egress) != kcp_keepalive_egress.end())
				kcp_keepalive_egress.erase(kcp_ptr_egress);

			{
				std::scoped_lock locker_kcp_looping{ mutex_kcp_looping };
				if (auto iter = kcp_looping.find(kcp_ptr_ingress); iter != kcp_looping.end())
					kcp_looping.erase(iter);
				if (auto iter = kcp_looping.find(kcp_ptr_egress); iter != kcp_looping.end())
					kcp_looping.erase(iter);
			}

			id_map_to_both_sides.erase(iter);
			kcp_ptr_ingress->SetOutput(empty_kcp_output);
			kcp_ptr_egress->SetOutput(empty_kcp_output);
		}
	}
}

void relay_mode::loop_keep_alive_ingress()
{
	auto timestamp_now = packet::right_now();
	std::shared_lock locker_kcp_looping{ mutex_kcp_keepalive_ingress };
	for (auto iter = kcp_keepalive_ingress.begin(), next_iter = iter; iter != kcp_keepalive_ingress.end(); iter = next_iter)
	{
		++next_iter;
		std::weak_ptr kcp_ptr_weak = iter->first;
		std::atomic<int64_t> &timestamp = iter->second;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
		if (kcp_ptr == nullptr || timestamp_now < timestamp.load())
			continue;

		if (timestamp.load() > packet::right_now())
			continue;
		timestamp += current_settings.ingress->keep_alive;

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->custom_data.load();
		protocol_type ptype = kcp_mappings_ptr->connection_protocol;
		std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_packet(ptype);
		kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());

		uint32_t next_refresh_time = kcp_ptr->Check(time_now_for_kcp());
		std::shared_lock locker_kcp_looping{ mutex_kcp_looping };
		if (auto iter = kcp_looping.find(kcp_ptr); iter != kcp_looping.end())
			iter->second.store(next_refresh_time);
		locker_kcp_looping.unlock();
	}
}

void relay_mode::loop_keep_alive_egress()
{
	auto timestamp_now = packet::right_now();
	std::shared_lock locker_kcp_looping{ mutex_kcp_keepalive_egress };
	for (auto iter = kcp_keepalive_egress.begin(), next_iter = iter; iter != kcp_keepalive_egress.end(); iter = next_iter)
	{
		++next_iter;
		std::weak_ptr kcp_ptr_weak = iter->first;
		std::atomic<int64_t> &timestamp = iter->second;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
		if (kcp_ptr == nullptr || timestamp_now < timestamp.load())
			continue;

		if (timestamp.load() > packet::right_now())
			continue;
		timestamp += current_settings.egress->keep_alive;

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->custom_data.load();
		protocol_type ptype = kcp_mappings_ptr->connection_protocol;
		std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_packet(ptype);
		kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());

		uint32_t next_refresh_time = kcp_ptr->Check(time_now_for_kcp());
		std::shared_lock locker_kcp_looping{ mutex_kcp_looping };
		if (auto iter = kcp_looping.find(kcp_ptr); iter != kcp_looping.end())
			iter->second.store(next_refresh_time);
		locker_kcp_looping.unlock();
	}
}

void relay_mode::send_stun_request(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (current_settings.ingress->stun_server.empty())
		return;

	resend_stun_8489_request(*udp_servers.begin()->second, current_settings.ingress->stun_server, stun_header.get(), current_settings.ingress->ipv4_only);

	timer_stun.expires_after(STUN_RESEND);
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}

void relay_mode::kcp_loop_updates(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_update_connections();

	timer_send_data.expires_after(KCP_UPDATE_INTERVAL);
	timer_send_data.async_wait([this](const asio::error_code &e) { kcp_loop_updates(e); });
}

void relay_mode::find_expires(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_find_expires();

	timer_find_expires.expires_after(FINDER_EXPIRES_INTERVAL);
	timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });
}

void relay_mode::expiring_kcp_loops(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	cleanup_expiring_handshake_connections();
	cleanup_expiring_forwarders();
	cleanup_expiring_data_connections();

	timer_expiring_kcp.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_kcp_loops(e); });
}

void relay_mode::keep_alive_ingress(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive_ingress();

	timer_keep_alive_ingress.expires_after(seconds{ current_settings.ingress->keep_alive });
	timer_keep_alive_ingress.async_wait([this](const asio::error_code& e) { keep_alive_ingress(e); });
}

void relay_mode::keep_alive_egress(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive_egress();

	timer_keep_alive_egress.expires_after(seconds{ current_settings.egress->keep_alive });
	timer_keep_alive_egress.async_wait([this](const asio::error_code& e) { keep_alive_egress(e); });
}
