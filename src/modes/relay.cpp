#include <climits>
#include "relay.hpp"
#include "../shares/data_operations.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;

relay_mode::~relay_mode()
{
	timer_find_expires.cancel();
	timer_expiring_kcp.cancel();
	timer_stun.cancel();
	timer_keep_alive_ingress.cancel();
	timer_keep_alive_egress.cancel();
	timer_status_log.cancel();
}

bool relay_mode::start()
{
	std::cout << app_name << " running in relay mode\n";

	auto func = std::bind(&relay_mode::udp_listener_incoming, this, _1, _2, _3, _4);

	std::set<uint16_t> listen_ports = convert_to_port_list(*current_settings.ingress);

	ip_only_options ip_only = current_settings.ingress->ip_version_only;
	udp::endpoint listen_on_ep;
	if (ip_only == ip_only_options::ipv4)
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

		if (local_address.is_v4() && ip_only == ip_only_options::not_set)
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
			connection_options conn_options = 
			{
				.ip_version_only = current_settings.ingress->ip_version_only,
				.fib_ingress = current_settings.fib_ingress,
				.fib_egress = current_settings.fib_egress
			};
			udp_servers.insert({ port_number, std::make_unique<udp_server>(io_context, sequence_task_pool_peer, task_limit, listen_on_ep, func, conn_options) });
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

		if (!current_settings.ingress->stun_server.empty())
		{
			stun_header = send_stun_8489_request(*udp_servers.begin()->second, current_settings.ingress->stun_server, ip_only);
			timer_stun.expires_after(std::chrono::seconds(1));
			timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
		}

		if (current_settings.ingress->keep_alive > 0)
		{
			timer_keep_alive_ingress.expires_after(gbv_keepalive_update_interval);
			timer_keep_alive_ingress.async_wait([this](const asio::error_code &e) { keep_alive_ingress(e); });
		}

		if (current_settings.egress->keep_alive > 0)
		{
			timer_keep_alive_egress.expires_after(gbv_keepalive_update_interval);
			timer_keep_alive_egress.async_wait([this](const asio::error_code &e) { keep_alive_egress(e); });
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
		running_well = false;
	}

	return running_well;
}

void relay_mode::udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type server_port_number)
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
		if (rfc8489::unpack_address_port(data_ptr, stun_header.get(), ipv4_address, ipv4_port, ipv6_address, ipv6_port))
		{
			save_external_ip_address(ipv4_address, ipv4_port, ipv6_address, ipv6_port);
			return;
		}
	}

	listener_status_counters.ingress_raw_traffic += data_size;

	auto [error_message, plain_size] = decrypt_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, data_ptr, (int)data_size);
	if (!error_message.empty())
		return;

	udp_listener_incoming_unpack(std::move(data), plain_size, peer, server_port_number);
}

void relay_mode::udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type server_port_number)
{
	if (data == nullptr)
		return;

	auto [packet_timestamp, data_ptr, packet_data_size] = packet::unpack(data.get(), plain_size);
	if (packet_data_size == 0)
		return;
	auto timestamp = packet::right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > gbv_time_gap_seconds)
		return;

	std::shared_ptr<kcp_mappings> kcp_mappings_ptr;
	std::shared_ptr<KCP::KCP> kcp_ptr_ingress;
	std::shared_ptr<KCP::KCP> kcp_ptr_egress;
	std::pair<std::unique_ptr<uint8_t[]>, size_t> original_data;
	uint32_t fec_sn = 0;
	uint8_t fec_sub_sn = 0;
	if (current_settings.ingress->fec_data > 0 && current_settings.ingress->fec_redundant > 0)
	{
		auto [packet_header, kcp_data_ptr, kcp_data_size] = packet::unpack_fec(data.get(), plain_size);
		fec_sn = packet_header.sn;
		fec_sub_sn = packet_header.sub_sn;
		if (packet_header.sub_sn >= current_settings.ingress->fec_data)
		{
			auto [packet_header_redundant, redundant_data_ptr, redundant_data_size] = packet::unpack_fec_redundant(data.get(), plain_size);
			std::shared_lock locker_id_map_to_both_sides{ mutex_id_map_to_both_sides };
			if (auto kcp_channels_iter = id_map_to_both_sides.find(packet_header_redundant.kcp_conv); kcp_channels_iter == id_map_to_both_sides.end())
				return;
			else
				kcp_mappings_ptr = kcp_channels_iter->second;
			locker_id_map_to_both_sides.unlock();

			if (kcp_mappings_ptr == nullptr)
				return;

			original_data.first = std::make_unique<uint8_t[]>(redundant_data_size);
			original_data.second = redundant_data_size;
			std::copy_n(redundant_data_ptr, redundant_data_size, original_data.first.get());
			kcp_mappings_ptr->fec_ingress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
			auto [recovered, restored_count] = fec_find_missings(kcp_mappings_ptr->ingress_kcp.get(), kcp_mappings_ptr->fec_egress_control, fec_sn, current_settings.ingress->fec_data);
			if (!recovered)
				return;
			listener_status_counters.fec_recovery_count += restored_count;
			data_ptr = nullptr;
			packet_data_size = 0;
		}
		else
		{
			data_ptr = kcp_data_ptr;
			packet_data_size = kcp_data_size;
			original_data.first = std::make_unique<uint8_t[]>(kcp_data_size);
			original_data.second = kcp_data_size;
			std::copy_n(kcp_data_ptr, kcp_data_size, original_data.first.get());
		}
	}

	if (data_ptr != nullptr)
	{
		uint32_t conv = KCP::KCP::GetConv(data_ptr);
		if (conv == 0)
		{
			udp_listener_incoming_new_connection(std::move(data), plain_size, peer, server_port_number);
			return;
		}

		if (kcp_mappings_ptr == nullptr)
		{
			std::shared_lock locker_id_map_to_both_sides{ mutex_id_map_to_both_sides };
			if (auto kcp_channels_iter = id_map_to_both_sides.find(conv); kcp_channels_iter == id_map_to_both_sides.end())
				return;
			else
				kcp_mappings_ptr = kcp_channels_iter->second;
			locker_id_map_to_both_sides.unlock();

			if (kcp_mappings_ptr == nullptr)
				return;
		}

		if (kcp_mappings_ptr->ingress_source_endpoint == nullptr || *kcp_mappings_ptr->ingress_source_endpoint != peer)
			kcp_mappings_ptr->ingress_source_endpoint = std::make_shared<udp::endpoint>(peer);

		kcp_ptr_ingress = kcp_mappings_ptr->ingress_kcp;
		kcp_ptr_egress = kcp_mappings_ptr->egress_kcp;

		if (current_settings.ingress->fec_data > 0 && current_settings.ingress->fec_redundant > 0)
		{
			kcp_mappings_ptr->fec_ingress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
			auto [recovered, restored_count] = fec_find_missings(kcp_ptr_ingress.get(), kcp_mappings_ptr->fec_egress_control, fec_sn, current_settings.ingress->fec_data);
			listener_status_counters.fec_recovery_count += restored_count;
		}

		kcp_ptr_ingress->Input((const char *)data_ptr, (long)packet_data_size);
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

		kcp_mappings_ptr->ingress_listener.store(udp_servers[server_port_number].get());

		auto [ftr, prtcl, unpacked_data_ptr, unpacked_data_size] = packet::unpack_inner(buffer_ptr, kcp_data_size);
		switch (ftr)
		{
		case feature::keep_alive:
		{
			std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_response_packet(prtcl);
			kcp_ptr_ingress->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());
			uint32_t next_update_time = current_settings.ingress->blast ? kcp_ptr_ingress->Refresh() : kcp_ptr_ingress->Check();
			kcp_updater.submit(kcp_ptr_ingress, next_update_time);
			break;
		}
		case feature::keep_alive_response:
			kcp_ptr_ingress->keep_alive_response_time.store(timestamp);
			break;
		case feature::raw_data:
			[[fallthrough]];
		case feature::mux_transfer:
			[[fallthrough]];
		case feature::mux_cancel:
			[[fallthrough]];
		case feature::pre_connect_custom_address:
		{
			kcp_ptr_egress->Send((const char *)buffer_ptr, kcp_data_size);

			uint32_t next_update_time = current_settings.ingress->blast ? kcp_mappings_ptr->ingress_kcp->Refresh() : kcp_mappings_ptr->ingress_kcp->Check();
			kcp_updater.submit(kcp_mappings_ptr->ingress_kcp, next_update_time);

			next_update_time = current_settings.egress->blast ? kcp_mappings_ptr->egress_kcp->Refresh() : kcp_mappings_ptr->egress_kcp->Check();
			kcp_updater.submit(kcp_mappings_ptr->egress_kcp, next_update_time);

			kcp_mappings_ptr->last_data_transfer_time.store(timestamp);
			break;
		}
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

		listener_status_counters.ingress_inner_traffic += kcp_data_size;
		forwarder_status_counters.egress_inner_traffic += kcp_data_size;
	}
}

void relay_mode::udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	auto [packet_timestamp, data_ptr, packet_data_size] = packet::unpack(data.get(), data_size);

	if (current_settings.ingress->fec_data > 0 && current_settings.ingress->fec_redundant > 0)
	{
		auto [packet_header, kcp_data_ptr, kcp_data_size] = packet::unpack_fec(data.get(), data_size);
		data_ptr = kcp_data_ptr;
		packet_data_size = kcp_data_size;
	}

	if (packet_data_size == 0)
		return;
	std::shared_lock shared_locker_handshake_channels{ mutex_handshake_ingress_map_to_channels, std::defer_lock };
	std::unique_lock unique_locker_handshake_channels{ mutex_handshake_ingress_map_to_channels, std::defer_lock };
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

			std::shared_ptr<kcp_mappings> handshake_kcp_mappings_ptr = std::make_shared<kcp_mappings>();
			handshake_ingress_map_to_channels[peer] = handshake_kcp_mappings_ptr;
			kcp_mappings *handshake_kcp_mappings = handshake_kcp_mappings_ptr.get();
			handshake_kcp_mappings->ingress_source_endpoint = std::make_shared<udp::endpoint>(peer);
			handshake_kcp_mappings->ingress_listener.store(udp_servers[port_number].get());
			if (current_settings.ingress->fec_data > 0 && current_settings.ingress->fec_redundant > 0)
			{
				size_t K = current_settings.ingress->fec_data;
				size_t N = K + current_settings.ingress->fec_redundant;
				handshake_kcp_mappings->fec_ingress_control.fecc.reset_martix(K, N);
			}

			std::shared_ptr<KCP::KCP> handshake_kcp_ingress = std::make_shared<KCP::KCP>(0);
			handshake_kcp_ingress->SetMTU(current_settings.ingress->kcp_mtu);
			handshake_kcp_ingress->NoDelay(1, 1, 3, 1);
			handshake_kcp_ingress->Update();
			handshake_kcp_ingress->RxMinRTO() = 10;
			handshake_kcp_ingress->SetBandwidth(current_settings.ingress->outbound_bandwidth, current_settings.ingress->inbound_bandwidth);
			handshake_kcp_ingress->SetOutput([this](const char *buf, int len, void *user) -> int
				{
					return kcp_sender_via_listener(buf, len, user);
				});

			if (handshake_kcp_ingress->Input((const char *)data_ptr, (long)packet_data_size) < 0)
				return;

			int buffer_size = handshake_kcp_ingress->PeekSize();
			if (buffer_size <= 0)
				return;

			int kcp_data_size = 0;
			if (kcp_data_size = handshake_kcp_ingress->Receive((char *)data_ptr, buffer_size); kcp_data_size < 0)
				return;

			auto [ftr, prtcl, unpacked_data_ptr, unpacked_data_size] = packet::unpack_inner(data_ptr, kcp_data_size);
			switch (ftr)
			{
			case feature::initialise:
			{
				std::unique_ptr<uint8_t[]> settings_data_ptr = std::make_unique<uint8_t[]>(unpacked_data_size);
				packet::convert_wrapper_byte_order(unpacked_data_ptr, settings_data_ptr.get(), unpacked_data_size);
				const packet::settings_wrapper *basic_settings_ptr = packet::get_initialise_details_from_unpacked_data(settings_data_ptr.get());
				packet::settings_wrapper basic_settings = *basic_settings_ptr;

				if (basic_settings.inbound_bandwidth > 0 && basic_settings.inbound_bandwidth > current_settings.egress->inbound_bandwidth)
					basic_settings.inbound_bandwidth = current_settings.egress->inbound_bandwidth;

				if (basic_settings.outbound_bandwidth > 0 && basic_settings.outbound_bandwidth > current_settings.egress->outbound_bandwidth)
					basic_settings.outbound_bandwidth = current_settings.egress->outbound_bandwidth;

				packet::modify_initialise_details_of_unpacked_data(unpacked_data_ptr, basic_settings);

				handshake_kcp_mappings->ingress_kcp = handshake_kcp_ingress;
				handshake_kcp_mappings->connection_protocol = prtcl;
				handshake_kcp_ingress->SetUserData(handshake_kcp_mappings);

				std::shared_ptr<KCP::KCP> handshake_kcp_egress = std::make_shared<KCP::KCP>(0);
				std::shared_ptr<forwarder> udp_forwarder = nullptr;
				try
				{
					connection_options conn_options =
					{
						.ip_version_only = current_settings.egress->ip_version_only,
						.fib_ingress = current_settings.fib_ingress,
						.fib_egress = current_settings.fib_egress
					};
					auto udp_func = std::bind(&relay_mode::udp_forwarder_incoming, this, _1, _2, _3, _4, _5);
					udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_local, task_limit, handshake_kcp_egress, udp_func, conn_options);
					if (udp_forwarder == nullptr)
					{
						expiring_handshakes[handshake_kcp_mappings_ptr] = packet::right_now();
						return;
					}
				}
				catch (std::exception &ex)
				{
					std::string error_message = time_to_string_with_square_brackets() + "Cannnot connect to destination UDP address. Error: " + ex.what() + "\n";
					std::cerr << error_message;
					print_message_to_file(error_message, current_settings.log_messages);
					expiring_handshakes[handshake_kcp_mappings_ptr] = packet::right_now();
					return;
				}
				handshake_kcp_mappings->egress_kcp = handshake_kcp_egress;
				handshake_kcp_mappings->egress_forwarder = udp_forwarder;
				handshake_kcp_mappings->changeport_timestamp.store(LLONG_MAX);
				if (current_settings.egress->fec_data > 0 && current_settings.egress->fec_redundant > 0)
				{
					size_t K = current_settings.egress->fec_data;
					size_t N = K + current_settings.egress->fec_redundant;
					handshake_kcp_mappings->fec_egress_control.fecc.reset_martix(K, N);
				}

				handshake_kcp_egress->SetUserData(handshake_kcp_mappings);
				handshake_kcp_egress->SetMTU(current_settings.egress->kcp_mtu);
				handshake_kcp_egress->NoDelay(0, 2, 0, 1);
				handshake_kcp_egress->RxMinRTO() = 10;
				handshake_kcp_egress->SetBandwidth(current_settings.egress->outbound_bandwidth, current_settings.egress->inbound_bandwidth);
				handshake_kcp_egress->Update();
				handshake_kcp_egress->SetOutput([this](const char *buf, int len, void *user) -> int
					{
						return kcp_sender_via_forwarder(buf, len, user);
					});

				bool connect_success = get_udp_target(udp_forwarder, handshake_kcp_mappings->egress_target_endpoint);
				if (current_settings.egress->ip_version_only == ip_only_options::ipv4)
					udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v4, ec);
				else
					udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v6, ec);

				udp_forwarder->async_receive();

				if (!connect_success || ec)
				{
					std::vector<uint8_t> data = packet::inform_error_packet(protocol_type::not_care, ec.message());
					handshake_kcp_ingress->Send((const char *)data.data(), data.size());

					uint32_t next_update_time = handshake_kcp_ingress->Check();
					kcp_updater.submit(handshake_kcp_ingress, next_update_time);
					
					std::scoped_lock locker{ mutex_expiring_handshakes };
					expiring_handshakes[handshake_kcp_mappings_ptr] = packet::right_now();
					return;
				}

				handshake_kcp_egress->Send((const char *)data_ptr, kcp_data_size);
				uint32_t next_update_time = handshake_kcp_ingress->Check();
				kcp_updater.submit(handshake_kcp_ingress, next_update_time);

				next_update_time = handshake_kcp_egress->Check();
				kcp_updater.submit(handshake_kcp_egress, next_update_time);
				
				std::scoped_lock locker{ mutex_expiring_handshakes };
				int64_t right_now = packet::right_now();
				expiring_handshakes[handshake_kcp_mappings_ptr] = packet::right_now();
				break;
			}
			case feature::test_connection:
			{
				std::vector<uint8_t> new_data = packet::create_test_connection_packet();
				handshake_kcp_ingress->Send((const char *)new_data.data(), (long)new_data.size());
				handshake_kcp_ingress->Update();
				uint32_t next_update_time = handshake_kcp_ingress->Check();
				kcp_updater.submit(handshake_kcp_ingress, next_update_time);

				std::scoped_lock lockers{ mutex_expiring_handshakes };
				expiring_handshakes[handshake_kcp_mappings_ptr] = packet::right_now();
				break;
			}
			default:
				break;
			}
		}
	}
	else
	{
		kcp_mappings *kcp_mappings_ptr = iter->second.get();
		std::shared_ptr<KCP::KCP> handshake_kcp_ingress = kcp_mappings_ptr->ingress_kcp;
		std::shared_ptr<KCP::KCP> handshake_kcp_egress = kcp_mappings_ptr->egress_kcp;

		int input_data = handshake_kcp_ingress->Input((const char *)data_ptr, (long)packet_data_size);

		if (input_data < 0)
			return;

		shared_locker_handshake_channels.unlock();

		int buffer_size = handshake_kcp_ingress->PeekSize();
		if (buffer_size <= 0)
			return;

		int kcp_data_size = 0;
		if (kcp_data_size = handshake_kcp_ingress->Receive((char *)data_ptr, buffer_size); kcp_data_size < 0)
			return;

		auto [ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack_inner(data_ptr, kcp_data_size);
		handshake_kcp_egress->Send((const char *)data_ptr, kcp_data_size);
	}
}

void relay_mode::udp_forwarder_incoming(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (data == nullptr || data_size == 0 || kcp_ptr == nullptr)
		return;

	forwarder_status_counters.ingress_raw_traffic += data_size;

	uint8_t *data_ptr = data.get();
	auto [error_message, plain_size] = decrypt_data(current_settings.egress->encryption_password, current_settings.egress->encryption, data_ptr, (int)data_size);

	if (!error_message.empty())
		return;

	udp_forwarder_incoming_unpack(kcp_ptr, std::move(data), plain_size, peer, local_port_number);
}

void relay_mode::udp_forwarder_incoming_unpack(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	auto [packet_timestamp, data_ptr, packet_data_size] = packet::unpack(data.get(), plain_size);
	auto timestamp = packet::right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > gbv_time_gap_seconds)
		return;

	uint32_t conv = 0;
	kcp_mappings *kcp_mappings_ptr = nullptr;
	std::pair<std::unique_ptr<uint8_t[]>, size_t> original_data;
	uint32_t fec_sn = 0;
	uint8_t fec_sub_sn = 0;
	if (current_settings.egress->fec_data > 0 && current_settings.egress->fec_redundant > 0)
	{
		auto [packet_header, kcp_data_ptr, kcp_data_size] = packet::unpack_fec(data.get(), plain_size);
		fec_sn = packet_header.sn;
		fec_sub_sn = packet_header.sub_sn;
		if (packet_header.sub_sn >= current_settings.egress->fec_data)
		{
			auto [packet_header_redundant, redundant_data_ptr, redundant_data_size] = packet::unpack_fec_redundant(data.get(), plain_size);
			kcp_ptr = verify_kcp_conv(kcp_ptr, packet_header_redundant.kcp_conv, peer);
			kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
			if (kcp_mappings_ptr == nullptr)
				return;
			original_data.first = std::make_unique<uint8_t[]>(redundant_data_size);
			original_data.second = redundant_data_size;
			std::copy_n(redundant_data_ptr, redundant_data_size, original_data.first.get());
			kcp_mappings_ptr->fec_egress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
			auto [recovered, restored_count] = fec_find_missings(kcp_ptr.get(), kcp_mappings_ptr->fec_egress_control, fec_sn, current_settings.egress->fec_data);
			forwarder_status_counters.fec_recovery_count += restored_count;
			data_ptr = nullptr;
			packet_data_size = 0;
		}
		else
		{
			data_ptr = kcp_data_ptr;
			packet_data_size = kcp_data_size;
			original_data.first = std::make_unique<uint8_t[]>(kcp_data_size);
			original_data.second = kcp_data_size;
			std::copy_n(kcp_data_ptr, kcp_data_size, original_data.first.get());
	
			conv = KCP::KCP::GetConv(data_ptr);
			kcp_ptr = verify_kcp_conv(kcp_ptr, conv, peer);
			kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
			if (kcp_mappings_ptr == nullptr)
				return;
			kcp_mappings_ptr->fec_egress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
			auto [recovered, restored_count] = fec_find_missings(kcp_ptr.get(), kcp_mappings_ptr->fec_egress_control, fec_sn, current_settings.egress->fec_data);
			forwarder_status_counters.fec_recovery_count += restored_count;
		}
	}
	else
	{
		conv = KCP::KCP::GetConv(data_ptr);
		kcp_ptr = verify_kcp_conv(kcp_ptr, conv, peer);
		kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
		if (kcp_mappings_ptr == nullptr)
			return;
	}

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

		auto [ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack_inner(buffer_ptr, kcp_data_size);
		switch (ftr)
		{
		case feature::initialise:
		{
			if (conv == 0)
			{
				std::unique_ptr<uint8_t[]> settings_data_ptr = std::make_unique<uint8_t[]>(unbacked_data_size);
				packet::convert_wrapper_byte_order(unbacked_data_ptr, settings_data_ptr.get(), unbacked_data_size);
				const packet::settings_wrapper *basic_settings_ptr = packet::get_initialise_details_from_unpacked_data(settings_data_ptr.get());
				packet::settings_wrapper basic_settings = *basic_settings_ptr;
				if (basic_settings.port_start != 0 && basic_settings.port_end != 0)
				{
					if (current_settings.egress->destination_port_start != basic_settings.port_start)
						current_settings.egress->destination_port_start = basic_settings.port_end;

					if (current_settings.egress->destination_port_end != basic_settings.port_start)
						current_settings.egress->destination_port_end = basic_settings.port_end;
				}
				basic_settings.port_start = current_settings.ingress->destination_port_start;
				basic_settings.port_end = current_settings.ingress->destination_port_end;

				if (basic_settings.inbound_bandwidth > 0 && basic_settings.inbound_bandwidth > current_settings.ingress->inbound_bandwidth)
					basic_settings.inbound_bandwidth = current_settings.ingress->inbound_bandwidth;

				if (basic_settings.outbound_bandwidth > 0 && basic_settings.outbound_bandwidth > current_settings.ingress->outbound_bandwidth)
					basic_settings.outbound_bandwidth = current_settings.ingress->outbound_bandwidth;

				packet::modify_initialise_details_of_unpacked_data(unbacked_data_ptr, basic_settings);
				create_kcp_bidirections(basic_settings.uid, kcp_mappings_ptr);
			}

			kcp_mappings_ptr->ingress_kcp->Send((const char *)buffer_ptr, kcp_data_size);
			uint32_t next_update_time = current_settings.ingress->blast ? kcp_mappings_ptr->ingress_kcp->Refresh() : kcp_mappings_ptr->ingress_kcp->Check();
			kcp_updater.submit(kcp_mappings_ptr->ingress_kcp, next_update_time);
			kcp_mappings_ptr->last_data_transfer_time.store(packet::right_now());
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
		{
			kcp_ptr->Send((const char *)buffer_ptr, kcp_data_size);
			uint32_t next_update_time = current_settings.ingress->blast ? kcp_ptr->Refresh() : kcp_ptr->Check();
			kcp_updater.submit(kcp_ptr, next_update_time);
			break;
		}
		case feature::keep_alive_response:
			kcp_ptr->keep_alive_response_time.store(timestamp);
			break;
		case feature::raw_data:
			[[fallthrough]];
		case feature::mux_transfer:
			[[fallthrough]];
		case feature::mux_cancel:
			[[fallthrough]];
		case feature::pre_connect_custom_address:
		{
			kcp_mappings_ptr->ingress_kcp->Send((const char *)buffer_ptr, kcp_data_size);

			uint32_t next_update_time = current_settings.ingress->blast ? kcp_mappings_ptr->ingress_kcp->Refresh() : kcp_mappings_ptr->ingress_kcp->Check();
			kcp_updater.submit(kcp_mappings_ptr->ingress_kcp, next_update_time);

			next_update_time = current_settings.egress->blast ? kcp_mappings_ptr->egress_kcp->Refresh() : kcp_mappings_ptr->egress_kcp->Check();
			kcp_updater.submit(kcp_mappings_ptr->egress_kcp, next_update_time);

			kcp_mappings_ptr->last_data_transfer_time.store(packet::right_now());

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

		forwarder_status_counters.ingress_inner_traffic += kcp_data_size;
		listener_status_counters.egress_inner_traffic += kcp_data_size;
	}
}

void relay_mode::change_new_port(kcp_mappings *kcp_mappings_ptr)
{
	auto timestamp = packet::right_now();
	if (kcp_mappings_ptr->changeport_timestamp.load() > timestamp)
		return;
	kcp_mappings_ptr->changeport_timestamp.store(LLONG_MAX);

	if (kcp_mappings_ptr->changeport_available.load())
		switch_new_port(kcp_mappings_ptr);
	else if (kcp_mappings_ptr->changeport_testing_ptr.expired())
		test_before_change(kcp_mappings_ptr);
}

void relay_mode::test_before_change(kcp_mappings * kcp_mappings_ptr)
{
	std::shared_ptr<kcp_mappings> hs = create_test_handshake();
	if (hs == nullptr)
	{
		kcp_mappings_ptr->changeport_timestamp.store(packet::right_now() + current_settings.dynamic_port_refresh);
		return;
	}

	hs->egress_kcp->Update();
	uint32_t next_update_time = hs->egress_kcp->Refresh();
	kcp_updater.submit(hs->egress_kcp, next_update_time);

	kcp_mappings_ptr->changeport_testing_ptr = hs;
	std::weak_ptr<kcp_mappings> kcp_mappings_weak = kcp_mappings_ptr->self_share();
	hs->changeport_testing_ptr = kcp_mappings_weak;
	hs->mapping_function = [hs]()
		{
			std::shared_ptr<kcp_mappings> kcp_mappings_ptr = hs->changeport_testing_ptr.lock();
			if (kcp_mappings_ptr == nullptr) return;
			kcp_mappings_ptr->changeport_available.store(true);
			kcp_mappings_ptr->changeport_timestamp.store(packet::right_now());
		};
}

void relay_mode::switch_new_port(kcp_mappings * kcp_mappings_ptr)
{
	std::shared_ptr<KCP::KCP> kcp_ptr_egress = kcp_mappings_ptr->egress_kcp;


	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	try
	{
		connection_options conn_options =
		{
			.ip_version_only = current_settings.egress->ip_version_only,
			.fib_ingress = current_settings.fib_ingress,
			.fib_egress = current_settings.fib_egress
		};
		auto udp_func = std::bind(&relay_mode::udp_forwarder_incoming, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_local, task_limit, kcp_ptr_egress, udp_func, conn_options);
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

	uint16_t destination_port_start = current_settings.egress->destination_port_start;
	uint16_t destination_port_end = current_settings.egress->destination_port_end;
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
		std::shared_lock locker{ mutex_egress_target_address };
		asio::ip::address temp_address = *target_address;
		locker.unlock();
		std::scoped_lock locker_egress{ kcp_mappings_ptr->mutex_egress_endpoint };
		kcp_mappings_ptr->egress_target_endpoint.address(temp_address);
		kcp_mappings_ptr->egress_target_endpoint.port(new_port_numer);
	}

	asio::error_code ec;
	if (current_settings.egress->ip_version_only == ip_only_options::ipv4)
		udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v6, ec);

	if (ec)
		return;

	udp_forwarder->async_receive();

	std::shared_ptr<forwarder> old_forwarder = kcp_mappings_ptr->egress_forwarder;
	kcp_mappings_ptr->egress_forwarder = udp_forwarder;

	std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
	expiring_forwarders.insert({ old_forwarder, packet::right_now()});
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
	kcp_mappings_ptr->last_data_transfer_time.store(timestamp);
	if (current_settings.ingress->fec_data > 0 && current_settings.ingress->fec_redundant > 0)
	{
		size_t K = current_settings.ingress->fec_data;
		size_t N = K + current_settings.ingress->fec_redundant;
		kcp_mappings_ptr->fec_ingress_control.fecc.reset_martix(K, N);
	}

	if (current_settings.egress->fec_data > 0 && current_settings.egress->fec_redundant > 0)
	{
		size_t K = current_settings.egress->fec_data;
		size_t N = K + current_settings.egress->fec_redundant;
		kcp_mappings_ptr->fec_egress_control.fecc.reset_martix(K, N);
	}

	std::shared_ptr<KCP::KCP> kcp_ptr_ingress = std::make_shared<KCP::KCP>(new_id);
	kcp_ptr_ingress->SetMTU(current_settings.ingress->kcp_mtu);
	kcp_ptr_ingress->SetWindowSize(current_settings.ingress->kcp_sndwnd, current_settings.ingress->kcp_rcvwnd);
	kcp_ptr_ingress->NoDelay(current_settings.ingress->kcp_nodelay, current_settings.ingress->kcp_interval, current_settings.ingress->kcp_resend, current_settings.ingress->kcp_nc);
	kcp_ptr_ingress->Update();
	kcp_ptr_ingress->RxMinRTO() = 10;
	kcp_ptr_ingress->SetBandwidth(current_settings.ingress->outbound_bandwidth, current_settings.ingress->inbound_bandwidth);
	kcp_ptr_ingress->SetOutput([this](const char *buf, int len, void *user) -> int
		{
			return kcp_sender_via_listener(buf, len, user);
		});
	kcp_ptr_ingress->SetUserData(kcp_mappings_ptr);
	kcp_ptr_ingress->keep_alive_send_time.store(timestamp);
	kcp_ptr_ingress->keep_alive_response_time.store(timestamp);

	std::shared_ptr<KCP::KCP> kcp_ptr_egress = std::make_shared<KCP::KCP>(new_id);
	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	try
	{
		connection_options conn_options =
		{
			.ip_version_only = current_settings.egress->ip_version_only,
			.fib_ingress = current_settings.fib_ingress,
			.fib_egress = current_settings.fib_egress
		};
		auto udp_func = std::bind(&relay_mode::udp_forwarder_incoming, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, kcp_ptr_egress, udp_func, conn_options);
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

	if (current_settings.egress->ip_version_only == ip_only_options::ipv4)
		udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.egress->kcp_mtu), local_empty_target_v6, ec);

	if (ec)
		return;

	udp_forwarder->async_receive();
	bool connect_success = get_udp_target(udp_forwarder, kcp_mappings_ptr->egress_target_endpoint);
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
	kcp_ptr_egress->Update();
	kcp_ptr_egress->SetUserData(kcp_mappings_ptr);
	kcp_ptr_ingress->keep_alive_send_time.store(timestamp);
	kcp_ptr_ingress->keep_alive_response_time.store(timestamp);

	kcp_mappings_ptr->ingress_kcp = kcp_ptr_ingress;
	kcp_mappings_ptr->ingress_listener.store(handshake_kcp_mappings_ptr->ingress_listener.load());
	kcp_mappings_ptr->egress_kcp = kcp_ptr_egress;
	kcp_mappings_ptr->egress_forwarder = udp_forwarder;
	if (current_settings.egress->dynamic_port_refresh == 0)
		kcp_mappings_ptr->changeport_timestamp.store(LLONG_MAX);
	else
		kcp_mappings_ptr->changeport_timestamp.store(timestamp + current_settings.egress->dynamic_port_refresh);

	kcp_mappings_ptr->ingress_kcp->Update();
	uint32_t next_update_time = kcp_mappings_ptr->ingress_kcp->Check();
	kcp_updater.submit(kcp_mappings_ptr->ingress_kcp, next_update_time);

	kcp_mappings_ptr->egress_kcp->Update();
	next_update_time = kcp_mappings_ptr->egress_kcp->Check();
	kcp_updater.submit(kcp_mappings_ptr->egress_kcp, next_update_time);

	if (current_settings.ingress->keep_alive > 0)
	{
		std::scoped_lock locker { mutex_kcp_keepalive_ingress };
		kcp_keepalive_ingress[kcp_ptr_ingress].store(timestamp);
	}

	if (current_settings.egress->keep_alive > 0)
	{
		std::scoped_lock locker { mutex_kcp_keepalive_egress };
		kcp_keepalive_egress[kcp_ptr_egress].store(timestamp);
	}

	std::weak_ptr hs_ingress_weak = handshake_kcp_mappings_ptr->ingress_kcp;
	std::weak_ptr hs_egress_weak = handshake_kcp_mappings_ptr->egress_kcp;
	std::weak_ptr data_ingress_weak = kcp_ptr_ingress;
	std::weak_ptr data_egress_weak = kcp_ptr_egress;
	handshake_kcp_mappings_ptr->mapping_function = [hs_ingress_weak, hs_egress_weak, data_ingress_weak, data_egress_weak]()
	{
		std::shared_ptr hs_ingress_ptr = hs_ingress_weak.lock();
		std::shared_ptr hs_egress_ptr = hs_egress_weak.lock();
		std::shared_ptr data_ingress_ptr = data_ingress_weak.lock();
		std::shared_ptr data_egress_ptr = data_egress_weak.lock();
		if (hs_ingress_ptr != nullptr && data_ingress_ptr != nullptr)
			data_ingress_ptr->ResetWindowValues(hs_ingress_ptr->GetRxSRTT());
		if (hs_egress_ptr != nullptr && data_egress_ptr != nullptr)
			data_egress_ptr->ResetWindowValues(hs_egress_ptr->GetRxSRTT());
	};
}

std::shared_ptr<kcp_mappings> relay_mode::create_test_handshake()
{
	std::shared_ptr<KCP::KCP> handshake_kcp = std::make_shared<KCP::KCP>();
	std::shared_ptr<kcp_mappings> handshake_kcp_mappings = std::make_shared<kcp_mappings>();
	handshake_kcp->SetUserData(handshake_kcp_mappings.get());
	handshake_kcp_mappings->egress_kcp = handshake_kcp;
	handshake_kcp_mappings->connection_protocol = protocol_type::not_care;
	handshake_kcp_mappings->changeport_timestamp.store(LLONG_MAX);
	handshake_kcp_mappings->handshake_setup_time.store(packet::right_now());

	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	try
	{
		connection_options conn_options =
		{
			.ip_version_only = current_settings.egress->ip_version_only,
			.fib_ingress = current_settings.fib_ingress,
			.fib_egress = current_settings.fib_egress
		};
		auto udp_func = std::bind(&relay_mode::handle_test_handshake, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, handshake_kcp, udp_func, conn_options);
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
			return kcp_sender_via_forwarder(buf, len, user);
		});

	asio::error_code ec;
	if (current_settings.ip_version_only == ip_only_options::ipv4)
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		udp_forwarder->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);
	udp_forwarder->async_receive();

	std::vector<uint8_t> handshake_data = packet::create_test_connection_packet();
	if (handshake_kcp->Send((const char *)handshake_data.data(), handshake_data.size()) < 0)
		return nullptr;

	handshake_kcp->Update();

	return handshake_kcp_mappings;
}

void relay_mode::handle_test_handshake(std::shared_ptr<KCP::KCP> kcp_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
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
		case feature::test_connection:
		{
			std::shared_ptr<kcp_mappings> kcp_mapping_share = kcp_mappings_ptr->self_share();
			std::scoped_lock lock_handshake{ mutex_expiring_forwarders };
			kcp_mappings_ptr->mapping_function();
			kcp_mappings_ptr->mapping_function = []() {};
			expiring_forwarders[kcp_mappings_ptr->egress_forwarder] = packet::right_now();
			kcp_mappings_ptr->egress_forwarder->stop();
			kcp_mappings_ptr->egress_forwarder = nullptr;
			break;
		}
		default:
			break;
		}
	}
}

bool relay_mode::handshake_timeout_detection(kcp_mappings *kcp_mappings_ptr)
{
	if (kcp_mappings_ptr == nullptr)
		return true;

	int64_t right_now = packet::right_now();
	int64_t time_diff = calculate_difference(kcp_mappings_ptr->handshake_setup_time.load(), right_now);
	if (time_diff < gbv_handshake_timeout)
		return false;

	protocol_type connection_protocol = kcp_mappings_ptr->connection_protocol;
	std::shared_ptr<kcp_mappings> new_kcp_mappings_ptr;
	if (connection_protocol != protocol_type::not_care)
		return false;

	new_kcp_mappings_ptr = create_test_handshake();
	if (std::shared_ptr<kcp_mappings> main_kcp_mappings_ptr = kcp_mappings_ptr->changeport_testing_ptr.lock();
		main_kcp_mappings_ptr == nullptr)
		return false;
	else
		main_kcp_mappings_ptr->changeport_testing_ptr = new_kcp_mappings_ptr;
	new_kcp_mappings_ptr->changeport_testing_ptr = kcp_mappings_ptr->changeport_testing_ptr;
	new_kcp_mappings_ptr->mapping_function = [new_kcp_mappings_ptr]()
		{
			std::shared_ptr<kcp_mappings> kcp_mappings_ptr = new_kcp_mappings_ptr->changeport_testing_ptr.lock();
			if (kcp_mappings_ptr == nullptr) return;
			kcp_mappings_ptr->changeport_available.store(true);
			kcp_mappings_ptr->changeport_timestamp.store(packet::right_now());
		};
	
	std::shared_ptr<kcp_mappings> kcp_mappings_share = kcp_mappings_ptr->self_share();
	kcp_mappings_ptr->egress_forwarder->stop();
	kcp_mappings_ptr->mapping_function = []() {};
	auto func = [this, kcp_mappings_share]()
		{
			std::unique_lock locker{ mutex_expiring_forwarders };
			if (auto iter = expiring_forwarders.find(kcp_mappings_share->egress_forwarder); iter == expiring_forwarders.end())
				expiring_forwarders.insert({ kcp_mappings_share->egress_forwarder, packet::right_now()});
			locker.unlock();

			kcp_mappings_share->egress_kcp->SetUserData(nullptr);
			kcp_updater.remove(kcp_mappings_share->egress_kcp);
		};
	sequence_task_pool_local.push_task((size_t)kcp_mappings_ptr, func);

	return true;
}

int relay_mode::kcp_sender_via_listener(const char *buf, int len, void *user)
{
	if (user == nullptr)
		return 0;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;
	if (kcp_mappings_ptr->ingress_source_endpoint == nullptr)
		return 0;

	if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
	{
		int buffer_size = 0;
		std::unique_ptr<uint8_t[]> new_buffer = packet::create_packet((const uint8_t *)buf, len, buffer_size);
		data_sender_via_listener(kcp_mappings_ptr, std::move(new_buffer), buffer_size);
	}
	else
	{
		fec_maker_via_listener(kcp_mappings_ptr, (const uint8_t *)buf, len);
	}
	return 0;
}

int relay_mode::kcp_sender_via_forwarder(const char *buf, int len, void *user)
{
	if (user == nullptr)
		return 0;
	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;

	if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
	{
		int buffer_size = 0;
		std::unique_ptr<uint8_t[]> new_buffer = packet::create_packet((const uint8_t *)buf, len, buffer_size);
		data_sender_via_forwarder(kcp_mappings_ptr, std::move(new_buffer), buffer_size);
	}
	else
	{
		fec_maker_via_forwarder(kcp_mappings_ptr, (const uint8_t *)buf, len);
	}
	return 0;
}

std::shared_ptr<KCP::KCP> relay_mode::verify_kcp_conv(std::shared_ptr<KCP::KCP> kcp_ptr, uint32_t conv, const udp::endpoint & peer)
{
	if (kcp_ptr->GetConv() != conv)
	{
		std::shared_lock locker_kcp_channels{ mutex_id_map_to_both_sides };
		auto iter = id_map_to_both_sides.find(conv);
		if (iter == id_map_to_both_sides.end())
		{
			locker_kcp_channels.unlock();
			std::string error_message = time_to_string_with_square_brackets() +
				"UDP<->KCP, conv is not the same as record : conv = " + std::to_string(conv) +
				", local kcp : " + std::to_string(kcp_ptr->GetConv()) + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			return kcp_ptr;
		}
		kcp_ptr = iter->second->egress_kcp;
	}
	return kcp_ptr;
}

void relay_mode::data_sender_via_listener(kcp_mappings * kcp_mappings_ptr, std::unique_ptr<uint8_t[]> new_buffer, size_t buffer_size)
{
	if (kcp_data_sender != nullptr)
	{
		auto func = [this, kcp_mappings_ptr, buffer_size](std::unique_ptr<uint8_t[]> new_buffer)
			{
				auto [error_message, cipher_size] = encrypt_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, new_buffer.get(), (int)buffer_size);
				if (!error_message.empty() || cipher_size == 0)
					return;
				std::shared_ptr<udp::endpoint> ingress_source_endpoint = kcp_mappings_ptr->ingress_source_endpoint;
				kcp_mappings_ptr->ingress_listener.load()->async_send_out(std::move(new_buffer), cipher_size, *ingress_source_endpoint);
				change_new_port(kcp_mappings_ptr);
				listener_status_counters.egress_raw_traffic += buffer_size;
			};
		kcp_data_sender->push_task((size_t)kcp_mappings_ptr->ingress_kcp.get(), func, std::move(new_buffer));
		return;
	}

	auto [error_message, cipher_size] = encrypt_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, new_buffer.get(), (int)buffer_size);
	if (!error_message.empty() || cipher_size == 0)
		return;
	std::shared_ptr<udp::endpoint> ingress_source_endpoint = kcp_mappings_ptr->ingress_source_endpoint;
	kcp_mappings_ptr->ingress_listener.load()->async_send_out(std::move(new_buffer), cipher_size, *ingress_source_endpoint);
	change_new_port(kcp_mappings_ptr);
	listener_status_counters.egress_raw_traffic += buffer_size;
}

void relay_mode::data_sender_via_forwarder(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> new_buffer, size_t buffer_size)
{
	if (kcp_data_sender != nullptr)
	{
		auto func = [this, kcp_mappings_ptr, buffer_size](std::unique_ptr<uint8_t[]> new_buffer)
			{
				auto [error_message, cipher_size] = encrypt_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, new_buffer.get(), (int)buffer_size);
				if (kcp_mappings_ptr->egress_forwarder == nullptr || !error_message.empty() || cipher_size == 0)
					return;
				std::shared_lock locker{ kcp_mappings_ptr->mutex_egress_endpoint };
				udp::endpoint peer = kcp_mappings_ptr->egress_target_endpoint;
				locker.unlock();

				kcp_mappings_ptr->egress_forwarder->async_send_out(std::move(new_buffer), cipher_size, peer);
				change_new_port(kcp_mappings_ptr);
				forwarder_status_counters.egress_raw_traffic += buffer_size;
			};
		kcp_data_sender->push_task((size_t)kcp_mappings_ptr->egress_kcp.get(), func, std::move(new_buffer));
		return;
	}

	auto [error_message, cipher_size] = encrypt_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, new_buffer.get(), (int)buffer_size);
	if (kcp_mappings_ptr->egress_forwarder == nullptr || !error_message.empty() || cipher_size == 0)
		return;
	std::shared_lock locker{ kcp_mappings_ptr->mutex_egress_endpoint };
	udp::endpoint peer = kcp_mappings_ptr->egress_target_endpoint;
	locker.unlock();

	kcp_mappings_ptr->egress_forwarder->async_send_out(std::move(new_buffer), cipher_size, peer);
	change_new_port(kcp_mappings_ptr);
	forwarder_status_counters.egress_raw_traffic += buffer_size;
}

std::pair<bool, size_t> relay_mode::fec_find_missings(KCP::KCP *kcp_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count)
{
	bool recovered = false;
	size_t restored_count = 0;
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
			restored_count++;
		}

		fec_controllor.fec_rcv_restored.insert(sn);
		recovered = true;
	}
	return { recovered, restored_count };
}

void relay_mode::fec_maker_via_listener(kcp_mappings *kcp_mappings_ptr, const uint8_t *input_data, int data_size)
{
	fec_control_data &fec_controllor = kcp_mappings_ptr->fec_egress_control;

	int conv = kcp_mappings_ptr->ingress_kcp->GetConv();
	int fec_data_buffer_size = 0;
	std::unique_ptr<uint8_t[]> fec_data_buffer = packet::create_fec_data_packet(input_data, data_size, fec_data_buffer_size,
		fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
	data_sender_via_listener(kcp_mappings_ptr, std::move(fec_data_buffer), fec_data_buffer_size);

	if (conv == 0)
	{
		fec_controllor.fec_snd_sub_sn.store(0);
		return;
	}

	fec_controllor.fec_snd_cache.emplace_back(clone_into_pair(input_data, data_size));

	if (fec_controllor.fec_snd_cache.size() == current_settings.ingress->fec_data)
	{
		auto [array_data, fec_align_length, total_size] = compact_into_container(fec_controllor.fec_snd_cache);
		auto redundants = fec_controllor.fecc.encode(array_data.get(), total_size, fec_align_length);
		for (auto &data_ptr : redundants)
		{
			int fec_redundant_buffer_size = 0;
			auto fec_redundant_buffer = packet::create_fec_redundant_packet(data_ptr.get(), (int)fec_align_length,
				fec_redundant_buffer_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++, conv);
			data_sender_via_listener(kcp_mappings_ptr, std::move(fec_redundant_buffer), fec_redundant_buffer_size);
		}
		fec_controllor.fec_snd_cache.clear();
		fec_controllor.fec_snd_sub_sn.store(0);
		fec_controllor.fec_snd_sn++;
	}
}

void relay_mode::fec_maker_via_forwarder(kcp_mappings *kcp_mappings_ptr, const uint8_t *input_data, int data_size)
{
	fec_control_data &fec_controllor = kcp_mappings_ptr->fec_egress_control;

	int conv = kcp_mappings_ptr->egress_kcp->GetConv();
	int fec_data_buffer_size = 0;
	std::unique_ptr<uint8_t[]> fec_data_buffer = packet::create_fec_data_packet(input_data, data_size, fec_data_buffer_size,
		fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
	data_sender_via_forwarder(kcp_mappings_ptr, std::move(fec_data_buffer), fec_data_buffer_size);

	if (conv == 0)
	{
		fec_controllor.fec_snd_sub_sn.store(0);
		return;
	}

	fec_controllor.fec_snd_cache.emplace_back(clone_into_pair(input_data, data_size));

	if (fec_controllor.fec_snd_cache.size() == current_settings.egress->fec_data)
	{
		auto [array_data, fec_align_length, total_size] = compact_into_container(fec_controllor.fec_snd_cache);
		auto redundants = fec_controllor.fecc.encode(array_data.get(), total_size, fec_align_length);
		for (auto &data_ptr : redundants)
		{
			int fec_redundant_buffer_size = 0;
			auto fec_redundant_buffer = packet::create_fec_redundant_packet(data_ptr.get(), (int)fec_align_length,
				fec_redundant_buffer_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++, conv);
			data_sender_via_forwarder(kcp_mappings_ptr, std::move(fec_redundant_buffer), fec_redundant_buffer_size);
		}
		fec_controllor.fec_snd_cache.clear();
		fec_controllor.fec_snd_sub_sn.store(0);
		fec_controllor.fec_snd_sn++;
	}
}

void relay_mode::process_disconnect(std::shared_ptr<KCP::KCP> kcp_ptr, const char *buffer, size_t len)
{
	kcp_ptr->Send(buffer, len);
	uint32_t next_update_time = kcp_ptr->Refresh();
	kcp_updater.submit(kcp_ptr, next_update_time);

	std::unique_lock locker_id_map_to_both_sides{ mutex_id_map_to_both_sides };
	if (auto kcp_channels_iter = id_map_to_both_sides.find(kcp_ptr->GetConv());
		kcp_channels_iter != id_map_to_both_sides.end())
	{
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr_original = kcp_channels_iter->second;
		locker_id_map_to_both_sides.unlock();
		if (std::scoped_lock lockers{ mutex_expiring_kcp };
			expiring_kcp.find(kcp_mappings_ptr_original) == expiring_kcp.end())
			expiring_kcp[kcp_mappings_ptr_original] = packet::right_now() + gbv_keepalive_timeout;
	}
}

bool relay_mode::get_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target)
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
	for (int i = 0; i <= gbv_retry_times; ++i)
	{
		const std::string &destination_address = current_settings.egress->destination_address;

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

	std::scoped_lock locker{ mutex_expiring_handshakes, mutex_handshake_ingress_map_to_channels };
	for (auto iter = expiring_handshakes.begin(), next_iter = iter; iter != expiring_handshakes.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<kcp_mappings> handshakes_kcp_mappings_ptr = iter->first.lock();
		if (handshakes_kcp_mappings_ptr == nullptr)
		{
			expiring_handshakes.erase(iter);
			continue;
		}

		int64_t expire_time = iter->second;
		if (time_right_now - expire_time < gbv_kcp_cleanup_waits)
			continue;

		if (handshakes_kcp_mappings_ptr->egress_forwarder != nullptr)
		{
			handshakes_kcp_mappings_ptr->egress_forwarder->remove_callback();
			handshakes_kcp_mappings_ptr->egress_forwarder->stop();
			handshakes_kcp_mappings_ptr->egress_forwarder->disconnect();
		}
		
		handshakes_kcp_mappings_ptr->mapping_function();
		handshakes_kcp_mappings_ptr->ingress_kcp->SetOutput(empty_kcp_output);
		handshakes_kcp_mappings_ptr->ingress_kcp->SetPostUpdate(empty_kcp_postupdate);
		handshakes_kcp_mappings_ptr->ingress_kcp->SetUserData(nullptr);
		handshakes_kcp_mappings_ptr->egress_kcp->SetOutput(empty_kcp_output);
		handshakes_kcp_mappings_ptr->egress_kcp->SetPostUpdate(empty_kcp_postupdate);
		handshakes_kcp_mappings_ptr->egress_kcp->SetUserData(nullptr);
		kcp_updater.remove(handshakes_kcp_mappings_ptr->ingress_kcp);
		kcp_updater.remove(handshakes_kcp_mappings_ptr->egress_kcp);
		handshake_ingress_map_to_channels.erase(*handshakes_kcp_mappings_ptr->ingress_source_endpoint);
		expiring_handshakes.erase(iter);
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

		if (time_elapsed > gbv_receiver_cleanup_waits / 2 &&
			udp_forwrder != nullptr)
		{
			udp_forwrder->remove_callback();
			udp_forwrder->stop();
		}

		if (time_elapsed <= gbv_receiver_cleanup_waits)
			continue;

		expiring_forwarders.erase(iter);
	}
}

void relay_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock locker{ mutex_expiring_kcp, mutex_id_map_to_both_sides };
	for (auto iter = expiring_kcp.begin(), next_iter = iter; iter != expiring_kcp.end(); iter = next_iter)
	{
		++next_iter;
		auto &[kcp_mappings_ptr, expire_time] = *iter;
		std::shared_ptr<KCP::KCP> ingress_kcp_ptr = kcp_mappings_ptr->ingress_kcp;
		std::shared_ptr<KCP::KCP> egress_kcp_ptr = kcp_mappings_ptr->ingress_kcp;
		uint32_t ingress_conv = ingress_kcp_ptr->GetConv();
		uint32_t egress_conv = egress_kcp_ptr->GetConv();

		if (time_right_now - expire_time < gbv_kcp_cleanup_waits)
			continue;

		ingress_kcp_ptr->SetOutput(empty_kcp_output);
		ingress_kcp_ptr->SetPostUpdate(empty_kcp_postupdate);
		ingress_kcp_ptr->SetUserData(nullptr);
		egress_kcp_ptr->SetOutput(empty_kcp_output);
		egress_kcp_ptr->SetPostUpdate(empty_kcp_postupdate);
		egress_kcp_ptr->SetUserData(nullptr);

		{
			std::scoped_lock locker_expiring_forwarders{ mutex_expiring_forwarders };
			std::shared_ptr<forwarder> forwarder_ptr = kcp_mappings_ptr->egress_forwarder;
			forwarder_ptr->remove_callback();
			forwarder_ptr->stop();
			if (expiring_forwarders.find(forwarder_ptr) == expiring_forwarders.end())
				expiring_forwarders.insert({ forwarder_ptr, packet::right_now() });
		}

		kcp_updater.remove(ingress_kcp_ptr);
		kcp_updater.remove(egress_kcp_ptr);

		expiring_kcp.erase(iter);

		if (auto kcp_channels_iter = id_map_to_both_sides.find(ingress_conv);
			kcp_channels_iter != id_map_to_both_sides.end())
			id_map_to_both_sides.erase(kcp_channels_iter);

		if (auto kcp_channels_iter = id_map_to_both_sides.find(egress_conv);
			kcp_channels_iter != id_map_to_both_sides.end())
			id_map_to_both_sides.erase(kcp_channels_iter);
	}
}

void relay_mode::loop_find_expires()
{
	auto time_right_now = packet::right_now();
	
	std::scoped_lock locker{ mutex_id_map_to_both_sides };
	for (auto iter = id_map_to_both_sides.begin(), next_iter = iter; iter != id_map_to_both_sides.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t conv = iter->first;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = iter->second;
		std::shared_ptr<KCP::KCP> kcp_ptr_ingress = kcp_mappings_ptr->ingress_kcp;
		std::shared_ptr<KCP::KCP> kcp_ptr_egress = kcp_mappings_ptr->egress_kcp;

		int64_t ingress_last_activity_gap = calculate_difference(kcp_ptr_ingress->LastInputTime(), packet::right_now());
		int64_t ingress_keep_alive_gap = calculate_difference(kcp_ptr_ingress->keep_alive_response_time.load(), kcp_ptr_ingress->keep_alive_send_time.load());
		int32_t ingress_timeout_seconds = gbv_keepalive_timeout + current_settings.ingress->keep_alive;

		int64_t egress_last_activity_gap = calculate_difference(kcp_ptr_egress->LastInputTime(), packet::right_now());
		int64_t egress_keep_alive_gap = calculate_difference(kcp_ptr_egress->keep_alive_response_time.load(), kcp_ptr_egress->keep_alive_send_time.load());
		int32_t egress_timeout_seconds = gbv_keepalive_timeout + current_settings.egress->keep_alive;

		bool ingress_keep_alive_timed_out = current_settings.ingress->keep_alive > 0 && std::min(ingress_last_activity_gap, ingress_keep_alive_gap) > ingress_timeout_seconds;

		bool egress_keep_alive_timed_out = current_settings.egress->keep_alive > 0 && std::min(egress_last_activity_gap, egress_keep_alive_gap) > egress_timeout_seconds;

		if (ingress_keep_alive_timed_out || egress_keep_alive_timed_out ||
			(calculate_difference(time_right_now, kcp_mappings_ptr->last_data_transfer_time.load()) > current_settings.egress->udp_timeout &&
			calculate_difference(time_right_now, kcp_ptr_ingress->LastInputTime()) > current_settings.egress->udp_timeout &&
			calculate_difference(time_right_now, kcp_ptr_egress->LastInputTime()) > current_settings.egress->udp_timeout))
		{
			if (std::scoped_lock locker_expiring_kcp{ mutex_expiring_kcp }; expiring_kcp.find(kcp_mappings_ptr) == expiring_kcp.end())
				expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() });

			if (std::scoped_lock locker_kcp_keepalive{mutex_kcp_keepalive_ingress}; kcp_keepalive_ingress.find(kcp_ptr_ingress) != kcp_keepalive_ingress.end())
				kcp_keepalive_ingress.erase(kcp_ptr_ingress);

			if (std::scoped_lock locker_kcp_keepalive{mutex_kcp_keepalive_egress}; kcp_keepalive_egress.find(kcp_ptr_egress) != kcp_keepalive_egress.end())
				kcp_keepalive_egress.erase(kcp_ptr_egress);

			kcp_updater.remove(kcp_ptr_ingress);
			kcp_updater.remove(kcp_ptr_egress);

			id_map_to_both_sides.erase(iter);
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

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
		protocol_type ptype = kcp_mappings_ptr->connection_protocol;
		std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_packet(ptype);
		kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());
		uint32_t next_update_time = current_settings.ingress->blast ? kcp_ptr->Refresh() : kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_update_time);
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

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
		protocol_type ptype = kcp_mappings_ptr->connection_protocol;
		std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_packet(ptype);
		kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());
		uint32_t next_update_time = current_settings.egress->blast ? kcp_ptr->Refresh() : kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_update_time);
	}
}

void relay_mode::send_stun_request(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (current_settings.ingress->stun_server.empty())
		return;

	resend_stun_8489_request(*udp_servers.begin()->second, current_settings.ingress->stun_server, stun_header.get(), current_settings.ingress->ip_version_only);

	timer_stun.expires_after(gbv_stun_resend);
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}

void relay_mode::find_expires(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_find_expires();

	timer_find_expires.expires_after(gbv_expring_update_interval);
	timer_find_expires.async_wait([this](const asio::error_code &e) { find_expires(e); });
}

void relay_mode::expiring_kcp_loops(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	cleanup_expiring_handshake_connections();
	cleanup_expiring_forwarders();
	cleanup_expiring_data_connections();

	timer_expiring_kcp.expires_after(gbv_expring_update_interval);
	timer_expiring_kcp.async_wait([this](const asio::error_code &e) { expiring_kcp_loops(e); });
}

void relay_mode::keep_alive_ingress(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive_ingress();

	timer_keep_alive_ingress.expires_after(gbv_keepalive_update_interval);
	timer_keep_alive_ingress.async_wait([this](const asio::error_code& e) { keep_alive_ingress(e); });
}

void relay_mode::keep_alive_egress(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive_egress();

	timer_keep_alive_egress.expires_after(gbv_keepalive_update_interval);
	timer_keep_alive_egress.async_wait([this](const asio::error_code& e) { keep_alive_egress(e); });
}

void relay_mode::log_status(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_get_status();

	timer_status_log.expires_after(gbv_logging_gap);
	timer_status_log.async_wait([this](const asio::error_code& e) { log_status(e); });
}

void relay_mode::loop_get_status()
{
	std::string output_text = time_to_string_with_square_brackets() + "Summary of " + current_settings.config_filename + "\n";
	constexpr auto duration_seconds = gbv_logging_gap.count();
	auto listener_receives_raw = to_speed_unit(listener_status_counters.ingress_raw_traffic.exchange(0) / duration_seconds);
	auto listener_receives_inner = to_speed_unit(listener_status_counters.ingress_inner_traffic.exchange(0) / duration_seconds);
	auto listener_send_inner = to_speed_unit(listener_status_counters.egress_inner_traffic.exchange(0) / duration_seconds);
	auto listener_send_raw = to_speed_unit(listener_status_counters.egress_raw_traffic.exchange(0) / duration_seconds);
	auto listener_fec_recovery = forwarder_status_counters.fec_recovery_count.exchange(0);
	auto forwarder_receives_raw = to_speed_unit(forwarder_status_counters.ingress_raw_traffic.exchange(0) / duration_seconds);
	auto forwarder_receives_inner = to_speed_unit(forwarder_status_counters.ingress_inner_traffic.exchange(0) / duration_seconds);
	auto forwarder_send_inner = to_speed_unit(forwarder_status_counters.egress_inner_traffic.exchange(0) / duration_seconds);
	auto forwarder_send_raw = to_speed_unit(forwarder_status_counters.egress_raw_traffic.exchange(0) / duration_seconds);
	auto forwarder_fec_recovery = forwarder_status_counters.fec_recovery_count.exchange(0);

#ifdef __cpp_lib_format
	output_text += std::format("[Client <-> This] receive (raw): {}, receive (inner): {}, send (inner): {}, send (raw): {}, fec recover: {}\n",
		listener_receives_raw, listener_receives_inner, listener_send_inner, listener_send_raw, listener_fec_recovery);
	output_text += std::format("[This <-> Remote] receive (raw): {}, receive (inner): {}, send (inner): {}, send (raw): {}, fec recover: {}\n",
		forwarder_receives_raw, forwarder_receives_inner, forwarder_send_inner, forwarder_send_raw, forwarder_fec_recovery);
#else
	std::ostringstream oss;
	oss << "[Client <-> This] receive (raw): " << listener_receives_raw << ", receive (inner): " << listener_receives_inner <<
		", send (inner): " << listener_send_inner << ", send (raw): " << listener_send_raw << ", fec recover: " << listener_fec_recovery << "\n";
	oss << "[This <-> Remote] receive (raw): " << forwarder_receives_raw << ", receive (inner): " << forwarder_receives_inner <<
		", send (inner): " << forwarder_send_inner << ", send (raw): " << forwarder_send_raw << ", fec recover: " << forwarder_fec_recovery << "\n";
	output_text += oss.str();
#endif

	std::shared_lock locker{ mutex_id_map_to_both_sides };
	for (auto &[conv, kcp_mappings_pr] : id_map_to_both_sides)
	{
#ifdef __cpp_lib_format
		output_text += std::format("[Client <-> This] KCP#{} average latency: {} ms\n", conv, kcp_mappings_pr->ingress_kcp->GetRxSRTT());
		output_text += std::format("[This <-> Remote] KCP#{} average latency: {} ms\n", conv, kcp_mappings_pr->egress_kcp->GetRxSRTT());
#else
		oss.clear();
		oss << "[Client <-> This] KCP#" << conv << " average latency: " << kcp_mappings_pr->ingress_kcp->GetRxSRTT() << " ms\n";
		oss << "[This <-> Remote] KCP#" << conv << " average latency: " << kcp_mappings_pr->egress_kcp->GetRxSRTT() << " ms\n";
		output_text += oss.str();
#endif
	}
	locker.unlock();

	output_text += "\n";

	if (!current_settings.log_status.empty())
		print_status_to_file(output_text, current_settings.log_status);
	std::cout << output_text << std::endl;
}
