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
	thread_local std::mt19937 mt(std::random_device{}());
	std::uniform_int_distribution<uint32_t> uniform_dist(32, std::numeric_limits<uint32_t>::max() - 1);
	return uniform_dist(mt);
}

server_mode::~server_mode()
{
	timer_find_expires.cancel();
	timer_expiring_kcp.cancel();
	timer_stun.cancel();
	timer_keep_alive.cancel();
	timer_status_log.cancel();
}

bool server_mode::start()
{
	std::cout << app_name << " is running in server mode\n";

	udp_server_callback_t func = std::bind(&server_mode::udp_listener_incoming, this, _1, _2, _3, _4);
	const std::vector<uint16_t> &listen_ports = current_settings.listen_ports;

	std::vector<udp::endpoint> listen_on_ep;
	const std::vector<std::string> &listen_on = current_settings.listen_on;
	if (listen_on.empty())
	{
		asio::ip::udp udp_ip_version = current_settings.ip_version_only == ip_only_options::ipv4 ? udp::v4() : udp::v6();
		listen_on_ep.resize(listen_ports.size());
		for (size_t i = 0; i < listen_ports.size(); i++)
			listen_on_ep[i] = udp::endpoint(udp_ip_version, listen_ports[i]);
	}
	else
	{
		asio::error_code ec;
		size_t port_count = listen_ports.size();
		size_t listen_count = port_count * listen_on.size();
		listen_on_ep.resize(listen_count);
		for (size_t index_address = 0; index_address < listen_on.size(); index_address++)
		{
			asio::ip::address local_address = asio::ip::make_address(listen_on[index_address], ec);
			if (ec)
			{
				std::string error_message = time_to_string_with_square_brackets() + "Listen Address incorrect - " + listen_on[index_address] + "\n";
				std::cerr << error_message;
				print_message_to_file(error_message, current_settings.log_messages);
				return false;
			}
			for (size_t index_ports = 0; index_ports < port_count; index_ports++)
			{
				size_t index = index_address * port_count + index_ports;
				if (local_address.is_v4() && current_settings.ip_version_only == ip_only_options::not_set)
					listen_on_ep[index].address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
				else
					listen_on_ep[index].address(local_address);
				listen_on_ep[index].port(listen_ports[index_ports]);
			}
		}
	}

	bool running_well = true;
	for (udp::endpoint ep : listen_on_ep)
	{
		try
		{
			auto bind_push_func = std::bind(&ttp::task_group_pool::push_task_listener, &sequence_task_pool, _1, _2, _3);
			udp_servers.emplace_back(std::make_unique<udp_server>(io_context, bind_push_func, ep, func, conn_options));
		}
		catch (std::exception &ex)
		{
			std::stringstream ss;
			ss << ep;
			std::string error_message = time_to_string_with_square_brackets() + ex.what() + "\tAddress: " + ss.str() + "\n";
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
			stun_header = send_stun_8489_request(*udp_servers.front(), current_settings.stun_server, current_settings.ip_version_only);
			timer_stun.expires_after(std::chrono::seconds(1));
			timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
		}

		if (current_settings.keep_alive > 0)
		{
			timer_keep_alive.expires_after(gbv_keepalive_update_interval);
			timer_keep_alive.async_wait([this](const asio::error_code &e) { keep_alive(e); });
		}

		if (!current_settings.log_status.empty())
		{
			timer_status_log.expires_after(gbv_logging_gap);
			timer_status_log.async_wait([this](const asio::error_code& e) { log_status(e); });
		}

		mux_tunnels = std::make_unique<mux_tunnel>(kcp_updater, current_settings, this);
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

void server_mode::udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, udp_server *listener_ptr)
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

	status_counters.ingress_raw_traffic += data_size;

	if (parallel_decryption_pool != nullptr)
	{
		parallel_decrypt(std::move(data), data_size, peer, listener_ptr);
		return;
	}

	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
	if (!error_message.empty())
		return;

	udp_listener_incoming_unpack(std::move(data), plain_size, peer, listener_ptr);
}

void server_mode::udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, udp_server *listener_ptr)
{
	if (data == nullptr)
		return;
	auto [packet_timestamp, data_ptr, packet_data_size] = packet::unpack(data.get(), plain_size);
	if (packet_data_size == 0)
		return;
	auto timestamp = packet::right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > gbv_time_gap_seconds)
		return;

	uint32_t conv = 0;
	std::shared_ptr<kcp_mappings> kcp_mappings_ptr;
	std::shared_ptr<KCP::KCP> kcp_ptr;
	std::pair<std::unique_ptr<uint8_t[]>, size_t> original_data;
	uint32_t fec_sn = 0;
	uint8_t fec_sub_sn = 0;
	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		auto [packet_header, kcp_data_ptr, kcp_data_size] = packet::unpack_fec(data.get(), plain_size);
		fec_sn = packet_header.sn;
		fec_sub_sn = packet_header.sub_sn;
		if (packet_header.sub_sn >= current_settings.fec_data)
		{
			auto [packet_header_redundant, redundant_data_ptr, redundant_data_size] = packet::unpack_fec_redundant(data.get(), plain_size);
			conv = packet_header_redundant.kcp_conv;
			std::shared_lock locker_kcp_channels{ mutex_kcp_channels };
			if (auto kcp_channel_iter = kcp_channels.find(packet_header_redundant.kcp_conv); kcp_channel_iter != kcp_channels.end())
				kcp_mappings_ptr = kcp_channel_iter->second;
			locker_kcp_channels.unlock();

			if (kcp_mappings_ptr == nullptr)
				return;

			original_data.first = std::make_unique<uint8_t[]>(redundant_data_size);
			original_data.second = redundant_data_size;
			std::copy_n(redundant_data_ptr, redundant_data_size, original_data.first.get());
			kcp_mappings_ptr->fec_ingress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
			if (!fec_find_missings(kcp_mappings_ptr->ingress_kcp.get(), kcp_mappings_ptr->fec_ingress_control, fec_sn, current_settings.fec_data))
				return;
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
		conv = KCP::KCP::GetConv(data_ptr);
		if (conv == 0)
		{
			udp_listener_incoming_new_connection(std::move(data), plain_size, peer, listener_ptr);
			return;
		}

		if (kcp_mappings_ptr == nullptr)
		{
			std::shared_lock locker_kcp_channels{ mutex_kcp_channels };
			if (auto kcp_channel_iter = kcp_channels.find(conv); kcp_channel_iter != kcp_channels.end())
				kcp_mappings_ptr = kcp_channel_iter->second;
			locker_kcp_channels.unlock();

			if (kcp_mappings_ptr == nullptr)
				return;
		}

		if (std::shared_ptr<udp::endpoint> ingress_source_endpoint = std::atomic_load(&(kcp_mappings_ptr->ingress_source_endpoint));
			ingress_source_endpoint == nullptr || *ingress_source_endpoint != peer)
			std::atomic_store(&(kcp_mappings_ptr->ingress_source_endpoint), std::make_shared<udp::endpoint>(peer));

		kcp_ptr = kcp_mappings_ptr->ingress_kcp;

		if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
		{
			kcp_mappings_ptr->fec_ingress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
			fec_find_missings(kcp_ptr.get(), kcp_mappings_ptr->fec_ingress_control, fec_sn, current_settings.fec_data);
		}

		kcp_ptr->Input((const char *)data_ptr, (long)packet_data_size);
	}

	resume_tcp(kcp_mappings_ptr.get());

	while (kcp_ptr != nullptr)
	{
		int buffer_size = kcp_ptr->PeekSize();
		if (buffer_size <= 0)
			break;

		std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique<uint8_t[]>(buffer_size);
		uint8_t *buffer_ptr = buffer_cache.get();

		int kcp_data_size = 0;
		if (kcp_data_size = kcp_ptr->Receive((char *)buffer_ptr, buffer_size); kcp_data_size < 0)
			break;

		kcp_mappings_ptr->ingress_listener.store(listener_ptr);

		auto [ftr, prtcl, unpacked_data_ptr, unpacked_data_size] = packet::unpack_inner(buffer_ptr, kcp_data_size);
		switch (ftr)
		{
		case feature::raw_data:
		{
			if (prtcl == protocol_type::tcp)
			{
				std::shared_ptr<tcp_session> &tcp_channel = kcp_mappings_ptr->local_tcp;
				if (tcp_channel != nullptr)
				{
					tcp_channel->async_send_data(std::move(buffer_cache), unpacked_data_ptr, unpacked_data_size);
				}
			}
			else if (prtcl == protocol_type::udp)
			{
				std::shared_ptr<udp_client> &udp_channel = kcp_mappings_ptr->local_udp;
				std::shared_ptr<udp::endpoint> egress_target_endpoint = std::atomic_load(&(kcp_mappings_ptr->egress_target_endpoint));
				if (current_settings.ignore_destination_address || current_settings.ignore_destination_port)
					udp_channel->async_send_out(std::move(buffer_cache), unpacked_data_ptr, unpacked_data_size, *egress_target_endpoint);
				else
					udp_channel->async_send_out(std::move(buffer_cache), unpacked_data_ptr, unpacked_data_size, *udp_target);
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
		case feature::disconnect:
		{
			if (prtcl == protocol_type::tcp)
			{
				std::shared_ptr<tcp_session> &tcp_channel = kcp_mappings_ptr->local_tcp;
				if (tcp_channel != nullptr)
					process_tcp_disconnect(tcp_channel.get(), kcp_ptr, false);
			}
			if (prtcl == protocol_type::udp)
			{
				std::shared_ptr<udp_client> &udp_channel = kcp_mappings_ptr->local_udp;
				udp_channel->stop();
			}
			if (prtcl == protocol_type::mux)
			{
				mux_tunnels->delete_mux_records(conv);
			}

			std::scoped_lock lockers{ mutex_expiring_kcp, mutex_kcp_channels };
			expiring_kcp[kcp_mappings_ptr] = packet::right_now() - current_settings.udp_timeout;
			kcp_channels.erase(conv);
			break;
		}
		case feature::mux_transfer:
		{
			mux_tunnels->transfer_data(prtcl, kcp_mappings_ptr.get(), std::move(buffer_cache), unpacked_data_ptr, unpacked_data_size);
			break;
		}
		case feature::mux_cancel:
		{
			mux_tunnels->delete_channel(prtcl, kcp_mappings_ptr.get(), unpacked_data_ptr, unpacked_data_size);
			break;
		}
		case feature::pre_connect_custom_address:
		{
			mux_tunnels->pre_connect_custom_address(prtcl, kcp_mappings_ptr.get(), std::move(buffer_cache), unpacked_data_ptr, unpacked_data_size);
			break;
		}
		default:
			break;
		}
		status_counters.ingress_inner_traffic += unpacked_data_size;
	}
}

void server_mode::sequential_extract()
{
	listener_decryption_task_count--;
	std::unique_lock locker{ mutex_decryptions_from_listener };
	if (decryptions_from_listener.empty())
		return;

	for (auto iter = decryptions_from_listener.begin(), next = iter;
		iter != decryptions_from_listener.end();
		iter = next)
	{
		next++;
		auto &task_results = *iter;
		if (task_results.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
			break;
		auto [error_message, data, plain_size, peer, listener] = task_results.get();
		if (error_message.empty() && plain_size > 0)
		{
			udp_listener_incoming_unpack(std::move(data), plain_size, peer, listener);
		}
		decryptions_from_listener.erase(iter);
	}

	if (decryptions_from_listener.empty())
		return;

	locker.unlock();
	if (listener_decryption_task_count.load() > 0)
		return;

	listener_decryption_task_count++;
	sequence_task_pool.push_task(std::this_thread::get_id(),
		[this](std::unique_ptr<uint8_t[]>) { sequential_extract(); },
		std::unique_ptr<uint8_t[]>{});
}

void server_mode::tcp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_session_weak)
{
	if (data == nullptr || incoming_session == nullptr)
		return;

	std::shared_ptr<KCP::KCP> kcp_session = kcp_session_weak.lock();
	if (kcp_session == nullptr)
		return;

	if (!incoming_session->session_is_ending() && !incoming_session->is_pause() && kcp_session->WaitQueueIsFull())
	{
		incoming_session->pause(true);
	}

	uint8_t *data_ptr = data.get();
	size_t new_data_size = packet::create_data_packet(protocol_type::tcp, data_ptr, data_size);
	kcp_session->Send((const char *)data_ptr, new_data_size);
	uint32_t next_update_time = current_settings.blast ? kcp_session->Refresh() : kcp_session->Check();
	kcp_updater.submit(kcp_session, next_update_time);

	status_counters.egress_inner_traffic += data_size;
}

void server_mode::udp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, std::weak_ptr<KCP::KCP> kcp_session_weak)
{
	if (data == nullptr)
		return;

	std::shared_ptr<KCP::KCP> kcp_session = kcp_session_weak.lock();
	if (kcp_session == nullptr)
		return;

	if (kcp_session->WaitQueueIsFull())
		return;

	uint8_t *data_ptr = data.get();
	size_t new_data_size = packet::create_data_packet(protocol_type::udp, data_ptr, data_size);

	kcp_session->Send((const char *)data_ptr, new_data_size);
	uint32_t next_update_time = kcp_session->Check();
	kcp_updater.submit(kcp_session, next_update_time);

	status_counters.egress_inner_traffic += data_size;
}

void server_mode::udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, udp_server *listener_ptr)
{
	if (data_size == 0)
		return;
	auto [timestamp, data_ptr, packet_data_size] = packet::unpack(data.get(), data_size);

	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		auto [packet_header, kcp_data_ptr, kcp_data_size] = packet::unpack_fec(data.get(), data_size);
		data_ptr = kcp_data_ptr;
		packet_data_size = kcp_data_size;
	}

	if (packet_data_size == 0)
		return;
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
			std::weak_ptr<kcp_mappings> handshake_kcp_mappings_weak = handshake_kcp_mappings;
			kcp_mappings *handshake_kcp_mappings_ptr = handshake_kcp_mappings.get();
			handshake_kcp_mappings_ptr->ingress_kcp = handshake_kcp;
			handshake_kcp_mappings_ptr->ingress_source_endpoint = std::make_shared<udp::endpoint>(peer);
			handshake_kcp_mappings_ptr->ingress_listener.store(listener_ptr);
			handshake_kcp_mappings->egress_target_endpoint = std::make_shared<udp::endpoint>();
			handshake_kcp_mappings->egress_previous_target_endpoint = std::make_shared<udp::endpoint>();

			if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
			{
				size_t K = current_settings.fec_data;
				size_t N = K + current_settings.fec_redundant;
				handshake_kcp_mappings_ptr->fec_ingress_control.fecc.reset_martix(K, N);
			}

			handshake_kcp->SetUserData(handshake_kcp_mappings_ptr);
			handshake_kcp->SetMTU(current_settings.kcp_mtu);
			handshake_kcp->NoDelay(1, 1, 3, 1);
			handshake_kcp->Update();
			handshake_kcp->RxMinRTO() = 10;
			handshake_kcp->SetBandwidth(current_settings.outbound_bandwidth, current_settings.inbound_bandwidth);
			handshake_kcp->SetOutput([this, handshake_kcp_mappings_weak](const char *buf, int len, void *user) -> int
				{
					auto handshake_kcp_mappings_ptr = handshake_kcp_mappings_weak.lock();
					if (handshake_kcp_mappings_ptr == nullptr) return 0;
					return kcp_sender(buf, len, user);
				});

			if (handshake_kcp->Input((const char *)data_ptr, (long)packet_data_size) < 0)
				return;

			int buffer_size = handshake_kcp->PeekSize();
			if (buffer_size <= 0)
				return;

			int kcp_data_size = 0;
			if (kcp_data_size = handshake_kcp->Receive((char *)data_ptr, buffer_size); kcp_data_size < 0)
				return;

			auto [ftr, prtcl, unbacked_data_ptr, unbacked_data_size] = packet::unpack_inner(data_ptr, kcp_data_size);
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

				std::unique_ptr<uint8_t[]> settings_data_ptr = std::make_unique<uint8_t[]>(unbacked_data_size + 1);	// plus 1 for C-style string ending
				packet::convert_wrapper_byte_order(unbacked_data_ptr, settings_data_ptr.get(), unbacked_data_size + 1);
				const packet::settings_wrapper *basic_settings = packet::get_initialise_details_from_unpacked_data(settings_data_ptr.get());
				uint64_t outbound_bandwidth = current_settings.outbound_bandwidth;
				const char *user_input_ip = basic_settings->user_input_ip;
				asio::ip::port_type user_input_port = basic_settings->user_input_port;
				if (basic_settings->inbound_bandwidth > 0 && outbound_bandwidth > basic_settings->inbound_bandwidth)
					outbound_bandwidth = basic_settings->inbound_bandwidth;

				std::shared_ptr<kcp_mappings> data_kcp_mappings = std::make_shared<kcp_mappings>();
				kcp_mappings *data_kcp_mappings_ptr = data_kcp_mappings.get();
				std::shared_ptr<KCP::KCP> data_kcp = std::make_shared<KCP::KCP>(new_id);
				data_kcp_mappings_ptr->ingress_kcp = data_kcp;
				data_kcp_mappings_ptr->connection_protocol = prtcl;
				data_kcp_mappings_ptr->ingress_listener.store(listener_ptr);
				data_kcp_mappings_ptr->ingress_source_endpoint = std::make_shared<udp::endpoint>();
				data_kcp_mappings_ptr->egress_target_endpoint = std::make_shared<udp::endpoint>();
				data_kcp_mappings_ptr->egress_previous_target_endpoint = std::make_shared<udp::endpoint>();
				data_kcp->SetUserData(data_kcp_mappings_ptr);
				data_kcp->keep_alive_send_time.store(timestamp);
				data_kcp->keep_alive_response_time.store(timestamp);
				data_kcp->SetMTU(current_settings.kcp_mtu);
				data_kcp->SetWindowSize(current_settings.kcp_sndwnd, current_settings.kcp_rcvwnd);
				data_kcp->NoDelay(current_settings.kcp_nodelay, current_settings.kcp_interval, current_settings.kcp_resend, current_settings.kcp_nc);
				data_kcp->Update();
				data_kcp->RxMinRTO() = 10;
				data_kcp->SetBandwidth(outbound_bandwidth, current_settings.inbound_bandwidth);
				
				if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
				{
					size_t K = current_settings.fec_data;
					size_t N = K + current_settings.fec_redundant;
					data_kcp_mappings->fec_ingress_control.fecc.reset_martix(K, N);
				}

				bool connect_success = false;

				switch (prtcl)
				{
				case protocol_type::mux:
				{
					connect_success = true;
					mux_tunnels->setup_mux_kcp(data_kcp);
					break;
				}
				case protocol_type::tcp:
				{
					connect_success = create_new_tcp_connection(handshake_kcp, data_kcp, user_input_ip, user_input_port);
					break;
				}
				case protocol_type::udp:
				{
					connect_success = create_new_udp_connection(handshake_kcp, data_kcp, peer, user_input_ip, user_input_port);
					break;
				}
				default:
					break;
				}

				if (connect_success)
				{
					uint16_t listen_port_start = 0, listen_port_end = 0;
					if (is_continuous(current_settings.listen_ports))
					{
						listen_port_start = current_settings.listen_ports.front();
						listen_port_end = current_settings.listen_ports.back();
					}
					packet::settings_wrapper basic_settings =
					{
						new_id,
						listen_port_start,
						listen_port_end,
						current_settings.outbound_bandwidth,
						current_settings.inbound_bandwidth
					};
					std::vector<uint8_t> new_data = packet::response_initialise_packet(prtcl, basic_settings);
					handshake_kcp->Send((const char *)new_data.data(), (long)new_data.size());
					handshake_kcp->Update();
					uint32_t next_update_time = handshake_kcp->Check();
					kcp_updater.submit(handshake_kcp, next_update_time);
					std::weak_ptr handshake_kcp_weak = handshake_kcp;
					std::weak_ptr data_ptr_weak = data_kcp;
					handshake_kcp_mappings->mapping_function = [this, handshake_kcp_weak, data_ptr_weak]() -> bool
						{ set_kcp_windows(handshake_kcp_weak, data_ptr_weak); return false; };

					std::scoped_lock lockers{ mutex_expiring_handshakes, mutex_kcp_channels, mutex_kcp_keepalive };
					handshake_channels[peer] = handshake_kcp_mappings;
					expiring_handshakes.insert({ handshake_kcp_mappings, timestamp });

					kcp_channels[new_id] = data_kcp_mappings;
					kcp_keepalive[data_kcp].store(timestamp);
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
		else
		{
			kcp_mappings *kcp_mappings_ptr = iter->second.get();
			std::shared_ptr<KCP::KCP> handshake_kcp = kcp_mappings_ptr->ingress_kcp;

			handshake_kcp->Input((const char *)data_ptr, (long)packet_data_size);
		}
		unique_locker_handshake_channels.unlock();
	}
	else
	{
		kcp_mappings *kcp_mappings_ptr = iter->second.get();
		std::shared_ptr<KCP::KCP> handshake_kcp = kcp_mappings_ptr->ingress_kcp;

		handshake_kcp->Input((const char *)data_ptr, (long)packet_data_size);
	}
}

bool server_mode::create_new_tcp_connection(std::shared_ptr<KCP::KCP> handshake_kcp, std::shared_ptr<KCP::KCP> data_kcp, const std::string &user_input_address, asio::ip::port_type user_input_port)
{
	bool connect_success = false;
	std::weak_ptr<KCP::KCP> weak_data_kcp = data_kcp;
	auto callback_function = [weak_data_kcp, this](std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> target_session)
	{
		tcp_connector_incoming(std::move(data), data_size, target_session, weak_data_kcp);
	};
	tcp_client target_connector(io_context, callback_function, conn_options);
	std::string destination_address = current_settings.destination_address_list.front();
	uint16_t destination_port = current_settings.destination_ports.front();

	if (current_settings.ignore_destination_address || current_settings.ignore_destination_port)
	{
		if (user_input_port == 0 || user_input_address.empty())
			return false;
		destination_address = user_input_address;
		destination_port = user_input_port;
	}

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
		kcp_mappings *kcp_mappings_ptr = (kcp_mappings*)data_kcp->GetUserData();
		if (kcp_mappings_ptr == nullptr)
			return false;
		
		connect_success = true;
		local_session->when_disconnect([weak_data_kcp, this](std::shared_ptr<tcp_session> session) { process_tcp_disconnect(session.get(), weak_data_kcp); });
		std::weak_ptr weak_session = local_session;
		std::weak_ptr handshake_kcp_mappings_weak = kcp_mappings_ptr->weak_from_this();
		data_kcp->SetOutput([this, handshake_kcp_mappings_weak](const char *buf, int len, void *user) -> int
			{
				auto handshake_kcp_mappings_ptr = handshake_kcp_mappings_weak.lock();
				if (handshake_kcp_mappings_ptr == nullptr) return 0;
				return kcp_sender(buf, len, user);
			});
		data_kcp->SetPostUpdate([this, handshake_kcp_mappings_weak](void *user)
			{
				auto handshake_kcp_mappings_ptr = handshake_kcp_mappings_weak.lock();
				if (handshake_kcp_mappings_ptr != nullptr) resume_tcp((kcp_mappings*)user);
			});

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

bool server_mode::create_new_udp_connection(std::shared_ptr<KCP::KCP> handshake_kcp, std::shared_ptr<KCP::KCP> data_kcp, const udp::endpoint &peer, const std::string &user_input_address, asio::ip::port_type user_input_port)
{
	bool connect_success = false;
	std::weak_ptr<KCP::KCP> weak_data_kcp = data_kcp;
	kcp_mappings *kcp_mappings_ptr = (kcp_mappings*)data_kcp->GetUserData();
	if (kcp_mappings_ptr == nullptr)
		return false;
	std::weak_ptr handshake_kcp_mappings_weak = kcp_mappings_ptr->weak_from_this();

	udp_client_callback_t udp_func_ap = [weak_data_kcp, this](std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
	{
		udp_connector_incoming(std::move(data), data_size, peer, port_number, weak_data_kcp);
	};

	std::shared_ptr<udp_client> target_connector = nullptr;
	for (int i = 0; i < gbv_retry_times; i++)
	{
		try
		{
			auto bind_push_func = std::bind(&ttp::task_group_pool::push_task_forwarder, &sequence_task_pool, _1, _2, _3);
			target_connector = std::make_shared<udp_client>(io_context, bind_push_func, udp_func_ap, conn_options);
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
	if (current_settings.ip_version_only == ip_only_options::ipv4)
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

	data_kcp->SetOutput([this, handshake_kcp_mappings_weak](const char *buf, int len, void *user) -> int
		{
			auto handshake_kcp_mappings_ptr = handshake_kcp_mappings_weak.lock();
			if (handshake_kcp_mappings_ptr == nullptr) return 0;
			return kcp_sender(buf, len, user);
		});
	
	bool resolve_completed = false;
	if (current_settings.ignore_destination_address || current_settings.ignore_destination_port)
	{
		if (user_input_port == 0 || user_input_address.empty())
			return false;

		asio::ip::address target_address = asio::ip::address::from_string(user_input_address);
		if ((current_settings.ip_version_only == ip_only_options::ipv4 && target_address.is_v6()) ||
			(current_settings.ip_version_only == ip_only_options::ipv6 && target_address.is_v4()))
			return false;

		udp::resolver::results_type udp_endpoints = target_connector->get_remote_hostname(user_input_address, 0, ec);
		if (ec || udp_endpoints.size() == 0)
			return false;

		udp::endpoint target_endpoint = *udp_endpoints.begin();
		target_endpoint.port(user_input_port);
		target_connector->async_receive();
		kcp_mappings_ptr->egress_target_endpoint = std::make_shared<udp::endpoint>(target_endpoint);

		resolve_completed = true;
	}
	else if (udp_target != nullptr || update_local_udp_target(target_connector))
	{
		resolve_completed = true;
	}

	if (resolve_completed)
	{
		target_connector->async_receive();
		kcp_mappings_ptr->ingress_source_endpoint = std::make_shared<udp::endpoint>(peer);
		kcp_mappings_ptr->local_udp = target_connector;
		data_kcp->Flush();
		connect_success = true;
	}

	return connect_success;
}

void server_mode::resume_tcp(kcp_mappings *kcp_mappings_ptr)
{
	std::shared_ptr data_kcp = kcp_mappings_ptr->ingress_kcp;
	std::shared_ptr session = kcp_mappings_ptr->local_tcp;
	if (data_kcp != nullptr && session != nullptr && session->is_pause() && data_kcp->WaitQueueBelowHalfCapacity())
		session->pause(false);
}

void server_mode::set_kcp_windows(std::weak_ptr<KCP::KCP> handshake_kcp, std::weak_ptr<KCP::KCP> data_ptr_weak)
{
	std::shared_ptr handshake_kcp_ptr = handshake_kcp.lock();
	if (handshake_kcp_ptr == nullptr)
		return;

	std::shared_ptr data_kcp_ptr = data_ptr_weak.lock();
	if (data_kcp_ptr == nullptr)
		return;

	data_kcp_ptr->ResetWindowValues(handshake_kcp_ptr->GetRxSRTT());

	std::scoped_lock mux_locks{ mux_tunnels->mutex_mux_tcp_cache, mux_tunnels->mutex_mux_udp_cache };
	if (auto iter = mux_tunnels->mux_tcp_cache_max_size.find(data_ptr_weak); iter != mux_tunnels->mux_tcp_cache_max_size.end())
		iter->second = data_kcp_ptr->GetSendWindowSize();;
	if (auto iter = mux_tunnels->mux_udp_cache_max_size.find(data_ptr_weak); iter != mux_tunnels->mux_udp_cache_max_size.end())
		iter->second = data_kcp_ptr->GetSendWindowSize();;
}

std::shared_ptr<mux_records> server_mode::create_mux_data_tcp_connection(uint32_t connection_id, std::weak_ptr<KCP::KCP> kcp_session_weak, const std::string &user_input_address, asio::ip::port_type user_input_port)
{
	std::shared_ptr<mux_records> mux_records_ptr = std::make_shared<mux_records>();
	std::weak_ptr<mux_records> mux_records_ptr_weak = mux_records_ptr;
	auto callback_function = [this, kcp_session_weak, mux_records_ptr_weak](std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> target_session)
		{
			mux_tunnels->read_tcp_data_to_cache(std::move(data), data_size, target_session, kcp_session_weak, mux_records_ptr_weak);
		};
	tcp_client target_connector(io_context, callback_function, conn_options);
	std::string destination_address = current_settings.destination_address_list.front();
	uint16_t destination_port = current_settings.destination_ports.front();

	if (current_settings.ignore_destination_address || current_settings.ignore_destination_port)
	{
		if (user_input_port == 0 || user_input_address.empty())
			return nullptr;
		destination_address = user_input_address;
		destination_port = user_input_port;
	}

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

	udp_client_callback_t udp_func_ap = [this, kcp_session_weak, mux_records_ptr_weak](std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
	{
		mux_tunnels->server_udp_data_to_cache(std::move(data), data_size, peer, port_number, kcp_session_weak, mux_records_ptr_weak);
	};

	std::shared_ptr<udp_client> target_connector = nullptr;
	for (int i = 0; i < gbv_retry_times; i++)
	{
		try
		{
			auto bind_push_func = std::bind(&ttp::task_group_pool::push_task_listener, &sequence_task_pool, _1, _2, _3);
			target_connector = std::make_shared<udp_client>(io_context, bind_push_func, udp_func_ap, conn_options);
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
	if (current_settings.ip_version_only == ip_only_options::ipv4)
		target_connector->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v4, ec);
	else
		target_connector->send_out(create_raw_random_data(current_settings.kcp_mtu), local_empty_target_v6, ec);

	if (ec)
	{
		return nullptr;
	}

	if (current_settings.ignore_destination_address || current_settings.ignore_destination_port ||
		udp_target != nullptr || update_local_udp_target(target_connector))
		target_connector->async_receive();
	else
		return nullptr;

	mux_records_ptr->local_udp = target_connector;
	mux_records_ptr->connection_id = connection_id;

	return mux_records_ptr;
}

int server_mode::kcp_sender(const char *buf, int len, void *user)
{
	if (user == nullptr)
		return 0;

	kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)user;
	if (std::atomic_load(&(kcp_mappings_ptr->ingress_source_endpoint)) == nullptr)
		return 0;

	if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
	{
		auto [new_buffer, buffer_size] = packet::create_packet((const uint8_t*)buf, len);
		data_sender(kcp_mappings_ptr, std::move(new_buffer), buffer_size);
	}
	else
	{
		fec_maker(kcp_mappings_ptr, (const uint8_t *)buf, len);
	}
	return 0;
}

void server_mode::data_sender(std::shared_ptr<kcp_mappings> kcp_mappings_ptr)
{
	if (kcp_mappings_ptr == nullptr)
		return;
	kcp_mappings_ptr->listener_encryption_task_count--;

	std::unique_lock locker{ kcp_mappings_ptr->mutex_encryptions_via_listener };
	if (kcp_mappings_ptr->encryptions_via_listener.empty())
		return;

	for (auto iter = kcp_mappings_ptr->encryptions_via_listener.begin(), next = iter;
		iter != kcp_mappings_ptr->encryptions_via_listener.end();
		iter = next)
	{
		next++;
		auto& task_results = *iter;
		if (task_results.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
			break;
		auto [error_message, data, cipher_size] = task_results.get();
		if (!error_message.empty() || cipher_size == 0)
			return;
		std::shared_ptr<udp::endpoint> ingress_source_endpoint = std::atomic_load(&(kcp_mappings_ptr->ingress_source_endpoint));
		kcp_mappings_ptr->ingress_listener.load()->async_send_out(std::move(data), cipher_size, *ingress_source_endpoint);
		kcp_mappings_ptr->encryptions_via_listener.erase(iter);
	}

	if (kcp_mappings_ptr->encryptions_via_listener.empty())
		return;

	locker.unlock();
	if (kcp_mappings_ptr->listener_encryption_task_count.load() > 0)
		return;

	std::weak_ptr<kcp_mappings> kcp_mappings_ptr_weak = kcp_mappings_ptr;
	kcp_mappings_ptr->listener_encryption_task_count++;
	sequence_task_pool.push_task_listener((size_t)kcp_mappings_ptr.get(),
		[this, kcp_mappings_ptr_weak](std::unique_ptr<uint8_t[]>) { data_sender(kcp_mappings_ptr_weak.lock()); },
		std::unique_ptr<uint8_t[]>{});
}

void server_mode::data_sender(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> new_buffer, size_t buffer_size)
{
	if (parallel_encryption_pool != nullptr)
	{
		parallel_encrypt(kcp_mappings_ptr, std::move(new_buffer), buffer_size);
		return;
	}

	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, new_buffer.get(), (int)buffer_size);
	if (!error_message.empty() || cipher_size == 0)
		return;
	std::shared_ptr<udp::endpoint> ingress_source_endpoint = std::atomic_load(&(kcp_mappings_ptr->ingress_source_endpoint));
	kcp_mappings_ptr->ingress_listener.load()->async_send_out(std::move(new_buffer), cipher_size, *ingress_source_endpoint);
	status_counters.egress_raw_traffic += cipher_size;
}

void server_mode::parallel_encrypt(kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	std::function<encryption_result(std::unique_ptr<uint8_t[]>)> func =
		[this, data_size](std::unique_ptr<uint8_t[]> data) mutable -> encryption_result
		{
			auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, data.get(), (int)data_size);
			return { std::move(error_message), std::move(data), cipher_size };
		};

	auto task_future = parallel_encryption_pool->submit(func, std::move(data));
	std::unique_lock locker{ kcp_mappings_ptr->mutex_encryptions_via_listener };
	kcp_mappings_ptr->encryptions_via_listener.emplace_back(std::move(task_future));
	locker.unlock();
	kcp_mappings_ptr->listener_encryption_task_count++;
	data_sender(kcp_mappings_ptr->shared_from_this());
}

void server_mode::parallel_decrypt(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, udp_server *listener_ptr)
{
	std::function<decryption_result_listener(std::unique_ptr<uint8_t[]>)> func =
		[this, data_size, peer, listener_ptr](std::unique_ptr<uint8_t[]> data) mutable -> decryption_result_listener
		{
			uint8_t *data_ptr = data.get();
			auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
			return { std::move(error_message), std::move(data), plain_size, peer, listener_ptr };
		};

	auto task_future = parallel_decryption_pool->submit(func, std::move(data));
	std::unique_lock locker{ mutex_decryptions_from_listener };
	decryptions_from_listener.emplace_back(std::move(task_future));
	locker.unlock();
	listener_decryption_task_count++;
	sequential_extract();
}

void server_mode::fec_maker(kcp_mappings *kcp_mappings_ptr, const uint8_t *input_data, int data_size)
{
	fec_control_data &fec_controllor = kcp_mappings_ptr->fec_ingress_control;

	int conv = kcp_mappings_ptr->ingress_kcp->GetConv();
	auto [fec_data_buffer, fec_data_buffer_size] = packet::create_fec_data_packet(
		input_data, data_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
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
			auto [fec_redundant_buffer, fec_redundant_buffer_size] = packet::create_fec_redundant_packet(
				data_ptr.get(), (int)fec_align_length, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++, conv);
			data_sender(kcp_mappings_ptr, std::move(fec_redundant_buffer), fec_redundant_buffer_size);
		}
		fec_controllor.fec_snd_cache.clear();
		fec_controllor.fec_snd_sub_sn.store(0);
		fec_controllor.fec_snd_sn++;
	}
}

bool server_mode::fec_find_missings(KCP::KCP *kcp_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count)
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

void server_mode::process_tcp_disconnect(tcp_session *session, std::weak_ptr<KCP::KCP> kcp_ptr_weak, bool inform_peer)
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
		if (inform_peer)
		{
			std::vector<uint8_t> data = packet::inform_disconnect_packet(protocol_type::tcp);
			kcp_ptr->Send((const char *)data.data(), data.size());
		}
		uint32_t next_update_time = kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_update_time);
		expiring_kcp.insert({ kcp_mappings_ptr, packet::right_now() + gbv_keepalive_timeout });

		session->session_is_ending(true);
		session->pause(false);
		session->stop();
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

	std::unique_ptr<uint8_t[]> empty_ptr;
	auto func = [this, kcp_ptr_weak](std::unique_ptr<uint8_t[]> data) mutable { mux_tunnels->refresh_mux_queue(kcp_ptr_weak); };
	sequence_task_pool.push_task((size_t)this, func, std::move(empty_ptr));

	session->session_is_ending(true);
	session->pause(false);
	session->stop();

	std::scoped_lock lockers{ mux_tunnels->mutex_id_map_to_mux_records, mux_tunnels->mutex_expiring_mux_records};
	mux_tunnels->id_map_to_mux_records.erase(complete_connection_id);
	mux_tunnels->expiring_mux_records.erase(complete_connection_id);
}

bool server_mode::update_local_udp_target(std::shared_ptr<udp_client> target_connector)
{
	bool connect_success = false;
	asio::error_code ec;
	for (int i = 0; i <= gbv_retry_times; ++i)
	{
		const std::string &destination_address = current_settings.destination_address_list.front();
		uint16_t destination_port = current_settings.destination_ports.front();
		udp::resolver::results_type udp_endpoints = target_connector->get_remote_hostname(destination_address, 0, ec);
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
			udp_target->port(destination_port);
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
		if (time_right_now - expire_time < (int64_t)gbv_kcp_cleanup_waits)
			continue;

		kcp_mappings_ptr->mapping_function();
		kcp_mappings_ptr->mapping_function = empty_mapping_function;
		kcp_ptr->SetOutput(empty_kcp_output);
		kcp_ptr->SetPostUpdate(empty_kcp_postupdate);
		kcp_ptr->SetUserData(nullptr);
		kcp_updater.remove(kcp_ptr);
		if (time_right_now - expire_time <= gbv_kcp_cleanup_waits * 2)
			continue;
		std::shared_ptr<udp::endpoint> ingress_source_endpoint = std::atomic_load(&(kcp_mappings_ptr->ingress_source_endpoint));
		handshake_channels.erase(*ingress_source_endpoint);
		expiring_handshakes.erase(iter);
	}
}

void server_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = packet::right_now();

	std::scoped_lock lockers{ mutex_expiring_kcp, mutex_kcp_channels };
	for (auto iter = expiring_kcp.begin(), next_iter = iter; iter != expiring_kcp.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = iter->first;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->ingress_kcp;
		int64_t expire_time = iter->second;
		uint32_t conv = kcp_ptr->GetConv();

		if (time_right_now - expire_time < (int64_t)gbv_kcp_cleanup_waits)
			continue;

		kcp_ptr->SetOutput(empty_kcp_output);
		kcp_ptr->SetPostUpdate(empty_kcp_postupdate);
		kcp_ptr->SetUserData(nullptr);

		switch (kcp_mappings_ptr->connection_protocol)
		{
		case protocol_type::tcp:
		{
			std::shared_ptr<tcp_session> &current_session = kcp_mappings_ptr->local_tcp;
			if (current_session != nullptr)
			{
				current_session->session_is_ending(true);
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
			}
			break;
		}
		default:
			break;
		}

		kcp_updater.remove(kcp_ptr);
		expiring_kcp.erase(iter);

		if (auto kcp_iter = kcp_channels.find(conv); kcp_iter != kcp_channels.end())
			kcp_channels.erase(kcp_iter);
	}
}

void server_mode::loop_find_expires()
{
	std::scoped_lock lockers{ mutex_kcp_channels, mutex_expiring_kcp };
	for (auto iter = kcp_channels.begin(), next_iter = iter; iter != kcp_channels.end(); iter = next_iter)
	{
		++next_iter;
		auto time_right_now = packet::right_now();
		uint32_t conv = iter->first;
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = iter->second;
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_mappings_ptr->ingress_kcp;
		int64_t kcp_last_activity_gap = calculate_difference(kcp_ptr->LastInputTime(), time_right_now);
		int64_t kcp_keep_alive_gap = calculate_difference(kcp_ptr->keep_alive_response_time.load(), kcp_ptr->keep_alive_send_time.load());
		int32_t timeout_seconds = gbv_keepalive_timeout + current_settings.keep_alive;
		bool keep_alive_timed_out = current_settings.keep_alive > 0 && std::min(kcp_last_activity_gap, kcp_keep_alive_gap) > timeout_seconds;

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

				uint32_t next_update_time = kcp_ptr->Check();
				kcp_updater.submit(kcp_ptr, next_update_time);
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
			if (calculate_difference(kcp_ptr->LastInputTime(), time_right_now) > gbv_mux_channels_cleanup || keep_alive_timed_out)
			{
				do_erase = true;
				kcp_ptr->SetOutput(empty_kcp_output);
				kcp_ptr->SetPostUpdate(empty_kcp_postupdate);
				kcp_ptr->SetUserData(nullptr);
				mux_tunnels->delete_mux_records(kcp_ptr->GetConv());
				mux_tunnels->remove_cached_kcp(kcp_ptr);
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
			uint32_t next_update_time = kcp_ptr->Check();
			kcp_updater.submit(kcp_ptr, next_update_time);
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

		kcp_mappings *kcp_mappings_ptr = (kcp_mappings *)kcp_ptr->GetUserData();
		if (kcp_mappings_ptr == nullptr)
			continue;
		protocol_type ptype = kcp_mappings_ptr->connection_protocol;
		std::vector<uint8_t> keep_alive_packet = packet::create_keep_alive_packet(ptype);
		kcp_ptr->Send((const char*)keep_alive_packet.data(), keep_alive_packet.size());

		uint32_t next_update_time = kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_update_time);
		kcp_ptr->keep_alive_send_time.store(packet::right_now());
	}
}

void server_mode::send_stun_request(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (current_settings.stun_server.empty())
		return;

	resend_stun_8489_request(*udp_servers.front(), current_settings.stun_server, stun_header.get(), current_settings.ip_version_only);

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
	mux_tunnels->cleanup_expiring_mux_records();

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

void server_mode::log_status(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_get_status();

	timer_status_log.expires_after(gbv_logging_gap);
	timer_status_log.async_wait([this](const asio::error_code& e) { log_status(e); });
}

void server_mode::loop_get_status()
{
	std::string output_text = time_to_string_with_square_brackets() + "Summary of " + current_settings.config_filename + "\n";
	constexpr auto duration_seconds = gbv_logging_gap.count();
	auto listener_receives_raw = to_speed_unit(status_counters.ingress_raw_traffic.exchange(0), duration_seconds);
	auto listener_receives_inner = to_speed_unit(status_counters.ingress_inner_traffic.exchange(0), duration_seconds);
	auto listener_send_inner = to_speed_unit(status_counters.egress_inner_traffic.exchange(0), duration_seconds);
	auto listener_send_raw = to_speed_unit(status_counters.egress_raw_traffic.exchange(0), duration_seconds);
	auto listener_fec_recovery = status_counters.fec_recovery_count.exchange(0);
	
#ifdef __cpp_lib_format
	output_text += std::format("receive (raw): {}, receive (inner): {}, send (inner): {}, send (raw): {}, fec recover: {}\n",
		listener_receives_raw, listener_receives_inner, listener_send_inner, listener_send_raw, listener_fec_recovery);
#else
	std::ostringstream oss;
	oss << "receive (raw): " << listener_receives_raw << ", receive (inner): " << listener_receives_inner <<
		", send (inner): " << listener_send_inner << ", send (raw): " << listener_send_raw << ", fec recover: " << listener_fec_recovery << "\n";
	output_text += oss.str();
#endif

	std::shared_lock locker{ mutex_kcp_channels };
	for (auto &[conv, kcp_mappings_pr] : kcp_channels)
	{
#ifdef __cpp_lib_format
		output_text += std::format("KCP#{} average latency: {} ms\n", conv, kcp_mappings_pr->ingress_kcp->GetRxSRTT());
#else
		oss.clear();
		oss << "KCP#" << conv << " average latency: " << kcp_mappings_pr->ingress_kcp->GetRxSRTT() << " ms\n";
		output_text += oss.str();
#endif
	}
	locker.unlock();

	if (mux_tunnels != nullptr)
	{
		auto mux_tcp_recv_traffic = to_speed_unit(mux_tunnels->tcp_recv_traffic.exchange(0), duration_seconds);
		auto mux_tcp_send_traffic = to_speed_unit(mux_tunnels->tcp_send_traffic.exchange(0), duration_seconds);
		auto mux_udp_recv_traffic = to_speed_unit(mux_tunnels->udp_recv_traffic.exchange(0), duration_seconds);
		auto mux_udp_send_traffic = to_speed_unit(mux_tunnels->udp_send_traffic.exchange(0), duration_seconds);
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
