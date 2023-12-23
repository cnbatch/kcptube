#include "mux_tunnel.hpp"
#include "server.hpp"
#include "client.hpp"

void mux_tunnel::tcp_accept_new_income(std::shared_ptr<tcp_session> incoming_session, const std::string & remote_output_address, asio::ip::port_type remote_output_port)
{
	if (!incoming_session->is_open())
		return;

	std::shared_ptr<KCP::KCP> kcp_ptr = client_ptr->pick_one_from_kcp_channels(protocol_type::tcp);
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
			read_tcp_data_to_cache(std::move(data), data_size, incoming_session, kcp_ptr_weak, mux_records_ptr_weak);
		});
	incoming_session->when_disconnect([this, kcp_ptr, mux_records_ptr](std::shared_ptr<tcp_session> session) { client_ptr->local_disconnect(kcp_ptr, session, mux_records_ptr); });

	std::unique_lock unique_lock_id_map_to_mux_records{ mutex_id_map_to_mux_records };
	id_map_to_mux_records[complete_connection_id] = mux_records_ptr;
	unique_lock_id_map_to_mux_records.unlock();

	if (current_settings.ignore_listen_address || current_settings.ignore_listen_port)
	{
		auto data = packet::mux_tell_server_connect_address(protocol_type::tcp, new_id, remote_output_address, remote_output_port);
		std::unique_ptr<uint8_t[]> data_sptr = std::make_unique<uint8_t[]>(data.size());
		uint8_t *data_ptr = data_sptr.get();
		std::copy(data.begin(), data.end(), data_ptr);
		mux_data_cache data_cache = { std::move(data_sptr), data_ptr, data.size() };

		std::unique_lock tcp_cache_locker{ mutex_mux_tcp_cache };
		auto cache_iter = mux_tcp_cache.find(kcp_ptr_weak);
		if (cache_iter == mux_tcp_cache.end())
			return;
		cache_iter->second.emplace_back(std::move(data_cache));
		tcp_cache_locker.unlock();
	}

	incoming_session->async_read_data();
}

void mux_tunnel::read_tcp_data_to_cache(std::unique_ptr<uint8_t[]> data, size_t data_size, std::shared_ptr<tcp_session> incoming_session, std::weak_ptr<KCP::KCP> kcp_ptr_weak, std::weak_ptr<mux_records> mux_records_weak)
{
	move_cached_data_to_tunnel(true);

	if (data == nullptr || incoming_session == nullptr || data_size == 0)
		return;

	std::shared_ptr<KCP::KCP> kcp_session = kcp_ptr_weak.lock();
	if (kcp_session == nullptr)
		return;

	std::shared_ptr<mux_records> mux_records_ptr = mux_records_weak.lock();
	if (mux_records_ptr == nullptr)
		return;

	std::shared_lock tcp_cache_shared_locker{ mutex_mux_tcp_cache };
	auto cache_iter = mux_tcp_cache.find(kcp_ptr_weak);
	auto size_iter = mux_tcp_cache_max_size.find(kcp_ptr_weak);
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

	std::unique_lock tcp_cache_locker{ mutex_mux_tcp_cache };
	cache_iter = mux_tcp_cache.find(kcp_ptr_weak);
	if (cache_iter == mux_tcp_cache.end())
		return;
	cache_iter->second.emplace_back(std::move(data_cache));
	tcp_cache_locker.unlock();

	mux_records_ptr->last_data_transfer_time.store(packet::right_now());
	move_cached_data_to_tunnel();
}

void mux_tunnel::client_udp_data_to_cache(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, const std::string &remote_output_address, asio::ip::port_type remote_output_port)
{
	move_cached_data_to_tunnel();

	if (data == nullptr)
		return;

	std::shared_ptr<mux_records> mux_records_ptr = nullptr;
	std::shared_ptr<KCP::KCP> kcp_ptr = nullptr;

	if (mux_records_ptr == nullptr)
	{
		std::shared_lock shared_locker_udp_map_to_mux_records{ mutex_udp_map_to_mux_records };
		if (udp_map_to_mux_records.find(peer) == udp_map_to_mux_records.end())
		{
			shared_locker_udp_map_to_mux_records.unlock();
			std::scoped_lock lockers{ mutex_udp_map_to_mux_records, mutex_id_map_to_mux_records };
			if (udp_map_to_mux_records.find(peer) == udp_map_to_mux_records.end())
			{
				kcp_ptr = client_ptr->pick_one_from_kcp_channels(protocol_type::udp);
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
				mux_records_ptr->custom_output_port = port_number;

				if (current_settings.ignore_listen_address || current_settings.ignore_listen_port)
				{
					auto data = packet::mux_tell_server_connect_address(protocol_type::udp, new_id, remote_output_address, remote_output_port);
					std::unique_ptr<uint8_t[]> data_sptr = std::make_unique<uint8_t[]>(data.size());
					uint8_t *data_ptr = data_sptr.get();
					std::copy(data.begin(), data.end(), data_ptr);
					mux_data_cache data_cache = { std::move(data_sptr), data_ptr, data.size() };

					std::unique_lock udp_cache_locker{ mutex_mux_udp_cache };
					auto cache_iter = mux_udp_cache.find(kcp_ptr);
					if (cache_iter == mux_udp_cache.end())
						return;
					cache_iter->second.emplace_back(std::move(data_cache));
					udp_cache_locker.unlock();
				}

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
		std::shared_lock locker_kcp_channels{ client_ptr->mutex_kcp_channels };
		if (auto iter = client_ptr->kcp_channels.find(kcp_conv); iter != client_ptr->kcp_channels.end())
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

	read_udp_data_to_cache(std::move(data), data_size, mux_records_ptr.get(), kcp_ptr);
}

void mux_tunnel::server_udp_data_to_cache(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, std::weak_ptr<KCP::KCP> kcp_session_weak, std::weak_ptr<mux_records> mux_records_weak)
{
	move_cached_data_to_tunnel();

	if (data == nullptr)
		return;

	std::shared_ptr<KCP::KCP> kcp_session = kcp_session_weak.lock();
	if (kcp_session == nullptr)
		return;

	std::shared_ptr<mux_records> mux_records_ptr = mux_records_weak.lock();
	if (mux_records_ptr == nullptr)
		return;

	read_udp_data_to_cache(std::move(data), data_size, mux_records_ptr.get(), kcp_session);
}

void mux_tunnel::transfer_data(protocol_type prtcl, kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> buffer_cache, uint8_t *unbacked_data_ptr, size_t unbacked_data_size)
{
	auto [mux_connection_id, mux_data, mux_data_size] = packet::extract_mux_data_from_unpacked_data(unbacked_data_ptr, unbacked_data_size);
	std::shared_ptr<KCP::KCP> &kcp_ptr = current_settings.mode == running_mode::server ? kcp_mappings_ptr->ingress_kcp : kcp_mappings_ptr->egress_kcp;
	uint64_t complete_connection_id = ((uint64_t)kcp_ptr->GetConv() << 32) + mux_connection_id;
	std::shared_ptr<mux_records> mux_records_ptr = nullptr;

	if (current_settings.mode == running_mode::server)
	{
		std::shared_lock locker_expiring_mux_records{ mutex_expiring_mux_records };
		if (expiring_mux_records.find(complete_connection_id) != expiring_mux_records.end())
		{
			send_cancel_packet(prtcl, mux_connection_id, kcp_ptr);
			return;
		}
	}

	{
		std::shared_lock shared_locker_iter_mux_records{ mutex_id_map_to_mux_records, std::defer_lock };
		std::unique_lock unique_locker_iter_mux_records{ mutex_id_map_to_mux_records, std::defer_lock };
		shared_locker_iter_mux_records.lock();
		auto iter_mux_records = id_map_to_mux_records.find(complete_connection_id);
		if (iter_mux_records == id_map_to_mux_records.end())
		{
			shared_locker_iter_mux_records.unlock();
			unique_locker_iter_mux_records.lock();
			iter_mux_records = id_map_to_mux_records.find(complete_connection_id);
			if (iter_mux_records == id_map_to_mux_records.end())
			{
				if (current_settings.mode == running_mode::client)
				{
					send_cancel_packet(prtcl, mux_connection_id, kcp_ptr);
					return;
				}

				if (prtcl == protocol_type::tcp)
					mux_records_ptr = server_ptr->create_mux_data_tcp_connection(mux_connection_id, kcp_ptr, "", 0);
				if (prtcl == protocol_type::udp)
					mux_records_ptr = server_ptr->create_mux_data_udp_connection(mux_connection_id, kcp_ptr);

				if (mux_records_ptr == nullptr)
				{
					send_cancel_packet(prtcl, mux_connection_id, kcp_ptr);
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
		if (current_settings.mode == running_mode::server)
		{
			std::shared_ptr<udp_client> udp_channel = mux_records_ptr->local_udp;
			if (current_settings.ignore_destination_address || current_settings.ignore_destination_port)
				udp_channel->async_send_out(std::move(buffer_cache), mux_data, mux_data_size, kcp_mappings_ptr->egress_target_endpoint);
			else
				udp_channel->async_send_out(std::move(buffer_cache), mux_data, mux_data_size, *server_ptr->udp_target);
		}
		
		if (current_settings.mode == running_mode::client)
		{
			udp::endpoint udp_client_ep = mux_records_ptr->source_endpoint;
			asio::ip::port_type output_port = mux_records_ptr->custom_output_port;
			client_ptr->udp_access_points[output_port]->async_send_out(std::move(buffer_cache), mux_data, mux_data_size, udp_client_ep);
		}

		mux_records_ptr->last_data_transfer_time.store(packet::right_now());
	}
}

void mux_tunnel::delete_channel(protocol_type prtcl, kcp_mappings *kcp_mappings_ptr, uint8_t *unbacked_data_ptr, size_t unbacked_data_size)
{
	auto [mux_connection_id, mux_data, mux_data_size] = packet::extract_mux_data_from_unpacked_data(unbacked_data_ptr, unbacked_data_size);
	std::shared_ptr<KCP::KCP> &kcp_ptr = current_settings.mode == running_mode::server ? kcp_mappings_ptr->ingress_kcp : kcp_mappings_ptr->egress_kcp;
	uint64_t complete_connection_id = ((uint64_t)kcp_ptr->GetConv() << 32) + mux_connection_id;
	std::shared_ptr<mux_records> mux_records_ptr = nullptr;

	{
		std::scoped_lock locker{ mutex_id_map_to_mux_records, mutex_expiring_mux_records };
		if(current_settings.mode == running_mode::server)
			if (expiring_mux_records.find(complete_connection_id) != expiring_mux_records.end())
				return;

		auto iter_mux_records = id_map_to_mux_records.find(complete_connection_id);
		if (iter_mux_records == id_map_to_mux_records.end())
			return;

		mux_records_ptr = iter_mux_records->second;
		id_map_to_mux_records.erase(iter_mux_records);
		if (current_settings.mode == running_mode::server)
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
	}

	if (prtcl == protocol_type::udp)
	{
		if (current_settings.mode == running_mode::server)
		{
			std::shared_ptr<udp_client> &udp_channel = mux_records_ptr->local_udp;
			udp_channel->stop();
		}

		if (current_settings.mode == running_mode::client)
		{
			std::scoped_lock locker{ mutex_udp_map_to_mux_records };
			udp_map_to_mux_records.erase(mux_records_ptr->source_endpoint);
		}
	}
}

void mux_tunnel::pre_connect_custom_address(protocol_type prtcl, kcp_mappings *kcp_mappings_ptr, std::unique_ptr<uint8_t[]> buffer_cache, uint8_t *unbacked_data_ptr, size_t unbacked_data_size)
{
	auto [mux_connection_id, user_input_port, user_input_ip] = packet::extract_mux_pre_connect_from_unpacked_data(unbacked_data_ptr, unbacked_data_size);
	uint64_t complete_connection_id = ((uint64_t)kcp_mappings_ptr->ingress_kcp->GetConv() << 32) + mux_connection_id;
	std::shared_ptr<mux_records> mux_records_ptr = nullptr;

	std::shared_lock locker_expiring_mux_records{ mutex_expiring_mux_records };
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
		std::shared_lock shared_locker_iter_mux_records{ mutex_id_map_to_mux_records, std::defer_lock };
		std::unique_lock unique_locker_iter_mux_records{ mutex_id_map_to_mux_records, std::defer_lock };
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
					mux_records_ptr = server_ptr->create_mux_data_tcp_connection(mux_connection_id, kcp_mappings_ptr->ingress_kcp, user_input_ip, user_input_port);

				if (prtcl == protocol_type::udp)
				{
					asio::error_code ec;
					mux_records_ptr = server_ptr->create_mux_data_udp_connection(mux_connection_id, kcp_mappings_ptr->ingress_kcp);
					udp::resolver::results_type udp_endpoints = mux_records_ptr->local_udp->get_remote_hostname(user_input_ip, user_input_port, ec);
					asio::ip::address user_input_address = asio::ip::address::from_string(user_input_ip);

					if (ec || udp_endpoints.size() == 0 || (current_settings.ipv4_only && !user_input_address.is_v4()))
						mux_records_ptr = nullptr;
					else
						kcp_mappings_ptr->egress_target_endpoint = *udp_endpoints.begin();
				}

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
		}
	}
}

void mux_tunnel::setup_mux_kcp(std::shared_ptr<KCP::KCP> kcp_ptr)
{
	if (current_settings.mode == running_mode::server)
	{
		kcp_ptr->SetOutput([this](const char *buf, int len, void *user) -> int { return server_ptr->kcp_sender(buf, len, user); });
		kcp_ptr->SetPostUpdate([this](void *user)
			{
				if (user == nullptr) return;
				std::shared_ptr<KCP::KCP> &data_kcp = ((kcp_mappings *)user)->ingress_kcp;
				if (data_kcp == nullptr) return;
				refresh_mux_queue(data_kcp);
			});
	}

	if (current_settings.mode == running_mode::client)
	{
		kcp_ptr->SetOutput([this](const char *buf, int len, void *user) -> int { return client_ptr->kcp_sender(buf, len, user); });
		kcp_ptr->SetPostUpdate([this](void *user)
			{
				if (user == nullptr) return;
				std::shared_ptr<KCP::KCP> &data_kcp = ((kcp_mappings *)user)->egress_kcp;
				if (data_kcp == nullptr) return;
				refresh_mux_queue(data_kcp);
			});
	}

	std::scoped_lock lockers{ mutex_mux_tcp_cache, mutex_mux_udp_cache };
	mux_tcp_cache[kcp_ptr].clear();
	mux_udp_cache[kcp_ptr].clear();
	mux_tcp_cache_max_size[kcp_ptr] = kcp_ptr->GetSendWindowSize();
	mux_udp_cache_max_size[kcp_ptr] = kcp_ptr->GetSendWindowSize();
}

void mux_tunnel::move_cached_data_to_tunnel(bool skip_kcp_update)
{
	if (skip_kcp_update)
	{
		std::scoped_lock cache_lockers{ mutex_mux_tcp_cache, mutex_mux_udp_cache };
		move_cached_data_to_tunnel(mux_udp_cache, 2, nullptr);
		move_cached_data_to_tunnel(mux_tcp_cache, 1, nullptr);
		return;
	}

	thread_local std::unordered_set<std::shared_ptr<KCP::KCP>> kcp_ptr_set;
	kcp_ptr_set.clear();
	{
		thread_local std::vector<std::shared_ptr<KCP::KCP>> kcp_ptr_list;
		kcp_ptr_list.clear();
		std::scoped_lock cache_lockers{ mutex_mux_tcp_cache, mutex_mux_udp_cache };
		move_cached_data_to_tunnel(mux_udp_cache, 2, &kcp_ptr_list);
		move_cached_data_to_tunnel(mux_tcp_cache, 1, &kcp_ptr_list);

		kcp_ptr_set.insert(kcp_ptr_list.begin(), kcp_ptr_list.end());
	}

	for (std::shared_ptr<KCP::KCP> kcp_ptr : kcp_ptr_set)
	{
		uint32_t next_update_time = kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_update_time);
	}
}

void mux_tunnel::move_cached_data_to_tunnel(std::map<std::weak_ptr<KCP::KCP>, std::deque<mux_data_cache>, std::owner_less<>> &data_queues, int one_x, std::vector<std::shared_ptr<KCP::KCP>> *kcp_ptr_list)
{
	if (one_x <= 0)
		one_x = 1;

	for (auto &[kcp_ptr_weak, data_cache] : data_queues)
	{
		std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
		if (kcp_ptr == nullptr)
			continue;

		int available_spaces = (int)kcp_ptr->GetWaitQueueAvailableCapacity();
		if (available_spaces <= 0)
			continue;

		available_spaces = available_spaces / one_x - 2;
		if (available_spaces <= 0)
			continue;
		size_t pickup_size = data_cache.size();
		if (pickup_size > available_spaces)
			pickup_size = (size_t)available_spaces;

		for (size_t i = 0; i < pickup_size; i++)
		{
			mux_data_cache cached_data = std::move(data_cache.front());
			kcp_ptr->Send((const char *)cached_data.sending_ptr, cached_data.data_size);
			data_cache.pop_front();
		}

		if (kcp_ptr_list != nullptr)
			kcp_ptr_list->emplace_back(kcp_ptr);
	}
}

void mux_tunnel::refresh_mux_queue(const std::shared_ptr<KCP::KCP> &kcp_ptr)
{
	move_cached_data_to_tunnel(true);

	if (kcp_ptr == nullptr)
		return;

	std::shared_lock tcp_cache_shared_locker{ mutex_mux_tcp_cache };
	auto cache_iter = mux_tcp_cache.find(kcp_ptr);
	if (cache_iter == mux_tcp_cache.end())
		return;
	size_t tcp_cache_size = cache_iter->second.size();
	tcp_cache_shared_locker.unlock();

	if (tcp_cache_size > 0)
		return;

	std::shared_lock locker{ mutex_id_map_to_mux_records };
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

void mux_tunnel::refresh_mux_queue(std::weak_ptr<KCP::KCP> kcp_ptr_weak)
{
	std::shared_ptr<KCP::KCP> kcp_ptr = kcp_ptr_weak.lock();
	if (kcp_ptr == nullptr)
		return;

	refresh_mux_queue(kcp_ptr);
}

void mux_tunnel::delete_mux_records(uint32_t conv)
{
	std::shared_mutex &other_record_mutex = current_settings.mode == running_mode::server ? mutex_expiring_mux_records : mutex_udp_map_to_mux_records;
	std::scoped_lock locker{ mutex_id_map_to_mux_records, other_record_mutex };
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
			mux_records_ptr->local_tcp = nullptr;
		}

		if (mux_records_ptr->local_udp != nullptr && current_settings.mode == running_mode::client)
		{
			mux_records_ptr->local_udp->stop();
			mux_records_ptr->local_udp = nullptr;
		}

		id_map_to_mux_records.erase(iter);
	}

	if (current_settings.mode == running_mode::server)
	{
		for (auto iter = expiring_mux_records.begin(), next_iter = iter; iter != expiring_mux_records.end(); iter = next_iter)
		{
			++next_iter;
			uint64_t connection_id = iter->first;
			std::shared_ptr<mux_records> mux_records_ptr = iter->second;
			if (mux_records_ptr->local_tcp != nullptr)
			{
				mux_records_ptr->local_tcp->when_disconnect(empty_tcp_disconnect);
				mux_records_ptr->local_tcp->stop();
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

	if (current_settings.mode == running_mode::client)
	{
		for (auto iter = udp_map_to_mux_records.begin(), next_iter = iter; iter != udp_map_to_mux_records.end(); iter = next_iter)
		{
			++next_iter;
			std::weak_ptr mux_records_ptr_weak = iter->second;
			if (mux_records_ptr_weak.expired())
				udp_map_to_mux_records.erase(iter);
		}
	}
}

void mux_tunnel::remove_cached_kcp(std::weak_ptr<KCP::KCP> kcp_ptr)
{
	std::scoped_lock mux_locks{ mutex_mux_tcp_cache, mutex_mux_udp_cache };
	mux_tcp_cache.erase(kcp_ptr);
	mux_tcp_cache_max_size.erase(kcp_ptr);
	mux_udp_cache.erase(kcp_ptr);
	mux_udp_cache_max_size.erase(kcp_ptr);
}

void mux_tunnel::cleanup_expiring_mux_records()
{
	auto time_right_now = packet::right_now();
	std::map<uint32_t, std::vector<std::vector<uint8_t>>> waiting_for_inform;	// kcp_conv, inform_data

	{
		std::shared_mutex &other_record_mutex = current_settings.mode == running_mode::server ? mutex_expiring_mux_records : mutex_udp_map_to_mux_records;
		std::scoped_lock lockers{ mutex_id_map_to_mux_records, other_record_mutex };
		for (auto iter = id_map_to_mux_records.begin(), next_iter = iter; iter != id_map_to_mux_records.end(); iter = next_iter)
		{
			++next_iter;
			uint64_t connection_id = iter->first;
			std::shared_ptr<mux_records> mux_records_ptr = iter->second;
			std::shared_ptr<tcp_session> local_tcp = mux_records_ptr->local_tcp;
			std::shared_ptr<udp_client> local_udp = mux_records_ptr->local_udp;

			if (local_tcp != nullptr && !local_tcp->is_stop())
				continue;

			if (current_settings.mode == running_mode::server)
			{
				if (local_udp != nullptr)
				{
					if (calculate_difference(mux_records_ptr->last_data_transfer_time.load(), time_right_now) < current_settings.udp_timeout)
						continue;

					local_udp->stop();

					std::vector<uint8_t> data = packet::inform_mux_cancel_packet(protocol_type::udp, mux_records_ptr->connection_id);
					waiting_for_inform[mux_records_ptr->kcp_conv].emplace_back(std::move(data));
				}
			}

			if (current_settings.mode == running_mode::client)
			{
				if (calculate_difference(mux_records_ptr->last_data_transfer_time.load(), time_right_now) < current_settings.udp_timeout)
					continue;
				
				udp::endpoint local_udp_ep = mux_records_ptr->source_endpoint;
				if (udp_map_to_mux_records.find(local_udp_ep) != udp_map_to_mux_records.end())
				{
					udp_map_to_mux_records.erase(local_udp_ep);

					std::vector<uint8_t> data = packet::inform_mux_cancel_packet(protocol_type::udp, mux_records_ptr->connection_id);
					waiting_for_inform[mux_records_ptr->kcp_conv].emplace_back(std::move(data));
				}
			}

			id_map_to_mux_records.erase(iter);

			if (current_settings.mode == running_mode::server)
				expiring_mux_records[connection_id] = mux_records_ptr;
		}
	}

	for (auto &[kcp_conv, data_list] : waiting_for_inform)
	{
		std::shared_ptr<kcp_mappings> kcp_mappings_ptr = nullptr;
		std::shared_mutex &mutex_kcp_channels = current_settings.mode == running_mode::server ? server_ptr->mutex_kcp_channels : client_ptr->mutex_kcp_channels;
		std::unordered_map<uint32_t, std::shared_ptr<kcp_mappings>> &kcp_channels = current_settings.mode == running_mode::server ? server_ptr->kcp_channels : client_ptr->kcp_channels;
		std::shared_lock locker{ mutex_kcp_channels };
		auto iter = kcp_channels.find(kcp_conv);
		if (iter == kcp_channels.end())
			continue;
		kcp_mappings_ptr = iter->second;
		locker.unlock();
		std::shared_ptr<KCP::KCP> &kcp_ptr = current_settings.mode == running_mode::server ? kcp_mappings_ptr->ingress_kcp : kcp_mappings_ptr->egress_kcp;
		for (std::vector<uint8_t> &data : data_list)
		{
			kcp_ptr->Send((const char *)data.data(), data.size());
		}
		uint32_t next_update_time = kcp_ptr->Check();
		kcp_updater.submit(kcp_ptr, next_update_time);
	}

	if (current_settings.mode == running_mode::server)
	{
		std::scoped_lock locker_expireing_mux_records{ mutex_expiring_mux_records };
		for (auto iter = expiring_mux_records.begin(), next_iter = iter; iter != expiring_mux_records.end(); iter = next_iter)
		{
			++next_iter;
			uint64_t connection_id = iter->first;
			std::shared_ptr<mux_records> mux_records_ptr = iter->second;

			if (calculate_difference(mux_records_ptr->last_data_transfer_time.load(), time_right_now) < gbv_cleanup_waits)
				continue;

			expiring_mux_records.erase(iter);
		}
	}
}

void mux_tunnel::send_cancel_packet(protocol_type prtcl, uint32_t mux_connection_id, std::shared_ptr<KCP::KCP> kcp_ptr)
{
	std::vector<uint8_t> mux_cancel_data = packet::inform_mux_cancel_packet(prtcl, mux_connection_id);
	kcp_ptr->Send((const char *)mux_cancel_data.data(), mux_cancel_data.size());
	uint32_t next_update_time = kcp_ptr->Check();
	kcp_updater.submit(kcp_ptr, next_update_time);
}

void mux_tunnel::read_udp_data_to_cache(std::unique_ptr<uint8_t[]> data, size_t data_size, mux_records *mux_records_ptr, std::weak_ptr<KCP::KCP> kcp_ptr)
{
	std::shared_lock udp_cache_shared_locker{ mutex_mux_udp_cache };
	auto cache_iter = mux_udp_cache.find(kcp_ptr);
	auto size_iter = mux_udp_cache_max_size.find(kcp_ptr);
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

	std::unique_lock udp_cache_locker{ mutex_mux_udp_cache };
	cache_iter = mux_udp_cache.find(kcp_ptr);
	if (cache_iter == mux_udp_cache.end())
		return;
	cache_iter->second.emplace_back(std::move(data_cache));
	udp_cache_locker.unlock();

	mux_records_ptr->last_data_transfer_time.store(packet::right_now());
	move_cached_data_to_tunnel();
}
