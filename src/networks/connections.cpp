#include <algorithm>
#include <chrono>
#include <memory>
#include <limits>
#include <random>
#include <thread>
#include "connections.hpp"

using namespace std::chrono;
using namespace std::literals;

void empty_tcp_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, std::shared_ptr<tcp_session> tmp2)
{
}

void empty_udp_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint tmp2, asio::ip::port_type tmp3)
{
}

void empty_tcp_disconnect(std::shared_ptr<tcp_session> tmp)
{
}

int empty_kcp_output(const char *, int, void *)
{
	return 0;
}

void empty_task_callback(std::unique_ptr<uint8_t[]> null_data)
{
}


std::unique_ptr<rfc3489::stun_header> send_stun_3489_request(udp_server &sender, const std::string &stun_host, bool v4_only)
{
	auto udp_version = v4_only ? udp::v4() : udp::v6();
	udp::resolver::resolver_base::flags input_flags = udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching;
	if (v4_only)
		input_flags = udp::resolver::numeric_service;
	
	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp_version, stun_host, "3478", input_flags, ec);

	if (ec)
		return nullptr;

	auto number = generate_random_number<uint64_t>();
	std::unique_ptr<rfc3489::stun_header> header = rfc3489::create_stun_header(number);
	size_t header_size = sizeof(rfc3489::stun_header);
	for (auto &target_address : remote_addresses)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)(header.get()), header_size, data.begin());
		sender.async_send_out(std::move(data), target_address);
	}

	return header;
}

std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(udp_server &sender, const std::string &stun_host, bool v4_only)
{
	auto udp_version = v4_only ? udp::v4() : udp::v6();
	udp::resolver::resolver_base::flags input_flags = udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching;
	if (v4_only)
		input_flags = udp::resolver::numeric_service;

	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp_version, stun_host, "3478", input_flags, ec);

	if (ec)
		return nullptr;

	auto number = generate_random_number<uint64_t>();
	std::unique_ptr<rfc8489::stun_header> header = rfc8489::create_stun_header(number);
	size_t header_size = sizeof(rfc8489::stun_header);

	for (auto &target_address : remote_addresses)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)header.get(), header_size, data.data());
		sender.async_send_out(std::move(data), target_address);
	}

	return header;
}

void resend_stun_8489_request(udp_server &sender, const std::string &stun_host, rfc8489::stun_header *header, bool v4_only)
{
	auto udp_version = v4_only ? udp::v4() : udp::v6();
	udp::resolver::resolver_base::flags input_flags = udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching;
	if (v4_only)
		input_flags = udp::resolver::numeric_service;

	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp_version, stun_host, "3478", input_flags, ec);

	if (ec)
		return;

	size_t header_size = sizeof(rfc8489::stun_header);
	for (auto &target_address : remote_addresses)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)header, header_size, data.data());
		sender.async_send_out(std::move(data), target_address);
	}

	return;
}

uint32_t time_now_for_kcp()
{
	return static_cast<uint32_t>((duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()) & 0xFFFF'FFFFul);
}

std::string_view feature_to_string(feature ftr)
{
	std::string_view str;
	switch (ftr)
	{
	case feature::initialise:
		str = "initialise";
		break;
	case feature::failure:
		str = "failure";
		break;
	case feature::disconnect:
		str = "disconnect";
		break;
	case feature::data:
		str = "data";
		break;
	default:
		break;
	}
	return str;
}

std::string protocol_type_to_string(protocol_type prtcl)
{
	std::string str;
	switch (prtcl)
	{
	case protocol_type::tcp:
		str = "tcp";
		break;
	case protocol_type::udp:
		str = "udp";
		break;
	default:
		str = std::to_string(int16_t(prtcl));
		break;
	}
	return str;
}

std::string debug_data_to_string(const uint8_t *data, size_t len)
{
	std::stringstream ss;
	for (int i = 0; i < len; ++i)
	{
		ss << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned short)(data[i])) << " ";
	}
	ss << "\nEND\n" << std::dec;
	return ss.str();
}

void debug_print_data(const uint8_t *data, size_t len)
{
	std::stringstream ss;
	for (int i = 0; i < len; ++i)
	{
		ss << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned short)(data[i])) << " ";
	}
	ss << "\nEND\n" << std::dec;
	std::cout << ss.str();
}

namespace packet
{
	int64_t right_now()
	{
		auto right_now = std::chrono::system_clock::now();
		return std::chrono::duration_cast<std::chrono::seconds>(right_now.time_since_epoch()).count();
	}

	std::vector<uint8_t> create_packet(feature ftr, protocol_type prtcl, const std::vector<uint8_t> &data)
	{
		auto timestamp = right_now();

		std::vector<uint8_t> new_data(sizeof(timestamp) + sizeof(uint8_t) + sizeof(uint8_t) + data.size());
		uint8_t *ptr = new_data.data();
		reinterpret_cast<decltype(timestamp)*>(ptr)[0] = timestamp;

		ptr = ptr + sizeof(timestamp);
		reinterpret_cast<uint8_t *>(ptr)[0] = static_cast<uint8_t>(ftr);

		ptr = ptr + sizeof(uint8_t);
		reinterpret_cast<uint8_t *>(ptr)[0] = static_cast<uint8_t>(prtcl);

		ptr = ptr + sizeof(uint8_t);
		if (data.size() > 0)
			std::copy(data.begin(), data.end(), ptr);

		return new_data;
	}

	size_t create_packet(feature ftr, protocol_type prtcl, uint8_t *input_data, size_t data_size)
	{
		auto timestamp = right_now();

		size_t new_size = sizeof(timestamp) + sizeof(uint8_t) + sizeof(uint8_t) + data_size;
		uint8_t new_data[BUFFER_SIZE + BUFFER_EXPAND_SIZE] = {};

		uint8_t *ptr = new_data;
		reinterpret_cast<decltype(timestamp)*>(ptr)[0] = timestamp;

		ptr = ptr + sizeof(timestamp);
		reinterpret_cast<uint8_t *>(ptr)[0] = static_cast<uint8_t>(ftr);

		ptr = ptr + sizeof(uint8_t);
		reinterpret_cast<uint8_t *>(ptr)[0] = static_cast<uint8_t>(prtcl);

		ptr = ptr + sizeof(uint8_t);
		if (data_size > 0)
			std::copy_n(input_data, data_size, ptr);

		std::copy_n(new_data, new_size, input_data);

		return new_size;
	}

	std::tuple<int64_t, feature, protocol_type, std::vector<uint8_t>> unpack(const std::vector<uint8_t> &data)
	{
		const uint8_t *ptr = data.data();
		int64_t timestamp = reinterpret_cast<const decltype(timestamp)*>(ptr)[0];
		ptr = ptr + sizeof(timestamp);

		feature ftr = (feature)reinterpret_cast<const uint8_t *>(ptr)[0];
		ptr = ptr + sizeof(uint8_t);

		protocol_type prtcl = (protocol_type)reinterpret_cast<const uint8_t *>(ptr)[0];
		ptr = ptr + sizeof(uint8_t);

		size_t data_size = data.size() - (ptr - data.data());

		return { timestamp, ftr, prtcl, std::vector<uint8_t>(ptr, ptr + data_size) };
	}

	std::tuple<int64_t, feature, protocol_type, uint8_t*, size_t> unpack(uint8_t *data, size_t length)
	{
		uint8_t *ptr = data;
		int64_t timestamp = reinterpret_cast<decltype(timestamp)*>(ptr)[0];
		ptr = ptr + sizeof(timestamp);

		feature ftr = (feature)reinterpret_cast<uint8_t *>(ptr)[0];
		ptr = ptr + sizeof(uint8_t);

		protocol_type prtcl = (protocol_type)reinterpret_cast<uint8_t *>(ptr)[0];
		ptr = ptr + sizeof(uint8_t);

		size_t data_size = length - (ptr - data);

		return { timestamp, ftr, prtcl, ptr, data_size };
	}

	std::tuple<uint32_t, uint16_t, uint16_t> get_initialise_details_from_unpacked_data(const std::vector<uint8_t> &data)
	{
		const uint8_t *ptr = data.data();
		uint32_t uid = reinterpret_cast<const decltype(uid)*>(ptr)[0];
		ptr = ptr + sizeof(uid);

		uint16_t port_start = reinterpret_cast<const decltype(port_start)*>(ptr)[0];
		ptr = ptr + sizeof(port_start);

		uint16_t port_end = reinterpret_cast<const decltype(port_end) *>(ptr)[0];

		return { uid, port_start, port_end };
	}

	std::tuple<uint32_t, uint16_t, uint16_t> get_initialise_details_from_unpacked_data(const uint8_t *data)
	{
		const uint8_t *ptr = data;
		uint32_t uid = reinterpret_cast<const decltype(uid)*>(ptr)[0];
		ptr = ptr + sizeof(uid);

		uint16_t port_start = reinterpret_cast<const decltype(port_start)*>(ptr)[0];
		ptr = ptr + sizeof(port_start);

		uint16_t port_end = reinterpret_cast<const decltype(port_end) *>(ptr)[0];

		return { uid, port_start, port_end };
	}

	std::vector<uint8_t> request_initialise_packet(protocol_type prtcl)
	{
		return create_packet(feature::initialise, prtcl, std::vector<uint8_t>(empty_data_size));
	}

	std::vector<uint8_t> response_initialise_packet(protocol_type prtcl, uint32_t uid, uint16_t port_start, uint16_t port_end)
	{
		std::vector<uint8_t> data(sizeof(uid) + sizeof(port_start) + sizeof(port_end));
		uint8_t *ptr = data.data();

		reinterpret_cast<decltype(uid) *>(ptr)[0] = uid;
		ptr = ptr + sizeof(uid);

		reinterpret_cast<decltype(port_start) *>(ptr)[0] = port_start;
		ptr = ptr + sizeof(port_start);

		reinterpret_cast<decltype(port_end) *>(ptr)[0] = port_end;

		return create_packet(feature::initialise, prtcl, data);
	}

	std::vector<uint8_t> inform_disconnect_packet(protocol_type prtcl)
	{
		return create_packet(feature::disconnect, prtcl, std::vector<uint8_t>(empty_data_size));
	}

	std::vector<uint8_t> inform_error_packet(protocol_type prtcl, const std::string &error_msg)
	{
		std::vector<uint8_t> message(error_msg.size() + 1);
		std::copy(error_msg.begin(), error_msg.end(), message.begin());
		return create_packet(feature::failure, prtcl, message);
	}

	std::vector<uint8_t> create_data_packet(protocol_type prtcl, const std::vector<uint8_t> &custom_data)
	{
		return create_packet(feature::data, prtcl, custom_data);
	}

	size_t create_data_packet(protocol_type prtcl, uint8_t *custom_data, size_t length)
	{
		return create_packet(feature::data, prtcl, custom_data, length);
	}

	std::vector<uint8_t> create_keep_alive_packet(protocol_type prtcl)
	{
		return create_packet(feature::keep_alive, prtcl, std::vector<uint8_t>(empty_data_size));
	}

	std::string get_error_message_from_unpacked_data(const std::vector<uint8_t> &data)
	{
		return std::string((const char *)data.data(), data.size());
	}

	std::string get_error_message_from_unpacked_data(uint8_t *data, size_t length)
	{
		return std::string((const char *)data, length);
	}

	std::tuple<uint32_t, std::vector<uint8_t>> get_confirm_data_from_unpacked_data(const std::vector<uint8_t> &data)
	{
		const uint8_t *ptr = data.data();
		uint32_t uid;
		uid = *(const uint32_t *)ptr;
		ptr = ptr + sizeof(uid);

		size_t data_size = data.size() - (ptr - data.data());

		return { uid, std::vector<uint8_t>(ptr, ptr + data_size) };
	}

	std::tuple<uint32_t, uint8_t*, size_t> get_confirm_data_from_unpacked_data(uint8_t *data, size_t length)
	{
		uint8_t *ptr = data;
		uint32_t uid;
		uid = *(const uint32_t *)ptr;
		ptr = ptr + sizeof(uid);

		size_t data_size = length - (ptr - data);

		return { uid, ptr, data_size };
	}
}	// namespace packet




void tcp_session::start()
{
	async_read_data();
}

void tcp_session::session_is_ending(bool set_ending)
{
	session_ending.store(set_ending);
}

bool tcp_session::session_is_ending()
{
	return session_ending.load();
}

void tcp_session::pause(bool set_as_pause)
{
	bool expect = set_as_pause;
	if (paused.compare_exchange_strong(expect, set_as_pause))
		return;
	paused.store(set_as_pause);
	async_read_data();
}

void tcp_session::stop()
{
	stopped.store(true);
	callback = empty_tcp_callback;
	if (is_open())
		connection_socket.close();
}

bool tcp_session::is_pause()
{
	return paused.load();
}

bool tcp_session::is_stop()
{
	return stopped.load();
}

bool tcp_session::is_open()
{
	return connection_socket.is_open();
}

void tcp_session::disconnect()
{
	asio::error_code ec;
	connection_socket.shutdown(asio::socket_base::shutdown_both, ec);
	connection_socket.close(ec);
}

void tcp_session::async_read_data()
{
	if (paused.load() || stopped.load())
		return;

	std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique<uint8_t[]>(BUFFER_SIZE);
	auto asio_buffer = asio::buffer(buffer_cache.get(), BUFFER_SIZE);
	asio::async_read(connection_socket, asio_buffer, asio::transfer_at_least(1),
		[data = std::move(buffer_cache), this, sptr = shared_from_this()](const asio::error_code &error, std::size_t bytes_transferred) mutable
		{
			after_read_completed(std::move(data), error, bytes_transferred);
		});
}

size_t tcp_session::send_data(const std::vector<uint8_t> &buffer_data)
{
	if (stopped.load())
		return 0;

	size_t sent_size = connection_socket.send(asio::buffer(buffer_data));
	last_send_time.store(packet::right_now());
	return sent_size;
}

size_t tcp_session::send_data(const uint8_t *buffer_data, size_t size_in_bytes)
{
	if (stopped.load() || buffer_data == nullptr)
		return 0;

	size_t sent_size = connection_socket.send(asio::buffer(buffer_data, size_in_bytes));
	last_send_time.store(packet::right_now());
	return sent_size;
}

size_t tcp_session::send_data(const uint8_t *buffer_data, size_t size_in_bytes, asio::error_code &ec)
{
	if (stopped.load() || buffer_data == nullptr)
		return 0;

	size_t sent_size = connection_socket.send(asio::buffer(buffer_data, size_in_bytes), 0, ec);
	last_send_time.store(packet::right_now());
	return sent_size;
}

void tcp_session::async_send_data(std::unique_ptr<std::vector<uint8_t>> data)
{
	if (stopped.load() || data == nullptr)
		return;

	auto asio_buffer = asio::buffer(*data);
	asio::async_write(connection_socket, asio_buffer,
		[this, data_ = std::move(data), sptr = shared_from_this()](const asio::error_code& error, size_t bytes_transferred)
		{
			after_write_completed(error, bytes_transferred);
		});
}

void tcp_session::async_send_data(std::vector<uint8_t> &&data)
{
	if (stopped.load())
		return;

	auto asio_buffer = asio::buffer(data);
	asio::async_write(connection_socket, asio_buffer,
		[this, data_ = std::move(data), sptr = shared_from_this()](const asio::error_code &error, size_t bytes_transferred)
	{ after_write_completed(error, bytes_transferred); });
}

void tcp_session::async_send_data(std::unique_ptr<uint8_t[]> buffer_data, size_t size_in_bytes)
{
	if (stopped.load() || buffer_data == nullptr)
		return;

	auto asio_buffer = asio::buffer(buffer_data.get(), size_in_bytes);
	asio::async_write(connection_socket, asio_buffer,
		[this, buffer_ptr = std::move(buffer_data), sptr = shared_from_this()](const asio::error_code &error, size_t bytes_transferred)
	{ after_write_completed(error, bytes_transferred); });
}

void tcp_session::async_send_data(std::unique_ptr<uint8_t[]> buffer_data, uint8_t *start_pos, size_t size_in_bytes)
{
	if (stopped.load() || buffer_data == nullptr || start_pos == nullptr)
		return;

	asio::async_write(connection_socket, asio::buffer(start_pos, size_in_bytes),
		[this, buffer_ptr = std::move(buffer_data), sptr = shared_from_this()](const asio::error_code &error, size_t bytes_transferred)
	{ after_write_completed(error, bytes_transferred); });
}

void tcp_session::async_send_data(const uint8_t *buffer_data, size_t size_in_bytes)
{
	if (stopped.load() || buffer_data == nullptr)
		return;

	asio::async_write(connection_socket, asio::buffer(buffer_data, size_in_bytes),
		std::bind(&tcp_session::after_write_completed, this,
			std::placeholders::_1, std::placeholders::_2));
}

void tcp_session::when_disconnect(std::function<void(std::shared_ptr<tcp_session>)> callback_before_disconnect)
{
	callback_for_disconnect = callback_before_disconnect;
}

void tcp_session::replace_callback(tcp_callback_t callback_func)
{
	callback = callback_func;
}

tcp::socket& tcp_session::socket()
{
	return connection_socket;
}

int64_t tcp_session::time_gap_of_receive()
{
	return calculate_difference(packet::right_now(), last_receive_time.load());
}

int64_t tcp_session::time_gap_of_send()
{
	return calculate_difference(packet::right_now(), last_send_time.load());
}

void tcp_session::after_write_completed(const asio::error_code &error, size_t bytes_transferred)
{
	if (stopped.load())
		return;

	if (error)
	{
		callback_for_disconnect(shared_from_this());
		if (connection_socket.is_open())
			this->disconnect();
		return;
	}
	last_send_time.store(packet::right_now());
}

void tcp_session::after_read_completed(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, size_t bytes_transferred)
{
	if (stopped.load())
		return;

	if (error)
	{
		callback_for_disconnect(shared_from_this());
		if (connection_socket.is_open())
			this->disconnect();
		return;
	}

	last_receive_time.store(packet::right_now());
	async_read_data();

	if (buffer_cache == nullptr || bytes_transferred == 0)
		return;

	if (BUFFER_SIZE - bytes_transferred < BUFFER_EXPAND_SIZE)
	{
		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE + BUFFER_EXPAND_SIZE);
		std::copy_n(buffer_cache.get(), bytes_transferred, new_buffer.get());
		buffer_cache.swap(new_buffer);
	}

	if (sequence_task_pool != nullptr)
	{
		size_t pointer_to_number = (size_t)this;
		sequence_task_pool->push_task(pointer_to_number, [this, bytes_transferred, self_shared = shared_from_this()](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, self_shared); },
			std::move(buffer_cache));
	}
	else if (task_assigner != nullptr)
	{
		task_assigner->push_task([this, bytes_transferred, self_shared = shared_from_this()](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, self_shared); },
			std::move(buffer_cache));
	}
	else
	{
		callback(std::move(buffer_cache), bytes_transferred, shared_from_this());
	}
}



void tcp_server::acceptor_initialise(const tcp::endpoint &ep)
{
	asio::ip::v6_only v6_option(false);
	asio::socket_base::keep_alive keep_alive_option(true);
	tcp_acceptor.open(ep.protocol());
	if (ep.address().is_v6())
		tcp_acceptor.set_option(v6_option);
	tcp_acceptor.set_option(keep_alive_option);
	tcp_acceptor.set_option(tcp::no_delay(true));
	tcp_acceptor.bind(ep);
	tcp_acceptor.listen(tcp_acceptor.max_connections);
}

void tcp_server::start_accept()
{
	std::shared_ptr<tcp_session> new_connection;
	if (sequence_task_pool != nullptr)
		new_connection = std::make_shared<tcp_session>(internal_io_context, *sequence_task_pool, task_limit, session_callback);
	else if (task_assigner != nullptr)
		new_connection = std::make_shared<tcp_session>(internal_io_context, *task_assigner, task_limit, session_callback);
	else
		new_connection = std::make_shared<tcp_session>(internal_io_context, session_callback);

	tcp_acceptor.async_accept(new_connection->socket(),
		[this, new_connection](const asio::error_code &error_code)
	{
		handle_accept(new_connection, error_code);
	});
}

void tcp_server::handle_accept(std::shared_ptr<tcp_session> new_connection, const asio::error_code &error_code)
{
	if (error_code)
	{
		if (!tcp_acceptor.is_open())
			return;
	}

	start_accept();
	acceptor_callback(new_connection);
}



std::shared_ptr<tcp_session> tcp_client::connect(asio::error_code &ec)
{
	std::shared_ptr<tcp_session> new_connection;
	if (sequence_task_pool != nullptr)
		new_connection = std::make_shared<tcp_session>(internal_io_context, *sequence_task_pool, task_limit, session_callback);
	else if (task_assigner != nullptr && sequence_task_pool != nullptr)
		new_connection = std::make_shared<tcp_session>(internal_io_context, *task_assigner, task_limit, session_callback);
	else
		new_connection = std::make_shared<tcp_session>(internal_io_context, session_callback);

	tcp::socket &current_socket = new_connection->socket();
	for (auto &endpoint_entry : remote_endpoints)
	{
		current_socket.open(endpoint_entry.endpoint().protocol());
		current_socket.set_option(asio::socket_base::keep_alive(true));
		current_socket.set_option(tcp::no_delay(true));
		if (endpoint_entry.endpoint().protocol() == tcp::v6())
			current_socket.set_option(asio::ip::v6_only(false));
		current_socket.connect(endpoint_entry, ec);
		if (!ec)
			break;
		current_socket.close();
	}
	return new_connection;
}

bool tcp_client::set_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec)
{
	return set_remote_hostname(remote_address, std::to_string(port_num), ec);
}

bool tcp_client::set_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec)
{
	auto tcp_version = ipv4_only ? tcp::v4() : tcp::v6();
	tcp::resolver::resolver_base::flags input_flags = tcp::resolver::numeric_service | tcp::resolver::v4_mapped | tcp::resolver::all_matching;
	if (ipv4_only)
		input_flags = tcp::resolver::numeric_service;

	remote_endpoints = resolver.resolve(tcp_version, remote_address, port_num, input_flags, ec);

	return remote_endpoints.size() > 0;
}



void udp_server::continue_receive()
{
	start_receive();
}

void udp_server::async_send_out(std::unique_ptr<std::vector<uint8_t>> data, const udp::endpoint &client_endpoint)
{
	if (data == nullptr)
		return;
	auto asio_buffer = asio::buffer(*data);
	connection_socket.async_send_to(asio_buffer, client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::unique_ptr<uint8_t[]> data, uint8_t *start_pos, size_t data_size, const udp::endpoint &client_endpoint)
{
	if (data == nullptr)
		return;
	connection_socket.async_send_to(asio::buffer(start_pos, data_size), client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &client_endpoint)
{
	if (data == nullptr)
		return;
	auto asio_buffer = asio::buffer(data.get(), data_size);
	connection_socket.async_send_to(asio_buffer, client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &client_endpoint)
{
	auto asio_buffer = asio::buffer(data);
	connection_socket.async_send_to(asio_buffer, client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}


void udp_server::initialise(const udp::endpoint &ep)
{
	asio::ip::v6_only v6_option(false);
	connection_socket.open(ep.protocol());
	if (ep.address().is_v6())
		connection_socket.set_option(v6_option);
	connection_socket.bind(ep);
}

void udp_server::start_receive()
{
	std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique<uint8_t[]>(BUFFER_SIZE);
	auto asio_buffer = asio::buffer(buffer_cache.get(), BUFFER_SIZE);
	connection_socket.async_receive_from(asio_buffer, incoming_endpoint,
		[buffer_ptr = std::move(buffer_cache), this](const asio::error_code &error, std::size_t bytes_transferred) mutable
		{
			handle_receive(std::move(buffer_ptr), error, bytes_transferred);
		});
}

void udp_server::handle_receive(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred)
{
	if (error)
	{
		if (!connection_socket.is_open())
			return;
	}

	udp::endpoint copy_of_incoming_endpoint = incoming_endpoint;
	start_receive();

	if (buffer_cache == nullptr || bytes_transferred == 0)
		return;

	if (BUFFER_SIZE - bytes_transferred < BUFFER_EXPAND_SIZE)
	{
		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE + BUFFER_EXPAND_SIZE);
		std::copy_n(buffer_cache.get(), bytes_transferred, new_buffer.get());
		buffer_cache.swap(new_buffer);
	}

	if (sequence_task_pool != nullptr)
	{
		size_t pointer_to_number = (size_t)this;
		if (task_limit > 0 && sequence_task_pool->get_task_count(pointer_to_number) > task_limit)
			return;
		sequence_task_pool->push_task(pointer_to_number, [this, bytes_transferred, copy_of_incoming_endpoint](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, copy_of_incoming_endpoint, port_number); },
			std::move(buffer_cache));
	}
	else if (task_assigner != nullptr)
	{
		if (task_limit > 0 && task_assigner->get_task_count() > task_limit)
			return;
		task_assigner->push_task([this, bytes_transferred, copy_of_incoming_endpoint](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, copy_of_incoming_endpoint, port_number); },
			std::move(buffer_cache));
	}
	else
	{
		callback(std::move(buffer_cache), bytes_transferred, copy_of_incoming_endpoint, port_number);
	}
}

asio::ip::port_type udp_server::get_port_number()
{
	return port_number;
}





void udp_client::pause(bool set_as_pause)
{
	bool expect = set_as_pause;
	if (paused.compare_exchange_strong(expect, set_as_pause))
		return;
	paused.store(set_as_pause);
	start_receive();
}

void udp_client::stop()
{
	stopped.store(true);
	callback = empty_udp_callback;
	this->disconnect();
}

bool udp_client::is_pause()
{
	return paused.load();
}

bool udp_client::is_stop()
{
	return stopped.load();
}

udp::resolver::results_type udp_client::get_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec)
{
	return get_remote_hostname(remote_address, std::to_string(port_num), ec);
}

udp::resolver::results_type udp_client::get_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec)
{
	if (ipv4_only)
		return resolver.resolve(udp::v4(), remote_address, port_num,
			udp::resolver::numeric_service | udp::resolver::address_configured, ec);
	else
		return resolver.resolve(udp::v6(), remote_address, port_num,
			udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching, ec);
}

void udp_client::disconnect()
{
	asio::error_code ec;
	connection_socket.close(ec);
}

void udp_client::async_receive()
{
	if (paused.load() || stopped.load())
		return;
	start_receive();
}

size_t udp_client::send_out(const std::vector<uint8_t> &data, const udp::endpoint &peer_endpoint, asio::error_code &ec)
{
	if (stopped.load())
		return 0;

	size_t sent_size = connection_socket.send_to(asio::buffer(data), peer_endpoint, 0, ec);
	last_send_time.store(packet::right_now());
	return sent_size;
}

size_t udp_client::send_out(const uint8_t *data, size_t size, const udp::endpoint &peer_endpoint, asio::error_code &ec)
{
	if (stopped.load() || data == nullptr)
		return 0;

	size_t sent_size = connection_socket.send_to(asio::buffer(data, size), peer_endpoint, 0, ec);
	last_send_time.store(packet::right_now());
	return sent_size;
}

void udp_client::async_send_out(std::unique_ptr<std::vector<uint8_t>> data, const udp::endpoint &peer_endpoint)
{
	if (stopped.load() || data == nullptr)
		return;

	auto asio_buffer = asio::buffer(*data);
	connection_socket.async_send_to(asio_buffer, peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(packet::right_now());
}

void udp_client::async_send_out(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer_endpoint)
{
	if (stopped.load() || data == nullptr)
		return;

	auto asio_buffer = asio::buffer(data.get(), data_size);
	connection_socket.async_send_to(asio_buffer, peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(packet::right_now());
}

void udp_client::async_send_out(std::unique_ptr<uint8_t[]> data, uint8_t *start_pos, size_t data_size, const udp::endpoint &peer_endpoint)
{
	if (stopped.load() || data == nullptr)
		return;

	connection_socket.async_send_to(asio::buffer(start_pos, data_size), peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(packet::right_now());
}

void udp_client::async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &peer_endpoint)
{
	if (stopped.load())
		return;

	auto asio_buffer = asio::buffer(data);
	connection_socket.async_send_to(asio_buffer, peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(packet::right_now());
}

int64_t udp_client::time_gap_of_receive()
{
	return calculate_difference(packet::right_now(), last_receive_time.load());
}

int64_t udp_client::time_gap_of_send()
{
	return calculate_difference(packet::right_now(), last_send_time.load());
}

void udp_client::initialise()
{
	asio::ip::v6_only v6_option(false);
	connection_socket.open(udp::v6());
	if (!ipv4_only)
		connection_socket.set_option(v6_option);
}

void udp_client::start_receive()
{
	if (paused.load() || stopped.load())
		return;

	std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique<uint8_t[]>(BUFFER_SIZE);

	auto asio_buffer = asio::buffer(buffer_cache.get(), BUFFER_SIZE);
	connection_socket.async_receive_from(asio_buffer, incoming_endpoint,
		[buffer_ptr = std::move(buffer_cache), this](const asio::error_code &error, std::size_t bytes_transferred) mutable
		{
			handle_receive(std::move(buffer_ptr), error, bytes_transferred);
		});
}

void udp_client::handle_receive(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred)
{
	if (stopped.load() || buffer_cache == nullptr)
		return;

	if (error)
	{
		if (connection_socket.is_open())
			start_receive();
		return;
	}

	last_receive_time.store(packet::right_now());
	udp::endpoint copy_of_incoming_endpoint = incoming_endpoint;
	asio::error_code ec;
	start_receive();

	if (buffer_cache == nullptr || bytes_transferred == 0)
		return;

	if (BUFFER_SIZE - bytes_transferred < BUFFER_EXPAND_SIZE)
	{
		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE + BUFFER_EXPAND_SIZE);
		std::copy_n(buffer_cache.get(), bytes_transferred, new_buffer.get());
		buffer_cache.swap(new_buffer);
	}

	if (sequence_task_pool != nullptr)
	{
		size_t pointer_to_number = (size_t)this;
		if (task_limit > 0 && sequence_task_pool->get_task_count(pointer_to_number) > task_limit)
			return;
		sequence_task_pool->push_task(pointer_to_number, [this, bytes_transferred, copy_of_incoming_endpoint](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, copy_of_incoming_endpoint, 0); },
			std::move(buffer_cache));
	}
	else if (task_assigner != nullptr)
	{
		if (task_limit > 0 && task_assigner->get_task_count() > task_limit)
			return;
		task_assigner->push_task([this, bytes_transferred, copy_of_incoming_endpoint](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, copy_of_incoming_endpoint, 0); },
			std::move(buffer_cache));
	}
	else
	{
		callback(std::move(buffer_cache), bytes_transferred, copy_of_incoming_endpoint, 0);
	}
}
