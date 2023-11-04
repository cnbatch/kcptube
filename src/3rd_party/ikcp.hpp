//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
// Modifier: cnbatch, 2023
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
#ifndef __IKCP_HPP__
#define __IKCP_HPP__

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <vector>
#include <unordered_map>


#ifdef _MSC_VER
#pragma warning(disable:4311)
#pragma warning(disable:4312)
#pragma warning(disable:4996)
#endif


namespace KCP
{
	//=====================================================================
	// SEGMENT
	//=====================================================================
	struct segment
	{
		uint32_t conv = 0;
		uint32_t cmd = 0;
		uint32_t frg = 0;
		uint32_t wnd = 0;
		uint32_t ts = 0;
		uint32_t sn = 0;
		uint32_t una = 0;
		uint32_t len = 0;
		uint32_t resendts = 0;
		uint32_t rto = 0;
		uint32_t fastack = 0;
		uint32_t xmit = 0;
		std::unique_ptr<char[]> data;

		segment() = default;
		segment(const segment &other) = delete;
		segment(segment &&other) = default;
		segment(uint32_t new_size)
		{
			data = std::make_unique<char[]>(new_size);
			if (data != nullptr)
				len = new_size;
		}

		bool resize(uint32_t new_size)
		{
			std::unique_ptr<char[]> new_data = std::make_unique<char[]>(new_size);
			if (new_data == nullptr) return false;
			if (data != nullptr)
				std::copy_n(data.get(), len, new_data.get());
			data = std::move(new_data);
			return true;
		}
	};


	//---------------------------------------------------------------------
	// IKCPCB
	//---------------------------------------------------------------------
	struct kcp_core
	{
		uint32_t conv, mtu, mss, state;
		uint32_t snd_una, snd_nxt, rcv_nxt;
		uint32_t ts_recent, ts_lastack, ssthresh;
		int32_t rx_rttval, rx_srtt, rx_rto, rx_minrto;
		uint32_t snd_wnd, rcv_wnd, rmt_wnd, cwnd, probe;
		uint32_t current, interval, ts_flush, xmit;
		uint32_t nodelay, updated;
		uint32_t ts_probe, probe_wait;
		uint32_t dead_link, incr;
		std::list<std::unique_ptr<segment>> snd_queue;
		std::list<segment> rcv_queue;
		//std::list<std::shared_ptr<segment>> snd_buf;
		std::map<uint32_t, std::shared_ptr<segment>> snd_buf;	// SN -> segment
		std::map<uint32_t, std::unordered_map<uint32_t, std::weak_ptr<segment>>> resendts_buf;	// resendts -> segment
		std::map<uint32_t, std::unordered_map<uint32_t, std::weak_ptr<segment>>> fastack_buf;	// fastack -> segment
		std::list<segment> rcv_buf;
		std::vector<std::pair<uint32_t, uint32_t>> acklist;
		void *user;
		std::unique_ptr<char[]> buffer;
		int fastresend;
		int fastlimit;
		int nocwnd, stream;
		int logmask;
		std::function<int(const char *, int, void *)> output_callback;	// int(*output)(const char *buf, int len, void *user)
		std::function<void(const char *, void *)> writelog;	//void(*writelog)(const char *log, void *user)

		//---------------------------------------------------------------------
		// interface
		//---------------------------------------------------------------------

		kcp_core() = default;
		// create a new kcp control object, 'conv' must equal in two endpoint
		// from the same connection. 'user' will be passed to the output callback
		// output callback can be setup like this: 'kcp->output = my_udp_output'
		bool initialise(uint32_t conv, void *user);
		void move_kcp(kcp_core &other);

		kcp_core(const kcp_core&) = delete;
		kcp_core(kcp_core &&other) noexcept { move_kcp(other); }
		kcp_core operator=(const kcp_core&) = delete;
		kcp_core& operator=(kcp_core &&other) noexcept { move_kcp(other); return *this; }

		// release kcp control object
		~kcp_core() = default;

		// set output callback, which will be invoked by kcp
		void set_output(std::function<int(const char *, int, void *)> output_callback);

		// user/upper level recv: returns size, returns below zero for EAGAIN
		int receive(char *buffer, int len);

		// user/upper level send, returns below zero for error
		int send(const char *buffer, int len);

		// update state (call it repeatedly, every 10ms-100ms), or you can ask 
		// ikcp_check when to call it again (without ikcp_input/_send calling).
		// 'current' - current timestamp in millisec. 
		void update(uint32_t current);

		// Determine when should you invoke ikcp_update:
		// returns when you should invoke ikcp_update in millisec, if there 
		// is no ikcp_input/_send calling. you can call ikcp_update in that
		// time, instead of call update repeatly.
		// Important to reduce unnacessary ikcp_update invoking. use it to 
		// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
		// or optimize ikcp_update when handling massive kcp connections)
		uint32_t check(uint32_t current);

		// when you received a low level packet (eg. UDP packet), call it
		int input(const char *data, long size);

		// flush pending data
		void flush(uint32_t current = 0);

		// check the size of next message in the recv queue
		int peek_size();

		// change MTU size, default is 1400
		int set_mtu(int mtu);

		// set maximum window size: sndwnd=32, rcvwnd=32 by default
		int set_wndsize(int sndwnd, int rcvwnd);

		// get how many packet is waiting to be sent
		int get_waitsnd();

		int set_interval(int interval);

		// fastest: ikcp_nodelay(kcp, 1, 20, 2, 1)
		// nodelay: 0:disable(default), 1:enable
		// interval: internal update timer interval in millisec, default is 100ms 
		// resend: 0:disable fast resend(default), 1:enable fast resend
		// nc: 0:normal congestion control(default), 1:disable congestion control
		int set_nodelay(int nodelay, int interval, int resend, int nc);


		void ikcp_log(int mask, const char *fmt, ...);

		// read conv
		static uint32_t get_conv(const void *ptr);
		uint32_t get_conv();

	protected:
		void update_ack(int32_t rtt);
		void shrink_buf();
		void parse_ack(uint32_t sn);
		void parse_una(uint32_t una);
		void parse_fastack(uint32_t sn, uint32_t ts);
		int get_wnd_unused();
		void parse_data(segment &newseg);
		int ikcp_canlog(int mask);
		int call_output(const void *data, int size);
		char* send_out(char *ptr, char *buffer, segment *newseg);
	};
}

#define IKCP_LOG_OUTPUT			1
#define IKCP_LOG_INPUT			2
#define IKCP_LOG_SEND			4
#define IKCP_LOG_RECV			8
#define IKCP_LOG_IN_DATA		16
#define IKCP_LOG_IN_ACK			32
#define IKCP_LOG_IN_PROBE		64
#define IKCP_LOG_IN_WINS		128
#define IKCP_LOG_OUT_DATA		256
#define IKCP_LOG_OUT_ACK		512
#define IKCP_LOG_OUT_PROBE		1024
#define IKCP_LOG_OUT_WINS		2048



#endif


