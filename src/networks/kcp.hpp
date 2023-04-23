#pragma once
// This is a wrapper of ikcp
#ifndef __KCP_HPP__
#define __KCP_HPP__

#include <atomic>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <utility>
#include <vector>

namespace KCP
{
	class KCP;
	int proxy_output(KCP *kcp, const char *buf, int len);
	void proxy_writelog(KCP *kcp, const char *buf);

	//---------------------------------------------------------------------
	// KCP wrapper
	//---------------------------------------------------------------------
	class KCP
	{
		friend int proxy_output(KCP *kcp, const char *buf, int len);
		friend void proxy_writelog(KCP *kcp, const char *buf);
	private:
		void *ikcp_ptr;
		uint64_t outbound_bandwidth = 0;
		uint64_t inbound_bandwidth = 0;
		std::atomic<void *> custom_data;
		mutable std::shared_mutex mtx;
		std::function<int(const char *, int, void *)> output;	// int(*output)(const char *buf, int len, void *user)
		std::function<void(const char *, void *)> writelog;	//void(*writelog)(const char *log, void *user)

		void Initialise(uint32_t conv, void *user);
		void MoveKCP(KCP &other) noexcept;
		void ResetWindowValues();

	public:

		KCP() { Initialise(0, this); }

		KCP(const KCP &other) noexcept;

		KCP(KCP &&other) noexcept { MoveKCP(other); }

		KCP& operator=(KCP &&other) noexcept { MoveKCP(other); return *this; }
		//---------------------------------------------------------------------
		// interface
		//---------------------------------------------------------------------

		// create a new kcp control object, 'conv' must equal in two endpoint
		// from the same connection. 'user' will be passed to the output callback
		// output callback can be setup like this: 'kcp->output = my_udp_output'
		KCP(uint32_t conv, void *user) { Initialise(conv, this); custom_data = user; }

		// release kcp control object
		~KCP();

		// set output callback, which will be invoked by kcp
		// int(*output)(const char *buf, int len, void *user)
		void SetOutput(std::function<int(const char *, int, void *)> output_func);

		// user/upper level recv: returns size, returns below zero for EAGAIN
		int Receive(char *buffer, int len);
		int Receive(std::vector<char> &buffer);

		// user/upper level send, returns below zero for error
		int Send(const char *buffer, size_t len);

		// update state (call it repeatedly, every 10ms-100ms), or you can ask 
		// Check when to call it again (without Input/_send calling).
		// 'current' - current timestamp in millisec. 
		void Update(uint32_t current);

		// Determine when should you invoke Update:
		// returns when you should invoke Update in millisec, if there 
		// is no Input/_send calling. you can call Update in that
		// time, instead of call update repeatly.
		// Important to reduce unnacessary Update invoking. use it to 
		// schedule Update (eg. implementing an epoll-like mechanism, 
		// or optimize Update when handling massive kcp connections)
		uint32_t Check(uint32_t current);

		void ReplaceUserPtr(void *user);

		// when you received a low level packet (eg. UDP packet), call it
		int Input(const char *data, long size);

		// flush pending data
		void Flush();

		// check the size of next message in the recv queue
		int PeekSize();

		// change MTU size, default is 1400
		int SetMTU(int mtu);
		int GetMTU();

		// set maximum window size: sndwnd=32, rcvwnd=32 by default
		void SetWindowSize(int sndwnd, int rcvwnd);
		void GetWindowSize(int &sndwnd, int &rcvwnd);
		std::pair<int, int> GetWindowSize();
		int GetSendWindowSize();
		int GetReceiveWindowSize();

		// get how many packet is waiting to be sent
		int WaitingForSend();

		// fastest: NoDelay(1, 20, 2, 1)
		// nodelay: 0:disable(default), 1:enable
		// interval: internal update timer interval in millisec, default is 100ms 
		// resend: 0:disable fast resend(default), 1:enable fast resend
		// nc: 0:normal congestion control(default), 1:disable congestion control
		int NoDelay(int nodelay, int interval, int resend, bool nc);


		void WriteLog(int mask, const char *fmt, ...);

		// read conv
		static uint32_t GetConv(const void *ptr);
		uint32_t GetConv();

		// check log mask
		bool CanLog(int mask);

		int Interval(int interval);

		void SetStreamMode(bool enable);

		int32_t& RxMinRTO();
		int& LogMask();
		void SetBandwidth(uint64_t out_bw, uint64_t in_bw);
	};
}


#endif


