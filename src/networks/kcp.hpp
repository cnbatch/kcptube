//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// Original author: skywind3000 (at) gmail.com, 2010-2011
// Modifier: cnbatch, 2021
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
#ifndef __KCP_HPP__
#define __KCP_HPP__

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <atomic>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <vector>


//=====================================================================
// QUEUE DEFINITION                                                  
//=====================================================================
#ifndef __IQUEUE_DEF__
#define __IQUEUE_DEF__


#ifdef _MSC_VER
#pragma warning(disable:4311)
#pragma warning(disable:4312)
#pragma warning(disable:4996)
#endif

#endif


namespace KCP
{
	//---------------------------------------------------------------------
	// BYTE ORDER & ALIGNMENT
	//---------------------------------------------------------------------
#ifndef IWORDS_BIG_ENDIAN
#ifdef _BIG_ENDIAN_
#if _BIG_ENDIAN_
#define IWORDS_BIG_ENDIAN 1
#endif
#endif
#ifndef IWORDS_BIG_ENDIAN
#if defined(__hppa__) || \
            defined(__m68k__) || defined(mc68000) || defined(_M_M68K) || \
            (defined(__MIPS__) && defined(__MIPSEB__)) || \
            defined(__ppc__) || defined(__POWERPC__) || defined(_M_PPC) || \
            defined(__sparc__) || defined(__powerpc__) || \
            defined(__mc68000__) || defined(__s390x__) || defined(__s390__)
#define IWORDS_BIG_ENDIAN 1
#endif
#endif
#ifndef IWORDS_BIG_ENDIAN
#define IWORDS_BIG_ENDIAN  0
#endif
#endif

#ifndef IWORDS_MUST_ALIGN
#if defined(__i386__) || defined(__i386) || defined(_i386_)
#define IWORDS_MUST_ALIGN 0
#elif defined(_M_IX86) || defined(_X86_) || defined(__x86_64__)
#define IWORDS_MUST_ALIGN 0
#elif defined(__amd64) || defined(__amd64__)
#define IWORDS_MUST_ALIGN 0
#else
#define IWORDS_MUST_ALIGN 1
#endif
#endif


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

	namespace internal_impl
	{
		//=====================================================================
		// SEGMENT
		//=====================================================================
		struct Segment
		{
			uint32_t conv = 0;
			uint32_t cmd = 0;
			uint32_t frg = 0;
			uint32_t wnd = 0;
			uint32_t ts = 0;
			uint32_t sn = 0;
			uint32_t una = 0;
			uint32_t resendts = 0;
			uint32_t rto = 0;
			uint32_t fastack = 0;
			uint32_t xmit = 0;
			size_t len = 0;
			std::unique_ptr<char[]> data = nullptr;

			Segment() = default;
			Segment(size_t sizes)
			{
				if (sizes > 0)
					data = std::make_unique<char[]>(sizes);
				len = sizes;
			}

			Segment(Segment &&other) noexcept
			{
				MoveSegment(other);
			}

			Segment& operator=(Segment &&other) noexcept
			{
				MoveSegment(other);
				return *this;
			}

		private:
			void MoveSegment(Segment &other) noexcept
			{
				this->conv = other.conv;
				this->cmd = other.cmd;
				this->frg = other.frg;
				this->wnd = other.wnd;
				this->ts = other.ts;
				this->sn = other.sn;
				this->una = other.una;
				this->resendts = other.resendts;
				this->rto = other.rto;
				this->fastack = other.fastack;
				this->xmit = other.xmit;
				this->len = other.len;
				this->data = std::move(other.data);
			}
		};
	}

	//---------------------------------------------------------------------
	// KCP
	//---------------------------------------------------------------------
	class KCP
	{
	private:
		uint32_t conv, mtu, mss, state;
		std::atomic<uint32_t> snd_una, snd_nxt, rcv_nxt;
		uint32_t ts_recent, ts_lastack, ssthresh;
		int32_t rx_rttval, rx_srtt, rx_rto, rx_minrto;
		std::atomic<uint32_t> snd_wnd, rcv_wnd, rmt_wnd, cwnd, probe;
		std::atomic<uint32_t> current, interval, ts_flush, xmit;
		uint32_t nodelay;
		uint32_t ts_probe, probe_wait;
		uint32_t dead_link;
		std::atomic<uint32_t> incr;
		std::list<internal_impl::Segment> snd_queue;
		std::list<internal_impl::Segment> rcv_queue;
		std::list<internal_impl::Segment> snd_buf;
		std::list<internal_impl::Segment> rcv_buf;
		std::vector<std::pair<uint32_t, uint32_t>> acklist;
		std::atomic<uint32_t> last_active;
		std::atomic<void*> user;
		int fastresend;
		int fastlimit;
		bool stream;
		std::atomic<bool> nocwnd, updated;
		std::vector<char> buffer;
		int logmask;
		std::shared_mutex mtx_rcv;
		std::shared_mutex mtx_snd;
		std::shared_mutex mtx_ack;
		std::function<int(const char *, int, void *)> output;	// int(*output)(const char *buf, int len, void *user)
		std::function<void(const char *, void *)> writelog;	//void(*writelog)(const char *log, void *user)

		static char * Encode8u(char *p, unsigned char c);
		static const char * Decode8u(const char *p, unsigned char *c);
		static char * Encode16u(char *p, unsigned short w);
		static const char * Decode16u(const char *p, unsigned short *w);
		static char * Encode32u(char *p, uint32_t l);
		static const char * Decode32u(const char *p, uint32_t *l);
		static char * EncodeSegment(char *ptr, const internal_impl::Segment &seg);
		void PrintQueue(const char *name, const std::list<internal_impl::Segment> &segment);
		void Initialise(uint32_t conv, void *user);
		void MoveKCP(KCP &other) noexcept;

	public:

		KCP() { Initialise(0, (void*)0); }

		KCP(const KCP &other) noexcept;

		KCP(KCP &&other) noexcept { MoveKCP(other); }

		KCP& operator=(KCP &&other) noexcept { MoveKCP(other); return *this; }
		//---------------------------------------------------------------------
		// interface
		//---------------------------------------------------------------------

		// create a new kcp control object, 'conv' must equal in two endpoint
		// from the same connection. 'user' will be passed to the output callback
		// output callback can be setup like this: 'kcp->output = my_udp_output'
		KCP(uint32_t conv, void *user) { Initialise(conv, user); }

		// release kcp control object
		~KCP() = default;

		// set output callback, which will be invoked by kcp
		// int(*output)(const char *buf, int len, void *user)
		void SetOutput(std::function<int(const char *, int, void *)> output);

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

	protected:

		int Output(const void *data, int size);
		void UpdateAck(int32_t rtt);
		void ShrinkBuffer();
		void ParseAck(uint32_t sn);
		void ParseUna(uint32_t una);
		void ParseFastAck(uint32_t sn, uint32_t ts);
		void ParseData(internal_impl::Segment &newseg);
		int WindowUnused();
		int PeekSizeWithoutLock();
	};
}


#endif


