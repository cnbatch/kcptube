#pragma once
#include <atomic>             // std::atomic
#include <condition_variable> // std::condition_variable
#include <exception>          // std::current_exception
#include <memory>             // std::make_shared, std::make_unique, std::shared_ptr, std::unique_ptr
#include <mutex>              // std::mutex, std::scoped_lock, std::unique_lock
#include <map>
#include <thread>             // std::thread
#include <type_traits>        // std::common_type_t, std::decay_t, std::invoke_result_t, std::is_void_v
#include <utility>            // std::forward, std::move, std::swap
#include <numeric>
#include "kcp.hpp"

#ifndef __KCP_UPDATER_HPP__
#define __KCP_UPDATER_HPP__

namespace KCP
{
	using concurrency_t = std::invoke_result_t<decltype(std::thread::hardware_concurrency)>;

	class [[nodiscard]] KCPUpdater
	{
		using task_queue = std::list<std::pair<std::weak_ptr<KCP>, std::weak_ptr<std::atomic<uint32_t>>>>;

	public:
		// ============================
		// Constructors and destructors
		// ============================

		/**
		* @brief Construct a new thread pool.
		*
		* @param thread_count_ The number of threads to use. The default value is the total number of hardware threads available, as reported by the implementation. This is usually determined by the number of cores in the CPU. If a core is hyperthreaded, it will count as two threads.
		*/
		KCPUpdater() : kcp_thread(std::make_unique<std::thread>())
		{
			create_thread();
		}

		KCPUpdater(const KCPUpdater &) = delete;
		KCPUpdater(KCPUpdater &&) = delete;

		/**
		* @brief Destruct the thread pool. Waits for all tasks to complete, then destroys all threads.
		*/
		~KCPUpdater()
		{
			wait_for_tasks();
			destroy_threads();
		}

		// =======================
		// Public member functions
		// =======================

		[[nodiscard]]
		size_t get_task_count() const
		{
			return kcp_tasks_total.load();
		}

		[[nodiscard]]
		size_t get_kcp_count() const;

		void submit(std::weak_ptr<KCP> kcp_ptr, uint32_t next_update_time);

		void remove(std::weak_ptr<KCP> kcp_ptr);

		/**
		* @brief Wait for tasks to be completed. Normally, this function waits for all tasks, both those that are currently running in the threads and those that are still waiting in the queue. Note: To wait for just one specific task, use submit() instead, and call the wait() member function of the generated future.
		*/
		void wait_for_tasks();

	private:
		// ========================
		// Private member functions
		// ========================

		/**
		* @brief Create the threads in the pool and assign a worker to each thread.
		*/
		void create_thread()
		{
			running = true;
			*kcp_thread = std::thread(&KCPUpdater::kcp_update_worker, this);
		}

		/**
		* @brief Destroy the threads in the pool.
		*/
		void destroy_threads();

		/**
		* @brief A worker function to be assigned to each thread in the pool. Waits until it is notified by push_task() that a task is available, and then retrieves the task from the queue and executes it. Once the task finishes, the worker notifies wait_for_tasks() in case it is waiting.
		*/
		void kcp_update_worker();

		// ============
		// Private data
		// ============

		std::condition_variable kcp_tasks_available_cv = {};
		std::condition_variable kcp_tasks_done_cv = {};
		//std::map<std::weak_ptr<KCP>, uint32_t, std::owner_less<>> pile_of_kcp = {};	// uint32_t is for storing next update time
		std::map<uint32_t, std::set<std::weak_ptr<KCP>, std::owner_less<>>> kcp_time_list;
		std::set<std::weak_ptr<KCP>, std::owner_less<>> expired_kcp;
		std::atomic<size_t> kcp_tasks_total = 0;
		mutable std::mutex kcp_tasks_mutex = {};
		std::unique_ptr<std::thread> kcp_thread = nullptr;
		std::atomic<bool> running = false;
		std::atomic<bool> waiting = false;

		std::atomic<uint32_t> nearest_update_time{std::numeric_limits<uint32_t>::max()};
	};

}

#endif