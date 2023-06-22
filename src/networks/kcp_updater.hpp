#pragma once
#include <atomic>             // std::atomic
#include <condition_variable> // std::condition_variable
#include <exception>          // std::current_exception
#include <future>             // std::future, std::promise
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

	using task_queue = std::map<std::weak_ptr<KCP>, uint32_t, std::owner_less<>>;
	using task_queue_ref = std::map<std::weak_ptr<KCP>, uint32_t, std::owner_less<>>;
	
	class [[nodiscard]] KCPUpdater
	{
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
			return tasks_total.load();
		}

		void submit(std::weak_ptr<KCP> kcp_ptr, uint32_t next_update_time)
		{
			{
				std::scoped_lock tasks_lock(tasks_mutex);
				tasks[kcp_ptr] = next_update_time;
				tasks_total.store(tasks.size());
			}

			if (nearest_update_time.load() > next_update_time)
			{
				task_available_cv.notify_one();
			}
		}

		//void direct_submit(std::weak_ptr<KCP> kcp_ptr, uint32_t next_update_time)
		//{
		//	tasks[kcp_ptr] = next_update_time;
		//	tasks_total.store(tasks.size());
		//}

		void remove(std::weak_ptr<KCP> kcp_ptr)
		{
			std::scoped_lock tasks_lock(tasks_mutex);
			auto iter = tasks.find(kcp_ptr);
			if (iter == tasks.end())
				return;
			tasks.erase(iter);
			tasks_total.store(tasks.size());
		}

		//void direct_remove(std::weak_ptr<KCP> kcp_ptr)
		//{
		//	auto iter = tasks.find(kcp_ptr);
		//	if (iter == tasks.end())
		//		return;
		//	tasks.erase(iter);
		//	tasks_total.store(tasks.size());
		//}

		/**
		* @brief Wait for tasks to be completed. Normally, this function waits for all tasks, both those that are currently running in the threads and those that are still waiting in the queue. Note: To wait for just one specific task, use submit() instead, and call the wait() member function of the generated future.
		*/
		void wait_for_tasks()
		{
			if (!waiting)
			{
				waiting = true;
				std::unique_lock<std::mutex> tasks_lock(tasks_mutex);
				task_done_cv.wait(tasks_lock, [this] { return (tasks_total == 0); });
				waiting = false;
			}
		}

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
			*kcp_thread = std::thread(&KCPUpdater::worker, this);
		}

		/**
		* @brief Destroy the threads in the pool.
		*/
		void destroy_threads()
		{
			running = false;
			{
				const std::scoped_lock tasks_lock(tasks_mutex);
				task_available_cv.notify_all();
			}
			kcp_thread->join();
		}

		/**
		* @brief A worker function to be assigned to each thread in the pool. Waits until it is notified by push_task() that a task is available, and then retrieves the task from the queue and executes it. Once the task finishes, the worker notifies wait_for_tasks() in case it is waiting.
		*/
		void worker()
		{
			while (running)
			{
				uint32_t kcp_refresh_time = TimeNowForKCP();
				uint32_t smallest_refresh_time = std::numeric_limits<uint32_t>::max();
				int64_t wait_time = std::abs((int64_t)(kcp_refresh_time) - (int64_t)(nearest_update_time.load()));
				task_queue kcp_task_without_lock;
				{
					std::unique_lock tasks_lock(tasks_mutex);
					task_available_cv.wait_for(tasks_lock, std::chrono::milliseconds{wait_time});
					if (running)
					{
						kcp_refresh_time = TimeNowForKCP();
						for (auto iter = tasks.begin(), next_iter = iter; iter != tasks.end(); iter = next_iter)
						{
							++next_iter;
							std::shared_ptr<KCP> kcp_ptr = iter->first.lock();
							if (kcp_ptr == nullptr)
							{
								tasks.erase(iter);
								tasks_total.store(tasks.size());
								continue;
							}
							uint32_t kcp_update_time = iter->second;
							kcp_task_without_lock[kcp_ptr] = kcp_update_time;

							if (smallest_refresh_time > kcp_update_time)
								smallest_refresh_time = kcp_update_time;
						}

						nearest_update_time.store(smallest_refresh_time);

						if (tasks.empty())
							nearest_update_time.store(std::numeric_limits<uint32_t>::max());
					}
				}

				kcp_refresh_time = TimeNowForKCP();
				smallest_refresh_time = std::numeric_limits<uint32_t>::max();
				for (auto iter = kcp_task_without_lock.begin(), next_iter = iter; iter != kcp_task_without_lock.end(); iter = next_iter)
				{
					++next_iter;
					std::shared_ptr<KCP> kcp_ptr = iter->first.lock();
					if (kcp_ptr == nullptr)
					{
						kcp_task_without_lock.erase(iter);
						continue;
					}
					uint32_t &kcp_update_time = iter->second;

					if (kcp_refresh_time >= kcp_update_time)
					{
						kcp_ptr->Update(kcp_refresh_time);
						kcp_update_time = kcp_ptr->Check(kcp_refresh_time);
					}

					if (smallest_refresh_time > kcp_update_time)
						smallest_refresh_time = kcp_update_time;
				}

				nearest_update_time.store(smallest_refresh_time);

				std::unique_lock tasks_lock(tasks_mutex);
				for (auto &[kcp_ptr, kcp_update_time] : kcp_task_without_lock)
				{
					auto iter = tasks.find(kcp_ptr);
					if (iter == tasks.end())
						continue;

					iter->second = kcp_update_time;
				}
				if (tasks.empty())
					nearest_update_time.store(std::numeric_limits<uint32_t>::max());
				tasks_lock.unlock();

				if (waiting)
					task_done_cv.notify_one();
			}
		}

		// ============
		// Private data
		// ============

		/**
		* @brief A condition variable used to notify worker() that a new task has become available.
		*/
		std::condition_variable task_available_cv = {};

		/**
		* @brief A condition variable used to notify wait_for_tasks() that a tasks is done.
		*/
		std::condition_variable task_done_cv = {};

		/**
		* @brief A queue of tasks to be executed by the threads.
		*/
		task_queue tasks = {};

		/**
		* @brief An atomic variable to keep track of the total number of unfinished tasks - either still in the queue, or running in a thread.
		*/
		std::atomic<size_t> tasks_total = 0;

		/**
		* @brief A mutex to synchronize access to the task queue by different threads.
		*/
		mutable std::mutex tasks_mutex = {};

		/**
		* @brief A smart pointer to manage the memory allocated for the threads.
		*/
		std::unique_ptr<std::thread> kcp_thread = nullptr;

		/**
		* @brief An atomic variable indicating to the workers to keep running. When set to false, the workers permanently stop working.
		*/
		std::atomic<bool> running = false;

		/**
		* @brief An atomic variable indicating that wait_for_tasks() is active and expects to be notified whenever a task is done.
		*/
		std::atomic<bool> waiting = false;

		std::atomic<uint32_t> nearest_update_time{std::numeric_limits<uint32_t>::max()};
	};

}

#endif