#pragma once

// this is a modified version of BS's thread_pool_light (https://github.com/bshoshany/thread-pool)

#ifndef __THREAD_POOL_HPP__
#define __THREAD_POOL_HPP__


#include <atomic>             // std::atomic
#include <condition_variable> // std::condition_variable
#include <exception>          // std::current_exception
#include <functional>         // std::bind, std::function, std::invoke
#include <future>             // std::future, std::promise
#include <memory>             // std::make_shared, std::make_unique, std::shared_ptr, std::unique_ptr
#include <mutex>              // std::mutex, std::scoped_lock, std::unique_lock
#include <deque>
#include <set>
#include <thread>             // std::thread
#include <type_traits>        // std::common_type_t, std::decay_t, std::invoke_result_t, std::is_void_v
#include <utility>            // std::forward, std::move, std::swap

namespace ttp
{
	/**
	* @brief A convenient shorthand for the type of std::thread::hardware_concurrency(). Should evaluate to unsigned int.
	*/
	using concurrency_t = std::invoke_result_t<decltype(std::thread::hardware_concurrency)>;

	using task_callback = std::function<void(std::unique_ptr<uint8_t[]>)>;
	using task_void_callback = std::function<void()>;
	using calculate_func = size_t(*)(size_t, concurrency_t);
	using task_queue = std::deque<task_callback>;
	using parameter_queue = std::deque<std::unique_ptr<uint8_t[]>>;

	static size_t always_zero(size_t input_value, concurrency_t thread_count) noexcept
	{
		return 0;
	}

	[[nodiscard]]
	static size_t calculate_odd(size_t input_value, concurrency_t thread_count) noexcept
	{
		size_t odd_value = (input_value % thread_count) * 2 + 1;
		size_t thread_number = (odd_value + thread_count) % thread_count | 1;
		return thread_number;
	}

	[[nodiscard]]
	static size_t calculate_even(size_t input_value, concurrency_t thread_count) noexcept
	{
		size_t even_value = (input_value % thread_count) * 2;
		size_t thread_number = (even_value + thread_count) % thread_count;
		return thread_number;
	}

	[[nodiscard]]
	static size_t calculate_assign(size_t input_value, concurrency_t thread_count) noexcept
	{
		size_t assign_value = (input_value % thread_count) * 2 + (input_value & 1);
		size_t thread_number = (assign_value + thread_count) % thread_count | (input_value & 1);
		return thread_number;
	}

	/**
	* @brief A fast, lightweight, and easy-to-use C++17 thread pool class. This is a lighter version of the main thread pool class.
	*/
	class [[nodiscard]] task_thread_pool
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
		task_thread_pool(const concurrency_t thread_count_ = 0) : thread_count(determine_thread_count(thread_count_)), threads(std::make_unique<std::thread[]>(thread_count))
		{
			create_threads();
		}

		/**
		* @brief Destruct the thread pool. Waits for all tasks to complete, then destroys all threads.
		*/
		~task_thread_pool()
		{
			wait_for_tasks();
			destroy_threads();
		}

		// =======================
		// Public member functions
		// =======================

		/**
		* @brief Get the number of threads in the pool.
		*
		* @return The number of threads.
		*/
		[[nodiscard]] concurrency_t get_thread_count() const
		{
			return thread_count;
		}

		[[nodiscard]]
		size_t get_task_count() const
		{
			return tasks_total.load();
		}

		/**
		* @brief Push a function with zero or more arguments, but no return value, into the task queue. Does not return a future, so the user must use wait_for_tasks() or some other method to ensure that the task finishes executing, otherwise bad things will happen.
		*
		* @tparam F The type of the function.
		* @tparam A The types of the arguments.
		* @param task The function to push.
		* @param args The zero or more arguments to pass to the function. Note that if the task is a class member function, the first argument must be a pointer to the object, i.e. &object (or this), followed by the actual arguments.
		*/
		//template <typename F, typename... A>
		//void push_task(F&& task, A&&... args)
		//{
		//    std::function<void()> task_function = std::bind(std::forward<F>(task), std::forward<A>(args)...);
		//    {
		//        const std::scoped_lock tasks_lock(tasks_mutex);
		//        tasks.push(task_function);
		//    }
		//    ++tasks_total;
		//    task_available_cv.notify_one();
		//}

		/**
		* @brief Push a function with no parameters, and no return value, into the task queue. Does not return a future, so the user must use wait_for_tasks() or some other method to ensure that the task finishes executing, otherwise bad things will happen.
		*
		* @param task_function The function to push.
		* @param data The data to be used by task_function.
		*/
		void push_task(task_callback task_function, std::unique_ptr<uint8_t[]> data)
		{
			{
				std::scoped_lock tasks_lock(tasks_mutex);
				tasks.emplace_back(std::move(task_function));
				parameters.emplace_back(std::move(data));
				++tasks_total;
			}
			task_available_cv.notify_one();
		}


		/**
		* @brief Submit a function with zero or more arguments into the task queue. If the function has a return value, get a future for the eventual returned value. If the function has no return value, get an std::future<void> which can be used to wait until the task finishes.
		*
		* @tparam F The type of the function.
		* @tparam A The types of the zero or more arguments to pass to the function.
		* @tparam R The return type of the function (can be void).
		* @param task The function to submit.
		* @param args The zero or more arguments to pass to the function. Note that if the task is a class member function, the first argument must be a pointer to the object, i.e. &object (or this), followed by the actual arguments.
		* @return A future to be used later to wait for the function to finish executing and/or obtain its returned value if it has one.
		*/
		//template <typename F, typename... A, typename R = std::invoke_result_t<std::decay_t<F>, std::decay_t<A>...>>
		//[[nodiscard]] std::future<R> submit(F&& task, A&&... args)
		//{
		//    std::function<R()> task_function = std::bind(std::forward<F>(task), std::forward<A>(args)...);
		//    std::shared_ptr<std::promise<R>> task_promise = std::make_shared<std::promise<R>>();
		//    push_task(
		//        [task_function, task_promise]
		//        {
		//            try
		//            {
		//                if constexpr (std::is_void_v<R>)
		//                {
		//                    std::invoke(task_function);
		//                    task_promise->set_value();
		//                }
		//                else
		//                {
		//                    task_promise->set_value(std::invoke(task_function));
		//                }
		//            }
		//            catch (...)
		//            {
		//                try
		//                {
		//                    task_promise->set_exception(std::current_exception());
		//                }
		//                catch (...)
		//                {
		//                }
		//            }
		//        });
		//    return task_promise->get_future();
		//}

		template <typename R, typename D = std::unique_ptr<uint8_t[]>>
		[[nodiscard]] std::future<R> submit(std::function<R(D)> task_function, D data)
		{
			std::shared_ptr<std::promise<R>> task_promise = std::make_shared<std::promise<R>>();
			push_task(
				[task_function, task_promise](D input_data)
				{
					try
					{
						if constexpr (std::is_void_v<R>)
						{
							std::invoke(task_function, std::move(input_data));
							task_promise->set_value();
						}
						else
						{
							task_promise->set_value(std::invoke(task_function, std::move(input_data)));
						}
					}
					catch (...)
					{
						try
						{
							task_promise->set_exception(std::current_exception());
						}
						catch (...)
						{
						}
					}
				}, std::move(data));
			return task_promise->get_future();
		}


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
		void create_threads()
		{
			running = true;
			for (concurrency_t i = 0; i < thread_count; ++i)
			{
				threads[i] = std::thread(&task_thread_pool::worker, this);
			}
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
			for (concurrency_t i = 0; i < thread_count; ++i)
			{
				threads[i].join();
			}
		}

		/**
		* @brief Determine how many threads the pool should have, based on the parameter passed to the constructor.
		*
		* @param thread_count_ The parameter passed to the constructor. If the parameter is a positive number, then the pool will be created with this number of threads. If the parameter is non-positive, or a parameter was not supplied (in which case it will have the default value of 0), then the pool will be created with the total number of hardware threads available, as obtained from std::thread::hardware_concurrency(). If the latter returns a non-positive number for some reason, then the pool will be created with just one thread.
		* @return The number of threads to use for constructing the pool.
		*/
		[[nodiscard]] concurrency_t determine_thread_count(const concurrency_t thread_count_)
		{
			if (thread_count_ > 0)
				return thread_count_;
			else
			{
				if (std::thread::hardware_concurrency() > 0)
					return std::thread::hardware_concurrency();
				else
					return 1;
			}
		}

		/**
		* @brief A worker function to be assigned to each thread in the pool. Waits until it is notified by push_task() that a task is available, and then retrieves the task from the queue and executes it. Once the task finishes, the worker notifies wait_for_tasks() in case it is waiting.
		*/
		void worker()
		{
			while (running)
			{
				std::unique_lock<std::mutex> tasks_lock(tasks_mutex);
				task_available_cv.wait(tasks_lock, [this] { return !tasks.empty() || !running; });
				if (running)
				{
					task_callback task = std::move(tasks.front());
					std::unique_ptr<uint8_t[]> data = std::move(parameters.front());
					tasks.pop_front();
					parameters.pop_front();
					tasks_lock.unlock();
					task(std::move(data));
					tasks_lock.lock();
					--tasks_total;
					if (waiting)
						task_done_cv.notify_one();
				}
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

		parameter_queue parameters = {};

		/**
		* @brief An atomic variable to keep track of the total number of unfinished tasks - either still in the queue, or running in a thread.
		*/
		std::atomic<size_t> tasks_total = 0;

		/**
		* @brief A mutex to synchronize access to the task queue by different threads.
		*/
		mutable std::mutex tasks_mutex = {};

		/**
		* @brief The number of threads in the pool.
		*/
		const concurrency_t thread_count;

		/**
		* @brief A smart pointer to manage the memory allocated for the threads.
		*/
		std::unique_ptr<std::thread[]> threads = nullptr;

		/**
		* @brief An atomic variable indicating to the workers to keep running. When set to false, the workers permanently stop working.
		*/
		std::atomic<bool> running = false;

		/**
		* @brief An atomic variable indicating that wait_for_tasks() is active and expects to be notified whenever a task is done.
		*/
		std::atomic<bool> waiting = false;
	};

	class [[nodiscard]] task_group_pool
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
		task_group_pool(const concurrency_t thread_count_ = 0) :
			thread_count(determine_thread_count(thread_count_)),
			threads(std::make_unique<std::thread[]>(thread_count)),
			listener_network_tasks_total_of_threads(std::make_unique<std::atomic<size_t>[]>(thread_count)),
			forwarder_network_tasks_total_of_threads(std::make_unique<std::atomic<size_t>[]>(thread_count))
		{
			task_queue_of_threads = std::make_unique<task_queue[]>(thread_count);
			parameter_queue_of_threads = std::make_unique<parameter_queue[]>(thread_count);
			tasks_total_of_threads = std::make_unique<std::atomic<size_t>[]>(thread_count);
			tasks_mutex_of_threads = std::make_unique<std::mutex[]>(thread_count);
			task_available_cv = std::make_unique<std::condition_variable[]>(thread_count);
			if (thread_count == 1)
			{
				assign_thread_odd = always_zero;
				assign_thread_even = always_zero;
				assign_thread = always_zero;
			}
			else
			{
				assign_thread_odd = calculate_odd;
				assign_thread_even = calculate_even;
				assign_thread = calculate_assign;
			}

			create_threads();
		}

		/**
		* @brief Destruct the thread pool. Waits for all tasks to complete, then destroys all threads.
		*/
		~task_group_pool()
		{
			wait_for_tasks();
			destroy_threads();
		}

		// =======================
		// Public member functions
		// =======================

		/**
		* @brief Get the number of threads in the pool.
		*
		* @return The number of threads.
		*/
		[[nodiscard]] concurrency_t get_thread_count() const
		{
			return thread_count;
		}

		[[nodiscard]]
		size_t get_task_count(size_t number) const
		{
			size_t thread_number = assign_thread(number, thread_count);
			return tasks_total_of_threads[thread_number].load();
		}

		[[nodiscard]]
		size_t get_task_count() const
		{
			size_t total = 0;
			for (size_t i = 0; i < thread_count; ++i)
				total += tasks_total_of_threads[i].load();
			return total;
		}

		[[nodiscard]]
		size_t get_listener_network_task_count_all() const
		{
			size_t total = 0;
			for (size_t i = 0; i < thread_count; ++i)
				total += listener_network_tasks_total_of_threads[i].load();
			return total;
		}

		[[nodiscard]]
		size_t get_forwarder_network_task_count_all() const
		{
			size_t total = 0;
			for (size_t i = 0; i < thread_count; ++i)
				total += forwarder_network_tasks_total_of_threads[i].load();
			return total;
		}

		[[nodiscard]]
		size_t get_listener_network_task_count(size_t number) const
		{
			size_t thread_number = assign_thread_odd(number, thread_count);
			return listener_network_tasks_total_of_threads[thread_number].load();
		}

		[[nodiscard]]
		size_t get_forwarder_network_task_count(size_t number) const
		{
			size_t thread_number = assign_thread_even(number, thread_count);
			return forwarder_network_tasks_total_of_threads[thread_number].load();
		}

		bool thread_id_exists(std::thread::id tid)
		{
			return thread_ids.find(tid) != thread_ids.end();
		}

		/**
		* @brief Push a function with no parameters, and no return value, into the task queue. Does not return a future, so the user must use wait_for_tasks() or some other method to ensure that the task finishes executing, otherwise bad things will happen.
		*
		* @param task_function The function to push.
		*/
		void push_task(size_t number, task_void_callback void_task_function)
		{
			size_t thread_number = assign_thread(number, thread_count);
			{
				std::scoped_lock tasks_lock(tasks_mutex_of_threads[thread_number]);
				auto task_function = [void_task_function](std::unique_ptr<uint8_t[]> data) { void_task_function(); };
				task_queue_of_threads[thread_number].emplace_back(std::move(task_function));
				parameter_queue_of_threads[thread_number].emplace_back(std::unique_ptr<uint8_t[]>{});
				++tasks_total_of_threads[thread_number];
			}
			task_available_cv[thread_number].notify_one();
		}

		void push_task(std::thread::id tid, task_void_callback void_task_function)
		{
			size_t thread_number = 0;
			if (auto iter = thread_ids.find(tid); iter == thread_ids.end())
				thread_number = assign_thread(std::hash<std::thread::id>{}(tid), thread_count);
			else
				thread_number = iter->second;

			{
				std::scoped_lock tasks_lock(tasks_mutex_of_threads[thread_number]);
				auto task_function = [void_task_function](std::unique_ptr<uint8_t[]> data) { void_task_function(); };
				task_queue_of_threads[thread_number].emplace_back(std::move(task_function));
				parameter_queue_of_threads[thread_number].emplace_back(std::unique_ptr<uint8_t[]>{});
				++tasks_total_of_threads[thread_number];
			}
			task_available_cv[thread_number].notify_one();
		}

		/**
		* @brief Push a function with no parameters, and no return value, into the task queue. Does not return a future, so the user must use wait_for_tasks() or some other method to ensure that the task finishes executing, otherwise bad things will happen.
		*
		* @param task_function The function to push.
		* @param data The data to be used by task_function.
		*/
		void push_task(size_t number, task_callback task_function, std::unique_ptr<uint8_t[]> data)
		{
			size_t thread_number = assign_thread(number, thread_count);
			{
				std::scoped_lock tasks_lock(tasks_mutex_of_threads[thread_number]);
				task_queue_of_threads[thread_number].emplace_back(std::move(task_function));
				parameter_queue_of_threads[thread_number].emplace_back(std::move(data));
				++tasks_total_of_threads[thread_number];
			}
			task_available_cv[thread_number].notify_one();
		}

		void push_task(std::thread::id tid, task_callback task_function, std::unique_ptr<uint8_t[]> data)
		{
			size_t thread_number = 0;
			if (auto iter = thread_ids.find(tid); iter == thread_ids.end())
				thread_number = assign_thread(std::hash<std::thread::id>{}(tid), thread_count);
			else
				thread_number = iter->second;

			{
				std::scoped_lock tasks_lock(tasks_mutex_of_threads[thread_number]);
				task_queue_of_threads[thread_number].emplace_back(std::move(task_function));
				parameter_queue_of_threads[thread_number].emplace_back(std::move(data));
				++tasks_total_of_threads[thread_number];
			}
			task_available_cv[thread_number].notify_one();
		}

		void push_task_listener(size_t number, task_callback task_function, std::unique_ptr<uint8_t[]> data)
		{
			size_t thread_number = assign_thread_odd(number, thread_count);
			{
				std::scoped_lock tasks_lock(tasks_mutex_of_threads[thread_number]);
				auto task_func = [task_function, this, thread_number](std::unique_ptr<uint8_t[]> data)
					{
						task_function(std::move(data));
						listener_network_tasks_total_of_threads[thread_number]--;
					};
				task_queue_of_threads[thread_number].emplace_back(std::move(task_func));
				parameter_queue_of_threads[thread_number].emplace_back(std::move(data));
				tasks_total_of_threads[thread_number]++;
				listener_network_tasks_total_of_threads[thread_number]++;
			}
			task_available_cv[thread_number].notify_one();
		}

		void push_task_forwarder(size_t number, task_callback task_function, std::unique_ptr<uint8_t[]> data)
		{
			size_t thread_number = assign_thread_even(number, thread_count);
			{
				std::scoped_lock tasks_lock(tasks_mutex_of_threads[thread_number]);
				auto task_func = [task_function, this, thread_number](std::unique_ptr<uint8_t[]> data)
					{
						task_function(std::move(data));
						forwarder_network_tasks_total_of_threads[thread_number]--;
					};
				task_queue_of_threads[thread_number].emplace_back(std::move(task_func));
				parameter_queue_of_threads[thread_number].emplace_back(std::move(data));
				tasks_total_of_threads[thread_number]++;
				forwarder_network_tasks_total_of_threads[thread_number]++;
			}
			task_available_cv[thread_number].notify_one();
		}

		void push_task(size_t number, std::shared_future<task_callback> task_function_run_later, std::unique_ptr<uint8_t[]> data)
		{
			size_t thread_number = assign_thread(number, thread_count);
			{
				std::scoped_lock tasks_lock(tasks_mutex_of_threads[thread_number]);
				auto task_func = [task_function_run_later](std::unique_ptr<uint8_t[]> data)
				{
					task_callback task_function = task_function_run_later.get();
					task_function(std::move(data));
				};
				task_queue_of_threads[thread_number].emplace_back(std::move(task_func));
				parameter_queue_of_threads[thread_number].emplace_back(std::move(data));
				++tasks_total_of_threads[thread_number];
			}
			task_available_cv[thread_number].notify_one();
		}

		/**
		* @brief Submit a function with zero or more arguments into the task queue. If the function has a return value, get a future for the eventual returned value. If the function has no return value, get an std::future<void> which can be used to wait until the task finishes.
		*
		* @tparam F The type of the function.
		* @tparam A The types of the zero or more arguments to pass to the function.
		* @tparam R The return type of the function (can be void).
		* @param task The function to submit.
		* @param args The zero or more arguments to pass to the function. Note that if the task is a class member function, the first argument must be a pointer to the object, i.e. &object (or this), followed by the actual arguments.
		* @return A future to be used later to wait for the function to finish executing and/or obtain its returned value if it has one.
		*/
		//template <typename F, typename... A, typename R = std::invoke_result_t<std::decay_t<F>, std::decay_t<A>...>>
		//[[nodiscard]] std::future<R> submit(F&& task, A&&... args)
		//{
		//    std::function<R()> task_function = std::bind(std::forward<F>(task), std::forward<A>(args)...);
		//    std::shared_ptr<std::promise<R>> task_promise = std::make_shared<std::promise<R>>();
		//    push_task(
		//        [task_function, task_promise]
		//        {
		//            try
		//            {
		//                if constexpr (std::is_void_v<R>)
		//                {
		//                    std::invoke(task_function);
		//                    task_promise->set_value();
		//                }
		//                else
		//                {
		//                    task_promise->set_value(std::invoke(task_function));
		//                }
		//            }
		//            catch (...)
		//            {
		//                try
		//                {
		//                    task_promise->set_exception(std::current_exception());
		//                }
		//                catch (...)
		//                {
		//                }
		//            }
		//        });
		//    return task_promise->get_future();
		//}

		template <typename R, typename D = std::unique_ptr<uint8_t[]>>
		[[nodiscard]] std::future<R> submit(size_t number, std::function<R(D)> task_function, D data)
		{
			std::shared_ptr<std::promise<R>> task_promise = std::make_shared<std::promise<R>>();
			push_task(number,
				[task_function, task_promise](D input_data)
				{
					try
					{
						if constexpr (std::is_void_v<R>)
						{
							std::invoke(task_function, std::move(input_data));
							task_promise->set_value();
						}
						else
						{
							task_promise->set_value(std::invoke(task_function, std::move(input_data)));
						}
					}
					catch (...)
					{
						try
						{
							task_promise->set_exception(std::current_exception());
						}
						catch (...)
						{
						}
					}
				}, std::move(data));
			return task_promise->get_future();
		}


		/**
		* @brief Wait for tasks to be completed. Normally, this function waits for all tasks, both those that are currently running in the threads and those that are still waiting in the queue. Note: To wait for just one specific task, use submit() instead, and call the wait() member function of the generated future.
		*/
		void wait_for_tasks()
		{
			if (!waiting)
			{
				waiting = true;
				for (concurrency_t i = 0; i < thread_count; ++i)
				{
					std::unique_lock<std::mutex> tasks_lock(tasks_mutex_of_threads[i]);
					task_done_cv.wait(tasks_lock, [this, i] { return (tasks_total_of_threads[i].load() == 0); });
				}
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
		void create_threads()
		{
			running = true;
			for (concurrency_t i = 0; i < thread_count; ++i)
			{
				threads[i] = std::thread(&task_group_pool::worker, this, i);
				thread_ids[threads[i].get_id()] = i;
			}
		}

		/**
		* @brief Destroy the threads in the pool.
		*/
		void destroy_threads()
		{
			running = false;
			for (concurrency_t i = 0; i < thread_count; ++i)
			{
				const std::scoped_lock tasks_lock(tasks_mutex_of_threads[i]);
				task_available_cv[i].notify_all();
			}

			for (concurrency_t i = 0; i < thread_count; ++i)
			{
				threads[i].join();
			}
		}

		/**
		* @brief Determine how many threads the pool should have, based on the parameter passed to the constructor.
		*
		* @param thread_count_ The parameter passed to the constructor. If the parameter is a positive number, then the pool will be created with this number of threads. If the parameter is non-positive, or a parameter was not supplied (in which case it will have the default value of 0), then the pool will be created with the total number of hardware threads available, as obtained from std::thread::hardware_concurrency(). If the latter returns a non-positive number for some reason, then the pool will be created with just one thread.
		* @return The number of threads to use for constructing the pool.
		*/
		[[nodiscard]] concurrency_t determine_thread_count(const concurrency_t thread_count_)
		{
			if (thread_count_ > 0)
				return thread_count_;
			else
			{
				if (std::thread::hardware_concurrency() > 0)
					return std::thread::hardware_concurrency();
				else
					return 1;
			}
		}

		/**
		* @brief A worker function to be assigned to each thread in the pool. Waits until it is notified by push_task() that a task is available, and then retrieves the task from the queue and executes it. Once the task finishes, the worker notifies wait_for_tasks() in case it is waiting.
		*/
		void worker(size_t thread_number)
		{
			while (running)
			{
				std::unique_lock<std::mutex> tasks_lock(tasks_mutex_of_threads[thread_number]);
				task_available_cv[thread_number].wait(tasks_lock, [this, thread_number] { return !task_queue_of_threads[thread_number].empty() || !running; });
				if (running)
				{
					task_callback task = std::move(task_queue_of_threads[thread_number].front());
					std::unique_ptr<uint8_t[]> data = std::move(parameter_queue_of_threads[thread_number].front());
					task_queue_of_threads[thread_number].pop_front();
					parameter_queue_of_threads[thread_number].pop_front();
					tasks_lock.unlock();
					task(std::move(data));
					tasks_lock.lock();
					--tasks_total_of_threads[thread_number];
					if (waiting)
						task_done_cv.notify_one();
				}
			}
		}

		// ============
		// Private data
		// ============

		/**
		* @brief A condition variable used to notify worker() that a new task has become available.
		*/
		std::unique_ptr<std::condition_variable[]> task_available_cv = {};

		/**
		* @brief A condition variable used to notify wait_for_tasks() that a tasks is done.
		*/
		std::condition_variable task_done_cv = {};

		/**
		* @brief Some queues of tasks to be executed by the threads.
		*/
		std::unique_ptr<task_queue[]> task_queue_of_threads;

		std::unique_ptr<parameter_queue[]> parameter_queue_of_threads;

		/**
		* @brief Some atomic variables to keep track of the total number of unfinished tasks - either still in the queue, or running in a thread.
		*/
		std::unique_ptr<std::atomic<size_t>[]> tasks_total_of_threads;

		/**
		* @brief Some mutex to synchronize access to the task queue by different threads.
		*/
		mutable std::unique_ptr<std::mutex[]> tasks_mutex_of_threads;

		/**
		* @brief The number of threads in the pool.
		*/
		const concurrency_t thread_count;

		/**
		* @brief A smart pointer to manage the memory allocated for the threads.
		*/
		std::unique_ptr<std::thread[]> threads = nullptr;

		/**
		* @brief An atomic variable indicating to the workers to keep running. When set to false, the workers permanently stop working.
		*/
		std::atomic<bool> running = false;

		/**
		* @brief An atomic variable indicating that wait_for_tasks() is active and expects to be notified whenever a task is done.
		*/
		std::atomic<bool> waiting = false;

		std::unique_ptr<std::atomic<size_t>[]> listener_network_tasks_total_of_threads;
		std::unique_ptr<std::atomic<size_t>[]> forwarder_network_tasks_total_of_threads;
		std::map<std::thread::id, size_t> thread_ids;
		calculate_func assign_thread_odd;
		calculate_func assign_thread_even;
		calculate_func assign_thread;
	};


} // namespace BS

#endif // __THREAD_POOL_HPP__
