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
#include <list>
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

	using task_queue = std::list<std::tuple<task_callback, std::unique_ptr<uint8_t[]>>>;

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
				tasks.push_back({ task_function, std::move(data) });
			}
			++tasks_total;
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
			waiting = true;
			std::unique_lock<std::mutex> tasks_lock(tasks_mutex);
			task_done_cv.wait(tasks_lock, [this] { return (tasks_total == 0); });
			waiting = false;
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
			task_available_cv.notify_all();
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
					std::tuple tuple_values = std::move(tasks.front());
					task_callback task = std::get<0>(tuple_values);
					std::unique_ptr<uint8_t[]> data = std::move(std::get<1>(tuple_values));
					tasks.pop_front();
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
			threads(std::make_unique<std::thread[]>(thread_count))
		{
			task_queue_of_threads = std::make_unique<task_queue[]>(thread_count);
			tasks_total_of_threads = std::make_unique<std::atomic<size_t>[]>(thread_count);
			tasks_mutex_of_threads = std::make_unique<std::mutex[]>(thread_count);
			task_available_cv = std::make_unique<std::condition_variable[]>(thread_count);

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
			size_t thread_number = number % thread_count;
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
		void push_task(size_t number, task_callback task_function, std::unique_ptr<uint8_t[]> data)
		{
			size_t thread_number = number % thread_count;
			{
				std::scoped_lock tasks_lock(tasks_mutex_of_threads[thread_number]);
				task_queue_of_threads[thread_number].push_back({ task_function, std::move(data) });
			}
			++tasks_total_of_threads[thread_number];
			task_available_cv[thread_number].notify_one();
		}

		void push_task(size_t number, std::shared_future<task_callback> task_function_run_later, std::unique_ptr<uint8_t[]> data)
		{
			size_t thread_number = number % thread_count;
			{
				std::scoped_lock tasks_lock(tasks_mutex_of_threads[thread_number]);
				auto task_func = [task_function_run_later](std::unique_ptr<uint8_t[]> data)
				{
					task_callback task_function = task_function_run_later.get();
					task_function(std::move(data));
				};
				task_queue_of_threads[thread_number].push_back({ task_func, std::move(data) });
			}
			++tasks_total_of_threads[thread_number];
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
			waiting = true;
			for (concurrency_t i = 0; i < thread_count; ++i)
			{
				std::unique_lock<std::mutex> tasks_lock(tasks_mutex_of_threads[i]);
				task_done_cv.wait(tasks_lock, [this, i] { return (tasks_total_of_threads[i].load() == 0); });
			}
			waiting = false;
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
					std::tuple tuple_values = std::move(task_queue_of_threads[thread_number].front());
					task_callback task = std::get<0>(tuple_values);
					std::unique_ptr<uint8_t[]> data = std::move(std::get<1>(tuple_values));
					task_queue_of_threads[thread_number].pop_front();
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
	};


} // namespace BS

#endif // __THREAD_POOL_HPP__
