#include <list>
#include "kcp_updater.hpp"

namespace KCP
{
	void KCPUpdater::submit(std::weak_ptr<KCP> kcp_ptr, uint32_t next_update_time)
	{
		{
			std::scoped_lock tasks_lock(kcp_pile_mutex);
			pile_of_kcp[kcp_ptr] = next_update_time;
			kcp_tasks_total.store(pile_of_kcp.size());
		}

		if (nearest_update_time.load() > next_update_time)
		{
			kcp_pile_available_cv.notify_one();
		}
	}

	void KCPUpdater::remove(std::weak_ptr<KCP> kcp_ptr)
	{
		std::scoped_lock tasks_lock(kcp_pile_mutex);
		auto iter = pile_of_kcp.find(kcp_ptr);
		if (iter == pile_of_kcp.end())
			return;
		pile_of_kcp.erase(iter);
		kcp_tasks_total.store(pile_of_kcp.size());
	}

	void KCPUpdater::wait_for_tasks()
	{
		if (!waiting)
		{
			waiting = true;
			std::unique_lock<std::mutex> tasks_lock(kcp_pile_mutex);
			kcp_pile_done_cv.wait(tasks_lock, [this] { return (kcp_tasks_total == 0); });
			waiting = false;
		}
	}

	void KCPUpdater::destroy_threads()
	{
		running = false;
		{
			const std::scoped_lock tasks_lock(kcp_pile_mutex);
			kcp_pile_available_cv.notify_all();
		}
		kcp_thread->join();
	}

	void KCPUpdater::kcp_update_worker()
	{
		while (running)
		{
			uint32_t kcp_refresh_time = TimeNowForKCP();
			uint32_t smallest_refresh_time = std::numeric_limits<uint32_t>::max();
			int64_t wait_time = (int64_t)(kcp_refresh_time)-(int64_t)(nearest_update_time.load());
			if (wait_time <= 0)
				wait_time = 1;
			//thread_local std::list<std::pair<std::weak_ptr<KCP>, uint32_t>> kcp_task_without_lock;
			//kcp_task_without_lock.clear();
			{
				std::unique_lock tasks_lock(kcp_pile_mutex);
				kcp_pile_available_cv.wait_for(tasks_lock, std::chrono::milliseconds{wait_time});
				if (running)
				{
					for (auto iter = pile_of_kcp.begin(), next_iter = iter; iter != pile_of_kcp.end(); iter = next_iter)
					{
						++next_iter;
						std::shared_ptr<KCP> kcp_ptr = iter->first.lock();
						if (kcp_ptr == nullptr)
						{
							pile_of_kcp.erase(iter);
							kcp_tasks_total.store(pile_of_kcp.size());
							continue;
						}

						kcp_refresh_time = TimeNowForKCP();
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

					if (pile_of_kcp.empty())
						nearest_update_time.store(std::numeric_limits<uint32_t>::max());

					if (waiting)
						kcp_pile_done_cv.notify_one();
				}
			}
		}
	}
}