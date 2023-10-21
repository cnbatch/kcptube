#include <list>
#include <set>
#include "kcp_updater.hpp"

namespace KCP
{
	void KCPUpdater::submit(std::weak_ptr<KCP> kcp_ptr, uint32_t next_update_time)
	{
		{
			std::scoped_lock tasks_lock(kcp_tasks_mutex);
			kcp_time_list[next_update_time].push_back(kcp_ptr);
			//pile_of_kcp[kcp_ptr] = next_update_time;
			++kcp_tasks_total;
		}

		if (nearest_update_time.load() > next_update_time)
		{
			kcp_tasks_available_cv.notify_one();
		}
	}

	//void KCPUpdater::remove(std::weak_ptr<KCP> kcp_ptr)
	//{
	//	std::scoped_lock tasks_lock(kcp_pile_mutex);
	//	auto iter = pile_of_kcp.find(kcp_ptr);
	//	if (iter == pile_of_kcp.end())
	//		return;
	//	pile_of_kcp.erase(iter);
	//	kcp_tasks_total.store(pile_of_kcp.size());
	//}

	void KCPUpdater::wait_for_tasks()
	{
		if (!waiting)
		{
			waiting = true;
			std::unique_lock<std::mutex> tasks_lock(kcp_tasks_mutex);
			kcp_tasks_done_cv.wait(tasks_lock, [this] { return (kcp_tasks_total == 0); });
			waiting = false;
		}
	}

	void KCPUpdater::destroy_threads()
	{
		running = false;
		{
			const std::scoped_lock tasks_lock(kcp_tasks_mutex);
			kcp_tasks_available_cv.notify_all();
		}
		kcp_thread->join();
	}

	void KCPUpdater::kcp_update_worker()
	{
		while (running)
		{
			uint32_t kcp_refresh_time = TimeNowForKCP();
			int64_t wait_time = ((int64_t)kcp_refresh_time) - (int64_t)(nearest_update_time.load());
			if (wait_time <= 0)
				wait_time = 1;

			thread_local std::set<std::weak_ptr<KCP>, std::owner_less<>> kcp_tasks;
			kcp_tasks.clear();
			{
				std::unique_lock tasks_lock(kcp_tasks_mutex);
				kcp_tasks_available_cv.wait_for(tasks_lock, std::chrono::milliseconds{wait_time});
				if (running)
				{
					for (auto iter = kcp_time_list.begin(), next_iter = iter; iter != kcp_time_list.end(); iter = next_iter)
					{
						++next_iter;
						uint32_t refresh_time_label = iter->first;
						kcp_refresh_time = TimeNowForKCP();
						if (refresh_time_label > kcp_refresh_time)
							break;

						kcp_tasks.insert(iter->second.begin(), iter->second.end());
						kcp_time_list.erase(iter);
					}

					tasks_lock.unlock();

					std::map<uint32_t, std::list<std::weak_ptr<KCP>>> temp_list;
					for (std::weak_ptr<KCP> kcp_weak_ptr : kcp_tasks)
					{
						std::shared_ptr<KCP> kcp_ptr = kcp_weak_ptr.lock();
						if (kcp_ptr == nullptr)
							continue;

						kcp_ptr->Update(kcp_refresh_time);
						uint32_t kcp_update_time = kcp_ptr->Check(kcp_refresh_time);
						temp_list[kcp_update_time].push_back(kcp_weak_ptr);
					}

					tasks_lock.lock();

					if (!temp_list.empty())
					{
						for (auto &[update_time, kcp_ptr_list] : temp_list)
						{
							kcp_time_list[update_time].assign(kcp_ptr_list.begin(), kcp_ptr_list.end());
						}
					}

					kcp_tasks_total.store(kcp_time_list.size());

					if (kcp_time_list.empty())
						nearest_update_time.store(std::numeric_limits<uint32_t>::max());
					else
						nearest_update_time.store(kcp_time_list.begin()->first);

					if (waiting)
						kcp_tasks_done_cv.notify_one();
				}
			}
		}
	}
}