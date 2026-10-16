// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/Threads.h>
#include <FEXCore/fextl/deque.h>
#include <FEXCore/fextl/memory.h>

#include <condition_variable>
#include <mutex>

namespace FEXCore {

class WorkQueueThread {
public:
  // destroyed after Run()
  struct WorkItem {
    virtual ~WorkItem() = default;
    virtual void Run() = 0;
  };

  WorkQueueThread(FEXCore::Threads::Flags Flags = {}, const char* ThreadName = nullptr);
  ~WorkQueueThread();

  void QueueWork(fextl::unique_ptr<WorkItem> Work);

  // Waits for the work item in progress, if any, and keeps the thread from starting another until Resume. The wait has
  // no timeout, so work items must not need locks that guest threads hold.
  void Pause();
  void Resume();

private:
  // static function for the ::Thread to refer to
  static void* ThreadEntry(void* Self) {
    static_cast<WorkQueueThread*>(Self)->ThreadProc();
    return nullptr;
  }
  void ThreadProc();

  std::mutex Mutex;
  std::condition_variable CV;
  // Signalled when a work item finishes, for Pause
  std::condition_variable IdleCV;
  fextl::deque<fextl::unique_ptr<WorkItem>> Queue;
  bool Stop = false;
  bool Paused = false;
  bool Running = false;

  fextl::unique_ptr<FEXCore::Threads::Thread> Thread;
};
} // namespace FEXCore
