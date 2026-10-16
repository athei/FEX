// SPDX-License-Identifier: MIT
#include <FEXCore/Utils/WorkQueueThread.h>
#include <FEXCore/Utils/LogManager.h>

namespace FEXCore {

WorkQueueThread::WorkQueueThread(FEXCore::Threads::Flags ThreadFlags, const char* ThreadName) {
  Thread = FEXCore::Threads::Thread::Create(ThreadEntry, this, ThreadFlags, ThreadName);
}

WorkQueueThread::~WorkQueueThread() {
  {
    std::unique_lock lk {Mutex};
    Stop = true;
  }
  CV.notify_one();

  if (Thread && Thread->joinable()) {
    Thread->join(nullptr);
  }
}

void WorkQueueThread::QueueWork(fextl::unique_ptr<WorkItem> Work) {
  {
    std::unique_lock lk {Mutex};
    Queue.push_back(std::move(Work));
  }
  CV.notify_one();
}

void WorkQueueThread::Pause() {
  std::unique_lock lk {Mutex};
  Paused = true;
  IdleCV.wait(lk, [this] { return !Running; });
}

void WorkQueueThread::Resume() {
  {
    std::unique_lock lk {Mutex};
    Paused = false;
  }
  CV.notify_one();
}

void WorkQueueThread::ThreadProc() {
  while (true) {
    fextl::unique_ptr<WorkItem> Work;
    {
      std::unique_lock lk {Mutex};
      while (!(Stop || (!Paused && !Queue.empty()))) {
        CV.wait(lk);
      }
      if (Paused || Queue.empty()) {
        // nothing to do, or paused? must be stopping
        LOGMAN_THROW_A_FMT(Stop, "WorkQueueThread wakes up empty but no Stop?");
        return;
      }

      Work = std::move(Queue.front());
      Queue.pop_front();
      Running = true;
    }

    Work->Run();
    Work.reset();

    {
      std::unique_lock lk {Mutex};
      Running = false;
    }
    IdleCV.notify_all();
  }
}

} // namespace FEXCore
