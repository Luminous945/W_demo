#pragma once
#include <thread>
#include <mutex>
#include <vector>
#include <queue>
#include <atomic>
#include <functional>
#include <condition_variable>
#include <map>
#include <future>
using namespace std;

// 线程池类
class ThreadPool
{
public:
    ThreadPool(int min = 4, int max = thread::hardware_concurrency());
    ~ThreadPool();
    void addTask(function<void()> f);

private:
    void manager();
    void worker();
private:
    thread* m_manager;
    // 线程ID和线程对象的映射表
    map<thread::id, thread> m_workers; 
    // 需要销毁的线程ID列表
    vector<thread::id> m_ids; 
    int m_minThreads;
    int m_maxThreads; 
    atomic<bool> m_stop; 
    // 线程池中当前线程的数量
    atomic<int> m_curThreads;
    // 线程池中空闲线程的数量
    atomic<int> m_idleThreads;
    // 需要销毁的线程数量
    atomic<int> m_exitNumber; 
    queue<function<void()>> m_tasks;
    // 互斥锁，用于保护线程池中的共享资源
    mutex m_idsMutex; 
    // 互斥锁，用于保护线程池中的任务队列
    mutex m_queueMutex;
    // 条件变量，用于通知线程池中的线程有任务需要处理
    condition_variable m_condition;
};

