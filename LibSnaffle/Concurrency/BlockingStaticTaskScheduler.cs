using LibSnaffle.FileDiscovery;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;

namespace LibSnaffle.Concurrency
{
    /// <summary>
    /// Represents a Task Scheduler which blocks when waiting for jobs.
    /// </summary>
    /// <remarks>
    /// Uses TaskFactory.StartNew to execute Action delegates.
    /// </remarks>
    public class BlockingStaticTaskScheduler
    {
        private static readonly object syncLock = new object();

        public LimitedConcurrencyLevelTaskScheduler Scheduler { get; set; }
        private TaskFactory taskFactory { get; }
        private CancellationTokenSource cancellationSource { get; }
        private int maxBacklog { get; set; }

        public BlockingStaticTaskScheduler(int maxThreads, int maxBacklog)
        {
            Scheduler = new LimitedConcurrencyLevelTaskScheduler(maxThreads);
            taskFactory = new TaskFactory(Scheduler);
            cancellationSource = new CancellationTokenSource();
            this.maxBacklog = maxBacklog;
        }

        /// <summary>
        /// Checks if the schedular has any jobs yet to execute.
        /// </summary>
        /// <returns>
        /// True if no jobs exist.
        /// </returns>
        public bool Done()
        {
            // single get, it's locked inside the method
            Scheduler.RecalculateCounters();
            TaskCounters taskCounters = Scheduler.GetTaskCounters();
            return taskCounters.CurrentTasksQueued + taskCounters.CurrentTasksRunning == 0;
        }

        /// <summary>
        /// Create a new task.
        /// </summary>
        /// <param name="action">
        /// Action delegate.
        /// </param>
        public void New(Action action)
        {
            // set up to not add the task as default
            bool proceed = false;

            while (proceed == false) // loop the calling thread until we are allowed to do the thing
            {
                lock (syncLock) // take out the lock
                {
                    // check to see how many tasks we have waiting and keep looping if it's too many
                    // single get, it's locked inside the method.
                    // _maxBacklog = 0 is 'infinite'
                    if (maxBacklog != 0)
                    {
                        if (Scheduler.GetTaskCounters().CurrentTasksQueued >= maxBacklog)
                            continue;
                    }

                    // okay, let's add the thing
                    proceed = true;

                    taskFactory.StartNew(action, cancellationSource.Token);
                }
            }
            // TODO: might be good to sleep here for a short time
        }

        /// <summary>
        /// Create a new task.
        /// </summary>
        /// <param name="action">
        /// Action delegate of with QueueAndPath parameter for use inside the delegate.
        /// </param>
        /// <param name="qp">
        /// QueueAndPath instance.
        /// </param>
        public void New(Action<Object> action, QueueAndPath qp)
        {
            // set up to not add the task as default
            bool proceed = false;

            while (proceed == false) // loop the calling thread until we are allowed to do the thing
            {
                lock (syncLock) // take out the lock
                {
                    // check to see how many tasks we have waiting and keep looping if it's too many
                    // single get, it's locked inside the method.
                    // maxBacklog = 0 is 'infinite'
                    if (maxBacklog != 0)
                    {
                        if (Scheduler.GetTaskCounters().CurrentTasksQueued >= maxBacklog)
                            continue;
                    }

                    // okay, let's add the thing
                    proceed = true;
                    taskFactory.StartNew(action, qp, cancellationSource.Token);
                }
            }
            // TODO: might be good to sleep here for a short time
        }
    }

    public class TaskCounters
    {
        public BigInteger TotalTasksQueued { get; set; }
        public BigInteger CurrentTasksQueued { get; set; }
        public BigInteger CurrentTasksRunning { get; set; }
        public BigInteger CurrentTasksRemaining { get; set; }
        public BigInteger CompletedTasks { get; set; }
    }

    public class LimitedConcurrencyLevelTaskScheduler : TaskScheduler
    {
        public TaskCounters _taskCounters { get; private set; }

        public TaskCounters GetTaskCounters()
        {
            lock (_taskCounters)
            {
                return _taskCounters;
            }
        }
        public void RecalculateCounters()
        {
            lock (_taskCounters)
            {
                _taskCounters.CurrentTasksQueued = _tasks.Count;
                _taskCounters.CurrentTasksRunning = _delegatesQueuedOrRunning;
                _taskCounters.CurrentTasksRemaining = _taskCounters.CurrentTasksQueued + _taskCounters.CurrentTasksRunning;
                _taskCounters.CompletedTasks = _taskCounters.TotalTasksQueued - _taskCounters.CurrentTasksRemaining;
            }
        }

        // Indicates whether the current thread is processing work items.
        [ThreadStatic] private static bool _currentThreadIsProcessingItems;

        // The list of tasks to be executed 
        public readonly LinkedList<Task> _tasks = new LinkedList<Task>();

        // The maximum concurrency level allowed by this scheduler. 
        private readonly int _maxThreads;

        // Indicates whether the scheduler is currently processing work items. 
        private int _delegatesQueuedOrRunning;

        // Creates a new instance with the specified degree of parallelism. 
        public LimitedConcurrencyLevelTaskScheduler(int maxThreads)
        {
            if (maxThreads < 1)
            {
                throw new ArgumentException("Max threads cannot be less than 1.");
            }
            _maxThreads = maxThreads;
            _taskCounters = new TaskCounters();
        }

        // Queues a task to the scheduler. 
        protected sealed override void QueueTask(Task task)
        {
            // Add the task to the list of tasks to be processed.  If there aren't enough 
            // delegates currently queued or running to process tasks, schedule another. 
            lock (_tasks)
            {
                _tasks.AddLast(task);
                ++_taskCounters.TotalTasksQueued;
                if (_delegatesQueuedOrRunning < _maxThreads)
                {
                    ++_delegatesQueuedOrRunning;
                    NotifyThreadPoolOfPendingWork();
                }
                RecalculateCounters();
            }
        }

        // Inform the ThreadPool that there's work to be executed for this scheduler. 
        private void NotifyThreadPoolOfPendingWork()
        {
            ThreadPool.UnsafeQueueUserWorkItem(_ =>
            {
                // Note that the current thread is now processing work items.
                // This is necessary to enable inlining of tasks into this thread.
                _currentThreadIsProcessingItems = true;
                try
                {
                    // Process all available items in the queue.
                    while (true)
                    {
                        Task item;
                        lock (_tasks)
                        {
                            // When there are no more items to be processed,
                            // note that we're done processing, and get out.
                            if (_tasks.Count == 0)
                            {
                                --_delegatesQueuedOrRunning;
                                break;
                            }

                            // Get the next item from the queue
                            item = _tasks.First.Value;
                            _tasks.RemoveFirst();
                            RecalculateCounters();
                        }

                        // Execute the task we pulled out of the queue
                        TryExecuteTask(item);
                    }
                }
                // We're done processing items on the current thread
                finally
                {
                    _currentThreadIsProcessingItems = false;
                }
            }, null);
        }

        // Attempts to execute the specified task on the current thread. 
        protected sealed override bool TryExecuteTaskInline(Task task, bool taskWasPreviouslyQueued)
        {
            // If this thread isn't already processing a task, we don't support inlining
            if (!_currentThreadIsProcessingItems) return false;

            // If the task was previously queued, remove it from the queue
            if (taskWasPreviouslyQueued)
                // Try to run the task. 
                if (TryDequeue(task))
                {
                    RecalculateCounters();
                    return TryExecuteTask(task);
                }
                else
                    return false;
            return TryExecuteTask(task);
        }

        // Gets the maximum concurrency level supported by this scheduler. 
        public sealed override int MaximumConcurrencyLevel => _maxThreads;

        // Gets an enumerable of the tasks currently scheduled on this scheduler. 
        protected sealed override IEnumerable<Task> GetScheduledTasks()
        {
            bool lockTaken = false;
            try
            {
                Monitor.TryEnter(_tasks, ref lockTaken);
                if (lockTaken) return _tasks;
                else throw new NotSupportedException();
            }
            finally
            {
                if (lockTaken) Monitor.Exit(_tasks);
            }
        }
    }
}