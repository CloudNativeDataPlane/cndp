/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

/*
 * Some portions of this software may have been derived from the
 * https://github.com/halayli/lthread which carrys the following license.
 *
 * Copyright (c) 2012, Hasan Alayli <halayli@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 *  @file cthread_api.h
 *
 * This file contains the public API for the D-thread subsystem
 *
 * The L_thread subsystem provides a simple cooperative scheduler to
 * enable arbitrary functions to run as cooperative threads within a
 * single P-thread.
 *
 * The subsystem provides a P-thread like API that is intended to assist in
 * reuse of legacy code written for POSIX p_threads.
 *
 * The D-thread subsystem relies on cooperative multitasking, as such
 * an D-thread must possess frequent rescheduling points. Often these
 * rescheduling points are provided transparently when the application
 * invokes an D-thread API.
 *
 * In some applications it is possible that the program may enter a loop the
 * exit condition for which depends on the action of another thread or a
 * response from hardware. In such a case it is necessary to yield the thread
 * periodically in the loop body, to allow other threads an opportunity to
 * run. This can be done by inserting a call to cthread_yield() or
 * cthread_sleep(n) in the body of the loop.
 *
 * If the application makes expensive / blocking system calls or does other
 * work that would take an inordinate amount of time to complete, this will
 * stall the cooperative scheduler resulting in very poor performance.
 *
 * In such cases an D-thread can be migrated temporarily to another scheduler
 * running in a different P-thread on another core. When the expensive or
 * blocking operation is completed it can be migrated back to the original
 * scheduler.  In this way other threads can continue to run on the original
 * scheduler and will be completely unaffected by the blocking behaviour.
 * To migrate an D-thread to another scheduler the API cthread_set_affinity()
 * is provided.
 *
 * If D-threads that share data are running on the same core it is possible
 * to design programs where mutual exclusion mechanisms to protect shared data
 * can be avoided. This is due to the fact that the cooperative threads cannot
 * preempt each other.
 *
 * There are two cases where mutual exclusion mechanisms are necessary.
 *
 *  a) Where the D-threads sharing data are running on different cores.
 *  b) Where code must yield while updating data shared with another thread.
 *
 * The D-thread subsystem provides a set of mutex APIs to help with such
 * scenarios, however excessive reliance on on these will impact performance
 * and is best avoided if possible.
 *
 * D-threads can synchronise using a fast condition variable implementation
 * that supports signal and broadcast. An D-thread running on any core can
 * wait on a condition.
 *
 * D-threads can have D-thread local storage with an API modelled on either the
 * P-thread get/set specific API or using PER_CTHREAD macros modelled on the
 * CNE_PER_THREAD macros. Alternatively a simple user data pointer may be set
 * and retrieved from a thread.
 */
#ifndef _CTHREAD_API_H
#define _CTHREAD_API_H

#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <cne_cycles.h>
#include <cne_log.h>
#include <cne_branch_prediction.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cthread;
struct cthread_cond;
struct cthread_sema;
struct cthread_mutex;
struct cthread_once;
struct cthread_barrier;
struct cthread_condattr;
struct cthread_sched;

/**
 * Semaphore attribute structure
 */
struct cthread_semaattr {
    int32_t cnt;
};

/**
 * Mutex attribute structure
 */
struct cthread_mutexattr {
    uint32_t flags;
};

#define MUTEX_RECURSIVE_ATTR 0x00000001 /**< Mutex recursive flag */

/**
 * Typedef for any cthread function called from cthread_create()
 */
typedef void (*cthread_func_t)(void *);

/*
 * Define the size of stack for an cthread
 * Then this is the size that will be allocated on cthread creation
 * This is a fixed size and will not grow.
 */
#define CTHREAD_DEFAULT_STACK_SIZE (1024 * 16)

/**
 * Define the maximum number of TLS keys that can be created
 *
 */
#define CTHREAD_MAX_KEYS 256

/**
 * Define the maximum number of attempts to destroy an cthread's
 * TLS data on thread exit
 */
#define CTHREAD_DESTRUCTOR_ITERATIONS 4

/**
 * Define the maximum number of threads that will support cthreads
 */
#define CTHREAD_MAX_THREADS CNE_MAX_THREADS

/**
 * How many cthread objects to pre-allocate as the system grows
 * applies to cthreads + stacks, TLS, mutexes, cond vars.
 *
 * @see _cthread_alloc()
 * @see _cond_alloc()
 * @see _sema_alloc()
 * @see _mutex_alloc()
 *
 */
#define CTHREAD_PREALLOC 64

/**
 * Set the number of schedulers in the system.
 *
 * This function may optionally be called before starting schedulers.
 *
 * If the number of schedulers is not set, or set to 0 then each scheduler
 * will begin scheduling cthreads immediately when it is started.

 * If the number of schedulers is set to greater than 0, then each scheduler
 * will wait until all schedulers have started before beginning to schedule
 * cthreads.
 *
 * If an application wishes to have threads migrate between cores using
 * cthread_set_affinity(), or join threads running on other cores using
 * cthread_join(), then it is prudent to set the number of schedulers to ensure
 * that all schedulers are initialised beforehand.
 *
 * @param num
 *  the number of schedulers in the system
 * @return
 * the number of schedulers in the system
 */
CNDP_API int cthread_num_schedulers_set(int num);

/**
 * Return the number of schedulers currently running
 * @return
 *  the number of schedulers in the system
 */
CNDP_API int cthread_active_schedulers(void);

/**
 * Shutdown the specified scheduler
 *
 *  This function tells the specified scheduler to
 *  exit if/when there is no more work to do.
 *
 *  Note that although the scheduler will stop
 *  resources are not freed.
 *
 * @param thread
 *	The thread of the scheduler to shutdown
 *
 * @return
 *  none
 */
CNDP_API void cthread_scheduler_shutdown(int thread);

/**
 * Shutdown all schedulers
 *
 *  This function tells all schedulers  including the current scheduler to
 *  exit if/when there is no more work to do.
 *
 *  Note that although the schedulers will stop
 *  resources are not freed.
 *
 * @return
 *  none
 */
CNDP_API void cthread_scheduler_shutdown_all(void);

/**
 * Run the cthread scheduler
 *
 *  Runs the cthread scheduler.
 *  This function returns only if/when all cthreads have exited.
 *  This function must be the main loop of an CNE thread.
 *
 * @return
 *	 none
 */

CNDP_API void cthread_run(void);

/**
 * Set the scheduler stack size all threads on the scheduler.
 *
 * Must be called before the scheduler is started and will become the default
 * stack size for all schedulers created after this call.
 *
 * @param stack_size
 *   Size in bytes of the scheduler stack, can be zero to use the default size.
 */
CNDP_API void cthread_sched_stack_size_set(size_t stack_size);

/**
 * Get the scheduler default stack size.
 *
 * @return
 *   The number of default bytes in a scheduler stack.
 */
CNDP_API size_t cthread_sched_stack_size(void);

/**
 * Start a scehduler on the current thread.
 *
 * @param stack_size
 *   The number of bytes to allocate for a stack for all threads in a scheduler.
 * @return
 *   The scheduler ID value or -1 on error
 */
CNDP_API int cthread_sched_create(size_t stack_size);

/**
 * Create an cthread
 *
 *  Creates an cthread and places it in the ready queue on a particular
 *  thread.
 *
 * @param name
 *  The name of the thread to be created, can be NULL
 * @param func
 *  Pointer to the function the for the thread to run
 * @param arg
 *  Pointer to args that will be passed to the thread
 *
 * @return
 *	 0    success
 *	 EAGAIN  no resources available
 *	 EINVAL  NULL thread or function pointer
 */
CNDP_API struct cthread *cthread_create(const char *name, cthread_func_t func, void *arg);

/**
 * Cancel an cthread
 *
 *  Cancels an cthread and causes it to be terminated
 *  If the cthread is detached it will be freed immediately
 *  otherwise its resources will not be released until it is joined.
 *
 * @param ct
 *  Pointer to an cthread that will be cancelled
 *
 * @return
 *	 0    success
 *	 EINVAL  thread was NULL
 */
CNDP_API int cthread_cancel(struct cthread *ct);

/**
 * Join an cthread
 *
 *  Joins the current thread with the specified cthread, and waits for that
 *  thread to exit.
 *  Passes an optional pointer to collect returned data.
 *
 * @param ct
 *  Pointer to the cthread to be joined
 * @param ptr
 *  Pointer to pointer to collect returned data
 *
 * @return
 *  0    success
 *  EINVAL cthread could not be joined.
 */
CNDP_API int cthread_join(struct cthread *ct, void **ptr);

/**
 * Detach an cthread
 *
 * Detaches the current thread
 * On exit a detached cthread will be freed immediately and will not wait
 * to be joined. The default state for a thread is not detached.
 *
 * @return
 *  none
 */
CNDP_API void cthread_detach(void);

/**
 *  Exit an cthread
 *
 * Terminate the current thread, optionally return data.
 * The data may be collected by cthread_join()
 *
 * After calling this function the cthread will be suspended until it is
 * joined. After it is joined then its resources will be freed.
 *
 * @param val
 *  Pointer to pointer to data to be returned
 *
 * @return
 *  none
 */
CNDP_API void cthread_exit(void *val);

/**
 * Cause the current cthread to sleep for n nanoseconds
 *
 * The current thread will be suspended until the specified time has elapsed
 * or has been exceeded.
 *
 * Execution will switch to the next cthread that is ready to run
 *
 * @param nsecs
 *  Number of nanoseconds to sleep
 *
 * @return
 *  none
 */
CNDP_API void cthread_sleep(uint64_t nsecs);

/**
 * Cause the current cthread to sleep for n milliseconds
 *
 * The current thread will be suspended until the specified time has elapsed
 * or has been exceeded.
 *
 * Execution will switch to the next cthread that is ready to run
 *
 * @param ms
 *  Number of milliseconds to sleep
 *
 * @return
 *  none
 */
CNDP_API void cthread_sleep_msec(uint64_t ms);

/**
 * Cause the current cthread to sleep for n cpu clock ticks
 *
 *  The current thread will be suspended until the specified time has elapsed
 *  or has been exceeded.
 *
 *	 Execution will switch to the next cthread that is ready to run
 *
 * @param clks
 *  Number of clock ticks to sleep
 *
 * @return
 *  none
 */
CNDP_API void cthread_sleep_clks(uint64_t clks);

/**
 * Cause the current cthread to sleep for n nsecs
 *
 *  The current thread will be suspended until the specified time has elapsed
 *  or has been exceeded.
 *
 *	 Execution will switch to the next cthread that is ready to run
 *
 * @param nsecs
 *  Number of nsecs to sleep
 *
 * @return
 *  none
 */
CNDP_API void cthread_sleep_nsecs(uint64_t nsecs);

/**
 * Return the state of the expired flag
 *
 * @param ct
 *   If \p ct is null then use THIS_CTHREAD
 * @return
 *   True if ct has expired a timer
 */
CNDP_API int cthread_timer_expired(struct cthread *ct);

/**
 * Yield the current cthread
 *
 *  The current thread will yield and execution will switch to the
 *  next cthread that is ready to run
 *
 * @return
 *  none
 */
CNDP_API void cthread_yield(void);

/**
 * Migrate the current thread to another scheduler
 *
 *  This function migrates the current thread to another scheduler.
 *  Execution will switch to the next cthread that is ready to run on the
 *  current scheduler. The current thread will be resumed on the new scheduler.
 *
 * @param thread
 *	The thread to migrate to
 *
 * @return
 *  0   success we are now running on the specified core
 *  EINVAL the destination thread was not valid
 */
CNDP_API int cthread_set_affinity(int thread);

/**
 * Return the current cthread
 *
 *  Returns the current cthread
 *
 * @return
 *  pointer to the current cthread
 */
CNDP_API struct cthread *cthread_current(void);

/**
 * Set the current thread name
 *
 * @param f
 *   The name of the thread
 */
CNDP_API void cthread_set_name(const char *f);

/**
 * Get the thread name string
 *
 * @param ct
 *   The cthread pointer
 * @return
 *   The string pointer the name of thread or NULL on error
 */
CNDP_API const char *cthread_get_name(struct cthread *ct);

/**
 * Associate user data with an cthread
 *
 *  This function sets a user data pointer in the current cthread
 *  The pointer can be retrieved with cthread_get_data()
 *  It is the users responsibility to allocate and free any data referenced
 *  by the user pointer.
 *
 * @param data
 *  pointer to user data
 *
 * @return
 *  none
 */
CNDP_API void cthread_set_data(void *data);

/**
 * Get user data for the current cthread
 *
 *  This function returns a user data pointer for the current cthread
 *  The pointer must first be set with cthread_set_data()
 *  It is the users responsibility to allocate and free any data referenced
 *  by the user pointer.
 *
 * @return
 *  pointer to user data
 */
CNDP_API void *cthread_get_data(void);

struct cthread_key;
/**
 * Destructor function pointer
 */
typedef void (*tls_destructor_func)(void *);

/**
 * Create a key for cthread TLS
 *
 *  This function is modelled on pthread_key_create
 *  It creates a thread-specific data key visible to all cthreads on the
 *  current scheduler.
 *
 *  Key values may be used to locate thread-specific data.
 *  The same key value	may be used by different threads, the values bound
 *  to the key by	cthread_setspecific() are maintained on	a per-thread
 *  basis and persist for the life of the calling thread.
 *
 *  An	optional destructor function may be associated with each key value.
 *  At	thread exit, if	a key value has	a non-NULL destructor pointer, and the
 *  thread has	a non-NULL value associated with the key, the function pointed
 *  to	is called with the current associated value as its sole	argument.
 *
 * @param key
 *   Pointer to the key to be created
 * @param destructor
 *   Pointer to destructor function
 *
 * @return
 *  0 success
 *  EINVAL the key ptr was NULL
 *  EAGAIN no resources available
 */
CNDP_API int cthread_key_create(unsigned int *key, tls_destructor_func destructor);

/**
 * Delete key for cthread TLS
 *
 *  This function is modelled on pthread_key_delete().
 *  It deletes a thread-specific data key previously returned by
 *  cthread_key_create().
 *  The thread-specific data values associated with the key need not be NULL
 *  at the time that cthread_key_delete is called.
 *  It is the responsibility of the application to free any application
 *  storage or perform any cleanup actions for data structures related to the
 *  deleted key. This cleanup can be done either before or after
 * cthread_key_delete is called.
 *
 * @param key
 *  The key to be deleted
 *
 * @return
 *  0 Success
 *  EINVAL the key was invalid
 */
CNDP_API int cthread_key_delete(unsigned int key);

/**
 * Get cthread TLS
 *
 *  This function is modelled on pthread_get_specific().
 *  It returns the value currently bound to the specified key on behalf of the
 *  calling thread. Calling cthread_getspecific() with a key value not
 *  obtained from cthread_key_create() or after key has been deleted with
 *  cthread_key_delete() will result in undefined behaviour.
 *  cthread_getspecific() may be called from a thread-specific data destructor
 *  function.
 *
 * @param key
 *  The key for which data is requested
 *
 * @return
 *  Pointer to the thread specific data associated with that key
 *  or NULL if no data has been set.
 */
CNDP_API void *cthread_getspecific(unsigned int key);

/**
 * Set cthread TLS
 *
 *  This function is modelled on pthread_set_specific()
 *  It associates a thread-specific value with a key obtained via a previous
 *  call to cthread_key_create().
 *  Different threads may bind different values to the same key. These values
 *  are typically pointers to dynamically allocated memory that have been
 *  reserved by the calling thread. Calling cthread_setspecific with a key
 *  value not obtained from cthread_key_create or after the key has been
 *  deleted with cthread_key_delete will result in undefined behaviour.
 *
 * @param key
 *  The key for which data is to be set
 * @param value
 *  Pointer to the user data
 *
 * @return
 *  0 success
 *  EINVAL the key was invalid
 */

CNDP_API int cthread_setspecific(unsigned int key, const void *value);

/**
 * The macros below provide an alternative mechanism to access cthread local
 *  storage.
 *
 * The macros can be used to declare define and access per cthread local
 * storage in a similar way to the CNE_PER_THREAD macros which control storage
 * local to an thread.
 *
 * Memory for per cthread variables declared in this way is allocated when the
 * cthread is created and a pointer to this memory is stored in the cthread.
 * The per cthread variables are accessed via the pointer + the offset of the
 * particular variable.
 *
 * The total size of per cthread storage, and the variable offsets are found by
 * defining the variables in a unique global memory section, the start and end
 * of which is known. This global memory section is used only in the
 * computation of the addresses of the cthread variables, and is never actually
 * used to store any data.
 *
 * Due to the fact that variables declared this way may be scattered across
 * many files, the start and end of the section and variable offsets are only
 * known after linking, thus the computation of section size and variable
 * addresses is performed at run time.
 *
 * These macros are primarily provided to aid porting of code that makes use
 * of the existing CNE_PER_THREAD macros. In principle it would be more efficient
 * to gather all cthread local variables into a single structure and
 * set/retrieve a pointer to that struct using the alternative
 * cthread_data_set/get APIs.
 *
 * These macros are mutually exclusive with the cthread_data_set/get APIs.
 * If you define storage using these macros then the cthread_data_set/get APIs
 * will not perform as expected, the cthread_data_set API does nothing, and the
 * cthread_data_get API returns the start of global section.
 *
 */
/* start and end of per cthread section */
extern char __start_per_dt;
extern char __stop_per_dt;

#define CNE_DEFINE_PER_CTHREAD(type, name) \
    __typeof__(type) __attribute((section("per_dt"))) per_dt_##name

/**
 * Macro to declare an er cthread variable "var" of type "type"
 */
#define CNE_DECLARE_PER_CTHREAD(type, name) \
    extern __typeof__(type) __attribute((section("per_dt"))) per_dt_##name
/**
 * Read/write the per-thread variable value
 */
#define CNE_PER_CTHREAD(name)                               \
    ((typeof(per_dt_##name) *)((char *)cthread_get_data() + \
                               ((char *)&per_dt_##name - &__start_per_dt)))

/**
 * Initialize a mutex
 *
 *  This function provides a mutual exclusion device, the need for which
 *  can normally be avoided in a cooperative multitasking environment.
 *  It is provided to aid porting of legacy code originally written for
 *  preemptive multitasking environments such as pthreads.
 *
 *  A mutex may be unlocked (not owned by any thread), or locked (owned by
 *  one thread).
 *
 *  A mutex can never be owned  by more than one thread simultaneously.
 *  A thread attempting to lock a mutex that is already locked by another
 *  thread is suspended until the owning thread unlocks the mutex.
 *
 *  cthread_mutex_init() initializes the mutex object pointed to by mutex
 *  Optional mutex attributes specified in mutexattr, are reserved for future
 *  use and are currently ignored.
 *
 *  If a thread calls cthread_mutex_lock() on the mutex, then if the mutex
 *  is currently unlocked,  it  becomes  locked  and  owned  by  the calling
 *  thread, and cthread_mutex_lock returns immediately. If the mutex is
 *  already locked by another thread, cthread_mutex_lock suspends the calling
 *  thread until the mutex is unlocked.
 *
 *  cthread_mutex_trylock behaves identically to cthread_mutex_lock, except
 *  that it does not block the calling  thread  if the mutex is already locked
 *  by another thread.
 *
 *  cthread_mutex_unlock() unlocks the specified mutex. The mutex is assumed
 *  to be locked and owned by the calling thread.
 *
 *  cthread_mutex_destroy() destroys a	mutex object, freeing its resources.
 *  The mutex must be unlocked with nothing blocked on it before calling
 *  cthread_mutex_destroy.
 *
 * @param name
 *  Optional pointer to string describing the mutex
 * @param mutex
 *  Pointer to pointer to the mutex to be initialized
 * @param attr
 *  Pointer to attribute - unused reserved
 *
 * @return
 *  0 success
 *  EINVAL mutex was not a valid pointer
 *  EAGAIN insufficient resources
 */

CNDP_API int cthread_mutex_init(const char *name, struct cthread_mutex **mutex,
                                const struct cthread_mutexattr *attr);

/**
 * Destroy a mutex
 *
 *  This function destroys the specified mutex freeing its resources.
 *  The mutex must be unlocked before calling cthread_mutex_destroy.
 *
 * @see cthread_mutex_init()
 *
 * @param mutex
 *  Pointer to pointer to the mutex to be initialized
 *
 * @return
 *  0 success
 *  EINVAL mutex was not an initialized mutex
 *  EBUSY mutex was still in use
 */
CNDP_API int cthread_mutex_destroy(struct cthread_mutex *mutex);

/**
 * Lock a mutex
 *
 *  This function attempts to lock a mutex.
 *  If a thread calls cthread_mutex_lock() on the mutex, then if the mutex
 *  is currently unlocked,  it  becomes  locked  and  owned  by  the calling
 *  thread, and cthread_mutex_lock returns immediately. If the mutex is
 *  already locked by another thread, cthread_mutex_lock suspends the calling
 *  thread until the mutex is unlocked.
 *
 * @see cthread_mutex_init()
 *
 * @param mutex
 *  Pointer to pointer to the mutex to be initialized
 *
 * @return
 *  0 success
 *  EINVAL mutex was not an initialized mutex
 *  EDEADLOCK the mutex was already owned by the calling thread
 */

CNDP_API int cthread_mutex_lock(struct cthread_mutex *mutex);

/**
 * Try to lock a mutex
 *
 *  This function attempts to lock a mutex.
 *  cthread_mutex_trylock behaves identically to cthread_mutex_lock, except
 *  that it does not block the calling  thread  if the mutex is already locked
 *  by another thread.
 *
 *
 * @see cthread_mutex_init()
 *
 * @param mutex
 *  Pointer to pointer to the mutex to be initialized
 *
 * @return
 * 0 success
 * EINVAL mutex was not an initialized mutex
 * EBUSY the mutex was already locked by another thread
 */
CNDP_API int cthread_mutex_trylock(struct cthread_mutex *mutex);

/**
 * Unlock a mutex
 *
 * This function attempts to unlock the specified mutex. The mutex is assumed
 * to be locked and owned by the calling thread.
 *
 * The oldest of any threads blocked on the mutex is made ready and may
 * compete with any other running thread to gain the mutex, it fails it will
 * be blocked again.
 *
 * @param mutex
 * Pointer to pointer to the mutex to be initialized
 *
 * @return
 *  0 mutex was unlocked
 *  EINVAL mutex was not an initialized mutex
 *  EPERM the mutex was not owned by the calling thread
 */
CNDP_API int cthread_mutex_unlock(struct cthread_mutex *mutex);

/**
 * Get the mutex state value
 *
 * @param m
 *   The mutex structure pointer
 * @return
 *   The state value
 */
CNDP_API int cthread_mutex_state(struct cthread_mutex *m);

/**
 * Initialize a barrier structure
 *
 * @param name
 *   The name of the barrier
 * @param barr
 *   Pointer to a pointer of the cthread_barrier structure
 * @param count
 *   The number of times cthread_barrier_wait() needs to be called.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cthread_barrier_init(const char *name, struct cthread_barrier **barr, unsigned count);

/**
 * Destroy a barrier structure
 *
 * @param b
 *   The cthread_barrier pointer
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cthread_barrier_destroy(struct cthread_barrier *b);

/**
 * Wait on a barrier counter to be decremented to zero before returning.
 *
 * @param b
 *   The barrier pointer to wait on
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cthread_barrier_wait(struct cthread_barrier *b);

/**
 * Initialize a condition variable
 *
 *  This function initializes a condition variable.
 *
 *  Condition variables can be used to communicate changes in the state of data
 *  shared between threads.
 *
 * @see cthread_cond_wait()
 *
 * @param name
 *  Pointer to optional string describing the condition variable
 * @param c
 *  Pointer to pointer to the condition variable to be initialized
 * @param attr
 *  Pointer to optional attribute reserved for future use, currently ignored
 *
 * @return
 *  0 success
 *  EINVAL cond was not a valid pointer
 *  EAGAIN insufficient resources
 */
CNDP_API int cthread_cond_init(const char *name, struct cthread_cond **c,
                               const struct cthread_condattr *attr);

/**
 * Destroy a condition variable
 *
 *  This function destroys a condition variable that was created with
 *  cthread_cond_init() and releases its resources.
 *
 * @param cond
 *  Pointer to pointer to the condition variable to be destroyed
 *
 * @return
 *  0 Success
 *  EBUSY condition variable was still in use
 *  EINVAL was not an initialised condition variable
 */
CNDP_API int cthread_cond_destroy(struct cthread_cond *cond);

/**
 * Reset a condition variable to initialized state.
 *
 * @param cond
 *  Pointer to pointer to the condition variable to be destroyed
 *
 * @return
 *  0 Success
 *  EBUSY condition variable was still in use
 *  EINVAL was not an initialised condition variable
 */
CNDP_API int cthread_cond_reset(struct cthread_cond *cond);

/**
 * Wait on a condition variable
 *
 *  The function blocks the current thread waiting on the condition variable
 *  specified by cond. The waiting thread unblocks only after another thread
 *  calls cthread_cond_signal, or cthread_cond_broadcast, specifying the
 *  same condition variable.
 *
 * @param c
 *  Pointer to pointer to the condition variable to be waited on
 *
 * @param m
 *  Mutex to release or NULL if no mutex. (Currently not supported)
 *
 * @return
 *  0 The condition was signalled ( Success )
 *  EINVAL was not a an initialised condition variable
 */
CNDP_API int cthread_cond_wait(struct cthread_cond *c, struct cthread_mutex *m);

/**
 * Wait on a condition variable with timeout
 *
 *  The function blocks the current thread waiting on the condition variable
 *  specified by cond. The waiting thread unblocks only after another thread
 *  calls cthread_cond_signal, or cthread_cond_broadcast, specifying the
 *  same condition variable.
 *
 * @param c
 *  Pointer to pointer to the condition variable to be waited on
 *
 * @param m
 *  Mutex to release or NULL if no mutex. (Currently not supported)
 *
 * @param abstime
 *  Timespec used for timeout value. (Currently not supported)
 *
 * @return
 *  0 The condition was signalled ( Success )
 *  EINVAL was not a an initialised condition variable
 */
CNDP_API int cthread_cond_timedwait(struct cthread_cond *c, struct cthread_mutex *m,
                                    const struct timespec *abstime);

/**
 * Signal a condition variable
 *
 *  The function unblocks one thread waiting for the condition variable cond.
 *  If no threads are waiting on cond, the cthread_cond_signal() function
 *  has no effect.
 *
 * @param c
 *  Pointer to pointer to the condition variable to be signalled
 *
 * @return
 *  0 The condition was signalled ( Success )
 *  EINVAL was not a an initialised condition variable
 */
CNDP_API int cthread_cond_signal(struct cthread_cond *c);

/**
 * Broadcast a condition variable
 *
 *  The function unblocks all threads waiting for the condition variable cond.
 *  If no threads are waiting on cond, the cthread_cond_broadcast()
 *  function has no effect.
 *
 * @param c
 *  Pointer to pointer to the condition variable to be signalled
 *
 * @return
 *  0 The condition was signalled ( Success )
 *  EINVAL was not a an initialised condition variable
 */
CNDP_API int cthread_cond_broadcast(struct cthread_cond *c);

/**
 * Same as cthread_cond_broadcast(), but does not reschedule the threads
 *
 * @param c
 *  Pointer to pointer to the condition variable to be signalled
 *
 * @return
 *  0 The condition was signalled ( Success )
 *  EINVAL was not a an initialised condition variable
 */
CNDP_API int cthread_cond_broadcast_no_sched(struct cthread_cond *c);

/**
 * Initialize a semaphore
 *
 * The semaphore can be used to communicate changes in the state of data
 * shared between threads.
 *
 * @see cthread_sema_wait()
 *
 * @param name
 *   Pointer to optional string describing the semaphore
 * @param s
 *   Pointer to pointer to the semaphore to be initialized
 * @param attr
 *   Pointer to optional attribute used to set the initial semaphore
 *   count
 * @return
 *   0 success
 *   EINVAL s is not a valid pointer
 *   EAGAIN insufficient resources
 */
CNDP_API int cthread_sema_init(const char *name, struct cthread_sema **s,
                               const struct cthread_semaattr *attr);

/**
 * Destroy a semaphore
 *
 * This function destroys a semaphore that was created with
 * cthread_sema_init() and releases its resources.
 *
 * @param sema
 *   Pointer to the semaphore to be destroyed
 * @return
 *   0 Success
 *   EBUSY sema is still in use
 *   EINVAL sema is not an initialised semaphore
 */
CNDP_API int cthread_sema_destroy(struct cthread_sema *sema);

/**
 * Reset a semaphore to initialized state.
 *
 * @param sema
 *   Pointer to the semaphore to be reset
 * @return
 *   0 Success
 *   EINVAL sema is not an initialised semaphore
 */
CNDP_API int cthread_sema_reset(struct cthread_sema *sema);

/**
 * Wait on a semaphore
 *
 * The function blocks the current thread waiting on the semaphore
 * specified by s. The waiting thread unblocks only after another thread
 * calls cthread_sema_signal specifying the same semaphore.
 *
 * @param s
 *   Pointer to the semaphore on which to wait
 * @param m
 *   Mutex to release or NULL if no mutex.
 * @return
 *   0 Success
 *   EINVAL s is not an initialised semaphore
 */
CNDP_API int cthread_sema_wait(struct cthread_sema *s, struct cthread_mutex *m);

/**
 * Wait on a semaphore with timeout
 *
 * The function blocks the current thread waiting on the semaphore
 * specified by s. The waiting thread unblocks only after another thread
 * calls cthread_sema_signal specifying the same semaphore, or abstime elapses.
 *
 * @param s
 *   Pointer to the semaphore to be waited on
 * @param m
 *   Mutex to release or NULL if no mutex.
 * @param abstime
 *   Timespec used for timeout value.
 * @return
 *   0 Success
 *   CT_STATE_EXPIRED timeout expired without semaphore signal
 *   EINVAL s is not an initialised semaphore
 */
CNDP_API int cthread_sema_timedwait(struct cthread_sema *s, struct cthread_mutex *m,
                                    const struct timespec *abstime);

/**
 * Signal a semaphore
 *
 * The function unblocks one thread waiting for the semaphore.
 *
 * @param s
 *   Pointer to the semaphore to be signalled
 * @return
 *   0 Success
 *   EINVAL s is not an initialised semaphore
 */
CNDP_API int cthread_sema_signal(struct cthread_sema *s);

/**
 * Flush a semaphore
 *
 * The function unblocks all threads waiting for the semaphore.
 *
 * @param s
 *   Pointer to the semaphore to be flushed
 * @return
 *   0 Success
 *   EINVAL s is not an initialised semaphore
 */
CNDP_API int cthread_sema_flush(struct cthread_sema *s);

/**
 * Flush a semaphore, but do not reschedule threads
 *
 * The function unblocks all threads waiting for the semaphore.
 *
 * @param s
 *   Pointer to the semaphore to be flushed
 * @return
 *   0 Success
 *   EINVAL s is not an initialised semaphore
 */
CNDP_API int cthread_sema_flush_no_sched(struct cthread_sema *s);

/**
 * Return true if the current cthread is running
 */
CNDP_API int is_cthread_running(void);

/**
 * cthread callback function pointer for the foreach type APIs
 */
typedef int (*cthread_cb_t)(struct cthread *c, void *arg, int idx);

/**
 * Find a cthread structure pointer for a given scheduler and thread id.
 *
 * @param s
 *   The cthread scheduler pointer
 * @param threadid
 *   The threadid value to look for on the scheduler.
 * @return
 *   pointer to cthread structure or NULL on not found
 */
CNDP_API struct cthread *cthread_find(struct cthread_sched *s, int threadid);

/**
 * Foreach cthread on a scheduler call the function with argument
 *
 * @param s
 *   The scheduler structure pointer
 * @param func
 *   The function pointer to call for each cthread
 * @param arg
 *   The arg supplied by the user to pass to the callback function
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cthread_foreach(struct cthread_sched *s, cthread_cb_t func, void *arg);

/**
 * Get the scheduler for the cthread structure.
 *
 * @param c
 *   The cthread structure pointer
 * @return
 *   NULL on error or the cthread_sched structure pointer.
 */
CNDP_API struct cthread_sched *cthread_get_sched(struct cthread *c);

/**
 * The callback for the cthread_sched_foreach() callback.
 */
typedef int (*sched_cb_t)(struct cthread_sched *s, void *arg, int idx);

/**
 * return the scheduler ID value
 *
 * @param s
 *   The scheduler structure pointer
 * @return
 *   -1 on error or scheduler ID value
 */
CNDP_API int cthread_sched_id(struct cthread_sched *s);

/**
 * return the cthread_sched pointer for the given sched ID
 *
 * @param schedid
 *   The schedid value to search for in the scheduler list.
 * @return
 *   NULL on error or pointer to cthread_sched structure.
 */
CNDP_API struct cthread_sched *cthread_sched_find(int schedid);

/**
 * Loop over all schedulers and call the function pointer with argument.
 *
 * @param func
 *   The function to callback foreach scheduler passing the argument given
 * @param arg
 *   The argument to pass to the callback function
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cthread_sched_foreach(sched_cb_t func, void *arg);

/**
 * return the thread private pointer or value
 *
 * @param c
 *   The cthread structure pointer.
 * @return
 *   The therad private pointer value.
 */
CNDP_API void *cthread_thread_private(struct cthread *c);

/**
 * Set a thread private pointer or value.
 *
 * @param c
 *   The cthread structure pointer.
 * @param arg
 *   The pointer value to set in the cthread structure. The value is not used
 *   or freed on thread exit.
 * @return
 *   0 on success or -1 on error.
 */
CNDP_API int cthread_set_thread_private(struct cthread *c, void *arg);

/**
 * Initialize a once only structure
 *
 * @param once
 *   Pointer to pointer of a cthread_once structure
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cthread_once_init(struct cthread_once **once);

/**
 * Destroy a cthread_once structure
 *
 * @param once
 *   Pointer to pointer of a cthread_once structure
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cthread_once_destroy(struct cthread_once *once);

/**
 * Reset a cthread_once structure
 *
 * @param once
 *   Pointer to pointer of a cthread_once structure
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cthread_once_reset(struct cthread_once *once);

/**
 * Execute the function only once with the cthread_once structure
 *
 * @param once
 *   Pointer to pointer of a cthread_once structure
 * @param func
 *   The function to call only once passsing the argument value.
 * @param arg
 *   The opaque data to pass to \p func.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cthread_once(struct cthread_once *once, int (*func)(void *), void *arg);

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_API_H */
