/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Red Hat, Inc.
 */

#ifndef CNE_LOCK_ANNOTATIONS_H
#define CNE_LOCK_ANNOTATIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CNE_ANNOTATE_LOCKS

#define __cne_lockable __attribute__((lockable))

#define __cne_guarded_by(...) __attribute__((guarded_by(__VA_ARGS__)))
#define __cne_guarded_var     __attribute__((guarded_var))

#define __cne_exclusive_locks_required(...) __attribute__((exclusive_locks_required(__VA_ARGS__)))
#define __cne_exclusive_lock_function(...)  __attribute__((exclusive_lock_function(__VA_ARGS__)))
#define __cne_exclusive_trylock_function(ret, ...) \
    __attribute__((exclusive_trylock_function(ret, __VA_ARGS__)))
#define __cne_assert_exclusive_lock(...) __attribute__((assert_exclusive_lock(__VA_ARGS__)))

#define __cne_shared_locks_required(...) __attribute__((shared_locks_required(__VA_ARGS__)))
#define __cne_shared_lock_function(...)  __attribute__((shared_lock_function(__VA_ARGS__)))
#define __cne_shared_trylock_function(ret, ...) \
    __attribute__((shared_trylock_function(ret, __VA_ARGS__)))
#define __cne_assert_shared_lock(...) __attribute__((assert_shared_lock(__VA_ARGS__)))

#define __cne_unlock_function(...) __attribute__((unlock_function(__VA_ARGS__)))

#define __cne_no_thread_safety_analysis __attribute__((no_thread_safety_analysis))

#else /* ! CNE_ANNOTATE_LOCKS */

#define __cne_lockable

#define __cne_guarded_by(...)
#define __cne_guarded_var

#define __cne_exclusive_locks_required(...)
#define __cne_exclusive_lock_function(...)
#define __cne_exclusive_trylock_function(...)
#define __cne_assert_exclusive_lock(...)

#define __cne_shared_locks_required(...)
#define __cne_shared_lock_function(...)
#define __cne_shared_trylock_function(...)
#define __cne_assert_shared_lock(...)

#define __cne_unlock_function(...)

#define __cne_no_thread_safety_analysis

#endif /* CNE_ANNOTATE_LOCKS */

#ifdef __cplusplus
}
#endif

#endif /* CNE_LOCK_ANNOTATIONS_H */
