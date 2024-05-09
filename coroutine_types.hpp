///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////

/// Source: https://raw.githubusercontent.com/lewissbaker/cppcoro/master/include/cppcoro/config.hpp
///

/////////////////////////////////////////////////////////////////////////////
// Compiler Detection

#if defined(_MSC_VER)
# define CPPCORO_COMPILER_MSVC _MSC_FULL_VER
#else
# define CPPCORO_COMPILER_MSVC 0
#endif

#if defined(__clang__)
# define CPPCORO_COMPILER_CLANG (__clang_major__ * 10000 + \
                                 __clang_minor__ * 100 + \
                                 __clang_patchlevel__)
#else
# define CPPCORO_COMPILER_CLANG 0
#endif

#if defined(__GNUC__)
# define CPPCORO_COMPILER_GCC (__GNUC__ * 10000 + \
                               __GNUC_MINOR__ * 100 + \
                               __GNUC_PATCHLEVEL__)
#else
# define CPPCORO_COMPILER_GCC 0
#endif

/// \def CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
/// Defined to 1 if the compiler supports returning a coroutine_handle from
/// the await_suspend() method as a way of transferring execution
/// to another coroutine with a guaranteed tail-call.
#if CPPCORO_COMPILER_CLANG
# if __clang_major__ >= 7
#  define CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER 1
# endif
#endif
#ifndef CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
# define CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER 0
#endif

#if CPPCORO_COMPILER_MSVC
# define CPPCORO_ASSUME(X) __assume(X)
#else
# define CPPCORO_ASSUME(X)
#endif

#if CPPCORO_COMPILER_MSVC
# define CPPCORO_NOINLINE __declspec(noinline)
#elif CPPCORO_COMPILER_CLANG || CPPCORO_COMPILER_GCC
# define CPPCORO_NOINLINE __attribute__((noinline))
#else
# define CPPCORO_NOINLINE
#endif

#if CPPCORO_COMPILER_MSVC
# define CPPCORO_FORCE_INLINE __forceinline
#elif CPPCORO_COMPILER_CLANG
# define CPPCORO_FORCE_INLINE __attribute__((always_inline))
#else
# define CPPCORO_FORCE_INLINE inline
#endif

/////////////////////////////////////////////////////////////////////////////
// OS Detection

/// \def CPPCORO_OS_WINNT
/// Defined to non-zero if the target platform is a WindowsNT variant.
/// 0x0500 - Windows 2000
/// 0x0501 - Windows XP/Server 2003
/// 0x0502 - Windows XP SP2/Server 2003 SP1
/// 0x0600 - Windows Vista/Server 2008
/// 0x0601 - Windows 7
/// 0x0602 - Windows 8
/// 0x0603 - Windows 8.1
/// 0x0A00 - Windows 10
#if defined(_WIN32_WINNT) || defined(_WIN32)
# if !defined(_WIN32_WINNT)
// Default to targeting Windows 10 if not defined.
#  define _WIN32_WINNT 0x0A00
# endif
# define CPPCORO_OS_WINNT _WIN32_WINNT
#else
# define CPPCORO_OS_WINNT 0
#endif

#if defined(__linux__)
# define CPPCORO_OS_LINUX 1
#else
# define CPPCORO_OS_LINUX 0
#endif

/////////////////////////////////////////////////////////////////////////////
// CPU Detection

/// \def CPPCORO_CPU_X86
/// Defined to 1 if target CPU is of x86 family.
#if CPPCORO_COMPILER_MSVC
# if defined(_M_IX86)
#  define CPPCORO_CPU_X86 1
# endif
#elif CPPCORO_COMPILER_GCC || CPPCORO_COMPILER_CLANG
# if defined(__i386__)
#  define CPPCORO_CPU_X86 1
# endif
#endif
#if !defined(CPPCORO_CPU_X86)
# define CPPCORO_CPU_X86 0
#endif

/// \def CPPCORO_CPU_X64
/// Defined to 1 if the target CPU is x64 family.
#if CPPCORO_COMPILER_MSVC
# if defined(_M_X64)
#  define CPPCORO_CPU_X64 1
# endif
#elif CPPCORO_COMPILER_GCC || CPPCORO_COMPILER_CLANG
# if defined(__x86_64__)
#  define CPPCORO_CPU_X64 1
# endif
#endif
#if !defined(CPPCORO_CPU_X64)
# define CPPCORO_CPU_X64 0
#endif

/// \def CPPCORO_CPU_32BIT
/// Defined if compiling for a 32-bit CPU architecture.
#if CPPCORO_CPU_X86
# define CPPCORO_CPU_32BIT 1
#else
# define CPPCORO_CPU_32BIT 0
#endif

/// \def CPPCORO_CPU_64BIT
/// Defined if compiling for a 64-bit CPU architecture.
#if CPPCORO_CPU_X64
# define CPPCORO_CPU_64BIT 1
#else
# define CPPCORO_CPU_64BIT 0
#endif

#if CPPCORO_COMPILER_MSVC
# define CPPCORO_CPU_CACHE_LINE std::hardware_destructive_interference_size
#else
// On most architectures we can assume a 64-byte cache line.
# define CPPCORO_CPU_CACHE_LINE 64
#endif

/// Source:
/// https://raw.githubusercontent.com/lewissbaker/cppcoro/master/include/cppcoro/detail/is_awaiter.hpp

#include <coroutine>

namespace cppcoro
{
	namespace detail
	{
		template<typename T>
		struct is_coroutine_handle
			: std::false_type
		{};

		template<typename PROMISE>
		struct is_coroutine_handle<std::coroutine_handle<PROMISE>>
			: std::true_type
		{};

		// NOTE: We're accepting a return value of coroutine_handle<P> here
		// which is an extension supported by Clang which is not yet part of
		// the C++ coroutines TS.
		template<typename T>
		struct is_valid_await_suspend_return_value : std::disjunction<
			std::is_void<T>,
			std::is_same<T, bool>,
			is_coroutine_handle<T>>
		{};

		template<typename T, typename = std::void_t<>>
		struct is_awaiter : std::false_type {};

		// NOTE: We're testing whether await_suspend() will be callable using an
		// arbitrary coroutine_handle here by checking if it supports being passed
		// a coroutine_handle<void>. This may result in a false-result for some
		// types which are only awaitable within a certain context.
		template<typename T>
		struct is_awaiter<T, std::void_t<
			decltype(std::declval<T>().await_ready()),
			decltype(std::declval<T>().await_suspend(std::declval<std::coroutine_handle<>>())),
			decltype(std::declval<T>().await_resume())>> :
			std::conjunction<
				std::is_constructible<bool, decltype(std::declval<T>().await_ready())>,
				detail::is_valid_await_suspend_return_value<
					decltype(std::declval<T>().await_suspend(std::declval<std::coroutine_handle<>>()))>>
		{};
	}
}

/// Source:
/// https://raw.githubusercontent.com/lewissbaker/cppcoro/master/include/cppcoro/detail/any.hpp

namespace cppcoro
{
	namespace detail
	{
		// Helper type that can be cast-to from any type.
		struct any
		{
			template<typename T>
			any(T&&) noexcept
			{}
		};
	}
}

/// Based on:
/// https://raw.githubusercontent.com/lewissbaker/cppcoro/master/include/cppcoro/detail/get_awaiter.hpp

namespace cppcoro
{
	namespace detail
	{
		template<typename T>
		auto get_awaiter_impl(T&& value, int)
			noexcept(noexcept(static_cast<T&&>(value).operator co_await()))
			-> decltype(static_cast<T&&>(value).operator co_await())
		{
			return static_cast<T&&>(value).operator co_await();
		}

		template<typename T>
		auto get_awaiter_impl(T&& value, long)
			noexcept(noexcept(operator co_await(static_cast<T&&>(value))))
			-> decltype(operator co_await(static_cast<T&&>(value)))
		{
			return operator co_await(static_cast<T&&>(value));
		}

		template<
			typename T,
			std::enable_if_t<cppcoro::detail::is_awaiter<T&&>::value, int> = 0>
		T&& get_awaiter_impl(T&& value, cppcoro::detail::any) noexcept
		{
			return static_cast<T&&>(value);
		}

		template<typename T>
		auto get_awaiter(T&& value)
			noexcept(noexcept(detail::get_awaiter_impl(static_cast<T&&>(value), 123)))
			-> decltype(detail::get_awaiter_impl(static_cast<T&&>(value), 123))
		{
			return detail::get_awaiter_impl(static_cast<T&&>(value), 123);
		}
	}
}

/// Source:
/// https://raw.githubusercontent.com/lewissbaker/cppcoro/master/include/cppcoro/awaitable_traits.hpp

#include <type_traits>

namespace cppcoro
{
	template<typename T, typename = void>
	struct awaitable_traits
	{};

	template<typename T>
	struct awaitable_traits<T, std::void_t<decltype(cppcoro::detail::get_awaiter(std::declval<T>()))>>
	{
		using awaiter_t = decltype(cppcoro::detail::get_awaiter(std::declval<T>()));

		using await_result_t = decltype(std::declval<awaiter_t>().await_resume());
	};
}

/// Source:
/// https://raw.githubusercontent.com/lewissbaker/cppcoro/master/include/cppcoro/detail/remove_rvalue_reference.hpp

namespace cppcoro
{
	namespace detail
	{
		template<typename T>
		struct remove_rvalue_reference
		{
			using type = T;
		};

		template<typename T>
		struct remove_rvalue_reference<T&&>
		{
			using type = T;
		};

		template<typename T>
		using remove_rvalue_reference_t = typename remove_rvalue_reference<T>::type;
	}
}

/// Source:
/// https://raw.githubusercontent.com/lewissbaker/cppcoro/master/include/cppcoro/task.hpp

#include <stdexcept>

namespace cppcoro
{
	/// \brief
	/// Exception thrown when you attempt to retrieve the result of
	/// a task that has been detached from its promise/coroutine.
	class broken_promise : public std::logic_error
	{
	public:
		broken_promise()
			: std::logic_error("broken promise")
		{}
	};
}

/// Source:
/// https://raw.githubusercontent.com/lewissbaker/cppcoro/master/include/cppcoro/task.hpp

#include <atomic>
#include <exception>
#include <utility>
#include <cstdint>
#include <cassert>

namespace cppcoro
{
	template<typename T> class task;

	namespace detail
	{
		class task_promise_base
		{
			friend struct final_awaitable;

			struct final_awaitable
			{
				bool await_ready() const noexcept { return false; }

#if CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
				template<typename PROMISE>
				std::coroutine_handle<> await_suspend(
					std::coroutine_handle<PROMISE> coro) noexcept
				{
					return coro.promise().m_continuation;
				}
#else
				// HACK: Need to add CPPCORO_NOINLINE to await_suspend() method
				// to avoid MSVC 2017.8 from spilling some local variables in
				// await_suspend() onto the coroutine frame in some cases.
				// Without this, some tests in async_auto_reset_event_tests.cpp
				// were crashing under x86 optimised builds.
				template<typename PROMISE>
				CPPCORO_NOINLINE
				void await_suspend(std::coroutine_handle<PROMISE> coroutine) noexcept
				{
					task_promise_base& promise = coroutine.promise();

					// Use 'release' memory semantics in case we finish before the
					// awaiter can suspend so that the awaiting thread sees our
					// writes to the resulting value.
					// Use 'acquire' memory semantics in case the caller registered
					// the continuation before we finished. Ensure we see their write
					// to m_continuation.
					if (promise.m_state.exchange(true, std::memory_order_acq_rel))
					{
						promise.m_continuation.resume();
					}
				}
#endif

				void await_resume() noexcept {}
			};

		public:

			task_promise_base() noexcept
#if !CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
				: m_state(false)
#endif
			{}

			auto initial_suspend() noexcept
			{
				return std::suspend_always{};
			}

			auto final_suspend() noexcept
			{
				return final_awaitable{};
			}

#if CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
			void set_continuation(std::coroutine_handle<> continuation) noexcept
			{
				m_continuation = continuation;
			}
#else
			bool try_set_continuation(std::coroutine_handle<> continuation)
			{
				m_continuation = continuation;
				return !m_state.exchange(true, std::memory_order_acq_rel);
			}
#endif

		private:

			std::coroutine_handle<> m_continuation;

#if !CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
			// Initially false. Set to true when either a continuation is registered
			// or when the coroutine has run to completion. Whichever operation
			// successfully transitions from false->true got there first.
			std::atomic<bool> m_state;
#endif

		};

		template<typename T>
		class task_promise final : public task_promise_base
		{
		public:

			task_promise() noexcept {}

			~task_promise()
			{
				switch (m_resultType)
				{
				case result_type::value:
					m_value.~T();
					break;
				case result_type::exception:
					m_exception.~exception_ptr();
					break;
				default:
					break;
				}
			}

			task<T> get_return_object() noexcept;

			void unhandled_exception() noexcept
			{
				::new (static_cast<void*>(std::addressof(m_exception))) std::exception_ptr(
					std::current_exception());
				m_resultType = result_type::exception;
			}

			template<
				typename VALUE,
				typename = std::enable_if_t<std::is_convertible_v<VALUE&&, T>>>
			void return_value(VALUE&& value)
				noexcept(std::is_nothrow_constructible_v<T, VALUE&&>)
			{
				::new (static_cast<void*>(std::addressof(m_value))) T(std::forward<VALUE>(value));
				m_resultType = result_type::value;
			}

			T& result() &
			{
				if (m_resultType == result_type::exception)
				{
					std::rethrow_exception(m_exception);
				}

				assert(m_resultType == result_type::value);

				return m_value;
			}

			// HACK: Need to have co_await of task<int> return prvalue rather than
			// rvalue-reference to work around an issue with MSVC where returning
			// rvalue reference of a fundamental type from await_resume() will
			// cause the value to be copied to a temporary. This breaks the
			// sync_wait() implementation.
			// See https://github.com/lewissbaker/cppcoro/issues/40#issuecomment-326864107
			using rvalue_type = std::conditional_t<
				std::is_arithmetic_v<T> || std::is_pointer_v<T>,
				T,
				T&&>;

			rvalue_type result() &&
			{
				if (m_resultType == result_type::exception)
				{
					std::rethrow_exception(m_exception);
				}

				assert(m_resultType == result_type::value);

				return std::move(m_value);
			}

		private:

			enum class result_type { empty, value, exception };

			result_type m_resultType = result_type::empty;

			union
			{
				T m_value;
				std::exception_ptr m_exception;
			};

		};

		template<>
		class task_promise<void> : public task_promise_base
		{
		public:

			task_promise() noexcept = default;

			task<void> get_return_object() noexcept;

			void return_void() noexcept
			{}

			void unhandled_exception() noexcept
			{
				m_exception = std::current_exception();
			}

			void result()
			{
				if (m_exception)
				{
					std::rethrow_exception(m_exception);
				}
			}

		private:

			std::exception_ptr m_exception;

		};

		template<typename T>
		class task_promise<T&> : public task_promise_base
		{
		public:

			task_promise() noexcept = default;

			task<T&> get_return_object() noexcept;

			void unhandled_exception() noexcept
			{
				m_exception = std::current_exception();
			}

			void return_value(T& value) noexcept
			{
				m_value = std::addressof(value);
			}

			T& result()
			{
				if (m_exception)
				{
					std::rethrow_exception(m_exception);
				}

				return *m_value;
			}

		private:

			T* m_value = nullptr;
			std::exception_ptr m_exception;

		};
	}

	/// \brief
	/// A task represents an operation that produces a result both lazily
	/// and asynchronously.
	///
	/// When you call a coroutine that returns a task, the coroutine
	/// simply captures any passed parameters and returns exeuction to the
	/// caller. Execution of the coroutine body does not start until the
	/// coroutine is first co_await'ed.
	template<typename T = void>
	class [[nodiscard]] task
	{
	public:

		using promise_type = detail::task_promise<T>;

		using value_type = T;

	private:

		struct awaitable_base
		{
			std::coroutine_handle<promise_type> m_coroutine;

			awaitable_base(std::coroutine_handle<promise_type> coroutine) noexcept
				: m_coroutine(coroutine)
			{}

			bool await_ready() const noexcept
			{
				return !m_coroutine || m_coroutine.done();
			}

#if CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
			std::coroutine_handle<> await_suspend(
				std::coroutine_handle<> awaitingCoroutine) noexcept
			{
				m_coroutine.promise().set_continuation(awaitingCoroutine);
				return m_coroutine;
			}
#else
			bool await_suspend(std::coroutine_handle<> awaitingCoroutine) noexcept
			{
				// NOTE: We are using the bool-returning version of await_suspend() here
				// to work around a potential stack-overflow issue if a coroutine
				// awaits many synchronously-completing tasks in a loop.
				//
				// We first start the task by calling resume() and then conditionally
				// attach the continuation if it has not already completed. This allows us
				// to immediately resume the awaiting coroutine without increasing
				// the stack depth, avoiding the stack-overflow problem. However, it has
				// the down-side of requiring a std::atomic to arbitrate the race between
				// the coroutine potentially completing on another thread concurrently
				// with registering the continuation on this thread.
				//
				// We can eliminate the use of the std::atomic once we have access to
				// coroutine_handle-returning await_suspend() on both MSVC and Clang
				// as this will provide ability to suspend the awaiting coroutine and
				// resume another coroutine with a guaranteed tail-call to resume().
				m_coroutine.resume();
				return m_coroutine.promise().try_set_continuation(awaitingCoroutine);
			}
#endif
		};

	public:

		task() noexcept
			: m_coroutine(nullptr)
		{}

		explicit task(std::coroutine_handle<promise_type> coroutine)
			: m_coroutine(coroutine)
		{}

		task(task&& t) noexcept
			: m_coroutine(t.m_coroutine)
		{
			t.m_coroutine = nullptr;
		}

		/// Disable copy construction/assignment.
		task(const task&) = delete;
		task& operator=(const task&) = delete;

		/// Frees resources used by this task.
		~task()
		{
			if (m_coroutine)
			{
				m_coroutine.destroy();
			}
		}

		task& operator=(task&& other) noexcept
		{
			if (std::addressof(other) != this)
			{
				if (m_coroutine)
				{
					m_coroutine.destroy();
				}

				m_coroutine = other.m_coroutine;
				other.m_coroutine = nullptr;
			}

			return *this;
		}

		/// \brief
		/// Query if the task result is complete.
		///
		/// Awaiting a task that is ready is guaranteed not to block/suspend.
		bool is_ready() const noexcept
		{
			return !m_coroutine || m_coroutine.done();
		}

		auto operator co_await() const & noexcept
		{
			struct awaitable : awaitable_base
			{
				using awaitable_base::awaitable_base;

				decltype(auto) await_resume()
				{
					if (!this->m_coroutine)
					{
						throw broken_promise{};
					}

					return this->m_coroutine.promise().result();
				}
			};

			return awaitable{ m_coroutine };
		}

		auto operator co_await() const && noexcept
		{
			struct awaitable : awaitable_base
			{
				using awaitable_base::awaitable_base;

				decltype(auto) await_resume()
				{
					if (!this->m_coroutine)
					{
						throw broken_promise{};
					}

					return std::move(this->m_coroutine.promise()).result();
				}
			};

			return awaitable{ m_coroutine };
		}

		/// \brief
		/// Returns an awaitable that will await completion of the task without
		/// attempting to retrieve the result.
		auto when_ready() const noexcept
		{
			struct awaitable : awaitable_base
			{
				using awaitable_base::awaitable_base;

				void await_resume() const noexcept {}
			};

			return awaitable{ m_coroutine };
		}

	private:

		std::coroutine_handle<promise_type> m_coroutine;

	};

	namespace detail
	{
		template<typename T>
		task<T> task_promise<T>::get_return_object() noexcept
		{
			return task<T>{ std::coroutine_handle<task_promise>::from_promise(*this) };
		}

		inline task<void> task_promise<void>::get_return_object() noexcept
		{
			return task<void>{ std::coroutine_handle<task_promise>::from_promise(*this) };
		}

		template<typename T>
		task<T&> task_promise<T&>::get_return_object() noexcept
		{
			return task<T&>{ std::coroutine_handle<task_promise>::from_promise(*this) };
		}
	}

	template<typename AWAITABLE>
	auto make_task(AWAITABLE awaitable)
		-> task<detail::remove_rvalue_reference_t<typename awaitable_traits<AWAITABLE>::await_result_t>>
	{
		co_return co_await static_cast<AWAITABLE&&>(awaitable);
	}
}

/// Source:
/// https://raw.githubusercontent.com/lewissbaker/cppcoro/master/include/cppcoro/detail/lightweight_manual_reset_event.hpp

#if CPPCORO_OS_LINUX || (CPPCORO_OS_WINNT >= 0x0602)
# include <atomic>
# include <cstdint>
#elif CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
#else
# include <mutex>
# include <condition_variable>
#endif

namespace cppcoro
{
	namespace detail
	{
		class lightweight_manual_reset_event
		{
		public:

			lightweight_manual_reset_event(bool initiallySet = false);

			~lightweight_manual_reset_event();

			void set() noexcept;

			void reset() noexcept;

			void wait() noexcept;

		private:

#if CPPCORO_OS_LINUX
			std::atomic<int> m_value;
#elif CPPCORO_OS_WINNT >= 0x0602
			// Windows 8 or newer we can use WaitOnAddress()
			std::atomic<std::uint8_t> m_value;
#elif CPPCORO_OS_WINNT
			// Before Windows 8 we need to use a WIN32 manual reset event.
			cppcoro::detail::win32::handle_t m_eventHandle;
#else
			// For other platforms that don't have a native futex
			// or manual reset event we can just use a std::mutex
			// and std::condition_variable to perform the wait.
			// Not so lightweight, but should be portable to all platforms.
			std::mutex m_mutex;
			std::condition_variable m_cv;
			bool m_isSet;
#endif
		};
	}
}

/// Source:
/// https://raw.githubusercontent.com/lewissbaker/cppcoro/master/include/cppcoro/detail/sync_wait_task.hpp

namespace cppcoro
{
	namespace detail
	{
		template<typename RESULT>
		class sync_wait_task;

		template<typename RESULT>
		class sync_wait_task_promise final
		{
			using coroutine_handle_t = std::coroutine_handle<sync_wait_task_promise<RESULT>>;

		public:

			using reference = RESULT&&;

			sync_wait_task_promise() noexcept
			{}

			void start(detail::lightweight_manual_reset_event& event)
			{
				m_event = &event;
				coroutine_handle_t::from_promise(*this).resume();
			}

			auto get_return_object() noexcept
			{
				return coroutine_handle_t::from_promise(*this);
			}

			std::suspend_always initial_suspend() noexcept
			{
				return{};
			}

			auto final_suspend() noexcept
			{
				class completion_notifier
				{
				public:

					bool await_ready() const noexcept { return false; }

					void await_suspend(coroutine_handle_t coroutine) const noexcept
					{
						coroutine.promise().m_event->set();
					}

					void await_resume() noexcept {}
				};

				return completion_notifier{};
			}

#if CPPCORO_COMPILER_MSVC
			// HACK: This is needed to work around a bug in MSVC 2017.7/2017.8.
			// See comment in make_sync_wait_task below.
			template<typename Awaitable>
			Awaitable&& await_transform(Awaitable&& awaitable)
			{
				return static_cast<Awaitable&&>(awaitable);
			}

			struct get_promise_t {};
			static constexpr get_promise_t get_promise = {};

			auto await_transform(get_promise_t)
			{
				class awaiter
				{
				public:
					awaiter(sync_wait_task_promise* promise) noexcept : m_promise(promise) {}
					bool await_ready() noexcept {
						return true;
					}
					void await_suspend(std::coroutine_handle<>) noexcept {}
					sync_wait_task_promise& await_resume() noexcept
					{
						return *m_promise;
					}
				private:
					sync_wait_task_promise* m_promise;
				};
				return awaiter{ this };
			}
#endif

			auto yield_value(reference result) noexcept
			{
				m_result = std::addressof(result);
				return final_suspend();
			}

			void return_void() noexcept
			{
				// The coroutine should have either yielded a value or thrown
				// an exception in which case it should have bypassed return_void().
				assert(false);
			}

			void unhandled_exception()
			{
				m_exception = std::current_exception();
			}

			reference result()
			{
				if (m_exception)
				{
					std::rethrow_exception(m_exception);
				}

				return static_cast<reference>(*m_result);
			}

		private:

			detail::lightweight_manual_reset_event* m_event;
			std::remove_reference_t<RESULT>* m_result;
			std::exception_ptr m_exception;

		};

		template<>
		class sync_wait_task_promise<void>
		{
			using coroutine_handle_t = std::coroutine_handle<sync_wait_task_promise<void>>;

		public:

			sync_wait_task_promise() noexcept
			{}

			void start(detail::lightweight_manual_reset_event& event)
			{
				m_event = &event;
				coroutine_handle_t::from_promise(*this).resume();
			}

			auto get_return_object() noexcept
			{
				return coroutine_handle_t::from_promise(*this);
			}

			std::suspend_always initial_suspend() noexcept
			{
				return{};
			}

			auto final_suspend() noexcept
			{
				class completion_notifier
				{
				public:

					bool await_ready() const noexcept { return false; }

					void await_suspend(coroutine_handle_t coroutine) const noexcept
					{
						coroutine.promise().m_event->set();
					}

					void await_resume() noexcept {}
				};

				return completion_notifier{};
			}

			void return_void() {}

			void unhandled_exception()
			{
				m_exception = std::current_exception();
			}

			void result()
			{
				if (m_exception)
				{
					std::rethrow_exception(m_exception);
				}
			}

		private:

			detail::lightweight_manual_reset_event* m_event;
			std::exception_ptr m_exception;

		};

		template<typename RESULT>
		class sync_wait_task final
		{
		public:

			using promise_type = sync_wait_task_promise<RESULT>;

			using coroutine_handle_t = std::coroutine_handle<promise_type>;

			sync_wait_task(coroutine_handle_t coroutine) noexcept
				: m_coroutine(coroutine)
			{}

			sync_wait_task(sync_wait_task&& other) noexcept
				: m_coroutine(std::exchange(other.m_coroutine, coroutine_handle_t{}))
			{}

			~sync_wait_task()
			{
				if (m_coroutine) m_coroutine.destroy();
			}

			sync_wait_task(const sync_wait_task&) = delete;
			sync_wait_task& operator=(const sync_wait_task&) = delete;

			void start(lightweight_manual_reset_event& event) noexcept
			{
				m_coroutine.promise().start(event);
			}

			decltype(auto) result()
			{
				return m_coroutine.promise().result();
			}

		private:

			coroutine_handle_t m_coroutine;

		};

#if CPPCORO_COMPILER_MSVC
		// HACK: Work around bug in MSVC where passing a parameter by universal reference
		// results in an error when passed a move-only type, complaining that the copy-constructor
		// has been deleted. The parameter should be passed by reference and the compiler should
		// notcalling the copy-constructor for the argument
		template<
			typename AWAITABLE,
			typename RESULT = typename cppcoro::awaitable_traits<AWAITABLE&&>::await_result_t,
			std::enable_if_t<!std::is_void_v<RESULT>, int> = 0>
		sync_wait_task<RESULT> make_sync_wait_task(AWAITABLE& awaitable)
		{
			// HACK: Workaround another bug in MSVC where the expression 'co_yield co_await x' seems
			// to completely ignore the co_yield an never calls promise.yield_value().
			// The coroutine seems to be resuming the 'co_await' after the 'co_yield'
			// rather than before the 'co_yield'.
			// This bug is present in VS 2017.7 and VS 2017.8.
			auto& promise = co_await sync_wait_task_promise<RESULT>::get_promise;
			co_await promise.yield_value(co_await std::forward<AWAITABLE>(awaitable));

			//co_yield co_await std::forward<AWAITABLE>(awaitable);
		}

		template<
			typename AWAITABLE,
			typename RESULT = typename cppcoro::awaitable_traits<AWAITABLE&&>::await_result_t,
			std::enable_if_t<std::is_void_v<RESULT>, int> = 0>
		sync_wait_task<void> make_sync_wait_task(AWAITABLE& awaitable)
		{
			co_await static_cast<AWAITABLE&&>(awaitable);
		}
#else
		template<
			typename AWAITABLE,
			typename RESULT = typename cppcoro::awaitable_traits<AWAITABLE&&>::await_result_t,
			std::enable_if_t<!std::is_void_v<RESULT>, int> = 0>
		sync_wait_task<RESULT> make_sync_wait_task(AWAITABLE&& awaitable)
		{
			co_yield co_await std::forward<AWAITABLE>(awaitable);
		}

		template<
			typename AWAITABLE,
			typename RESULT = typename cppcoro::awaitable_traits<AWAITABLE&&>::await_result_t,
			std::enable_if_t<std::is_void_v<RESULT>, int> = 0>
		sync_wait_task<void> make_sync_wait_task(AWAITABLE&& awaitable)
		{
			co_await std::forward<AWAITABLE>(awaitable);
		}
#endif
	}
}

/// Source:
/// https://raw.githubusercontent.com/lewissbaker/cppcoro/master/include/cppcoro/sync_wait.hpp

#include <cstdint>
#include <atomic>

namespace cppcoro
{
	template<typename AWAITABLE>
	auto sync_wait(AWAITABLE&& awaitable)
		-> typename cppcoro::awaitable_traits<AWAITABLE&&>::await_result_t
	{
#if CPPCORO_COMPILER_MSVC
		// HACK: Need to explicitly specify template argument to make_sync_wait_task
		// here to work around a bug in MSVC when passing parameters by universal
		// reference to a coroutine which causes the compiler to think it needs to
		// 'move' parameters passed by rvalue reference.
		auto task = detail::make_sync_wait_task<AWAITABLE>(awaitable);
#else
		auto task = detail::make_sync_wait_task(std::forward<AWAITABLE>(awaitable));
#endif
		detail::lightweight_manual_reset_event event;
		task.start(event);
		event.wait();
		return task.result();
	}
}

/// Source:
/// https://raw.githubusercontent.com/lewissbaker/cppcoro/master/lib/lightweight_manual_reset_event.cpp

#include <system_error>

#if CPPCORO_OS_WINNT
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <Windows.h>

# if CPPCORO_OS_WINNT >= 0x0602

cppcoro::detail::lightweight_manual_reset_event::lightweight_manual_reset_event(bool initiallySet)
	: m_value(initiallySet ? 1 : 0)
{}

cppcoro::detail::lightweight_manual_reset_event::~lightweight_manual_reset_event()
{
}

void cppcoro::detail::lightweight_manual_reset_event::set() noexcept
{
	m_value.store(1, std::memory_order_release);
	::WakeByAddressAll(&m_value);
}

void cppcoro::detail::lightweight_manual_reset_event::reset() noexcept
{
	m_value.store(0, std::memory_order_relaxed);
}

void cppcoro::detail::lightweight_manual_reset_event::wait() noexcept
{
	// Wait in a loop as WaitOnAddress() can have spurious wake-ups.
	int value = m_value.load(std::memory_order_acquire);
	BOOL ok = TRUE;
	while (value == 0)
	{
		if (!ok)
		{
			// Previous call to WaitOnAddress() failed for some reason.
			// Put thread to sleep to avoid sitting in a busy loop if it keeps failing.
			::Sleep(1);
		}

		ok = ::WaitOnAddress(&m_value, &value, sizeof(m_value), INFINITE);
		value = m_value.load(std::memory_order_acquire);
	}
}

# else

cppcoro::detail::lightweight_manual_reset_event::lightweight_manual_reset_event(bool initiallySet)
	: m_eventHandle(::CreateEventW(nullptr, TRUE, initiallySet, nullptr))
{
	if (m_eventHandle == NULL)
	{
		const DWORD errorCode = ::GetLastError();
		throw std::system_error
		{
			static_cast<int>(errorCode),
			std::system_category()
		};
	}
}

cppcoro::detail::lightweight_manual_reset_event::~lightweight_manual_reset_event()
{
	// Ignore failure to close the object.
	// We can't do much here as we want destructor to be noexcept.
	(void)::CloseHandle(m_eventHandle);
}

void cppcoro::detail::lightweight_manual_reset_event::set() noexcept
{
	if (!::SetEvent(m_eventHandle))
	{
		std::abort();
	}
}

void cppcoro::detail::lightweight_manual_reset_event::reset() noexcept
{
	if (!::ResetEvent(m_eventHandle))
	{
		std::abort();
	}
}

void cppcoro::detail::lightweight_manual_reset_event::wait() noexcept
{
	constexpr BOOL alertable = FALSE;
	DWORD waitResult = ::WaitForSingleObjectEx(m_eventHandle, INFINITE, alertable);
	if (waitResult == WAIT_FAILED)
	{
		std::abort();
	}
}

# endif

#elif CPPCORO_OS_LINUX

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <linux/futex.h>
#include <cerrno>
#include <climits>
#include <cassert>

namespace
{
	namespace local
	{
		// No futex() function provided by libc.
		// Wrap the syscall ourselves here.
		int futex(
			int* UserAddress,
			int FutexOperation,
			int Value,
			const struct timespec* timeout,
			int* UserAddress2,
			int Value3)
		{
			return syscall(
				SYS_futex,
				UserAddress,
				FutexOperation,
				Value,
				timeout,
				UserAddress2,
				Value3);
		}
	}
}

cppcoro::detail::lightweight_manual_reset_event::lightweight_manual_reset_event(bool initiallySet)
	: m_value(initiallySet ? 1 : 0)
{}

cppcoro::detail::lightweight_manual_reset_event::~lightweight_manual_reset_event()
{
}

void cppcoro::detail::lightweight_manual_reset_event::set() noexcept
{
	m_value.store(1, std::memory_order_release);

	constexpr int numberOfWaitersToWakeUp = INT_MAX;

	[[maybe_unused]] int numberOfWaitersWokenUp = local::futex(
		reinterpret_cast<int*>(&m_value),
		FUTEX_WAKE_PRIVATE,
		numberOfWaitersToWakeUp,
		nullptr,
		nullptr,
		0);

	// There are no errors expected here unless this class (or the caller)
	// has done something wrong.
	assert(numberOfWaitersWokenUp != -1);
}

void cppcoro::detail::lightweight_manual_reset_event::reset() noexcept
{
	m_value.store(0, std::memory_order_relaxed);
}

void cppcoro::detail::lightweight_manual_reset_event::wait() noexcept
{
	// Wait in a loop as futex() can have spurious wake-ups.
	int oldValue = m_value.load(std::memory_order_acquire);
	while (oldValue == 0)
	{
		int result = local::futex(
			reinterpret_cast<int*>(&m_value),
			FUTEX_WAIT_PRIVATE,
			oldValue,
			nullptr,
			nullptr,
			0);
		if (result == -1)
		{
			if (errno == EAGAIN)
			{
				// The state was changed from zero before we could wait.
				// Must have been changed to 1.
				return;
			}

			// Other errors we'll treat as transient and just read the
			// value and go around the loop again.
		}

		oldValue = m_value.load(std::memory_order_acquire);
	}
}

#else

cppcoro::detail::lightweight_manual_reset_event::lightweight_manual_reset_event(bool initiallySet)
	: m_isSet(initiallySet)
{
}

cppcoro::detail::lightweight_manual_reset_event::~lightweight_manual_reset_event()
{
}

void cppcoro::detail::lightweight_manual_reset_event::set() noexcept
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_isSet = true;
	m_cv.notify_all();
}

void cppcoro::detail::lightweight_manual_reset_event::reset() noexcept
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_isSet = false;
}

void cppcoro::detail::lightweight_manual_reset_event::wait() noexcept
{
	std::unique_lock<std::mutex> lock(m_mutex);
	m_cv.wait(lock, [this] { return m_isSet; });
}

#endif