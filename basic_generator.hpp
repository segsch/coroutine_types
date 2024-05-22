/// The spec's example as-is: https://eel.is/c++draft/dcl.fct.def.coroutine

#include <coroutine>

// ::operator new(size_t, nothrow_t) will be used if allocation is needed
template <typename T>
struct generator {
    struct promise_type;
    using handle = std::coroutine_handle<promise_type>;
    struct promise_type {
        T current_value_;
        static auto get_return_object_on_allocation_failure() { return generator{nullptr}; }
        auto get_return_object() { return generator{handle::from_promise(*this)}; }
        auto initial_suspend() { return std::suspend_always{}; }
        auto final_suspend() noexcept { return std::suspend_always{}; }
        void unhandled_exception() { std::terminate(); }
        void return_void() {}
        auto yield_value(T value) {
            current_value_ = value;
            return std::suspend_always{};
        }
  };
  bool move_next() { 
        if (coro_) {
            coro_.resume();
            return !coro_.done();
        }   
        return false; 
  }
  T current_value() { return coro_.promise().current_value_; }
  generator(generator const&) = delete;
  generator(generator && rhs) : coro_(rhs.coro_) { rhs.coro_ = nullptr; }
  ~generator() { if (coro_) coro_.destroy(); }
private:
    generator(handle h) : coro_(h) {}
    handle coro_;
};
