#pragma once

#include <concepts>
#include <csignal>
#include <exception>
#include <functional>

class ScopeGuard
{
    std::function< void() > destruct_;

public:
    ScopeGuard() = default;

    template< std::invocable Dtor >
    ScopeGuard(Dtor&& destruct)
      : destruct_([dtor = std::forward< Dtor >(destruct)]() { (void)dtor(); })
    {
    }

    ScopeGuard(const ScopeGuard&) = default;
    ScopeGuard& operator=(const ScopeGuard&) = default;

    ScopeGuard(ScopeGuard&&) noexcept = default;
    ScopeGuard& operator=(ScopeGuard&&) = default;

    template< std::invocable Dtor >
    [[maybe_unused]] ScopeGuard& operator=(Dtor&& destruct)
    {
        destruct_ = [dtor = std::forward< Dtor >(destruct)]() { (void)dtor(); };
        return *this;
    }

    [[maybe_unused]] ScopeGuard& Reset() noexcept
    {
        destruct_ = nullptr;
        return *this;
    }

    ~ScopeGuard()
    {
        if (destruct_)
        {
            bool pending_exception = std::uncaught_exception();
            try
            {
                destruct_();
            }
            catch (...)
            {
                if (pending_exception)
                {
#if (defined __linux__) || (defined __APPLE__)
                    raise(SIGTRAP);
#elif (defined _WIN32)
                    __debugbreak();
#endif
                }
            }
        }
    }
};
