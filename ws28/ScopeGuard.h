#pragma once

#include <concepts>
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
            destruct_();
    }
};
