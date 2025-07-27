#pragma once

#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace ws28
{
class Client;
class Server;

class HTTPRequestHeaders
{
public:
    void Set(std::string_view key, std::string_view value)
    {
        m_Headers.push_back({ key, value });
    }

    template< typename F >
    void ForEachValueOf(std::string_view key, const F &f) const
    {
        for (const auto &p : m_Headers)
        {
            if (p.first == key)
                f(p.second);
        }
    }

    std::optional< std::string_view > Get(std::string_view key) const
    {
        for (const auto &p : m_Headers)
        {
            if (p.first == key)
                return p.second;
        }

        return std::nullopt;
    }

    template< typename F >
    void ForEach(const F &f) const
    {
        for (const auto &p : m_Headers)
        {
            f(p.first, p.second);
        }
    }

private:
    std::vector< std::pair< std::string_view, std::string_view > > m_Headers;

    friend class Client;
    friend class Server;
};

} // namespace ws28
