#pragma once

#include <cstdint>
#include <string_view>

class CodePoint
{
public:
    /** unknown / unrecognized / unrepresentable / '<?>' / U+FFFD  */
    static constexpr uint32_t replacement = 0xfffd;
    /** invalid character / U+FFFE */
    static constexpr uint32_t no_character = 0xfffe;

private:
    uint32_t code_point_ = no_character;

public:
    CodePoint() = default;

    CodePoint(uint32_t code_point)
      : code_point_(code_point)
    {
    }

    operator uint32_t() const { return code_point_; }

    explicit operator bool() const
    {
        return code_point_ != no_character && code_point_ != replacement;
    }
};

class UTF8CodePointIterator
{
private:
    using size_type = std::string_view::size_type;

    std::string_view sv_;
    size_type begin_ = 0;
    size_type end_ = 0;
    CodePoint code_point_;

public:
    UTF8CodePointIterator() = default;

    UTF8CodePointIterator(std::string_view sv);

    UTF8CodePointIterator& operator++();

    CodePoint operator*() const { return code_point_; }

    explicit operator bool() const { return begin_ <= end_; }
};

inline bool
IsValidUTF8(std::string_view sv)
{
    for (auto it = UTF8CodePointIterator(sv); it; ++it)
        if (!*it)
            return false; // invalid code point
    return true;
}
