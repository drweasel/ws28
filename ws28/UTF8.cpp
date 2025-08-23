#include "UTF8.h"

#include <bit>

UTF8CodePointIterator::UTF8CodePointIterator(std::string_view sv)
  : sv_(sv)
  , end_(sv.size())
{
    // skip a leading UTF-8 BOM, if it exists (unusual, but allowed)
    static constexpr uint8_t bom_bytes[] = { 0xef, 0xbb, 0xbf };
    if (
      end_ >= 3 &&
      uint8_t(sv.at(0)) == bom_bytes[0] &&
      uint8_t(sv.at(1)) == bom_bytes[1] &&
      uint8_t(sv.at(2)) == bom_bytes[2])
    {
        begin_ = 3;
    }
    operator++(); // init first code point
}

UTF8CodePointIterator&
UTF8CodePointIterator::operator++()
{
    if (!end_ || begin_ == end_)
    {
        // default constructed iterator or end of string
        begin_++;
        return *this;
    }

    auto byte = uint8_t(sv_.at(begin_++));
    uint32_t cp = 0;
    const std::ptrdiff_t leading_ones = std::countl_one(byte);

    switch (leading_ones)
    {
    case 0:
        // 7-bit ASCII character
        code_point_ = CodePoint(byte);
        break;
    case 2:
        [[fallthrough]];
    case 3:
        [[fallthrough]];
    case 4:
        if (leading_ones == 2)
        {
            if ((byte >> 5) != 0b110 || begin_ >= end_)
            {
                // invalid leading byte for a 2-byte seq. or out of bytes
                code_point_ = CodePoint();
                begin_ = end_;
                break;
            }
            cp = byte & 0b1'1111;
        }
        else
        {
            if ((byte >> 4) != 0b1110 || begin_ + (leading_ones - 1) >= end_)
            {
                // invalid leading byte for a 2-byte seq. or out of bytes
                code_point_ = CodePoint();
                begin_ = end_;
                break;
            }
            cp = byte & 0b1111;
        }
        for (int i = 1; i < leading_ones; ++i)
        {
            byte = uint8_t(sv_.at(begin_++));
            if ((byte >> 6) != 0b10)
            {
                // invalid continuation byte
                code_point_ = CodePoint();
                begin_ = end_;
                return *this;
            }
            cp = (cp << 6) | (byte & 0b11'1111);
        }
        code_point_ = CodePoint(cp);
        break;
    default:
        // invalid encoding
        code_point_ = CodePoint();
        begin_ = end_;
        break;
    }
    return *this;
}
