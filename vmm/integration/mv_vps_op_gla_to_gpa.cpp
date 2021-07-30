/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#include <integration_utils.hpp>
#include <mv_hypercall_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/debug.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>

namespace hypercall
{
    /// @brief provides a variable to get the GPA of
    alignas(HYPERVISOR_PAGE_SIZE.get()) bool g_test{};
    /// <!-- description -->
    ///   @brief Always returns bsl::exit_success. If a failure occurs,
    ///     this function will exit early.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success. If a failure occurs,
    ///     this function will exit early.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        auto const gla{bsl::to_umax(reinterpret_cast<bsl::uintmax>(&g_test))};
        /// NOTE:
        /// - Since we only support 64bit, a global variable's GVA will always
        ///   be a GLA on at least Intel, AMD and ARM.
        ///
        mv_hypercall_t mut_hvc{};
        integration::verify(mut_hvc.initialize());
        auto const translation{mut_hvc.mv_vps_op_gla_to_gpa(MV_SELF_ID, gla)};
        integration::verify(translation.is_valid);
        bsl::error() << "the result is:\n"
                     << "  - vaddr: " << bsl::hex(translation.vaddr) << bsl::endl
                     << "  - laddr: " << bsl::hex(translation.laddr) << bsl::endl
                     << "  - paddr: " << bsl::hex(translation.paddr) << bsl::endl
                     << "  - flags: " << bsl::hex(translation.flags) << bsl::endl
                     << "  - is_valid: " << translation.is_valid << bsl::endl
                     << bsl::endl;
        return bsl::exit_success;
    }
}

/// <!-- description -->
///   @brief Provides the main entry point for this application.
///
/// <!-- inputs/outputs -->
///   @return bsl::exit_success on success, bsl::exit_failure otherwise.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::enable_color();
    return hypercall::tests();
}
