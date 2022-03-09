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

#ifndef DISPATCH_VMEXIT_IO_HPP
#define DISPATCH_VMEXIT_IO_HPP

#include <bf_syscall_t.hpp>
#include <dispatch_abi_helpers.hpp>
#include <dispatch_vmcall_helpers.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_run_t.hpp>
#include <mv_exit_io_t.hpp>
#include <pp_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/span.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief Dispatches IO VMExits.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param mut_tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_pp_pool the pp_pool_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_vmexit_io(
        gs_t const &gs,
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        page_pool_t &mut_page_pool,
        intrinsic_t const &intrinsic,
        pp_pool_t &mut_pp_pool,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        bsl::expects(!mut_sys.is_the_active_vm_the_root_vm());

        bsl::discard(gs);

        // ---------------------------------------------------------------------
        // Context: Guest VM
        // ---------------------------------------------------------------------

        auto const exitinfo1{mut_sys.bf_vs_op_read(vsid, syscall::bf_reg_t::bf_reg_t_exitinfo1)};
        bsl::expects(exitinfo1.is_valid());

        auto const rax{mut_sys.bf_tls_rax()};
        auto const rcx{mut_sys.bf_tls_rcx()};

        constexpr auto page_mask{0xFFFFFFFFFFFFF000_u64};

        constexpr auto port_mask{0xFFFF0000_u64};
        constexpr auto port_shft{16_u64};
        constexpr auto reps_mask{0x00000008_u64};
        constexpr auto reps_shft{3_u64};
        constexpr auto type_mask{0x00000001_u64};
        constexpr auto type_shft{0_u64};
        constexpr auto strn_mask{0x00000004_u64};
        constexpr auto strn_shft{2_u64};

        constexpr auto sz32_mask{0x00000040_u64};
        constexpr auto sz32_shft{6_u64};
        constexpr auto sz16_mask{0x00000020_u64};
        constexpr auto sz16_shft{5_u64};
        constexpr auto sz08_mask{0x00000010_u64};
        constexpr auto sz08_shft{4_u64};

        auto const addr{(exitinfo1 & port_mask) >> port_shft};

        auto mut_num_pages{1_u64};

        bsl::safe_u64 mut_bytes{};
        enum hypercall::mv_bit_size_t mut_size{};
        auto mut_reps{bsl::safe_u64::magic_1()};

        auto const vmid{mut_sys.bf_tls_vmid()};


        // bsl::debug() << "exitinfo1 = " << bsl::hex(exitinfo1) << bsl::endl;


        if (((exitinfo1 & reps_mask) >> reps_shft).is_pos()) {
            mut_reps = rcx.get();
        }
        else {
            mut_reps = bsl::safe_u64::magic_1().get();
        }

        if (((exitinfo1 & sz32_mask) >> sz32_shft).is_pos()) {
            mut_size = hypercall::mv_bit_size_t::mv_bit_size_t_32;
            constexpr auto four{4_u64};
            mut_bytes = (four * mut_reps).checked();
        }
        else if (((exitinfo1 & sz16_mask) >> sz16_shft).is_pos()) {
            mut_size = hypercall::mv_bit_size_t::mv_bit_size_t_16;
            mut_bytes = (bsl::safe_u64::magic_2() * mut_reps).checked();
        }
        else if (((exitinfo1 & sz08_mask) >> sz08_shft).is_pos()) {
            mut_size = hypercall::mv_bit_size_t::mv_bit_size_t_8;
            mut_bytes = mut_reps;
        }
        else {
            bsl::touch();
        }

        if (((exitinfo1 & strn_mask) >> strn_shft).is_pos()) {
            bsl::safe_u64 mut_string_addr{};

            if (((exitinfo1 & type_mask) >> type_shft).is_zero()) {
                // OUT instruction
                mut_string_addr = mut_sys.bf_tls_rsi();
            }
            else {
                // IN instruction
                mut_string_addr = mut_sys.bf_tls_rdi();
            }

            mut_num_pages = (bsl::safe_u64::magic_1()).checked();
            auto const end_addr{(mut_string_addr + mut_bytes).checked()};
            mut_num_pages += (end_addr >> HYPERVISOR_PAGE_SHIFT) - (mut_string_addr >> HYPERVISOR_PAGE_SHIFT);
            mut_num_pages = mut_num_pages.checked();
            if (mut_num_pages > bsl::safe_u64::magic_2()) {
                bsl::error() << "Too many pages: " << mut_num_pages << bsl::endl;
                mut_num_pages = bsl::safe_u64::magic_2();
            }
            else {
                bsl::touch();
            }

            bsl::debug()
                << "Got string operation, mut_string_addr = "
                << bsl::hex(mut_string_addr)
                << " mut_num_pages "
                << mut_num_pages
                << bsl::endl;

            for (auto mut_i{0_idx}; mut_i < mut_num_pages; ++mut_i) {
                bsl::safe_u64 mut_spa{};
                bsl::safe_u64 mut_gpa{};
                if (mut_i != bsl::safe_idx::magic_0()) {
                    mut_string_addr = ((mut_string_addr & page_mask) + (bsl::to_umx(mut_i) * HYPERVISOR_PAGE_SIZE).checked()).checked();
                }
                //
                //FIXME: This doesn't consider 16-bit segment base values!!
                //
                auto const translation{mut_vs_pool.gla_to_gpa(mut_sys, mut_tls, mut_page_pool, mut_pp_pool, mut_vm_pool, mut_string_addr, vsid)};
                mut_gpa = translation.paddr;
                bsl::debug() << "mut_string_addr = " << bsl::hex(mut_string_addr) << " gpa = " << bsl::hex(mut_gpa) << bsl::endl;
                mut_spa = mut_vm_pool.gpa_to_spa(mut_tls, mut_sys, mut_page_pool, mut_gpa, vmid);
                bsl::debug() << "mut_string_addr = " << bsl::hex(mut_string_addr) << " gpa = " << bsl::hex(mut_gpa) << " spa = " << bsl::hex(mut_spa) << bsl::endl;
                mut_vs_pool.io_set_spa(mut_sys, vsid, mut_spa, mut_i);
            }
        }
        else {
            bsl::touch();
        }

        // ---------------------------------------------------------------------
        // Context: Change To Root VM
        // ---------------------------------------------------------------------

        switch_to_root(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, true);

        // ---------------------------------------------------------------------
        // Context: Root VM
        // ---------------------------------------------------------------------

        auto mut_run_return{mut_pp_pool.shared_page<hypercall::mv_run_return_t>(mut_sys)};
        auto mut_exit_io{&mut_run_return->mv_exit_io};

        mut_exit_io->addr = addr.get();
        mut_exit_io->size = mut_size;
        mut_exit_io->reps = mut_reps.get();

        // TODO handle hypercall continuation
        if (bsl::unlikely(mut_bytes > hypercall::MV_EXIT_IO_MAX_DATA)) {
            bsl::error()
                << "FIXME: The requested size of "    // --
                << bsl::hex(mut_bytes)    // --
                << " is too large."    // --
                << bsl::endl    // --
                << bsl::here();    // --

            return vmexit_failure_advance_ip_and_run;
        }
        else {
            bsl::touch();
        }

        if (((exitinfo1 & type_mask) >> type_shft).is_zero()) {
            mut_exit_io->type = hypercall::MV_EXIT_IO_OUT.get();
        }
        else {
            mut_exit_io->type = hypercall::MV_EXIT_IO_IN.get();
        }

        if (((exitinfo1 & strn_mask) >> strn_shft).is_pos()) {
            using page_t = bsl::array<uint8_t, HYPERVISOR_PAGE_SIZE.get()>;

            bsl::safe_idx mut_i{};
            bsl::safe_u64 mut_spa{mut_vs_pool.io_spa(mut_sys, vsid, mut_i)};

            if (bsl::unlikely(mut_spa.is_invalid())) {
                bsl::error() << bsl::here();
                return vmexit_failure_advance_ip_and_run;
            }

            auto const idx{mut_spa & ~page_mask};
            if (bsl::unlikely(hypercall::MV_RUN_MAX_IOMEM_SIZE < mut_bytes)) {
                bsl::error()
                    << "FIXME: mv_run_t.iomem will overflow:"    // --
                    << " mut_bytes = " << bsl::hex(mut_bytes)    // --
                    << bsl::endl                                 // --
                    << bsl::here();                              // --
                return vmexit_failure_advance_ip_and_run;
            }
            else if (bsl::unlikely(hypercall::MV_EXIT_IO_MAX_DATA < mut_bytes)) {
                bsl::error()
                    << "FIXME: mv_exit_io_t.data will overflow:"    // --
                    << " mut_bytes = "                              // --
                    << bsl::hex(mut_bytes)                          // --
                    << bsl::endl                                    // --
                    << bsl::here();                                 // --
                return vmexit_failure_advance_ip_and_run;
            }
            else {
                bsl::touch();
            }

            auto const bytes_cur_page{(HYPERVISOR_PAGE_SIZE - idx).checked()};
            {
                auto const size{bytes_cur_page.min(mut_bytes)};
                auto const page{mut_pp_pool.map<page_t>(mut_sys, mut_spa & page_mask)};
                bsl::debug() << " idx " << bsl::hex(idx) << " size " << bsl::hex(size) << bsl::endl;
                auto const data{page.span(idx, size)};
                if (bsl::unlikely(data.is_invalid())) {
                    bsl::error()
                        << "data is invalid"    // --
                        << bsl::endl            // --
                        << bsl::here();         // --

                    return vmexit_failure_advance_ip_and_run;
                }
                else {
                    bsl::touch();
                }

                bsl::builtin_memcpy(mut_exit_io->data.data(), data.data(), data.size_bytes());
            }

            if (bsl::unlikely(bytes_cur_page < mut_bytes)) {
                bsl::debug() << "Handling page boudary" << bsl::endl;

                auto const size{(mut_bytes - bytes_cur_page).checked()};
                mut_spa = mut_vs_pool.io_spa(mut_sys, vsid, ++mut_i);
                if (bsl::unlikely(mut_spa.is_invalid())) {
                    bsl::error()
                        << "SPA for second page is invalid"    // --
                        << bsl::endl    // --
                        << bsl::here();    // --
                    return vmexit_failure_advance_ip_and_run;
                }
                else if (bsl::unlikely((mut_spa & ~page_mask).is_pos())) {
                    bsl::error()
                        << "SPA should be page aligned but is "    // --
                        << bsl::hex(mut_spa)
                        << bsl::endl    // --
                        << bsl::here();    // --
                    return vmexit_failure_advance_ip_and_run;
                }

                auto const page{mut_pp_pool.map<page_t>(mut_sys, mut_spa)};
                auto const data{page.span({}, size)};
                bsl::expects((bytes_cur_page + data.size_bytes()).checked() == mut_bytes);
                // bsl::debug() << "bytes_cur_page " << bytes_cur_page << " size_bytes " << data.size_bytes() << " mut_bytes " << mut_bytes << " size " << size << bsl::endl;
                // return vmexit_failure_advance_ip_and_run;
                bsl::builtin_memcpy(mut_exit_io->data.at_if(bsl::to_idx(bytes_cur_page)), data.data(), data.size_bytes());
            }
            else {
                bsl::touch();
            }
        }
        else {
            hypercall::io_to_u64(mut_exit_io->data) = rax.get();
        }

        // if (((exitinfo1 & type_mask) >> type_shft).is_zero()) {
        //     bsl::debug() << __FILE__ << " OUT " << " port=" << bsl::hex(mut_exit_io->addr) << " data=" << bsl::hex(hypercall::io_to_u64(mut_exit_io->data)) << " size=" << bsl::hex(static_cast<bsl::uint32>(mut_exit_io->size)) << bsl::endl;
        // }
        // else {
        //     bsl::debug() << __FILE__ << " IN " << " port=" << bsl::hex(mut_exit_io->addr) << " data=" << bsl::hex(hypercall::io_to_u64(mut_exit_io->data)) << " size=" << bsl::hex(static_cast<bsl::uint32>(mut_exit_io->size)) << bsl::endl;
        // }
        
        set_reg_return(mut_sys, hypercall::MV_STATUS_SUCCESS);
        set_reg0(mut_sys, bsl::to_u64(hypercall::EXIT_REASON_IO));

        return vmexit_success_advance_ip_and_run;
    }
}

#endif
