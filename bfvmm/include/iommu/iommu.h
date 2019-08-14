//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef MICROV_IOMMU_H
#define MICROV_IOMMU_H

#include <array>
#include <bftypes.h>
#include <bfvmm/hve/arch/x64/unmapper.h>
#include <bfvmm/memory_manager/memory_manager.h>
#include <hve/arch/intel_x64/domain.h>
#include <unordered_map>
#include <vector>

#include "dmar.h"
#include "entry.h"
#include "regs.h"
#include "../pci/cfg.h"

namespace microv::intel_x64 {
    class domain;
}

namespace microv {

struct pci_dev;
using namespace iommu_regs;

class iommu {
public:
    static constexpr auto table_size = page_size / sizeof(struct iommu_entry);
    using entry_t = struct iommu_entry;
    using dom_t = class microv::intel_x64::domain;
    using bus_t = uint32_t;

    void dump_faults() const;
    void map_dma(bus_t bus, uint32_t devfn, dom_t *dom);

    ~iommu() = default;
    iommu(struct drhd *drhd);
    iommu(iommu &&) = default;
    iommu(const iommu &) = delete;
    iommu &operator=(iommu &&) = default;
    iommu &operator=(const iommu &) = delete;

private:
    page_ptr<entry_t> m_root;
    std::unordered_map<bus_t, page_ptr<entry_t>> m_ctxt_map;
    struct drhd *m_drhd{};
    struct drhd_devscope *m_scope{};
    uintptr_t m_reg_hva{};
    uint32_t m_ver{};
    uint64_t m_cap{};
    uint64_t m_ecap{};
    uint8_t m_mgaw{};
    uint8_t m_sagaw{};
    uint8_t m_aw{};
    uint8_t m_did_bits{};

    size_t m_iotlb_reg_off{};
    static constexpr size_t iotlb_reg_num = 2;
    static constexpr size_t iotlb_reg_len = 8;
    static constexpr size_t iotlb_reg_bytes = iotlb_reg_num * iotlb_reg_len;

    size_t m_frcd_reg_off{};
    size_t m_frcd_reg_num{};
    size_t m_frcd_reg_bytes{};
    static constexpr size_t frcd_reg_len = 16;

    std::vector<struct pci_dev *> m_host_devs{};
    std::vector<struct pci_dev *> m_guest_devs{};
    bool m_scope_all{};
    bool m_remapping_dma{};

    uint64_t read64(size_t offset) const
    {
        return *reinterpret_cast<volatile uint64_t *>(m_reg_hva + offset);
    }

    uint32_t read32(size_t offset) const
    {
        return *reinterpret_cast<volatile uint32_t *>(m_reg_hva + offset);
    }

    void write64(size_t offset, uint64_t val)
    {
        *reinterpret_cast<volatile uint64_t *>(m_reg_hva + offset) = val;
    }

    void write32(size_t offset, uint32_t val)
    {
        *reinterpret_cast<volatile uint32_t *>(m_reg_hva + offset) = val;
    }

    uint32_t read_gcmd() { return read32(gcmd_offset); }
    uint32_t read_gsts() { return read32(gsts_offset); }
    uint64_t read_rtaddr() { return read64(rtaddr_offset); }
    uint64_t read_ccmd() { return read64(ccmd_offset); }
    uint64_t read_iotlb() { return read64(m_iotlb_reg_off + 8); }

    void write_gcmd(uint32_t val) { write32(gcmd_offset, val); }
    void write_rtaddr(uint64_t val) { write64(rtaddr_offset, val); }
    void write_ccmd(uint64_t val) { write64(ccmd_offset, val); }
    void write_iotlb(uint64_t val) { write64(m_iotlb_reg_off + 8, val); }

    void map_regs();
    void init_regs();
    void dump_devices();
    void bind_devices();
    void bind_device(struct pci_dev *pdev);
    void bind_bus(uint32_t bus);

    size_t nr_domains() const
    {
        return 1UL << m_did_bits;
    }

    size_t did(const dom_t *dom) const
    {
        /*
         * Remapping hardware reserves a DID of 0 if caching mode (CAP.CM) is
         * set, so we add CM to each domain::id to get the DID that goes in the
         * table entry.
         */
        return dom->id() + ((m_cap & cap_cm_mask) >> cap_cm_from);
    }

    void enable_dma_remapping();
    void clflush(void *p);
    void clflush_range(void *p, unsigned int bytes);
    void clflush_slpt();
};

extern char *mcfg_hva;
extern size_t mcfg_len;

void init_vtd();
void iommu_dump();

}

#endif
