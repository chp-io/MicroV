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

#ifndef MICROV_XEN_XENVER_H
#define MICROV_XEN_XENVER_H

#include "types.h"
#include <public/xen.h>

namespace microv {

class xenver {
private:
    xen *m_xen{};
    xen_vcpu *m_vcpu{};

public:
    bool build_id();
    bool capabilities();
    bool changeset();
    bool commandline();
    bool compile_info();
    bool extraversion();
    bool get_features();
    bool guest_handle();
    bool pagesize();
    bool platform_parameters();
    bool version();

    xenver(xen *xen);
    ~xenver() = default;
    xenver(xenver &&) = default;
    xenver &operator=(xenver &&) = default;
    xenver(const xenver &) = delete;
    xenver &operator=(const xenver &) = delete;
};

}
#endif
