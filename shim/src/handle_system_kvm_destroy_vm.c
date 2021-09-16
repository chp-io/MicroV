/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <g_mut_hndl.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <platform.h>
#include <shim_vm_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_destroy_vm.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vm the VM to destroy
 */
void
handle_system_kvm_destroy_vm(struct shim_vm_t *const pmut_vm) NOEXCEPT
{
    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);
    platform_expects(NULL != pmut_vm);

    platform_mutex_destroy(&pmut_vm->mutex);

    platform_expects(MV_STATUS_SUCCESS == mv_vm_op_destroy_vm(g_mut_hndl, pmut_vm->vmid));
}
