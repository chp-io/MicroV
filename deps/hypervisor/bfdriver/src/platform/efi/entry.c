/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <efi.h>
#include <efilib.h>
#include <efiapi.h>

#include <vmm.h>
#include <common.h>

#include <bfdebug.h>
#include <bftypes.h>
#include <bfconstants.h>
#include <bfdriverinterface.h>

#include <xue.h>

extern int g_uefi_boot;
extern int g_enable_winpv;
extern int g_disable_xen_pfd;
extern int g_enable_xue;

extern struct xue g_xue;
extern struct xue_ops g_xue_ops;
struct xue_efi g_xue_efi;

uint64_t g_vcpuid = 0;

struct pmodule_t {
    char *data;
    uint64_t size;
};

uint64_t g_num_pmodules = 0;
struct pmodule_t pmodules[MAX_NUM_MODULES] = {{0}};

static const CHAR16 *opt_disable_xen_pfd = L"--disable-xen-pfd";
static const CHAR16 *opt_enable_winpv = L"--enable-winpv";
static const CHAR16 *opt_disable_winpv = L"--disable-winpv";
static const CHAR16 *opt_no_pci_pt = L"--no-pci-pt";
static const CHAR16 *opt_enable_xue = L"--enable-xue";

#define NO_PCI_PT_LIST_SIZE 256
extern uint64_t no_pci_pt_list[NO_PCI_PT_LIST_SIZE];
extern uint64_t no_pci_pt_count;

#ifndef EFI_BOOT_NEXT
#define EFI_BOOT_NEXT L"\\EFI\\boot\\bootx64.efi"
#endif

EFI_EVENT mExitBootServicesEvent = NULL;

#ifdef EFI_DELAYED_START
int g_delayed_start = 1;
#else
int g_delayed_start = 0;
#endif

// ExitBootServices GUID (gEfiEventExitBootServicesGuid)
static const EFI_GUID g_ebs_guid
    = { 0x27ABF055, 0xB1B8, 0x4C26, { 0x80, 0x48, 0x74, 0x8F, 0x37, 0xBA, 0xA2, 0xDF }};
EFI_EXIT_BOOT_SERVICES     gOrigExitBootServices;

void unmap_vmm_from_root_domain(void);

static int64_t
ioctl_add_module(const char *file, uint64_t len)
{
    char *buf;
    int64_t ret;

    if (g_num_pmodules >= MAX_NUM_MODULES) {
        BFALERT("IOCTL_ADD_MODULE: too many modules have been loaded\n");
        return BF_IOCTL_FAILURE;
    }

    buf = platform_alloc_rw(len);
    if (buf == NULL) {
        BFALERT("IOCTL_ADD_MODULE: failed to allocate memory for the module\n");
        return BF_IOCTL_FAILURE;
    }

    gBS->CopyMem(buf, (void *)file, len);

    ret = common_add_module(buf, len);
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_ADD_MODULE: common_add_module failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto failed;
    }

    pmodules[g_num_pmodules].data = buf;
    pmodules[g_num_pmodules].size = len;

    g_num_pmodules++;

    return BF_IOCTL_SUCCESS;

failed:

    platform_free_rw(buf, len);

    BFALERT("IOCTL_ADD_MODULE: failed\n");
    return BF_IOCTL_FAILURE;
}

static long
ioctl_load_vmm(void)
{
    int64_t ret;

    g_uefi_boot = 1;

    ret = common_load_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_LOAD_VMM: common_load_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto failure;
    }

    return BF_IOCTL_SUCCESS;

failure:

    BFDEBUG("IOCTL_LOAD_VMM: failed\n");
    return BF_IOCTL_FAILURE;
}

static long
ioctl_start_vmm(void)
{
    int64_t ret;

    ret = common_start_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_START_VMM: common_start_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto failure;
    }

    return BF_IOCTL_SUCCESS;

failure:

    BFDEBUG("IOCTL_START_VMM: failed\n");
    return BF_IOCTL_FAILURE;
}

/* -------------------------------------------------------------------------- */
/* Load / Image                                                               */
/* -------------------------------------------------------------------------- */

/**
 * TODO
 *
 * Instead of loading the OS, we need to actually load a EFI/BOOT/chain.efi
 * file which is the previous EFI/BOOT/boot64.efi. This will allow us to
 * support the different types of loaders that are instealled regardless of
 * which one is actually installed.
 */

static long
load_start_vm(EFI_HANDLE ParentImage)
{
    /**
     * TODO
     *
     * Need to check to see if there are deallocate functions for a lot of
     * these functions as they are returning pointers.
     */

    EFI_STATUS status;

    UINTN i;
    UINTN NumberFileSystemHandles = 0;
    EFI_HANDLE *FileSystemHandles = NULL;

    status =
        gBS->LocateHandleBuffer(
            ByProtocol,
            &gEfiBlockIoProtocolGuid,
            NULL,
            &NumberFileSystemHandles,
            &FileSystemHandles
        );

    if (EFI_ERROR(status)) {
        BFALERT("LocateHandleBuffer failed\n");
        return EFI_ABORTED;
    }

    for(i = 0; i < NumberFileSystemHandles; ++i) {

        EFI_DEVICE_PATH_PROTOCOL *FilePath = NULL;
        EFI_BLOCK_IO *BlkIo = NULL;
        EFI_HANDLE ImageHandle = NULL;
        EFI_LOADED_IMAGE_PROTOCOL *ImageInfo = NULL;

        status =
            gBS->HandleProtocol(
                FileSystemHandles[i],
                &gEfiBlockIoProtocolGuid,
                (VOID**) &BlkIo
            );

        if (EFI_ERROR(status)) {
            continue;
        }

        FilePath = FileDevicePath(FileSystemHandles[i], EFI_BOOT_NEXT);

        status =
            gBS->LoadImage(
                FALSE,
                ParentImage,
                FilePath,
                NULL,
                0,
                &ImageHandle
            );

        gBS->FreePool(FilePath);

        if (EFI_ERROR(status)) {
            continue;
        }

        status =
            gBS->HandleProtocol(
                ImageHandle,
                &gEfiLoadedImageProtocolGuid,
                (VOID **) &ImageInfo
        );

        if (EFI_ERROR(status)) {
            continue;
        }

        if(ImageInfo->ImageCodeType != EfiLoaderCode) {
            continue;
        }

        gBS->StartImage(ImageHandle, NULL, NULL);

        break;
    }

    BFALERT("Unable to locate EFI bootloader\n");
    return EFI_ABORTED;
}

void parse_cmdline(EFI_HANDLE image)
{
    INTN argc, i;
    CHAR16 **argv;

    argc = GetShellArgcArgv(image, &argv);

    for (i = 0; i < argc; i++) {
        if (!StrnCmp(opt_enable_xue, argv[i], StrLen(opt_enable_xue))) {
#if(USE_XUE)
            Print(L"Enabling Xue USB Debugger\n");
#else
            Print(L"Error: Xue USB Debugger was disabled at compile time\n");
#endif
            g_enable_xue = 1;
        }

        if (!StrnCmp(opt_enable_winpv, argv[i], StrLen(opt_enable_winpv))) {
            Print(L"Enabling Windows PV\n");
            g_enable_winpv = 1;
        }

        if (!StrnCmp(opt_disable_winpv, argv[i], StrLen(opt_disable_winpv))) {
            Print(L"Disabling Windows PV\n");
            g_enable_winpv = 0;
        }

        if (!StrnCmp(opt_disable_xen_pfd, argv[i], StrLen(opt_disable_xen_pfd))) {
            Print(L"Disabling Xen Platform PCI device\n");
            g_disable_xen_pfd = 1;
        }

        if (!StrnCmp(opt_no_pci_pt, argv[i], StrLen(opt_no_pci_pt))) {
            if (i >= argc - 1) {
                continue;
            }

            CHAR16 *bdf_str = argv[i + 1];
            UINTN bdf_len = StrLen(bdf_str);

            if (bdf_len != 7) {
                Print(L"Invalid BDF string size: %u\n", bdf_len);
                Print(L"  usage: --no-pci-pt BB:DD.F\n");
                continue;
            }

            CHAR8 bus_str[16];
            CHAR8 dev_str[16];
            CHAR8 fun_str[16];

            ZeroMem(bus_str, 16);
            ZeroMem(dev_str, 16);
            ZeroMem(fun_str, 16);

            CopyMem(bus_str, bdf_str, 4);
            CopyMem(dev_str, (char *)bdf_str + 6, 4);
            CopyMem(fun_str, (char *)bdf_str + 12, 2);

            UINTN bus = xtoi((CHAR16 *)bus_str);
            UINTN dev = xtoi((CHAR16 *)dev_str);
            UINTN fun = xtoi((CHAR16 *)fun_str);

            if (bus > 255 || dev > 31 || fun > 7) {
                Print(L"BDF out of range: bus=%lx, dev=%lx, fun=%lx\n",
                      bus, dev, fun);
                continue;
            }

            no_pci_pt_list[no_pci_pt_count] =
                (bus << 16) | (dev << 11) | (fun << 8);
            no_pci_pt_count++;

            Print(L"Disabling passthrough for %02x:%02x.%02x\n", bus, dev, fun);
        }
    }
}

void start_vmm_and_unmap()
{
    Print(L"-- ioctl_start_vmm\n");
    ioctl_start_vmm();

    Print(L"-- unmap_vmm_from_root_domain\n");
    unmap_vmm_from_root_domain();
}

EFI_STATUS EFIAPI ExitBootServicesHook(IN EFI_HANDLE ImageHandle, IN UINTN MapKey)
{
    (void) MapKey;
    EFI_STATUS status;
    UINTN MemoryMapSize;
    EFI_MEMORY_DESCRIPTOR *MemoryMap;
    UINTN LocalMapKey;
    UINTN DescriptorSize;
    UINT32 DescriptorVersion;

    Print(L"-- exit boot services hook called\n");

    // start_vmm_and_unmap();

	/* Fix the pointer in the boot services table */
	/* If you don't do this, sometimes your hook method will be called repeatedly, which you don't want */
    gBS->ExitBootServices = gOrigExitBootServices;

    /* Get the memory map */
    MemoryMap = NULL;
    MemoryMapSize = 0;
	
    do {
        status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &LocalMapKey, &DescriptorSize,&DescriptorVersion);
        if (status == EFI_BUFFER_TOO_SMALL){
            MemoryMap = AllocatePool(MemoryMapSize + 1);
            status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &LocalMapKey, &DescriptorSize,&DescriptorVersion);
        } else {
            /* status is likely success - let the while() statement check success */
        }
        Print(L"This time through the memory map loop, status = %r\n", status);

    } while (status != EFI_SUCCESS);

    status = gOrigExitBootServices(ImageHandle,LocalMapKey);
    Print(L"-- original exit boot services called\n");

    start_vmm_and_unmap();

    return status;
}

void EFIAPI notify_exit_boot_services(EFI_EVENT event, void *context)
{
    (void) event;
    (void) context;

    Print(L"-- notify_exit_boot_services: start_vmm_and_unmap\n");
    start_vmm_and_unmap();
}

void delayed_start()
{
#if 0
    EFI_STATUS status;

    Print(L"-- create exit boot services event\n");
    //
    // Create event to stop the HC when exit boot service.
    //
    status = gBS->CreateEventEx(
                    EVT_NOTIFY_SIGNAL,
                    TPL_NOTIFY,
                    notify_exit_boot_services,
                    NULL,
                    &g_ebs_guid,
                    &mExitBootServicesEvent
                    );

    if (EFI_ERROR(status)) {
        Print(L"Failed to create ExitBootServices event\n");
    }
#else
    (void) g_ebs_guid;
    Print(L"-- hook exit boot services\n");
    gOrigExitBootServices = gBS->ExitBootServices;
    gBS->ExitBootServices = ExitBootServicesHook;
#endif
}

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
    InitializeLib(image, systab);

    if (common_init() != BF_SUCCESS) {
        return EFI_ABORTED;
    }

    g_enable_winpv = 1;
    parse_cmdline(image);

#ifdef USE_XUE
    if (g_enable_xue) {
        xue_mset(&g_xue, 0, sizeof(g_xue));
        xue_mset(&g_xue_ops, 0, sizeof(g_xue_ops));
        xue_mset(&g_xue_efi, 0, sizeof(g_xue_efi));

        g_xue_efi.img_hand = image;
        g_xue.sysid = xue_sysid_efi;
        xue_open(&g_xue, &g_xue_ops, &g_xue_efi);
    }
#endif

    Print(L"-- ioctl_add_module\n");
    ioctl_add_module((char *)vmm, vmm_len);
    Print(L"-- ioctl_load_vmm\n");
    ioctl_load_vmm();
    if (g_delayed_start) {
        Print(L"-- delayed_start\n");
        delayed_start();
    } else {
        Print(L"-- start_vmm_and_unmap\n");
        start_vmm_and_unmap();
    }
    load_start_vm(image);

    // an error occured
    Print(L"-- ERROR: Shouldn't have reached here\n");
    gBS->CloseEvent(mExitBootServicesEvent);

    return EFI_SUCCESS;
}
