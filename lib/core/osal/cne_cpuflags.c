/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2023 Intel Corporation
 */

#include <stdbool.h>                 // for bool, true
#include <stdio.h>                   // for fprintf, stderr, NULL
#include <errno.h>                   // for EFAULT, EINVAL, ENOENT
#include <stdint.h>                  // for uint32_t, uint16_t
#include <cne_cpuid.h>               // for CNE_REG_ECX, CNE_REG_EDX, CNE_REG_EBX
#include <cne_common.h>              // for cne_is_power_of_2, CNE_DIM, CNE_INIT
#include <cpuid.h>                   // for __get_cpuid_max, __cpuid_count
#include <cne_vect_generic.h>        // for CNE_VECT_SIMD_DEFAULT, CNE_VECT_SIMD_D...

#include "cne_cpuflags.h"            // for cne_cpu_flag_t, CNE_CPUFLAG_NUMFLAGS
#include "cne_build_config.h"        // for CNE_COMPILE_TIME_CPUFLAGS

/** Restricted Transactional Memory (RTM) cpuflag is set or not */
static bool cne_rtm_supported;

/** waitpkg cpuflag is set or not */
static bool cne_waitpkg_supported;

/** Default SIMD bitwidth */
static uint16_t cne_simd_bitwidth = CNE_VECT_SIMD_DEFAULT;

/**
 * Struct to hold a processor feature entry
 */
struct feature_entry {
    uint32_t leaf;    /**< cpuid leaf */
    uint32_t subleaf; /**< cpuid subleaf */
    uint32_t reg;     /**< cpuid register */
    uint32_t bit;     /**< cpuid register bit */
#define CPU_FLAG_NAME_MAX_LEN 64
    char name[CPU_FLAG_NAME_MAX_LEN]; /**< String for printing */
};

#define FEAT_DEF(name, leaf, subleaf, reg, bit) \
    [CNE_CPUFLAG_##name] = {leaf, subleaf, reg, bit, #name},

// clang-format off
const struct feature_entry cne_cpu_feature_table[] = {
    FEAT_DEF(SSE3, 0x00000001, 0, CNE_REG_ECX,  0)
    FEAT_DEF(PCLMULQDQ, 0x00000001, 0, CNE_REG_ECX,  1)
    FEAT_DEF(DTES64, 0x00000001, 0, CNE_REG_ECX,  2)
    FEAT_DEF(MONITOR, 0x00000001, 0, CNE_REG_ECX,  3)
    FEAT_DEF(DS_CPL, 0x00000001, 0, CNE_REG_ECX,  4)
    FEAT_DEF(VMX, 0x00000001, 0, CNE_REG_ECX,  5)
    FEAT_DEF(SMX, 0x00000001, 0, CNE_REG_ECX,  6)
    FEAT_DEF(EIST, 0x00000001, 0, CNE_REG_ECX,  7)
    FEAT_DEF(TM2, 0x00000001, 0, CNE_REG_ECX,  8)
    FEAT_DEF(SSSE3, 0x00000001, 0, CNE_REG_ECX,  9)
    FEAT_DEF(CNXT_ID, 0x00000001, 0, CNE_REG_ECX, 10)
    FEAT_DEF(FMA, 0x00000001, 0, CNE_REG_ECX, 12)
    FEAT_DEF(CMPXCHG16B, 0x00000001, 0, CNE_REG_ECX, 13)
    FEAT_DEF(XTPR, 0x00000001, 0, CNE_REG_ECX, 14)
    FEAT_DEF(PDCM, 0x00000001, 0, CNE_REG_ECX, 15)
    FEAT_DEF(PCID, 0x00000001, 0, CNE_REG_ECX, 17)
    FEAT_DEF(DCA, 0x00000001, 0, CNE_REG_ECX, 18)
    FEAT_DEF(SSE4_1, 0x00000001, 0, CNE_REG_ECX, 19)
    FEAT_DEF(SSE4_2, 0x00000001, 0, CNE_REG_ECX, 20)
    FEAT_DEF(X2APIC, 0x00000001, 0, CNE_REG_ECX, 21)
    FEAT_DEF(MOVBE, 0x00000001, 0, CNE_REG_ECX, 22)
    FEAT_DEF(POPCNT, 0x00000001, 0, CNE_REG_ECX, 23)
    FEAT_DEF(TSC_DEADLINE, 0x00000001, 0, CNE_REG_ECX, 24)
    FEAT_DEF(AES, 0x00000001, 0, CNE_REG_ECX, 25)
    FEAT_DEF(XSAVE, 0x00000001, 0, CNE_REG_ECX, 26)
    FEAT_DEF(OSXSAVE, 0x00000001, 0, CNE_REG_ECX, 27)
    FEAT_DEF(AVX, 0x00000001, 0, CNE_REG_ECX, 28)
    FEAT_DEF(F16C, 0x00000001, 0, CNE_REG_ECX, 29)
    FEAT_DEF(RDRAND, 0x00000001, 0, CNE_REG_ECX, 30)
    FEAT_DEF(HYPERVISOR, 0x00000001, 0, CNE_REG_ECX, 31)

    FEAT_DEF(FPU, 0x00000001, 0, CNE_REG_EDX,  0)
    FEAT_DEF(VME, 0x00000001, 0, CNE_REG_EDX,  1)
    FEAT_DEF(DE, 0x00000001, 0, CNE_REG_EDX,  2)
    FEAT_DEF(PSE, 0x00000001, 0, CNE_REG_EDX,  3)
    FEAT_DEF(TSC, 0x00000001, 0, CNE_REG_EDX,  4)
    FEAT_DEF(MSR, 0x00000001, 0, CNE_REG_EDX,  5)
    FEAT_DEF(PAE, 0x00000001, 0, CNE_REG_EDX,  6)
    FEAT_DEF(MCE, 0x00000001, 0, CNE_REG_EDX,  7)
    FEAT_DEF(CX8, 0x00000001, 0, CNE_REG_EDX,  8)
    FEAT_DEF(APIC, 0x00000001, 0, CNE_REG_EDX,  9)
    FEAT_DEF(SEP, 0x00000001, 0, CNE_REG_EDX, 11)
    FEAT_DEF(MTRR, 0x00000001, 0, CNE_REG_EDX, 12)
    FEAT_DEF(PGE, 0x00000001, 0, CNE_REG_EDX, 13)
    FEAT_DEF(MCA, 0x00000001, 0, CNE_REG_EDX, 14)
    FEAT_DEF(CMOV, 0x00000001, 0, CNE_REG_EDX, 15)
    FEAT_DEF(PAT, 0x00000001, 0, CNE_REG_EDX, 16)
    FEAT_DEF(PSE36, 0x00000001, 0, CNE_REG_EDX, 17)
    FEAT_DEF(PSN, 0x00000001, 0, CNE_REG_EDX, 18)
    FEAT_DEF(CLFSH, 0x00000001, 0, CNE_REG_EDX, 19)
    FEAT_DEF(DS, 0x00000001, 0, CNE_REG_EDX, 21)
    FEAT_DEF(ACPI, 0x00000001, 0, CNE_REG_EDX, 22)
    FEAT_DEF(MMX, 0x00000001, 0, CNE_REG_EDX, 23)
    FEAT_DEF(FXSR, 0x00000001, 0, CNE_REG_EDX, 24)
    FEAT_DEF(SSE, 0x00000001, 0, CNE_REG_EDX, 25)
    FEAT_DEF(SSE2, 0x00000001, 0, CNE_REG_EDX, 26)
    FEAT_DEF(SS, 0x00000001, 0, CNE_REG_EDX, 27)
    FEAT_DEF(HTT, 0x00000001, 0, CNE_REG_EDX, 28)
    FEAT_DEF(TM, 0x00000001, 0, CNE_REG_EDX, 29)
    FEAT_DEF(PBE, 0x00000001, 0, CNE_REG_EDX, 31)

    FEAT_DEF(DIGTEMP, 0x00000006, 0, CNE_REG_EAX,  0)
    FEAT_DEF(TRBOBST, 0x00000006, 0, CNE_REG_EAX,  1)
    FEAT_DEF(ARAT, 0x00000006, 0, CNE_REG_EAX,  2)
    FEAT_DEF(PLN, 0x00000006, 0, CNE_REG_EAX,  4)
    FEAT_DEF(ECMD, 0x00000006, 0, CNE_REG_EAX,  5)
    FEAT_DEF(PTM, 0x00000006, 0, CNE_REG_EAX,  6)

    FEAT_DEF(MPERF_APERF_MSR, 0x00000006, 0, CNE_REG_ECX,  0)
    FEAT_DEF(ACNT2, 0x00000006, 0, CNE_REG_ECX,  1)
    FEAT_DEF(ENERGY_EFF, 0x00000006, 0, CNE_REG_ECX,  3)

    FEAT_DEF(FSGSBASE, 0x00000007, 0, CNE_REG_EBX,  0)
    FEAT_DEF(BMI1, 0x00000007, 0, CNE_REG_EBX,  2)
    FEAT_DEF(HLE, 0x00000007, 0, CNE_REG_EBX,  4)
    FEAT_DEF(AVX2, 0x00000007, 0, CNE_REG_EBX,  5)
    FEAT_DEF(SMEP, 0x00000007, 0, CNE_REG_EBX,  6)
    FEAT_DEF(BMI2, 0x00000007, 0, CNE_REG_EBX,  7)
    FEAT_DEF(ERMS, 0x00000007, 0, CNE_REG_EBX,  8)
    FEAT_DEF(INVPCID, 0x00000007, 0, CNE_REG_EBX, 10)
    FEAT_DEF(RTM, 0x00000007, 0, CNE_REG_EBX, 11)
    FEAT_DEF(AVX512F, 0x00000007, 0, CNE_REG_EBX, 16)
    FEAT_DEF(RDSEED, 0x00000007, 0, CNE_REG_EBX, 18)

    FEAT_DEF(LAHF_SAHF, 0x80000001, 0, CNE_REG_ECX,  0)
    FEAT_DEF(LZCNT, 0x80000001, 0, CNE_REG_ECX,  4)

    FEAT_DEF(SYSCALL, 0x80000001, 0, CNE_REG_EDX, 11)
    FEAT_DEF(XD, 0x80000001, 0, CNE_REG_EDX, 20)
    FEAT_DEF(1GB_PG, 0x80000001, 0, CNE_REG_EDX, 26)
    FEAT_DEF(RDTSCP, 0x80000001, 0, CNE_REG_EDX, 27)
    FEAT_DEF(EM64T, 0x80000001, 0, CNE_REG_EDX, 29)

    FEAT_DEF(INVTSC, 0x80000007, 0, CNE_REG_EDX,  8)

    FEAT_DEF(AVX512DQ, 0x00000007, 0, CNE_REG_EBX, 17)
    FEAT_DEF(AVX512IFMA, 0x00000007, 0, CNE_REG_EBX, 21)
    FEAT_DEF(AVX512CD, 0x00000007, 0, CNE_REG_EBX, 28)
    FEAT_DEF(AVX512BW, 0x00000007, 0, CNE_REG_EBX, 30)
    FEAT_DEF(AVX512VL, 0x00000007, 0, CNE_REG_EBX, 31)
    FEAT_DEF(AVX512VBMI, 0x00000007, 0, CNE_REG_ECX, 1)
    FEAT_DEF(WAITPKG, 0x00000007, 0, CNE_REG_ECX, 5)
    FEAT_DEF(AVX512VBMI2, 0x00000007, 0, CNE_REG_ECX, 6)
    FEAT_DEF(GFNI, 0x00000007, 0, CNE_REG_ECX, 8)
    FEAT_DEF(VAES, 0x00000007, 0, CNE_REG_ECX, 9)
    FEAT_DEF(VPCLMULQDQ, 0x00000007, 0, CNE_REG_ECX, 10)
    FEAT_DEF(AVX512VNNI, 0x00000007, 0, CNE_REG_ECX, 11)
    FEAT_DEF(AVX512BITALG, 0x00000007, 0, CNE_REG_ECX, 12)
    FEAT_DEF(AVX512VPOPCNTDQ, 0x00000007, 0, CNE_REG_ECX,  14)
    FEAT_DEF(CLDEMOTE, 0x00000007, 0, CNE_REG_ECX, 25)
    FEAT_DEF(MOVDIRI, 0x00000007, 0, CNE_REG_ECX, 27)
    FEAT_DEF(MOVDIR64B, 0x00000007, 0, CNE_REG_ECX, 28)
    FEAT_DEF(AVX512VP2INTERSECT, 0x00000007, 0, CNE_REG_EDX, 8)
};
// clang-format on

int
cne_cpu_is_supported(void)
{
    /* This is generated at compile-time by the build system */
    static const enum cne_cpu_flag_t compile_time_flags[] = {CNE_COMPILE_TIME_CPUFLAGS};
    unsigned count                                        = CNE_DIM(compile_time_flags), i;
    int ret;

    for (i = 0; i < count; i++) {
        ret = cne_cpu_get_flag_enabled(compile_time_flags[i]);

        if (ret < 0) {
            fprintf(stderr, "ERROR: CPU feature flag lookup failed with error %d\n", ret);
            return 0;
        }
        if (!ret) {
            const char *name = cne_cpu_get_flag_name(compile_time_flags[i]);

            if (name)
                fprintf(stderr,
                        "ERROR: This system does not support \"%s\".\n"
                        "Please check that CNE_MACHINE is set correctly.\n",
                        name);
            else
                fprintf(stderr, "ERROR: This system does not support \"UNKNOWN\".\n"
                                "Please check that CNE_MACHINE is set correctly.\n");

            return 0;
        }
    }

    return 1;
}

int
cne_cpu_get_flag_enabled(enum cne_cpu_flag_t feature)
{
    const struct feature_entry *feat;
    cpuid_registers_t regs;
    unsigned int maxleaf;

    if (feature >= CNE_CPUFLAG_NUMFLAGS)
        /* Flag does not match anything in the feature tables */
        return -ENOENT;

    feat = &cne_cpu_feature_table[feature];

    if (!feat->leaf)
        /* This entry in the table wasn't filled out! */
        return -EFAULT;

    maxleaf = __get_cpuid_max(feat->leaf & 0x80000000, NULL);

    if (maxleaf < feat->leaf)
        return 0;

    __cpuid_count(feat->leaf, feat->subleaf, regs[CNE_REG_EAX], regs[CNE_REG_EBX],
                  regs[CNE_REG_ECX], regs[CNE_REG_EDX]);

    /* check if the feature is enabled */
    return (regs[feat->reg] >> feat->bit) & 1;
}

const char *
cne_cpu_get_flag_name(enum cne_cpu_flag_t feature)
{
    if (feature >= CNE_CPUFLAG_NUMFLAGS)
        return NULL;
    return cne_cpu_feature_table[feature].name;
}

bool
cne_cpu_rtm_is_supported(void)
{
    return cne_rtm_supported;
}

bool
cne_cpu_waitpkg_is_supported(void)
{
    return cne_waitpkg_supported;
}

uint16_t
cne_vect_get_max_simd_bitwidth(void)
{
    return cne_simd_bitwidth;
}

int
cne_vect_set_max_simd_bitwidth(uint16_t bitwidth)
{
    if (bitwidth < CNE_VECT_SIMD_DISABLED || !cne_is_power_of_2(bitwidth))
        return -EINVAL;

    cne_simd_bitwidth = bitwidth;
    return 0;
}

CNE_INIT(cne_cpuflag_init)
{
    if (cne_cpu_get_flag_enabled(CNE_CPUFLAG_RTM) == 1)
        cne_rtm_supported = true;

    if (cne_cpu_get_flag_enabled(CNE_CPUFLAG_WAITPKG) == 1)
        cne_waitpkg_supported = true;
}
