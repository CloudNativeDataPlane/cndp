/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 */

#ifndef _CNE_CPUFLAGS_H_
#define _CNE_CPUFLAGS_H_

/**
 * @file
 * CPU Flags routine for x86 archs. Gather and provide APIs to detect x86 CPU flags.
 */

#include <stdbool.h>        // for bool

#include <errno.h>

#include "cne_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// clang-format off
/**
 * Set of flags or enums for each CPU flag ID
 */
enum cne_cpu_flag_t {         /**< Enumeration of CPU Flags */
    /* (EAX 01h) ECX features*/
    CNE_CPUFLAG_SSE3 = 0,     /**< SSE3 */
    CNE_CPUFLAG_PCLMULQDQ,    /**< PCLMULQDQ */
    CNE_CPUFLAG_DTES64,       /**< DTES64 */
    CNE_CPUFLAG_MONITOR,      /**< MONITOR */
    CNE_CPUFLAG_DS_CPL,       /**< DS_CPL */
    CNE_CPUFLAG_VMX,          /**< VMX */
    CNE_CPUFLAG_SMX,          /**< SMX */
    CNE_CPUFLAG_EIST,         /**< EIST */
    CNE_CPUFLAG_TM2,          /**< TM2 */
    CNE_CPUFLAG_SSSE3,        /**< SSSE3 */
    CNE_CPUFLAG_CNXT_ID,      /**< CNXT_ID */
    CNE_CPUFLAG_FMA,          /**< FMA */
    CNE_CPUFLAG_CMPXCHG16B,   /**< CMPXCHG16B */
    CNE_CPUFLAG_XTPR,         /**< XTPR */
    CNE_CPUFLAG_PDCM,         /**< PDCM */
    CNE_CPUFLAG_PCID,         /**< PCID */
    CNE_CPUFLAG_DCA,          /**< DCA */
    CNE_CPUFLAG_SSE4_1,       /**< SSE4_1 */
    CNE_CPUFLAG_SSE4_2,       /**< SSE4_2 */
    CNE_CPUFLAG_X2APIC,       /**< X2APIC */
    CNE_CPUFLAG_MOVBE,        /**< MOVBE */
    CNE_CPUFLAG_POPCNT,       /**< POPCNT */
    CNE_CPUFLAG_TSC_DEADLINE, /**< TSC_DEADLINE */
    CNE_CPUFLAG_AES,          /**< AES */
    CNE_CPUFLAG_XSAVE,        /**< XSAVE */
    CNE_CPUFLAG_OSXSAVE,      /**< OSXSAVE */
    CNE_CPUFLAG_AVX,          /**< AVX */
    CNE_CPUFLAG_F16C,         /**< F16C */
    CNE_CPUFLAG_RDRAND,       /**< RDRAND */
    CNE_CPUFLAG_HYPERVISOR,   /**< Running in a VM */

    /* (EAX 01h) EDX features */
    CNE_CPUFLAG_FPU,   /**< FPU */
    CNE_CPUFLAG_VME,   /**< VME */
    CNE_CPUFLAG_DE,    /**< DE */
    CNE_CPUFLAG_PSE,   /**< PSE */
    CNE_CPUFLAG_TSC,   /**< TSC */
    CNE_CPUFLAG_MSR,   /**< MSR */
    CNE_CPUFLAG_PAE,   /**< PAE */
    CNE_CPUFLAG_MCE,   /**< MCE */
    CNE_CPUFLAG_CX8,   /**< CX8 */
    CNE_CPUFLAG_APIC,  /**< APIC */
    CNE_CPUFLAG_SEP,   /**< SEP */
    CNE_CPUFLAG_MTRR,  /**< MTRR */
    CNE_CPUFLAG_PGE,   /**< PGE */
    CNE_CPUFLAG_MCA,   /**< MCA */
    CNE_CPUFLAG_CMOV,  /**< CMOV */
    CNE_CPUFLAG_PAT,   /**< PAT */
    CNE_CPUFLAG_PSE36, /**< PSE36 */
    CNE_CPUFLAG_PSN,   /**< PSN */
    CNE_CPUFLAG_CLFSH, /**< CLFSH */
    CNE_CPUFLAG_DS,    /**< DS */
    CNE_CPUFLAG_ACPI,  /**< ACPI */
    CNE_CPUFLAG_MMX,   /**< MMX */
    CNE_CPUFLAG_FXSR,  /**< FXSR */
    CNE_CPUFLAG_SSE,   /**< SSE */
    CNE_CPUFLAG_SSE2,  /**< SSE2 */
    CNE_CPUFLAG_SS,    /**< SS */
    CNE_CPUFLAG_HTT,   /**< HTT */
    CNE_CPUFLAG_TM,    /**< TM */
    CNE_CPUFLAG_PBE,   /**< PBE */

    /* (EAX 06h) EAX features */
    CNE_CPUFLAG_DIGTEMP, /**< DIGTEMP */
    CNE_CPUFLAG_TRBOBST, /**< TRBOBST */
    CNE_CPUFLAG_ARAT,    /**< ARAT */
    CNE_CPUFLAG_PLN,     /**< PLN */
    CNE_CPUFLAG_ECMD,    /**< ECMD */
    CNE_CPUFLAG_PTM,     /**< PTM */

    /* (EAX 06h) ECX features */
    CNE_CPUFLAG_MPERF_APERF_MSR, /**< MPERF_APERF_MSR */
    CNE_CPUFLAG_ACNT2,           /**< ACNT2 */
    CNE_CPUFLAG_ENERGY_EFF,      /**< ENERGY_EFF */

    /* (EAX 07h, ECX 0h) EBX features */
    CNE_CPUFLAG_FSGSBASE, /**< FSGSBASE */
    CNE_CPUFLAG_BMI1,     /**< BMI1 */
    CNE_CPUFLAG_HLE,      /**< Hardware Lock elision */
    CNE_CPUFLAG_AVX2,     /**< AVX2 */
    CNE_CPUFLAG_SMEP,     /**< SMEP */
    CNE_CPUFLAG_BMI2,     /**< BMI2 */
    CNE_CPUFLAG_ERMS,     /**< ERMS */
    CNE_CPUFLAG_INVPCID,  /**< INVPCID */
    CNE_CPUFLAG_RTM,      /**< Transactional memory */
    CNE_CPUFLAG_AVX512F,  /**< AVX512F */
    CNE_CPUFLAG_RDSEED,   /**< RDSEED instruction */

    /* (EAX 80000001h) ECX features */
    CNE_CPUFLAG_LAHF_SAHF, /**< LAHF_SAHF */
    CNE_CPUFLAG_LZCNT,     /**< LZCNT */

    /* (EAX 80000001h) EDX features */
    CNE_CPUFLAG_SYSCALL, /**< SYSCALL */
    CNE_CPUFLAG_XD,      /**< XD */
    CNE_CPUFLAG_1GB_PG,  /**< 1GB_PG */
    CNE_CPUFLAG_RDTSCP,  /**< RDTSCP */
    CNE_CPUFLAG_EM64T,   /**< EM64T */

    /* (EAX 80000007h) EDX features */
    CNE_CPUFLAG_INVTSC, /**< INVTSC */

    CNE_CPUFLAG_AVX512DQ,    /**< AVX512 Doubleword and Quadword */
    CNE_CPUFLAG_AVX512IFMA,  /**< AVX512 Integer Fused Multiply-Add */
    CNE_CPUFLAG_AVX512CD,    /**< AVX512 Conflict Detection*/
    CNE_CPUFLAG_AVX512BW,    /**< AVX512 Byte and Word */
    CNE_CPUFLAG_AVX512VL,    /**< AVX512 Vector Length */
    CNE_CPUFLAG_AVX512VBMI,  /**< AVX512 Vector Bit Manipulation */
    CNE_CPUFLAG_AVX512VBMI2, /**< AVX512 Vector Bit Manipulation 2 */
    CNE_CPUFLAG_GFNI,        /**< Galois Field New Instructions */
    CNE_CPUFLAG_VAES,        /**< Vector AES */
    CNE_CPUFLAG_VPCLMULQDQ,  /**< Vector Carry-less Multiply */
    CNE_CPUFLAG_AVX512VNNI,
    /**< AVX512 Vector Neural Network Instructions */
    CNE_CPUFLAG_AVX512BITALG,       /**< AVX512 Bit Algorithms */
    CNE_CPUFLAG_AVX512VPOPCNTDQ,    /**< AVX512 Vector Popcount */
    CNE_CPUFLAG_CLDEMOTE,           /**< Cache Line Demote */
    CNE_CPUFLAG_MOVDIRI,            /**< Direct Store Instructions */
    CNE_CPUFLAG_MOVDIR64B,          /**< Direct Store Instructions 64B */
    CNE_CPUFLAG_AVX512VP2INTERSECT, /**< AVX512 Two Register Intersection */

    CNE_CPUFLAG_WAITPKG,            /**< umonitor/umwait/tpause */

    /* The last item */
    CNE_CPUFLAG_NUMFLAGS, /**< This should always be the last! */
};
// clang-format on

/**
 * Enumeration of all CPU features supported
 */
__extension__ enum cne_cpu_flag_t;

/**
 * Get name of CPU flag
 *
 * @param feature
 *     CPU flag ID
 * @return
 *     flag name
 *     NULL if flag ID is invalid
 */
CNDP_API const char *cne_cpu_get_flag_name(enum cne_cpu_flag_t feature);

/**
 * Function for checking a CPU flag availability
 *
 * @param feature
 *     CPU flag to query CPU for
 * @return
 *     1 if flag is available
 *     0 if flag is not available
 *     -ENOENT if flag is invalid
 */
CNDP_API int cne_cpu_get_flag_enabled(enum cne_cpu_flag_t feature);

/**
 * This function checks that the currently used CPU supports the CPU features
 * that were specified at compile time. This version returns a
 * result so that decisions may be made (for instance, graceful shutdowns).
 */
CNDP_API int cne_cpu_is_supported(void);

/**
 * This function attempts to retrieve a value from the auxiliary vector.
 * If it is unsuccessful, the result will be 0, and errno will be set.
 *
 * @param type
 *   Type of aux value to retrieve
 *
 * @return A value from the auxiliary vector.  When the value is 0, check
 * errno to determine if an error occurred.
 */
CNDP_API unsigned long cne_cpu_getauxval(unsigned long type);

/**
 * This function retrieves a value from the auxiliary vector, and compares it
 * as a string against the value retrieved.
 *
 * @param type
 *   Type of aux value to retrieve
 *
 * @param str
 *   The string pointer to compare
 *
 * @return The result of calling strcmp() against the value retrieved from
 * the auxiliary vector.  When the value is 0 (meaning a match is found),
 * check errno to determine if an error occurred.
 */
CNDP_API int cne_cpu_strcmp_auxval(unsigned long type, const char *str);

/**
 * The following cne_cpu_*_is_supported() APIs are provided to quickly
 * determine whether a cpu flag is set. They are faster than than parsing
 * the feature flag by name.
 */

/**
 * Determine if rtm cpu flag is set
 *
 * When the rtm cpu flag is set, then transactional memory instructions
 * can be executed.
 *
 * @return
 *   true if rtm is set, otherwise false
 */
CNDP_API bool cne_cpu_rtm_is_supported(void);

/**
 * Determine if waitpkg cpu flag is set
 *
 * When the waitpkg cpu flag is set, then umonitor, umwait, and tpause
 * instructions can be executed.
 *
 * @return
 *   true if waitpkg is set, otherwise false
 */
CNDP_API bool cne_cpu_waitpkg_is_supported(void);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_CPUFLAGS_H_ */
