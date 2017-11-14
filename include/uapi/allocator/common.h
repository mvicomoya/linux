/*
 * Copyright (c) 2016-2017 NVIDIA CORPORATION.  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __ALLOCATOR_COMMON_H__
#define __ALLOCATOR_COMMON_H__

#if defined(__KERNEL__)

#include <linux/types.h>

#elif defined(__linux__)

#include <linux/types.h>

#else /* One of the BSDs */

#include <sys/types.h>
typedef int8_t   __s8;
typedef uint8_t  __u8;
typedef int16_t  __s16;
typedef uint16_t __u16;
typedef int32_t  __s32;
typedef uint32_t __u32;
typedef int64_t  __s64;
typedef uint64_t __u64;
typedef size_t   __kernel_size_t;

#endif

/*! TODO: Namespace everything when we settle on a project name (libgbm2?) */

/*!
 * \file Allocator definitions and declarations used by kernel drivers
 */

/*!
 * Vendor IDs
 *
 * Vendor IDs are used to establish namespaces where device manufacturers and
 * driver authors may define vendor-specific extensions and allocation
 * properties.  The special vendor VENDOR_BASE is used to define a global
 * namespace that is expected to be understood by all driver vendors.  Vendors
 * may reference and parse properties and extensions from eachother's
 * namespaces as well, but applications should not rely on such interopation
 * in general.
 *
 * Vendors should register their vendor ID by adding it here.  The suggested
 * value is the same as the vendor's Vulkan vendor ID if it has one, which is
 * generally the vendor's PCI vendor ID or a value of the form 0x0001XXXX
 * registered with Khronos.  If the vendor does not have a PCI vendor ID or
 * a Vulkan vendor ID registered with Khronos, please use the first available
 * ID of the form 0xFFFFXXXX.
 *
 * For clarity, keep the vendor ID list in numerical order.
 */
#define VENDOR_BASE                             0x00000000
#define VENDOR_NVIDIA                           0x000010DE
#define VENDOR_ARM                              0x000013B5
#define VENDOR_INTEL                            0x00008086

/*!
 * \defgroup constraints
 * @{
 */

typedef struct constraint {
    __u32 name;

    /*!
     * TODO: [JRJ] Is it portable to send unions of this form over the
     *       wire using a simple memcpy()/write()?
     */
    union {
        /*! CONSTRAINT_ADDRESS_ALIGNMENT */
        struct {
            __u64 value;
        } address_alignment;

        /*! CONSTRAINT_PITCH_ALIGNMENT */
        struct {
            __u32 value;
        } pitch_alignment;

        /*! CONSTRAINT_MAX_PITCH */
        struct {
            __u32 value;
        } max_pitch;
    } u;
} constraint_t;
#define CONSTRAINT_ADDRESS_ALIGNMENT                                0x00000000
#define CONSTRAINT_PITCH_ALIGNMENT                                  0x00000001
#define CONSTRAINT_MAX_PITCH                                        0x00000002
#define CONSTRAINT_END                                              ((CONSTRAINT_MAX_PITCH) + 1)

/*!
 * @}
 * End of the constraint group
 */

/*!
 * Common header for usage and capabilities
 */
typedef struct header {
    __u32 vendor;
    __u16 name;
    __u16 length_in_words;
} header_t;

/*!
 * \defgroup capabilities
 * @{
 */

/*!
 * Capabilities need an additional "required" field so they subclass header_t
 *
 * Note common_header::length_in_words does not include any bytes in the
 * defined header, meaning the "required" field is not included in
 * length_in_words.
 */
typedef struct capability_header {
    header_t common;

    /*!
     * If non-zero, removing this field via capability list intersection causes
     * the intersection operation to fail.
     */
    __s8 required;
} capability_header_t;

/*!
 * The ability to represent 2D images using pitch x height pixel layout.
 *
 * This is a binary capability with no additional properties, so its mere
 * presence is sufficient to express it.  No additional fields beyond the
 * header are needed.
 */
typedef struct capability_pitch_linear {
    capability_header_t header; // { VENDOR_BASE, CAP_BASE_PITCH_LINEAR, 0 }
} capability_pitch_linear_t;
#define CAP_BASE_PITCH_LINEAR 0x0000

/*!
 * Capability sets are made up of zero or more constraints and one or more
 * capability descriptors
 *
 * Device capabilities and constraints can not be mixed arbitrarily.  For
 * example, a device may support pitch linear tiling, proprietary tiling,
 * and image compression, but not all independently.  Compression may only
 * be available when using certain proprietary tiling capabilities.
 * Therefore, capabilities must be reported and compared as immutable sets.
 *
 * Constraints need to be included in capability sets because they may be
 * specific to a set of capabilities.  For example, a device may have one
 * address alignment requirement for pitch linear, but another requirement
 * for proprietary tiling.
 */
typedef struct capability_set {
    __u32 num_constraints;
    __u32 num_capabilities;
    const constraint_t *constraints;
    const capability_header_t *const *capabilities;
} capability_set_t;

/*!
 * @}
 * End of the capabilities group
 */

/*!
 * \defgroup assertions
 * @{
 */

/*!
 * An assertion is the parameters the application supplies when requesting
 * a surface allocation, or when requesting capabilities.  The parameters
 * here are different from requested usage in that they are requirements.
 * In other words, it is not expected that the application will retry with
 * different values for these parameters if the returned capability set is
 * zero, whereas usage is something that is intended to be negotiated via
 * several capability requests.  As such, these should be kept to a minimum.
 */
typedef struct assertion {
    /*! Required surface width */
    __u32 width;

    /*! Required surface height */
    __u32 height;

    /*! Required surface pixel format.
     *
     * TODO: Non-consensus!  Decide if this is Khronos data format or fourcc
     */
    const __u64 format;

    /*!
     * To handle extended assertions, define a new structure whose first
     * member is a value describing its type, and point to it here.
     */
    void __user *ext;
} assertion_t;

/*!
 * @}
 * End of the assertions group
 */

#endif /* __ALLOCATOR_COMMON_H__ */
