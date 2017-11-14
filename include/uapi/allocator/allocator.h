/*
 * Copyright (c) 2017 NVIDIA CORPORATION.  All rights reserved.
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

#ifndef __ALLOCATOR_ALLOCATOR_H__
#define __ALLOCATOR_ALLOCATOR_H__

#include <allocator/common.h>

/*!
 * \file Allocator metadata (aka capability set) constructs shared by allocator
 *       kernel and user space clients
 */

/*!
 * Free an array of capability sets created by the allocator library using the
 * provided <pFree> function.
 */
static inline void
__free_capability_set(__u32 num_capability_sets,
		      capability_set_t *capability_sets,
		      void (* pFree)(const void *ptr))
{
	__u32 i, j;

	if (!capability_sets)
		return;

	for (i = 0; i < num_capability_sets; i++) {
		if (capability_sets[i].constraints)
			pFree((const void *)capability_sets[i].constraints);

		if (!capability_sets[i].capabilities)
			continue;

		for (j = 0; j <	capability_sets[i].num_capabilities; j++) {
			if (capability_sets[i].capabilities[j])
				pFree((const void *)capability_sets[i].capabilities[j]);
		}

		pFree((const void *)capability_sets[i].capabilities);
	}

	pFree((const void *)capability_sets);
}

/*!
 * Allocate a capability set using the provided <pCalloc> function and populate
 * it from a raw stream of bytes.
 *
 * The caller is responsible for freeing the memory pointed to by
 * <capability_set>, even upon failure:
 *
 *     __free_capability_set(1, *capability_set, free);
 */
static inline int
__deserialize_capability_set(size_t data_size,
			     const void *data_ptr,
			     capability_set_t **capability_set,
			     void * (* pCalloc)(size_t n, size_t size))
{
	const __u8 *d = NULL;
	constraint_t *constraints = NULL;
	capability_header_t **capabilities = NULL;
	capability_set_t *set = NULL;
	__u32 i;

	d = data_ptr;

	set = pCalloc(1, sizeof(*set));
	*capability_set = set;
	if (!set)
		return -1;

#define PEEK_DESERIALIZE(dst, size) \
	if (((d + (size)) - (__u8 *)data_ptr) > data_size) \
		return -1; \
	memcpy((dst), d, (size))

#define DESERIALIZE(dst, size) \
	PEEK_DESERIALIZE((dst), (size)); \
	d += (size)

	DESERIALIZE(&set->num_constraints, sizeof(set->num_constraints));
	DESERIALIZE(&set->num_capabilities, sizeof(set->num_capabilities));

	constraints = pCalloc(set->num_constraints, sizeof(*set->constraints));
	set->constraints = constraints;
	if (!constraints)
		return -1;

	for (i = 0; i < set->num_constraints; i++) {
		DESERIALIZE(&constraints[i], sizeof(set->constraints[i]));
	}

	capabilities = pCalloc(set->num_capabilities, sizeof(*capabilities));
	set->capabilities = (const capability_header_t * const *)capabilities;
	if (!capabilities)
		return -1;

	for (i = 0; i < set->num_capabilities; i++) {
		capability_header_t tmp_header;

		PEEK_DESERIALIZE(&tmp_header, sizeof(tmp_header));

		capabilities[i] = pCalloc(1, sizeof(tmp_header) +
					  tmp_header.common.length_in_words *
					  sizeof(__u32));
		if (!capabilities[i])
			return -1;

		DESERIALIZE(capabilities[i], sizeof(*capabilities[i]) +
			    tmp_header.common.length_in_words * sizeof(__u32));
	}

#undef DESERIALIZE
#undef PEEK_DESERIALIZE

	return 0;
}

#endif /* __ALLOCATOR_ALLOCATOR_H__ */
