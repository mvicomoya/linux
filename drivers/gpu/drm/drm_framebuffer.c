/*
 * Copyright (c) 2016 Intel Corporation
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#include <linux/export.h>
#include <drm/drmP.h>
#include <drm/drm_auth.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_atomic.h>

#include "drm_crtc_internal.h"

#if IS_ENABLED(CONFIG_DRM_ALLOCATOR_METADATA)
#include <allocator/allocator.h>
#endif

/**
 * DOC: overview
 *
 * Frame buffers are abstract memory objects that provide a source of pixels to
 * scanout to a CRTC. Applications explicitly request the creation of frame
 * buffers through the DRM_IOCTL_MODE_ADDFB(2) ioctls and receive an opaque
 * handle that can be passed to the KMS CRTC control, plane configuration and
 * page flip functions.
 *
 * Frame buffers rely on the underlying memory manager for allocating backing
 * storage. When creating a frame buffer applications pass a memory handle
 * (or a list of memory handles for multi-planar formats) through the
 * &struct drm_mode_fb_cmd2 argument. For drivers using GEM as their userspace
 * buffer management interface this would be a GEM handle.  Drivers are however
 * free to use their own backing storage object handles, e.g. vmwgfx directly
 * exposes special TTM handles to userspace and so expects TTM handles in the
 * create ioctl and not GEM handles.
 *
 * Framebuffers are tracked with &struct drm_framebuffer. They are published
 * using drm_framebuffer_init() - after calling that function userspace can use
 * and access the framebuffer object. The helper function
 * drm_helper_mode_fill_fb_struct() can be used to pre-fill the required
 * metadata fields.
 *
 * The lifetime of a drm framebuffer is controlled with a reference count,
 * drivers can grab additional references with drm_framebuffer_get() and drop
 * them again with drm_framebuffer_put(). For driver-private framebuffers for
 * which the last reference is never dropped (e.g. for the fbdev framebuffer
 * when the struct &struct drm_framebuffer is embedded into the fbdev helper
 * struct) drivers can manually clean up a framebuffer at module unload time
 * with drm_framebuffer_unregister_private(). But doing this is not
 * recommended, and it's better to have a normal free-standing &struct
 * drm_framebuffer.
 */

int drm_framebuffer_check_src_coords(uint32_t src_x, uint32_t src_y,
				     uint32_t src_w, uint32_t src_h,
				     const struct drm_framebuffer *fb)
{
	unsigned int fb_width, fb_height;

	fb_width = fb->width << 16;
	fb_height = fb->height << 16;

	/* Make sure source coordinates are inside the fb. */
	if (src_w > fb_width ||
	    src_x > fb_width - src_w ||
	    src_h > fb_height ||
	    src_y > fb_height - src_h) {
		DRM_DEBUG_KMS("Invalid source coordinates "
			      "%u.%06ux%u.%06u+%u.%06u+%u.%06u\n",
			      src_w >> 16, ((src_w & 0xffff) * 15625) >> 10,
			      src_h >> 16, ((src_h & 0xffff) * 15625) >> 10,
			      src_x >> 16, ((src_x & 0xffff) * 15625) >> 10,
			      src_y >> 16, ((src_y & 0xffff) * 15625) >> 10);
		return -ENOSPC;
	}

	return 0;
}

/**
 * drm_mode_addfb - add an FB to the graphics configuration
 * @dev: drm device for the ioctl
 * @data: data pointer for the ioctl
 * @file_priv: drm file for the ioctl call
 *
 * Add a new FB to the specified CRTC, given a user request. This is the
 * original addfb ioctl which only supported RGB formats.
 *
 * Called by the user via ioctl.
 *
 * Returns:
 * Zero on success, negative errno on failure.
 */
int drm_mode_addfb(struct drm_device *dev,
		   void *data, struct drm_file *file_priv)
{
	struct drm_mode_fb_cmd *or = data;
	struct drm_mode_fb_cmd2 r = {};
	int ret;

	/* convert to new format and call new ioctl */
	r.fb_id = or->fb_id;
	r.width = or->width;
	r.height = or->height;
	r.pitches[0] = or->pitch;
	r.pixel_format = drm_mode_legacy_fb_format(or->bpp, or->depth);
	r.handles[0] = or->handle;

	ret = drm_mode_addfb2(dev, &r, file_priv);
	if (ret)
		return ret;

	or->fb_id = r.fb_id;

	return 0;
}

static int fb_plane_width(int width,
			  const struct drm_format_info *format, int plane)
{
	if (plane == 0)
		return width;

	return DIV_ROUND_UP(width, format->hsub);
}

static int fb_plane_height(int height,
			   const struct drm_format_info *format, int plane)
{
	if (plane == 0)
		return height;

	return DIV_ROUND_UP(height, format->vsub);
}

static int framebuffer_check_common(struct drm_device *dev,
				   __u32 width, __u32 height,
				   __u32 pixel_format, __u32 flags)
{
	struct drm_mode_config *config = &dev->mode_config;
	const struct drm_format_info *info;

	if (flags & ~(DRM_MODE_FB_INTERLACED | DRM_MODE_FB_MODIFIERS)) {
		DRM_DEBUG_KMS("bad framebuffer flags 0x%08x\n", flags);
		return -EINVAL;
	}

	if ((config->min_width > width) || (width > config->max_width)) {
		DRM_DEBUG_KMS("bad framebuffer width %d, should be >= %d && "
			      "<= %d\n", width, config->min_width,
			      config->max_width);
		return -EINVAL;
	}
	if ((config->min_height > height) || (height > config->max_height)) {
		DRM_DEBUG_KMS("bad framebuffer height %d, should be >= %d && "
			      "<= %d\n", height, config->min_height,
			      config->max_height);
		return -EINVAL;
	}

	if (flags & DRM_MODE_FB_MODIFIERS && !config->allow_fb_modifiers) {
		DRM_DEBUG_KMS("driver does not support fb modifiers\n");
		return -EINVAL;
	}

	/* check if the format is supported at all */
	info = __drm_format_info(pixel_format & ~DRM_FORMAT_BIG_ENDIAN);
	if (!info) {
		struct drm_format_name_buf format_name;
		DRM_DEBUG_KMS("bad framebuffer format %s\n",
			      drm_get_format_name(pixel_format,
						  &format_name));
		return -EINVAL;
	}

	return 0;
}

static int framebuffer_check_plane(__u32 plane, __u32 fb_width, __u32 fb_height,
				   const struct drm_format_info *info,
				   __u32 handle, __u32 pitch, __u32 pitch_alignment,
				   __u32 max_pitch, __u64 address_alignment,
				   __u32 offset, __u64 modifier, __u32 flags)
{
	__u32 width = fb_plane_width(fb_width, info, plane);
	__u32 height = fb_plane_height(fb_height, info, plane);
	__u32 cpp = info->cpp[plane];

	if (!handle) {
		DRM_DEBUG_KMS("no buffer object handle for plane %d\n", plane);
		return -EINVAL;
	}

	if ((__u64) width * cpp > UINT_MAX) {
		DRM_DEBUG_KMS("bad width %u for plane %d\n", width, plane);
		return -ERANGE;
	}

	if ((__u64) height * pitch + offset > UINT_MAX) {
		DRM_DEBUG_KMS("bad width %u for plane %d\n", height, plane);
		return -ERANGE;
	}

	if (address_alignment < 1 || address_alignment > UINT_MAX ||
        (address_alignment & (address_alignment - 1)) != 0) {
		DRM_DEBUG_KMS("bad address alignment %llu for plane %d\n",
			      address_alignment, plane);
		return -ERANGE;
	}

	if (pitch_alignment < 1 || pitch_alignment > UINT_MAX ||
        (pitch_alignment & (pitch_alignment - 1)) != 0) {
		DRM_DEBUG_KMS("bad pitch alignment %u for plane %d\n",
			      pitch_alignment, plane);
		return -ERANGE;
	}

	if (max_pitch > UINT_MAX) {
		DRM_DEBUG_KMS("bad maximum pitch %u for plane %d\n",
			      max_pitch, plane);
		return -EINVAL;
	}

	if (pitch < width * cpp || pitch > max_pitch) {
		DRM_DEBUG_KMS("bad pitch %u for plane %d\n", pitch, plane);
		return -EINVAL;
	}

	if (modifier && !(flags & DRM_MODE_FB_MODIFIERS)) {
		DRM_DEBUG_KMS("bad fb modifier %llu for plane %d\n",
			      modifier, plane);
		return -EINVAL;
	}

	/* modifier specific checks: */
	switch (modifier) {
	case DRM_FORMAT_MOD_SAMSUNG_64_32_TILE:
		/* NOTE: the pitch restriction may be lifted later if it turns
		 * out that no hw has this restriction:
		 */
		if (info->format != DRM_FORMAT_NV12 ||
				width % 128 || height % 32 ||
				pitch % 128) {
			DRM_DEBUG_KMS("bad modifier data for plane %d\n", plane);
			return -EINVAL;
		}
		break;

	default:
		break;
	}

	return 0;
}

static int framebuffer_check_cmd2(struct drm_device *dev,
				  const struct drm_mode_fb_cmd2 *r)
{
	const struct drm_format_info *info;
	int ret;
	int i;

	if ((ret = framebuffer_check_common(dev, r->width, r->height,
					    r->pixel_format, r->flags)))
		return ret;

	/* let the driver pick its own format info */
	info = drm_get_format_info(dev, r);

	for (i = 0; i < info->num_planes; i++) {
		if ((ret = framebuffer_check_plane(i, r->width, r->height, info,
						   r->handles[i], r->pitches[i],
						   1, UINT_MAX, 1, r->offsets[i],
						   r->modifier[i], r->flags)))
			return ret;

		if (r->flags & DRM_MODE_FB_MODIFIERS &&
		    r->modifier[i] != r->modifier[0]) {
			DRM_DEBUG_KMS("bad fb modifier %llu for plane %d\n",
				      r->modifier[i], i);
			return -EINVAL;
		}
	}

	for (i = info->num_planes; i < 4; i++) {
		if (r->modifier[i]) {
			DRM_DEBUG_KMS("non-zero modifier for unused plane %d\n", i);
			return -EINVAL;
		}

		/* Pre-FB_MODIFIERS userspace didn't clear the structs properly. */
		if (!(r->flags & DRM_MODE_FB_MODIFIERS))
			continue;

		if (r->handles[i]) {
			DRM_DEBUG_KMS("buffer object handle for unused plane %d\n", i);
			return -EINVAL;
		}

		if (r->pitches[i]) {
			DRM_DEBUG_KMS("non-zero pitch for unused plane %d\n", i);
			return -EINVAL;
		}

		if (r->offsets[i]) {
			DRM_DEBUG_KMS("non-zero offset for unused plane %d\n", i);
			return -EINVAL;
		}
	}

	return 0;
}

struct drm_framebuffer *
drm_internal_framebuffer_create(struct drm_device *dev,
				const struct drm_mode_fb_cmd2 *r,
				struct drm_file *file_priv)
{
	struct drm_framebuffer *fb;
	int ret;

	ret = framebuffer_check_cmd2(dev, r);
	if (ret)
		return ERR_PTR(ret);

	fb = dev->mode_config.funcs->fb_create(dev, file_priv, r);
	if (IS_ERR(fb)) {
		DRM_DEBUG_KMS("could not create framebuffer\n");
		return fb;
	}

	return fb;
}

/**
 * drm_mode_addfb2 - add an FB to the graphics configuration
 * @dev: drm device for the ioctl
 * @data: data pointer for the ioctl
 * @file_priv: drm file for the ioctl call
 *
 * Add a new FB to the specified CRTC, given a user request with format. This is
 * the 2nd version of the addfb ioctl, which supports multi-planar framebuffers
 * and uses fourcc codes as pixel format specifiers.
 *
 * Called by the user via ioctl.
 *
 * Returns:
 * Zero on success, negative errno on failure.
 */
int drm_mode_addfb2(struct drm_device *dev,
		    void *data, struct drm_file *file_priv)
{
	struct drm_mode_fb_cmd2 *r = data;
	struct drm_framebuffer *fb;

	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		return -EINVAL;

	fb = drm_internal_framebuffer_create(dev, r, file_priv);
	if (IS_ERR(fb))
		return PTR_ERR(fb);

	DRM_DEBUG_KMS("[FB:%d]\n", fb->base.id);
	r->fb_id = fb->base.id;

	/* Transfer ownership to the filp for reaping on close */
	mutex_lock(&file_priv->fbs_lock);
	list_add(&fb->filp_head, &file_priv->fbs);
	mutex_unlock(&file_priv->fbs_lock);

	return 0;
}

#if IS_ENABLED(CONFIG_DRM_ALLOCATOR_METADATA)

/**
 * drm_framebuffer_read_constraint - Parse an allocator's capability set and
 * return the requested constraint value if found
 *
 * @set: Allocator's capability set
 * @name: Requested constraint name
 * @value: Set if requested constraint is found; otherwise, untouched
 */
int drm_framebuffer_read_constraint(const capability_set_t *set,
				    __u32 name,
				    void *value)
{
	__u32 idx = set->num_constraints;
	__u32 i;

	/* Find the corresponding constraint, but also check it's set at most
	 * once */
	for (i = 0; i < set->num_constraints; i++) {
		if (set->constraints[i].name == name) {
			if (idx != set->num_constraints)
				return -1;
			idx = i;
		}
	}

#define WRITE_CONSTRAINT(NAME, UNION_MEMBER, VALUE_TYPE) \
	case CONSTRAINT_ ## NAME: \
		*((VALUE_TYPE *)value) = set->constraints[idx].u.UNION_MEMBER.value; \
		break

	if (idx < set->num_constraints) {
		switch (set->constraints[idx].name) {
		WRITE_CONSTRAINT(ADDRESS_ALIGNMENT, address_alignment, __u64);
		WRITE_CONSTRAINT(PITCH_ALIGNMENT, pitch_alignment, __u32);
		WRITE_CONSTRAINT(MAX_PITCH, max_pitch, __u32);
		default:
			DRM_DEBUG_KMS("unknown constraint %u\n",
				      set->constraints[idx].name);
			break;
		}
	}

#undef WRITE_CONSTRAINT

	return 0;
}
EXPORT_SYMBOL(drm_framebuffer_read_constraint);

static int
framebuffer_check_with_metadata(struct drm_device *dev,
				struct drm_mode_fb_cmd_with_metadata *r,
				capability_set_t *metadata[4])
{
	const struct drm_format_info *info;
	int ret = 0;
	int i;

	if (!dev->mode_config.funcs->fb_create_with_metadata)
		return -ENOSYS;

	if ((ret = framebuffer_check_common(dev, r->width, r->height,
					    r->pixel_format, 0)))
		return ret;

	/* TODO: Let the driver pick its own format info */
	info = __drm_format_info(r->pixel_format & ~DRM_FORMAT_BIG_ENDIAN);

	/* Check planes */
	for (i = 0; i < info->num_planes; i++) {
		__u64 width = fb_plane_width(r->width, info, i);
		__u64 cpp = info->cpp[i];
		__u64 address_alignment = 1;
		__u64 pitch_alignment = 1;
		__u64 max_pitch = UINT_MAX;
		__u64 pitch;

		if (!metadata[i]) {
			DRM_DEBUG_KMS("no buffer object metadata for plane %d\n", i);
			return -EINVAL;
		}

		if (drm_framebuffer_read_constraint(metadata[i],
						    CONSTRAINT_ADDRESS_ALIGNMENT,
						    (void *)&address_alignment) ||
		    drm_framebuffer_read_constraint(metadata[i],
						    CONSTRAINT_PITCH_ALIGNMENT,
						    (void *)&pitch_alignment) ||
		    drm_framebuffer_read_constraint(metadata[i],
						    CONSTRAINT_MAX_PITCH,
						    (void *)&max_pitch)) {
			DRM_DEBUG_KMS("bad metadata for plane %d\n", i);
			return -EINVAL;
		}

		/* Compute pitch, aligned to the pitch alignment constraint */
		pitch = width * cpp;
		pitch += (pitch_alignment - 1);
		pitch &= ~(pitch_alignment - 1);

		if ((ret = framebuffer_check_plane(i, r->width, r->height, info,
						   r->handles[i], pitch,
						   pitch_alignment, max_pitch,
						   address_alignment, r->offsets[i], 0, 0)))
			return ret;
	}

	for (i = info->num_planes; i < 4; i++) {
		if (r->handles[i]) {
			DRM_DEBUG_KMS("buffer object handle for unused plane %d\n", i);
			return -EINVAL;
		}

		if (r->offsets[i]) {
			DRM_DEBUG_KMS("non-zero offset for unused plane %d\n", i);
			return -EINVAL;
		}

		if (metadata[i]) {
			DRM_DEBUG_KMS("metadata for unused plane %d\n", i);
			return -EINVAL;
		}
	}

	return 0;
}

static void * deserialize_calloc(size_t n, size_t size)
{
	return kcalloc(n, size, GFP_KERNEL);
}

static int deserialize_capability_set(size_t data_size,
				      const void __user *data_ptr,
				      capability_set_t **capability_set)
{
	void *kdata_ptr;
	int ret;

	kdata_ptr = kcalloc(1, data_size, GFP_KERNEL);
	if (!kdata_ptr)
		return -1;

	ret = copy_from_user(kdata_ptr, data_ptr, data_size);
	if (ret != 0)
		goto done;

	ret = __deserialize_capability_set(data_size,
					   kdata_ptr,
					   capability_set,
					   deserialize_calloc);

	if (ret != 0)
		__free_capability_set(1, *capability_set, kfree);

done:
	kfree(kdata_ptr);

	return ret;
}

/**
 * drm_mode_addfb_with_metadata - add an FB to the graphics configuration
 * @dev: drm device for the ioctl
 * @data: data pointer for the ioctl
 * @file_priv: drm file for the ioctl call
 *
 * Add a new FB to the specified CRTC, given a user request with format. This is
 * the metadata version of the addfb ioctl, which supports multi-planar
 * framebuffers and uses fourcc codes as pixel format specifiers. It takes
 * generic allocator metadata pointers to describe the layout and other
 * properties of each plane (e.g. pitch alignment, page alignment, etc.).
 *
 * Called by the user via ioctl.
 *
 * Returns:
 * Zero on success, negative errno on failure.
 */
int drm_mode_addfb_with_metadata(struct drm_device *dev,
				 void *data, struct drm_file *file_priv)
{
	struct drm_mode_fb_cmd_with_metadata *r = data;
	capability_set_t *metadata[4] = { 0 };
	struct drm_framebuffer *fb;
	int ret = 0;
	int i;

	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		return -EINVAL;

	/* Deserialize metadata from user space */
	for (i = 0; i < 4; i++) {
		if (r->metadata[i].ptr && r->metadata[i].size > 0) {
			ret = deserialize_capability_set(r->metadata[i].size,
							 (const void *)r->metadata[i].ptr,
							 &metadata[i]);
			if (ret) {
				DRM_DEBUG_KMS("unable to deserialize metadata "
					      "for plane %d\n", i);
				ret = -EFAULT;
				goto free_metadata;
			}
		}
	}

	ret = framebuffer_check_with_metadata(dev, r, metadata);
	if (ret)
		goto free_metadata;

	fb = dev->mode_config.funcs->fb_create_with_metadata(dev, file_priv,
			r->width, r->height, r->pixel_format, r->handles, r->offsets,
			(const capability_set_t **)metadata);
	if (IS_ERR(fb)) {
		DRM_DEBUG_KMS("could not create framebuffer\n");
		ret = PTR_ERR(fb);
		goto free_metadata;
	}

	DRM_DEBUG_KMS("[FB:%d]\n", fb->base.id);
	r->fb_id = fb->base.id;

	/* Transfer ownership to the filp for reaping on close */
	mutex_lock(&file_priv->fbs_lock);
	list_add(&fb->filp_head, &file_priv->fbs);
	mutex_unlock(&file_priv->fbs_lock);

free_metadata:
	for (i = 0; i < 4; i++) {
		__free_capability_set(1, metadata[i], kfree);
	}

	return ret;
}

#endif

struct drm_mode_rmfb_work {
	struct work_struct work;
	struct list_head fbs;
};

static void drm_mode_rmfb_work_fn(struct work_struct *w)
{
	struct drm_mode_rmfb_work *arg = container_of(w, typeof(*arg), work);

	while (!list_empty(&arg->fbs)) {
		struct drm_framebuffer *fb =
			list_first_entry(&arg->fbs, typeof(*fb), filp_head);

		list_del_init(&fb->filp_head);
		drm_framebuffer_remove(fb);
	}
}

/**
 * drm_mode_rmfb - remove an FB from the configuration
 * @dev: drm device for the ioctl
 * @data: data pointer for the ioctl
 * @file_priv: drm file for the ioctl call
 *
 * Remove the FB specified by the user.
 *
 * Called by the user via ioctl.
 *
 * Returns:
 * Zero on success, negative errno on failure.
 */
int drm_mode_rmfb(struct drm_device *dev,
		   void *data, struct drm_file *file_priv)
{
	struct drm_framebuffer *fb = NULL;
	struct drm_framebuffer *fbl = NULL;
	uint32_t *id = data;
	int found = 0;

	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		return -EINVAL;

	fb = drm_framebuffer_lookup(dev, *id);
	if (!fb)
		return -ENOENT;

	mutex_lock(&file_priv->fbs_lock);
	list_for_each_entry(fbl, &file_priv->fbs, filp_head)
		if (fb == fbl)
			found = 1;
	if (!found) {
		mutex_unlock(&file_priv->fbs_lock);
		goto fail_unref;
	}

	list_del_init(&fb->filp_head);
	mutex_unlock(&file_priv->fbs_lock);

	/* drop the reference we picked up in framebuffer lookup */
	drm_framebuffer_put(fb);

	/*
	 * we now own the reference that was stored in the fbs list
	 *
	 * drm_framebuffer_remove may fail with -EINTR on pending signals,
	 * so run this in a separate stack as there's no way to correctly
	 * handle this after the fb is already removed from the lookup table.
	 */
	if (drm_framebuffer_read_refcount(fb) > 1) {
		struct drm_mode_rmfb_work arg;

		INIT_WORK_ONSTACK(&arg.work, drm_mode_rmfb_work_fn);
		INIT_LIST_HEAD(&arg.fbs);
		list_add_tail(&fb->filp_head, &arg.fbs);

		schedule_work(&arg.work);
		flush_work(&arg.work);
		destroy_work_on_stack(&arg.work);
	} else
		drm_framebuffer_put(fb);

	return 0;

fail_unref:
	drm_framebuffer_put(fb);
	return -ENOENT;
}

/**
 * drm_mode_getfb - get FB info
 * @dev: drm device for the ioctl
 * @data: data pointer for the ioctl
 * @file_priv: drm file for the ioctl call
 *
 * Lookup the FB given its ID and return info about it.
 *
 * Called by the user via ioctl.
 *
 * Returns:
 * Zero on success, negative errno on failure.
 */
int drm_mode_getfb(struct drm_device *dev,
		   void *data, struct drm_file *file_priv)
{
	struct drm_mode_fb_cmd *r = data;
	struct drm_framebuffer *fb;
	int ret;

	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		return -EINVAL;

	fb = drm_framebuffer_lookup(dev, r->fb_id);
	if (!fb)
		return -ENOENT;

	r->height = fb->height;
	r->width = fb->width;
	r->depth = fb->format->depth;
	r->bpp = fb->format->cpp[0] * 8;
	r->pitch = fb->pitches[0];
	if (fb->funcs->create_handle) {
		if (drm_is_current_master(file_priv) || capable(CAP_SYS_ADMIN) ||
		    drm_is_control_client(file_priv)) {
			ret = fb->funcs->create_handle(fb, file_priv,
						       &r->handle);
		} else {
			/* GET_FB() is an unprivileged ioctl so we must not
			 * return a buffer-handle to non-master processes! For
			 * backwards-compatibility reasons, we cannot make
			 * GET_FB() privileged, so just return an invalid handle
			 * for non-masters. */
			r->handle = 0;
			ret = 0;
		}
	} else {
		ret = -ENODEV;
	}

	drm_framebuffer_put(fb);

	return ret;
}

/**
 * drm_mode_dirtyfb_ioctl - flush frontbuffer rendering on an FB
 * @dev: drm device for the ioctl
 * @data: data pointer for the ioctl
 * @file_priv: drm file for the ioctl call
 *
 * Lookup the FB and flush out the damaged area supplied by userspace as a clip
 * rectangle list. Generic userspace which does frontbuffer rendering must call
 * this ioctl to flush out the changes on manual-update display outputs, e.g.
 * usb display-link, mipi manual update panels or edp panel self refresh modes.
 *
 * Modesetting drivers which always update the frontbuffer do not need to
 * implement the corresponding &drm_framebuffer_funcs.dirty callback.
 *
 * Called by the user via ioctl.
 *
 * Returns:
 * Zero on success, negative errno on failure.
 */
int drm_mode_dirtyfb_ioctl(struct drm_device *dev,
			   void *data, struct drm_file *file_priv)
{
	struct drm_clip_rect __user *clips_ptr;
	struct drm_clip_rect *clips = NULL;
	struct drm_mode_fb_dirty_cmd *r = data;
	struct drm_framebuffer *fb;
	unsigned flags;
	int num_clips;
	int ret;

	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		return -EINVAL;

	fb = drm_framebuffer_lookup(dev, r->fb_id);
	if (!fb)
		return -ENOENT;

	num_clips = r->num_clips;
	clips_ptr = (struct drm_clip_rect __user *)(unsigned long)r->clips_ptr;

	if (!num_clips != !clips_ptr) {
		ret = -EINVAL;
		goto out_err1;
	}

	flags = DRM_MODE_FB_DIRTY_FLAGS & r->flags;

	/* If userspace annotates copy, clips must come in pairs */
	if (flags & DRM_MODE_FB_DIRTY_ANNOTATE_COPY && (num_clips % 2)) {
		ret = -EINVAL;
		goto out_err1;
	}

	if (num_clips && clips_ptr) {
		if (num_clips < 0 || num_clips > DRM_MODE_FB_DIRTY_MAX_CLIPS) {
			ret = -EINVAL;
			goto out_err1;
		}
		clips = kcalloc(num_clips, sizeof(*clips), GFP_KERNEL);
		if (!clips) {
			ret = -ENOMEM;
			goto out_err1;
		}

		ret = copy_from_user(clips, clips_ptr,
				     num_clips * sizeof(*clips));
		if (ret) {
			ret = -EFAULT;
			goto out_err2;
		}
	}

	if (fb->funcs->dirty) {
		ret = fb->funcs->dirty(fb, file_priv, flags, r->color,
				       clips, num_clips);
	} else {
		ret = -ENOSYS;
	}

out_err2:
	kfree(clips);
out_err1:
	drm_framebuffer_put(fb);

	return ret;
}

/**
 * drm_fb_release - remove and free the FBs on this file
 * @priv: drm file for the ioctl
 *
 * Destroy all the FBs associated with @filp.
 *
 * Called by the user via ioctl.
 *
 * Returns:
 * Zero on success, negative errno on failure.
 */
void drm_fb_release(struct drm_file *priv)
{
	struct drm_framebuffer *fb, *tfb;
	struct drm_mode_rmfb_work arg;

	INIT_LIST_HEAD(&arg.fbs);

	/*
	 * When the file gets released that means no one else can access the fb
	 * list any more, so no need to grab fpriv->fbs_lock. And we need to
	 * avoid upsetting lockdep since the universal cursor code adds a
	 * framebuffer while holding mutex locks.
	 *
	 * Note that a real deadlock between fpriv->fbs_lock and the modeset
	 * locks is impossible here since no one else but this function can get
	 * at it any more.
	 */
	list_for_each_entry_safe(fb, tfb, &priv->fbs, filp_head) {
		if (drm_framebuffer_read_refcount(fb) > 1) {
			list_move_tail(&fb->filp_head, &arg.fbs);
		} else {
			list_del_init(&fb->filp_head);

			/* This drops the fpriv->fbs reference. */
			drm_framebuffer_put(fb);
		}
	}

	if (!list_empty(&arg.fbs)) {
		INIT_WORK_ONSTACK(&arg.work, drm_mode_rmfb_work_fn);

		schedule_work(&arg.work);
		flush_work(&arg.work);
		destroy_work_on_stack(&arg.work);
	}
}

void drm_framebuffer_free(struct kref *kref)
{
	struct drm_framebuffer *fb =
			container_of(kref, struct drm_framebuffer, base.refcount);
	struct drm_device *dev = fb->dev;

	/*
	 * The lookup idr holds a weak reference, which has not necessarily been
	 * removed at this point. Check for that.
	 */
	drm_mode_object_unregister(dev, &fb->base);

	fb->funcs->destroy(fb);
}

/**
 * drm_framebuffer_init - initialize a framebuffer
 * @dev: DRM device
 * @fb: framebuffer to be initialized
 * @funcs: ... with these functions
 *
 * Allocates an ID for the framebuffer's parent mode object, sets its mode
 * functions & device file and adds it to the master fd list.
 *
 * IMPORTANT:
 * This functions publishes the fb and makes it available for concurrent access
 * by other users. Which means by this point the fb _must_ be fully set up -
 * since all the fb attributes are invariant over its lifetime, no further
 * locking but only correct reference counting is required.
 *
 * Returns:
 * Zero on success, error code on failure.
 */
int drm_framebuffer_init(struct drm_device *dev, struct drm_framebuffer *fb,
			 const struct drm_framebuffer_funcs *funcs)
{
	int ret;

	if (WARN_ON_ONCE(fb->dev != dev || !fb->format))
		return -EINVAL;

	INIT_LIST_HEAD(&fb->filp_head);

	fb->funcs = funcs;

	ret = __drm_mode_object_add(dev, &fb->base, DRM_MODE_OBJECT_FB,
				    false, drm_framebuffer_free);
	if (ret)
		goto out;

	mutex_lock(&dev->mode_config.fb_lock);
	dev->mode_config.num_fb++;
	list_add(&fb->head, &dev->mode_config.fb_list);
	mutex_unlock(&dev->mode_config.fb_lock);

	drm_mode_object_register(dev, &fb->base);
out:
	return ret;
}
EXPORT_SYMBOL(drm_framebuffer_init);

/**
 * drm_framebuffer_lookup - look up a drm framebuffer and grab a reference
 * @dev: drm device
 * @id: id of the fb object
 *
 * If successful, this grabs an additional reference to the framebuffer -
 * callers need to make sure to eventually unreference the returned framebuffer
 * again, using drm_framebuffer_put().
 */
struct drm_framebuffer *drm_framebuffer_lookup(struct drm_device *dev,
					       uint32_t id)
{
	struct drm_mode_object *obj;
	struct drm_framebuffer *fb = NULL;

	obj = __drm_mode_object_find(dev, id, DRM_MODE_OBJECT_FB);
	if (obj)
		fb = obj_to_fb(obj);
	return fb;
}
EXPORT_SYMBOL(drm_framebuffer_lookup);

/**
 * drm_framebuffer_unregister_private - unregister a private fb from the lookup idr
 * @fb: fb to unregister
 *
 * Drivers need to call this when cleaning up driver-private framebuffers, e.g.
 * those used for fbdev. Note that the caller must hold a reference of it's own,
 * i.e. the object may not be destroyed through this call (since it'll lead to a
 * locking inversion).
 *
 * NOTE: This function is deprecated. For driver-private framebuffers it is not
 * recommended to embed a framebuffer struct info fbdev struct, instead, a
 * framebuffer pointer is preferred and drm_framebuffer_put() should be called
 * when the framebuffer is to be cleaned up.
 */
void drm_framebuffer_unregister_private(struct drm_framebuffer *fb)
{
	struct drm_device *dev;

	if (!fb)
		return;

	dev = fb->dev;

	/* Mark fb as reaped and drop idr ref. */
	drm_mode_object_unregister(dev, &fb->base);
}
EXPORT_SYMBOL(drm_framebuffer_unregister_private);

/**
 * drm_framebuffer_cleanup - remove a framebuffer object
 * @fb: framebuffer to remove
 *
 * Cleanup framebuffer. This function is intended to be used from the drivers
 * &drm_framebuffer_funcs.destroy callback. It can also be used to clean up
 * driver private framebuffers embedded into a larger structure.
 *
 * Note that this function does not remove the fb from active usage - if it is
 * still used anywhere, hilarity can ensue since userspace could call getfb on
 * the id and get back -EINVAL. Obviously no concern at driver unload time.
 *
 * Also, the framebuffer will not be removed from the lookup idr - for
 * user-created framebuffers this will happen in in the rmfb ioctl. For
 * driver-private objects (e.g. for fbdev) drivers need to explicitly call
 * drm_framebuffer_unregister_private.
 */
void drm_framebuffer_cleanup(struct drm_framebuffer *fb)
{
	struct drm_device *dev = fb->dev;

	mutex_lock(&dev->mode_config.fb_lock);
	list_del(&fb->head);
	dev->mode_config.num_fb--;
	mutex_unlock(&dev->mode_config.fb_lock);
}
EXPORT_SYMBOL(drm_framebuffer_cleanup);

static int atomic_remove_fb(struct drm_framebuffer *fb)
{
	struct drm_modeset_acquire_ctx ctx;
	struct drm_device *dev = fb->dev;
	struct drm_atomic_state *state;
	struct drm_plane *plane;
	struct drm_connector *conn;
	struct drm_connector_state *conn_state;
	int i, ret = 0;
	unsigned plane_mask;

	state = drm_atomic_state_alloc(dev);
	if (!state)
		return -ENOMEM;

	drm_modeset_acquire_init(&ctx, 0);
	state->acquire_ctx = &ctx;

retry:
	plane_mask = 0;
	ret = drm_modeset_lock_all_ctx(dev, &ctx);
	if (ret)
		goto unlock;

	drm_for_each_plane(plane, dev) {
		struct drm_plane_state *plane_state;

		if (plane->state->fb != fb)
			continue;

		plane_state = drm_atomic_get_plane_state(state, plane);
		if (IS_ERR(plane_state)) {
			ret = PTR_ERR(plane_state);
			goto unlock;
		}

		if (plane_state->crtc->primary == plane) {
			struct drm_crtc_state *crtc_state;

			crtc_state = drm_atomic_get_existing_crtc_state(state, plane_state->crtc);

			ret = drm_atomic_add_affected_connectors(state, plane_state->crtc);
			if (ret)
				goto unlock;

			crtc_state->active = false;
			ret = drm_atomic_set_mode_for_crtc(crtc_state, NULL);
			if (ret)
				goto unlock;
		}

		drm_atomic_set_fb_for_plane(plane_state, NULL);
		ret = drm_atomic_set_crtc_for_plane(plane_state, NULL);
		if (ret)
			goto unlock;

		plane_mask |= BIT(drm_plane_index(plane));

		plane->old_fb = plane->fb;
	}

	for_each_new_connector_in_state(state, conn, conn_state, i) {
		ret = drm_atomic_set_crtc_for_connector(conn_state, NULL);

		if (ret)
			goto unlock;
	}

	if (plane_mask)
		ret = drm_atomic_commit(state);

unlock:
	if (plane_mask)
		drm_atomic_clean_old_fb(dev, plane_mask, ret);

	if (ret == -EDEADLK) {
		drm_atomic_state_clear(state);
		drm_modeset_backoff(&ctx);
		goto retry;
	}

	drm_atomic_state_put(state);

	drm_modeset_drop_locks(&ctx);
	drm_modeset_acquire_fini(&ctx);

	return ret;
}

static void legacy_remove_fb(struct drm_framebuffer *fb)
{
	struct drm_device *dev = fb->dev;
	struct drm_crtc *crtc;
	struct drm_plane *plane;

	drm_modeset_lock_all(dev);
	/* remove from any CRTC */
	drm_for_each_crtc(crtc, dev) {
		if (crtc->primary->fb == fb) {
			/* should turn off the crtc */
			if (drm_crtc_force_disable(crtc))
				DRM_ERROR("failed to reset crtc %p when fb was deleted\n", crtc);
		}
	}

	drm_for_each_plane(plane, dev) {
		if (plane->fb == fb)
			drm_plane_force_disable(plane);
	}
	drm_modeset_unlock_all(dev);
}

/**
 * drm_framebuffer_remove - remove and unreference a framebuffer object
 * @fb: framebuffer to remove
 *
 * Scans all the CRTCs and planes in @dev's mode_config.  If they're
 * using @fb, removes it, setting it to NULL. Then drops the reference to the
 * passed-in framebuffer. Might take the modeset locks.
 *
 * Note that this function optimizes the cleanup away if the caller holds the
 * last reference to the framebuffer. It is also guaranteed to not take the
 * modeset locks in this case.
 */
void drm_framebuffer_remove(struct drm_framebuffer *fb)
{
	struct drm_device *dev;

	if (!fb)
		return;

	dev = fb->dev;

	WARN_ON(!list_empty(&fb->filp_head));

	/*
	 * drm ABI mandates that we remove any deleted framebuffers from active
	 * useage. But since most sane clients only remove framebuffers they no
	 * longer need, try to optimize this away.
	 *
	 * Since we're holding a reference ourselves, observing a refcount of 1
	 * means that we're the last holder and can skip it. Also, the refcount
	 * can never increase from 1 again, so we don't need any barriers or
	 * locks.
	 *
	 * Note that userspace could try to race with use and instate a new
	 * usage _after_ we've cleared all current ones. End result will be an
	 * in-use fb with fb-id == 0. Userspace is allowed to shoot its own foot
	 * in this manner.
	 */
	if (drm_framebuffer_read_refcount(fb) > 1) {
		if (drm_drv_uses_atomic_modeset(dev)) {
			int ret = atomic_remove_fb(fb);
			WARN(ret, "atomic remove_fb failed with %i\n", ret);
		} else
			legacy_remove_fb(fb);
	}

	drm_framebuffer_put(fb);
}
EXPORT_SYMBOL(drm_framebuffer_remove);

/**
 * drm_framebuffer_plane_width - width of the plane given the first plane
 * @width: width of the first plane
 * @fb: the framebuffer
 * @plane: plane index
 *
 * Returns:
 * The width of @plane, given that the width of the first plane is @width.
 */
int drm_framebuffer_plane_width(int width,
				const struct drm_framebuffer *fb, int plane)
{
	if (plane >= fb->format->num_planes)
		return 0;

	return fb_plane_width(width, fb->format, plane);
}
EXPORT_SYMBOL(drm_framebuffer_plane_width);

/**
 * drm_framebuffer_plane_height - height of the plane given the first plane
 * @height: height of the first plane
 * @fb: the framebuffer
 * @plane: plane index
 *
 * Returns:
 * The height of @plane, given that the height of the first plane is @height.
 */
int drm_framebuffer_plane_height(int height,
				 const struct drm_framebuffer *fb, int plane)
{
	if (plane >= fb->format->num_planes)
		return 0;

	return fb_plane_height(height, fb->format, plane);
}
EXPORT_SYMBOL(drm_framebuffer_plane_height);
