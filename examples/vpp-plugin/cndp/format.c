/*
 * format.c - CNDP formats
 *
 * Copyright (c) 2021-2022 Intel Corporation
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdarg.h>
#include <vppinfra/format.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>

#include <cndp/cndp.h>

u8 *format_cndp_device_name (u8 *s, va_list *args)
{
  u32 i = va_arg (*args, u32);
  cndp_main_t *cmp = &cndp_main;
  cndp_device_t *device = cmp->devices[i];

  s = format (s, "%s", device->ifname);
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
