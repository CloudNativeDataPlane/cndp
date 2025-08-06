..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2010-2025 Intel Corporation.

Known Issues and Limitations in Legacy Releases
===============================================

This section describes known issues with the CNDP software that aren't covered in the version specific release notes sections.

* `uds_path`` not supported through lport-group configuration. Support needs to be added for `uds_base_dir` and `uds_name`
  so that the `uds_path` can be generated on a per port basis.
* `xsk_pin_path` not supported through lport-group configuration. Support needs to be added for `pin_path_base_dir` and `map_name`
  so that the `xsk_pin_path` can be generated on a per port basis.
