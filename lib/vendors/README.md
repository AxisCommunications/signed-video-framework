*Copyright (C) 2022, Axis Communications AB, Lund, Sweden. All Rights Reserved.*

# Using vendor specific operations
It is necessary for the Signed Video Framework to handle vendor specific metadata. For example,
when adding the public key to the stream, validating the public key, in addition to validating the
video, is necessary. Such process will vary from vendor to vendor.

Each vendor has a subfolder. API and file naming should follow the style `sv_vendor_<vendor name>`.

Public API declarations necessary on the signing and/or the validation side are located in
[lib/src/includes/](../src/includes/).

For an example, see code in [axis-communications/](./axis-communications/).
