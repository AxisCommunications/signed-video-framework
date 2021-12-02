# Using the Signed Video Framework library
The Signed Video Framework handles both the signing part as well as the validation part. All public APIs needed are located in [includes/](./includes/).

## Making your own validation application
The APIs needed are [signed_video_common.h](./includes/signed_video_common.h) and [signed_video_auth.h](./includes/signed_video_auth.h).
To validate a H264 or H265 video you need to split the video into NAL Units. For a detailed description and example code see [signed_video_auth.h](./includes/signed_video_auth.h) or look at the validator in the [signed-video-framework-examples](https://github.com/AxisCommunications/signed-video-framework-examples) repository.

## Making your own signing application
The APIs needed are [signed_video_common.h](./includes/signed_video_common.h) and [signed_video_sign.h](./includes/signed_video_sign.h).
To sign a H264 or H265 video you need to split the video into NAL Units. Before signing can begin you need to configure the Signed Video session. Setting a private key is mandatory, but there are also possibilites to also add some product information and what level of authentication shall be used. The public key, needed for validation, is automatically added to the stream.

The Signed Video Framework generates SEI frames including signatures and other information. Getting them and instructions on how to add them to the current stream are handled through the API `signed_video_get_nalu_to_prepend()`. Note that the framework follows the Access Unit format of H264, hence SEI frames have to prepend the current picture frame.

For a detailed description and example code see [signed_video_sign.h](./includes/signed_video_sign.h) or look at the signer in the [signed-video-framework-examples](https://github.com/AxisCommunications/signed-video-framework-examples) repository.

## Making your own signing plugin
There is currently no signing plugin management in the Signed Video Framework. It currently builds with the [unthreaded-signing/plugin.c](../plugins/unthreaded-signing/plugin.c). The APIs [signed_video_interfaces.h](./includes/signed_video_interfaces.h) and [signed_video_openssl.h](./includes/signed_video_openssl.h) are for plugins. For more information see [lib/plugins/](../plugins/).
