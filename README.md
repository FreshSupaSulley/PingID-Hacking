# PingID Hacking

Reverse engineering the PingID Android app.

## What is this?

I've been reverse-engineering the first release of the PingID app on the Google Play store by decompiling the APK, injecting smali log statements and running [APKLab](https://github.com/APKLab/APKLab) SSL unpinning functions and studying the result all in an Android Simulator.
This repo completely exposes the *onboarding* flow, which is what PingID internally calls the entire process of activating a new device.

### Quick start

This gradle project can register new devices and store their data in the running directory, or load a previously created device by reading a device data file. Either way, you'll have a `PingID` instance to start getting TOTPs to login with. See `Main.java` to get started.

## Onboarding flow

Here's the 4 endpoints mobile devices hit to register themselves to PingID:

1. `verify_activation_code`. This sends your 12-digit activation code to the Ping API.
2. `provision`. Your device generates an RSA key to store locally, then tells PingID where the HOTP counter starts, along with basic device information and capabilities.
3. `test_otp`. Generates and sends an HOTP (or apparently a TOTP, see `PingID.java`) to verify everything is working.
4. `finalize_onboarding`. The response to `verify_activation_code` will tell the device which params to fill out (I've only seen `nickname` so far). This answers those questions.

## Next steps

It would be great to reverse-engineer more endpoints, namely figuring out how to approve logins with `mobile_ack` (which I believe is the right `request_type`, but could be wrong). There seems to be a lot more functionality to reverse-engineer.
