# Tasks: the Swift sample app

Tasks is the SwiftUI version of the demo task app (DESIGN.md M6). It runs on iOS 26 and macOS 14. It uses the same app ID, change format and merge rules as the Python demo, so a demo device and an app device can share a space.

| File | Content |
| --- | --- |
| `project.yml` | The XcodeGen project. `make app-project` writes `Tasks.xcodeproj`. Git ignores the `.xcodeproj`. |
| `Tasks/SyncDevice.swift` | The delivery loop of DESIGN.md "App integration": edit, outbox, `enqueue_many`, sync and pull. |
| `Tasks/KeychainKeyStore.swift` | The `key_store` of the app: the data protection keychain, fail-closed (C62). |
| `Tasks/SignInFlow.swift` | The native sign-in with `ASWebAuthenticationSession` and the first-device setup (S1). |
| `Tasks/EnrollmentFlow.swift`, `Tasks/QRCode.swift` | QR enrollment in both directions (S2). |
| `Tasks/AppModel.swift`, `Tasks/ContentView.swift` | Removal of a lost device (S4), recovery key replacement (T9) and full recovery with the paper recovery key (S5), `PROTOCOL.md` section 13. |
| `Tasks/Measurements.swift` | The sync delay log and the durable commit benchmark. |
| `tools/approver.py` | The passkey step of the sign-in for the tests, because the simulator cannot make a passkey. It also drives a Python demo device, so a test can share a space with the demo. |

## Build and test

| Command | What it does |
| --- | --- |
| `make test-app IOS_SIM=...` | Builds the app with no signing, and runs the tests on the simulator and on macOS against a relay process. |
| `make test-app-signed` | Runs the macOS tests with the team of `Config/Local.xcconfig`. The keychain tests then use the data protection keychain. |
| `make app-ios-device DEVICE=<UDID>` | Builds the app for an iPhone with `Config/Local.xcconfig`, and installs it. |

A build with no `Config/Local.xcconfig` has no team and no entitlements. On macOS, the data protection keychain refuses it, and the app fails closed.

To sign a build, do these steps:

1. Copy `Config/Local.xcconfig.example` to `Config/Local.xcconfig`.
2. Set `DEVELOPMENT_TEAM` and a `BUNDLE_ID_PREFIX` that your team owns.
3. Sign in to your Apple account in Xcode.

If a signed build fails, find the error in this table:

| Error | Cause and fix |
| --- | --- |
| `No Accounts: Add a new account in Accounts settings.` | Xcode has no signed-in account, or the shell cannot read it. An agent sandbox cannot read the Xcode account. Run the command in a terminal outside the sandbox. If Xcode signed you out, sign in again in Xcode > Settings > Apple Accounts. |
| `Build input file cannot be found: '.../Provisioning Profiles/<UUID>.provisionprofile'` | The first run with `-allowProvisioningUpdates` creates the profiles, and one target can refer to a profile before it exists. Run the same command again. |

## Run the demo: an iPhone joins from a Mac

The iPhone must reach the relay. Use an HTTPS relay URL, for example a Tailscale `ts.net` name, because a passkey works only on its domain.

1. Start the relay with the public authority and origin of its HTTPS URL.
2. Run `snailfish-relay user add sam`, and open the invite link to register a passkey.
3. On the Mac, open Tasks, select the sync button, set the relay URL, and select "Turn on sync".
4. Sign in with the passkey, and allow the app.
5. Write the recovery key on paper, and type it back.
6. On the Mac, select "Show a code for the new device".
7. On the iPhone, select "Scan the code of my other device", and scan the QR code.
8. If both devices show the same 6-digit code, select "Yes, they match" on each device.
9. Add a task on each device, and check that it appears on the other device.

## Run the demo: a stolen phone (S4)

1. On the user page, create the machine group "Sam's phone" and add the iPhone device to it.
2. Select "Block" on the group. The iPhone shows `paused: blocked` at its next sync.
3. On the Mac, open the sync settings and select "Remove a device".
4. Select the iPhone. Check the list of the devices that stay, and select "Remove and make a new key".
5. On the user page, select "Unblock". The iPhone shows `stopped: removed`.

## Run the demo: all devices lost (S5)

1. Delete the app on every device, or use a new device with a new data directory.
2. Open Tasks, open the sync settings, and type the recovery key from your paper under "All my devices are lost".
3. Select "Recover with the recovery key", and sign in with the passkey.
4. The app shows the old devices. Select each one, and select "Remove and make a new key".
5. Check that the tasks are on the device.

If the passkey is lost too, the relay operator runs `snailfish-relay user invite <user>` and sends the new invite link.

## Measurements

The app writes `measure.jsonl`. On iOS it is in the Documents folder of the app, which Finder file sharing shows. Each line is one JSON object.

| `kind` | Fields |
| --- | --- |
| `arrival` | `delay_ms`: the arrival time minus the edit time from the change clock. `background` is true for a background refresh. |
| `refresh` | The start and end time of one `BGAppRefreshTask`, and the sync status. |
| `commit` | `median_ms` and `p95_ms` of 500 durable commits (WAL, `synchronous=FULL`, `fullfsync=ON`). |

The delay includes the clock difference of the two devices. Both clocks use NTP.

To measure the commit cost on an iPhone, do these steps:

1. Run `xcrun devicectl device process launch --device <UDID> <bundle ID> -- -bench-commit YES`.
2. Run `xcrun devicectl device copy from --device <UDID> --domain-type appDataContainer --domain-identifier <bundle ID> --source Documents/measure.jsonl --destination .`.
3. Read the `commit` line.

To measure the background sync delay, do these steps:

1. Set up the Mac and the iPhone in one space.
2. On the iPhone, open Tasks, then go to the home screen.
3. Leave the iPhone on charge, on Wi-Fi, for some hours.
4. On the Mac, add or edit a task about every 10 minutes.
5. Copy `measure.jsonl` off the iPhone, as for the commit cost.
6. Read the `arrival` lines with `"background": true`.
