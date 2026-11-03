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
| `Tasks/UITestSeam.swift` | The test seam of the UI tests, in Debug builds only. The sign-in goes to `tools/approver.py`, and the scan screen takes the QR payload as text. |
| `TasksUITests/AppFlowTests.swift` | The UI tests: S4, S5 and the recovery key replacement through the screens. |
| `tools/approver.py` | The passkey step of the sign-in for the tests, because the simulator cannot make a passkey. It also drives a Python demo device and the user page, so a test can share a space with the demo and block a device. |

## Build and test

| Command | What it does |
| --- | --- |
| `make test-app IOS_SIM=...` | Builds the app with no signing, and runs the unit tests and the UI tests on the simulator and on macOS against a relay process. Then it checks that a Release build has no UI test seam. |
| `make test-app-signed` | Runs the macOS tests with the team of `Config/Local.xcconfig`. The keychain tests then use the data protection keychain. |
| `make app-ios-device DEVICE=<UDID>` | Builds the app for an iPhone with `Config/Local.xcconfig`, and installs it. |

The macOS UI tests need Automation Mode. Enable it once on each Mac. The command asks for your password, so run it in a terminal outside the agent sandbox:

```bash
automationmodetool enable-automationmode-without-authentication
```

The UI tests control the mouse and the keyboard on macOS, so do not use the Mac while they run. On macOS, the UI test seam keeps the keys in files, because an unsigned build has no keychain. The iOS simulator uses the keychain.

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

## Smoke test on a real iPhone

The UI tests replace the passkey and the camera, and the simulator does not use Tailscale. This check covers those parts only. The iPhone must reach the relay at an HTTPS URL, for example a Tailscale `ts.net` name, because a passkey works only on its domain.

1. Start the relay with the public authority and origin of its HTTPS URL.
2. Run `snailfish-relay user add sam`, and open the invite link on the iPhone to register a passkey.
3. Install the app with `make app-ios-device DEVICE=<UDID>`.
4. On the iPhone, open Tasks, select the sync button, set the relay URL, and select "Turn on sync".
5. Sign in with the passkey, and allow the app. Write the recovery key on paper, and type it back.
6. On the Mac, open Tasks, set the relay URL, and select "Show a code for my other device".
7. On the iPhone, select "Scan the code of the new device", and scan the QR code with the camera.
8. If both devices show the same 6-digit code, select "Yes, they match" on each device.
9. Force quit the app on the iPhone, and open it again. The keys come from the iOS keychain.
10. Add a task on the iPhone, and check that it appears on the Mac.

If the passkey is lost, the relay operator runs `snailfish-relay user invite <user>` and sends the new invite link.

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
