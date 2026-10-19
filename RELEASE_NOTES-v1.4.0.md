# Dishonored 2 FPS Fix v1.4.0

## What changed

- Added support for the Steam release. Its `Dishonored2.exe` reports the same
  version 1.77.9.0 but is a separate February 2025 rebuild, so every code and
  data address differs while the engine data structures are unchanged. v1.3.0
  refused it safely; v1.4.0 carries a layout profile for each build, selects
  the one whose renderer-view call site matches, and then runs the unchanged
  strict validation on it. The GOG profile is identical to v1.3.0.
  `ShadowTransforms` is not mapped for Steam and is disabled there.
- Cutscenes keep full interpolation. Added
  `Interpolation/FullInterpolationInCutscenes`, default `1`. While the game's
  cinematic state is active, such as during vehicle rides, every enabled
  interpolation layer stays on even if the adaptive gate would shed it, and
  those frames are excluded from the gate's measurements. Afterwards the gate
  resumes the mode it had chosen for gameplay. This fixes heavily stepped
  vehicles in demanding cutscenes such as the mission 2 boat ride.
- Mouse sensitivity is now independent of the frame rate below 120 FPS too.
  `StabilizeMouseSensitivity=1` keeps the game's own look scaling but makes it
  divide by the simulation time step instead of the real frame time, so the
  turn per mouse count is the same at every frame rate. Previously, look speed
  rose when the frame rate dropped below 120 FPS.
- **Sensitivity changes:** it now matches the unmodified game at its normal
  120 FPS cap, about twice the high-FPS sensitivity of v1.3.0. If you raised
  the in-game sensitivity for an earlier version, lower it to about half.
- The log now records the selected layout profile, game-logic state changes,
  and the start and end of each cutscene.
- Added an offline layout-profile test for development. It maps a real
  `Dishonored2.exe` without running it and verifies every hook and patch the
  plugin would install.

## Release archives

- `Dishonored2-FPSFix-v1.4.0-plugin-only.zip` contains the ASI, configuration,
  project license, documentation, and payload hashes for installations that
  already have a compatible x64 ASI loader.
  SHA-256:
  `5A90754848F836AA5F4EAFCDFC2085BF328117032A011411C0CC9B9B56C0EC69`
- `Dishonored2-FPSFix-v1.4.0-with-Ultimate-ASI-Loader-v9.7.4.zip` additionally
  contains the pinned x64 loader and its required MIT notice.
  SHA-256:
  `7517421DDFF78A9B8E531C96048ECB95E123738B9681A6253ED960C298C7AFC6`

## Validation

- Reference executable SHA-256 values:
  - GOG: `C3150F9F2D9BF967D23CA6A79BB32703B90116854AAD9892C7FC1F46A1060293`
  - Steam: `B671F8249422862BF557D00AAB2F4BB671ED4515CC10AD8A8A9DECAD84516180`
- ASI SHA-256:
  `809E24EDB83909DE62EE1AD795A1848908F9A6DDC4C6E1E3898D33D42FB49A92`
- Ultimate ASI Loader v9.7.4 x64 SHA-256:
  `FA266E3513D02C08A1B808F28C10538A489EAFFAA4B0707F7CC1066E71B5AFD7`
- Compilation with warnings enabled, joint-pose tests, direct ASI loading, and
  both fail-closed host tests passed.
- The offline layout-profile test passed against both real executables: each
  selected its own profile, passed strict validation, and had every hook,
  trampoline, and the mouse-look patch installed and byte-checked.
- The release ASI was played on both builds through Ultimate ASI Loader
  v9.7.4. Steam sessions covered several levels, the mission 2 boat cutscene,
  and a mouse-sensitivity check; GOG sessions covered gameplay, cutscenes, and
  the mouse-sensitivity check. Cutscene detection engaged and released as
  expected, including across in-cutscene conversations. Sensitivity no longer
  rose in low-FPS scenes. No crash, capacity miss, upload failure, or visible
  regression was observed.
- Both extracted archives passed their payload-manifest checks, direct-load
  and fail-closed tests, and, for the loader bundle, external-loader discovery,
  DirectInput forwarding, and plugin loading.

`ShadowTransforms` remains unsupported and disabled. Simulated cloth remains
outside the release scope.
