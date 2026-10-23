# Dishonored 2 FPS Fix v1.5.0

## What changed

- Mouse turning is now even at frame rates that are not a multiple of 120,
  such as 90 or 144 FPS. Since v1.4.0 the game turns the view once per game
  frame by the mouse input gathered since the previous one, but camera
  prediction still extrapolated that turn by simulation time. Below 120 FPS
  this made turning stutter while walking stayed smooth (at 90 FPS a 30 Hz
  judder). Added `Fix/RealTimeTurnPrediction`, default `1`: camera rotation
  follows the real time between game frames, while position keeps the
  simulation-time prediction. Cutscenes and menus keep the previous rotation
  rule, which suits scripted cameras. **Ctrl+F10** switches between the two
  rules in game for an A/B comparison; F10 is unchanged.
- Slow motion is smooth. Kill cams, executions, takedowns, the power wheel,
  and slowed-time powers make the game run fewer, longer simulation ticks (the
  engine slows two of its timers, down to 5% of normal speed for the power
  wheel). New states then arrive less often than frames at any frame rate,
  which is the "low frame rate" feel of slow motion in the unmodified game.
  Added `Interpolation/FullInterpolationInSlowMotion`, default `1`. While the
  game slows time, every enabled interpolation layer stays on even if the
  adaptive gate would shed it; below about 130 FPS the gate sheds all of them.
  Those frames are also excluded from the gate's measurements.
- During slow motion every layer, the camera included, accepts the longer gap
  between simulation samples instead of treating it as a stall. Ownerless
  character models, such as some used in takedowns, are interpolated as well.
  Outside slow motion the cinematic layers still admit only small ownerless
  controls.
- Added `Diagnostics/TimeScaleLog`, default `1`. It logs the engine clock's time
  scales when they change and summarizes each slow-motion period.
- Added an offline camera-prediction and slow-motion test for development.

If you keep the d2-high-fps-fix.ini from an earlier version, the new settings
take their defaults (all enabled); the new INI documents them.

## Release archives

- `Dishonored2-FPSFix-v1.5.0-plugin-only.zip` contains the ASI, configuration,
  project license, documentation, and payload hashes for installations that
  already have a compatible x64 ASI loader.
  SHA-256:
  `C4C56823D71A0D2A294107F49F8F62F4C9CA0CAFA4D7EC25E7B135F36E5D067B`
- `Dishonored2-FPSFix-v1.5.0-with-Ultimate-ASI-Loader-v9.7.4.zip` additionally
  contains the pinned x64 loader and its required MIT notice.
  SHA-256:
  `C8E1355A552138C687204E7D23D574CFEC2BAB7D8B5AAD6946E93DF66E9A7656`

## Validation

- Reference executable SHA-256 values:
  - GOG: `C3150F9F2D9BF967D23CA6A79BB32703B90116854AAD9892C7FC1F46A1060293`
  - Steam: `B671F8249422862BF557D00AAB2F4BB671ED4515CC10AD8A8A9DECAD84516180`
- ASI SHA-256:
  `5544AC6D315CBE950FFA9084F1F815E12C4BC704B773B7F74FBB879852EDA634`
- Ultimate ASI Loader v9.7.4 x64 SHA-256:
  `FA266E3513D02C08A1B808F28C10538A489EAFFAA4B0707F7CC1066E71B5AFD7`
- Compilation with warnings enabled, joint-pose tests, direct ASI loading, and
  both fail-closed host tests passed.
- The new camera-prediction and slow-motion test passed. It drives the
  plugin's own predictor with the engine's clock rules at 60-360 FPS, with and
  without frame-time jitter. Mouse turning stays within 0.02 frames RMS of the
  ideal path; the previous rotation rule, still used for cutscenes and menus,
  is bit-identical to v1.4.0; walking is unchanged. Slow-motion cadences down
  to 5% of normal speed stay smooth with the scaled sample-interval limit.
- The offline layout-profile test passed against both real executables.
- The release ASI was played on the GOG build through Ultimate ASI Loader
  v9.7.4 at 90, 144, and 350 FPS. The session covered gameplay, 57 slow-motion
  periods (kill cams, takedowns, and the power wheel), 24 cutscenes, deaths,
  and level transitions. Turning was even, slow motion was smooth, and no
  crash, capacity miss, upload failure, interpolation rejection, or visible
  regression was observed.
- A shorter Steam session with the same ASI covered gameplay, five slow-motion
  periods (kill cams and a nine-second slow-down with the world at 37% and the
  player at 75%), and a death. Slow motion was detected and ended as on GOG, and
  no crash, capacity miss, upload failure, interpolation rejection, or visible
  issue was observed.
- Both extracted archives passed their payload-manifest checks, direct-load
  and fail-closed tests, and, for the loader bundle, external-loader discovery,
  DirectInput forwarding, and plugin loading.

`ShadowTransforms` remains unsupported and disabled. Simulated cloth remains
outside the release scope.
