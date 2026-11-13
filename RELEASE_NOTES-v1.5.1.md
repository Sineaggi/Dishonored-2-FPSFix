# Dishonored 2 FPS Fix v1.5.1

## What changed

- The held weapon is now smooth while it moves relative to the camera, for
  example while the blade unfolds or the weapon is holstered in the power
  wheel. First-person models were only moved with the smoothed camera, so
  their own motion relative to it, such as a weapon carried by the animated
  hand, still stepped at the simulation rate. This was barely visible at
  normal speed but obvious while time is slowed (the power wheel runs at 5%,
  one step every 167 ms), where the hand fingers also seemed to snap against
  the stepped grip. That motion is now interpolated at the same presentation
  time as the hand animation. Models fixed to the camera keep exactly the
  previous correction. This is part of `FirstPersonSkeletons` and runs
  whenever the first-person hand animation is interpolated.
- World objects no longer pause briefly within each step of deep slow motion.
  Their extrapolation limit was a fixed 8.3 ms instead of one step of the
  slowed clock. Normal speed is unchanged.
- The log adds a periodic "First-person transform" diagnostics line.

There are no new settings. An existing d2-high-fps-fix.ini from v1.5.0 can be
kept.

## Release archives

- `Dishonored2-FPSFix-v1.5.1-plugin-only.zip` contains the ASI, configuration,
  project license, documentation, and payload hashes for installations that
  already have a compatible x64 ASI loader.
  SHA-256:
  `9B70C02896D06042F4E69F12CFB6D0D2F5F855657237D5EAB082E48DDB8E5307`
- `Dishonored2-FPSFix-v1.5.1-with-Ultimate-ASI-Loader-v9.7.4.zip` additionally
  contains the pinned x64 loader and its required MIT notice.
  SHA-256:
  `45004D951EF7AF0696C2E08B92B1721C0185CEAF5AA33B1FC2237AD891ACE575`

## Validation

- Reference executable SHA-256 values:
  - GOG: `C3150F9F2D9BF967D23CA6A79BB32703B90116854AAD9892C7FC1F46A1060293`
  - Steam: `B671F8249422862BF557D00AAB2F4BB671ED4515CC10AD8A8A9DECAD84516180`
- ASI SHA-256:
  `AB42572E47E79CC90B748327C15E7109B0E590E3B30E54413988F14536F723F6`
- Ultimate ASI Loader v9.7.4 x64 SHA-256:
  `FA266E3513D02C08A1B808F28C10538A489EAFFAA4B0707F7CC1066E71B5AFD7`
- Compilation with warnings enabled, joint-pose tests, direct ASI loading, and
  both fail-closed host tests passed.
- The camera-prediction and slow-motion test passed, now including a
  first-person attachment that moves relative to a moving camera. At 60-360
  FPS and simulation speeds down to 5%, its motion relative to the camera
  follows the presentation time exactly; its previous-frame matrices
  reproduce the previously presented pose; and a model fixed to the camera
  keeps the previous correction.
- The offline layout-profile test passed against both real executables.
- The release ASI was played on the GOG build through Ultimate ASI Loader
  v9.7.4 for 11.6 minutes, covering the power-wheel weapon case, a slowed-time
  power, and a regression check. The weapon stayed smooth in the power wheel.
  No crash, capacity miss, upload failure, interpolation rejection, or visible
  regression was observed.
- A short Steam session with the same ASI covered the power-wheel weapon case,
  a slowed-time power, and kill cams. The weapon stayed smooth, and no crash or
  visible issue was observed.
- Both extracted archives passed their payload-manifest checks, direct-load
  and fail-closed tests, and, for the loader bundle, external-loader discovery,
  DirectInput forwarding, and plugin loading.

`ShadowTransforms` remains unsupported and disabled. Simulated cloth remains
outside the release scope.
