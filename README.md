# Dishonored 2 FPS Fix

> [!WARNING]
> This patch has been pretty much entirely been generated using AI; 
> I won't and will never claim to have enough knowledge or expertise to do this 
> kind of reverse-engineering by myself; I've tested three levels at 360hz + 
> briefly tested at 120, 144 and 240 and so far spotted 
> no major issues (on my machine ofc, if you have issues feel free to open an Issue)
> this patch currently probably only works for the latest GOG version of the game, I do have 
> the Steam version too but still have to test that, so no guarantees for now.
> If you're interested and want more (human generated) info, I have a blog post [here](https://slop-blog.enkhayzomachines.net/posts/dishonored-2-high-fps-fix) :)

A source-only high-frame-rate fix for the GOG release of Dishonored 2. It keeps the game's simulation and physics at their native 120 Hz while smoothing presentation above 120 FPS by interpolating all world assets, player included, alongside skeletal animations to match the display framerate, with an additional per-frame mouse delta override to keep mouse input latency low.

Current release: **v1.3.0**

## Compatibility

The fully tested reference executable is:

- Dishonored 2 GOG, version 1.77.9.0
- `Dishonored2.exe` SHA-256: `C3150F9F2D9BF967D23CA6A79BB32703B90116854AAD9892C7FC1F46A1060293`
- Windows x64

A layout profile also exists for the Steam executable (Steam build 17576867,
version 1.77.9.0):

- `Dishonored2.exe` SHA-256: `B671F8249422862BF557D00AAB2F4BB671ED4515CC10AD8A8A9DECAD84516180`

The Steam executable is not SteamStub-encrypted, but it is a separate link of
the same source, so every code and data address differs from GOG. Its profile
was mapped by static analysis (object layouts and field offsets are identical
to GOG). `ShadowTransforms` is not yet mapped on Steam; if it is enabled there
it is switched off with a log message rather than blocking the other fixes.

The SHA-256 is now an identity diagnostic rather than a hard allowlist. Before
installing any hook, the ASI verifies that the host is a PE32+ x64
`Dishonored2.exe`, that every required RVA has the expected code/data section
permissions, that the renderer-view call, deep-copy target signature, and
relevant vtables still point to the expected functions, and that every enabled
hook has its original byte signature. An executable with a different SHA can
therefore activate when it retains the complete verified runtime layout.
Builds that relocate or change
any required path fail closed and need a separately researched layout profile.
Only the GOG build above has received full live testing; layout-compatible
acceptance is not a gameplay-support claim for other releases. An unknown hash
is checked against each known layout profile in turn.

## What it fixes

- Removes the game's internal 120 FPS presentation cap so an external limiter can be used.
- Smooths the renderer camera above the 120 Hz simulation rate.
- Selects the game's frame-rate-independent mouse sensitivity path.
- Optionally keeps first-person body and weapon roots aligned with the smoothed camera.
- Provides separately gated interpolation for eligible world transforms, first-person skeletal animation, selected world skeletal animation, and small ownerless cinematic controls.

The patch does not raise the simulation rate or modify authoritative physics, AI, scripts, animation events, or gameplay state. Presentation corrections are applied only to temporary renderer-owned data.

## Current status

Camera prediction, FPS unlocking, mouse stabilization, first-person root correction, world/root interpolation, skeletal interpolation, and cinematic-control interpolation have passed focused live tests and multi-level gameplay/lifecycle testing without a major issue. The validated presentation layers remain enabled by default and can still be disabled independently.

Two areas are deliberately unsupported:

- Simulated cloth, including the cinematic hoodie/garment case, still advances at the native simulation cadence.
- `ShadowTransforms` must remain `0`. The investigated shadow boundary was rejected because it could crash during transitions or cause caster flicker.

## Build

Install Visual Studio 2022 or the current Visual Studio Build Tools with the **Desktop development with C++** workload, then run from a Command Prompt:

```bat
build-msvc.cmd
```

The script locates the x64 MSVC toolchain, builds
`build\Dishonored2HighFPSFix.asi`, builds and runs the direct ASI load test,
builds the external-loader integration host, and builds and runs the joint-pose
interpolation tests. No game files are needed to compile or test the source.

To run the ASI load test manually:

```bat
build\asi-load-test.exe build\Dishonored2HighFPSFix.asi
```

The test loads the `.asi` directly into an unsupported host and verifies that
it has no DirectInput proxy export, resolves its sibling log path, and refuses
to install game hooks. It does not replace in-game testing through the selected
ASI loader.

To test discovery and forwarding through an external loader without modifying
the game installation, build first and then provide the path to an x64 loader:

```powershell
.\test-asi-loader.ps1 -LoaderPath C:\path\to\dinput8.dll
```

The script creates a disposable staging directory below `build`, runs the
integration host, and verifies loader discovery, system DirectInput forwarding,
plugin loading, sibling logging, and safe unsupported-host rejection. The
official Ultimate ASI Loader v9.7.4 x64 build passes this test and the v1.3.0
in-game feature-parity validation.

## Package

After building and validating the plugin, create the canonical plugin-only
archive and the optional tested-loader convenience archive with:

```powershell
.\package-release.ps1 -Version 1.3.0 `
  -LoaderPath .\build\third-party\ultimate-asi-loader-v9.7.4\extracted\dinput8.dll
```

The packaging script pins the expected loader hash, generates per-file and ZIP
SHA-256 manifests, includes the required third-party notice only in the loader
bundle, and refuses to overwrite an existing release archive. Omit
`-LoaderPath` to produce only the plugin-only archive.

## Install

1. Close Dishonored 2.
2. Build the project.
3. Install a compatible x64 ASI loader, such as Ultimate ASI Loader, according
   to that loader's documentation. If the game already has a compatible
   loader, keep it.
4. Copy `build\Dishonored2HighFPSFix.asi` and `d2-high-fps-fix.ini` beside
   `Dishonored2.exe`, or into the plugin directory configured for the loader.
   Keep the ASI and INI together.
5. Keep **Triple Buffering** disabled in the game.
6. Set the desired maximum frame rate in the NVIDIA Control Panel or another external limiter. Do not run completely uncapped.
7. Launch the game normally.

The canonical release is plugin-only. A separately named convenience archive
also bundles the tested Ultimate ASI Loader v9.7.4 x64 build. When using that
archive on a game with no loader, copy its `dinput8.dll` too. If the game
already has a compatible loader, do not overwrite it; copy only the ASI and
INI. [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)
is MIT-licensed, and the convenience archive includes its required notice.

The patch writes `d2-high-fps-fix.log` beside the ASI. It records whether the
reference hash was recognized and explains any executable-layout, call-target,
vtable, section-permission, or hook-signature failure.

## Configuration

Edit `d2-high-fps-fix.ini` while the game is closed.

### Stable settings

- `UnlockAbove120=1` disables the game's frame spinner. An external FPS limiter is still required.
- `StabilizeMouseSensitivity=1` removes the game's FPS-dependent mouse multiplier. Mouse sensitivity will feel lower at high FPS; raise the in-game sensitivity once to taste.
- `StabilizeFirstPersonHands=1` enables the validated renderer-only first-person root correction. It is enabled by default.

Press **F10** in game to toggle camera prediction and the enabled first-person root correction for an A/B comparison. F10 does not change the FPS limit or the separate interpolation options.

For development performance comparisons, set
`Diagnostics/InterpolationABProbe=1`. The in-session controls are:

- **Ctrl+F11** starts or stops a clean measurement segment. Stop it while
  travelling between test locations so those frames are excluded.
- **F11** toggles all configured world, skeletal, and cinematic interpolation
  layers. If a segment is active, the old mode is summarized and a new segment
  starts automatically.
- **Alt+F11** cycles through **All**, **Transforms only**, **Skeletons only**,
  and **Off**. This is the preferred control for isolating the two expensive
  interpolation families in one game session.
- **Shift+F11** toggles only first-person root stabilization so the shared
  renderer-model hook can be measured independently.

Every segment discards its first two seconds as warm-up and writes its mode,
presentation-serial range, average FPS, frame-time percentiles, simulation-tick
cadence, and interpolation work counters to `d2-high-fps-fix.log`. These keys do
not change camera prediction, mouse stabilization, or the FPS unlock.

### Interpolation settings

The following validated layers are enabled by default and can be disabled independently:

- `WorldTransforms=1`
- `FirstPersonSkeletons=1`
- `WorldSkeletons=1`
- `CinematicTransforms=1`
- `CinematicSkeletons=1`

The supplied configuration enables all five together for the complete validated presentation path. Unsupported models, invalid layouts, discontinuities, teleports, identity changes, and missing history snap to the current native state instead of being blended.

`AdaptivePerformanceGate=1` monitors presentation cadence through the fixed
120 Hz simulation clock. When full interpolation cannot retain useful native-
rate headroom, it disables skeletal interpolation first and keeps the cheaper
transform layer active when practical. If transforms alone remain below the
guard, it disables them too. Recovery uses the recently measured cost of each
layer and requires sustained headroom. If the active reduced profile becomes
materially faster than the scene in which that cost was learned, the gate makes
one controlled re-probe and relearns the local cost if it fails. This prevents
a stale expensive-scene estimate as well as a simple on/off cycle around 120
FPS. Selecting a profile manually with F11 or Alt+F11 suspends the adaptive gate
until the next launch. This controller is enabled by default. Set
`AdaptivePerformanceGate=0` to keep every individually enabled interpolation
layer active continuously, regardless of measured performance.

Leave these settings unchanged:

- `ShadowTransforms=0` — required; the prototype is not safe for normal use.
- `Telemetry=0` — normal play does not need the development telemetry block.

For ordinary play, keep `InterpolationABProbe=0`.

## Uninstall

Close the game and remove these files from the game directory:

- `Dishonored2HighFPSFix.asi`
- `d2-high-fps-fix.ini`
- `d2-high-fps-fix.log` (optional diagnostic log)

Do not remove a shared or pre-existing ASI loader when uninstalling this
plugin.

## Technical outline

The patch is an x64 ASI plugin loaded by an external ASI loader. On a
successfully validated executable layout it installs guarded renderer hooks,
retains recent
fixed-step samples, and evaluates temporary camera, model-matrix, or
joint-palette data at presentation time. It does not export or forward
`DirectInput8Create`. All optional layers are bounded and fail closed when
their expected layout, identity, timing, or continuity checks do not pass.

The repository contains the patch source and build/package instructions. Release
archives contain only the built plugin, configuration, documentation, hashes,
and—only in the explicitly named convenience archive—the third-party ASI
loader and its required notice. No Dishonored 2 executable or game asset is
distributed.
