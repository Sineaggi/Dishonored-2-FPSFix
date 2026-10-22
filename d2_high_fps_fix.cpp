#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <d3d11_1.h>
#include <dxgi1_2.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <limits>
#include <vector>

#include "joint_pose_interpolation.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")

namespace {

// Executable-specific addresses and entry signatures. Everything else the
// plugin touches (object layouts, field offsets, the view-copy body) is shared
// by every supported build of Dishonored 2 1.77.9.0.
struct VtableLayout {
    std::uintptr_t rva;
    std::array<std::uintptr_t, 4> targets;
};

constexpr std::size_t kMaximumHookLength = 32;

struct HookSiteLayout {
    std::uintptr_t rva;
    // Leading whole instructions copied into the trampoline. They must be
    // position-independent and cover at least the 14-byte absolute jump.
    std::size_t length;
    std::array<unsigned char, kMaximumHookLength> bytes;
};

struct GameBuildLayout {
    const char* name;
    std::array<unsigned char, 32> sha256;
    std::uintptr_t gamePointerRva;
    VtableLayout gameVtable;
    std::uintptr_t frameSpinningRva;
    std::uintptr_t tripleBufferingRva;
    std::uintptr_t fixMouseSensibilityRva;
    // idCVar object for com_timeScaler, which despite its name is the menu's
    // frame-rate limiter: the frame spinner waits (1/30 s) / value. The name
    // pointer is checked at runtime before the value is ever written.
    std::uintptr_t frameLimiterCvarRva;
    std::uintptr_t copyViewRva;
    std::uintptr_t copyCallsiteRva;
    HookSiteLayout renderModelGpuCopy;
    VtableLayout renderModelStaticVtable;
    VtableLayout skinnedModelVtable;
    HookSiteLayout skinnedPoseUpload;
    // The Steam pose-upload function returns a bool in AL only, leaving the
    // upper bits of RAX unspecified.
    bool skinnedPoseUploadReturnsByte;
    // Builds where the shadow caster-list builders have not been located
    // force ShadowTransforms off instead of failing the whole plugin.
    bool shadowCasterBuildSupported;
    std::array<HookSiteLayout, 2> shadowCasterBuild;
    // Source-level transform layer (SourceLevelTransforms). Builds where the
    // render-world flush and render-model MarkDirty/Commit have not been
    // located leave this unsupported and the layer disables itself.
    bool sourceLevelSupported;
    // idRenderWorldLocal vtable; the flush slot commits every dirty render
    // model (rebuilding +0x20/+0xA0) once per rendered frame.
    VtableLayout renderWorldVtable;
    std::size_t renderWorldFlushSlot;
    std::uintptr_t renderWorldFlushRva;
    // Shared idRenderModelStatic/arkSkinnedRenderModel MarkDirty (vtable
    // +0x28) and Commit (vtable +0xC0).
    std::size_t renderModelMarkDirtySlot;
    std::uintptr_t renderModelMarkDirtyRva;
    std::size_t renderModelCommitSlot;
    std::uintptr_t renderModelCommitRva;
    // Entry signatures checked before any vtable slot is replaced.
    std::array<unsigned char, 16> renderWorldFlushBytes;
    std::array<unsigned char, 16> renderModelMarkDirtyBytes;
    std::array<unsigned char, 16> renderModelCommitBytes;
    // arkRenderModelAssembly: its MarkDirty (vtable +0x28) recomposes each
    // part's origin/axis/scale from the assembly transform and then calls the
    // part's own (static) MarkDirty. Hooked for diagnostics only.
    VtableLayout assemblyVtable;
    std::uintptr_t assemblyMarkDirtyRva;
    std::array<unsigned char, 16> assemblyMarkDirtyBytes;
    // Load-screen "press a key" gate: the static idCommonLocal object, its
    // vtable, the prompt callback handle (-1 when no prompt is armed) and the
    // flag byte whose bit 1 (value 2) lets the loading loop continue.
    bool autoContinueSupported;
    std::uintptr_t commonObjectRva;
    std::uintptr_t commonVtableRva;
    std::size_t commonLoadPromptHandleOffset;
    std::size_t commonLoadFlagsOffset;
};

constexpr GameBuildLayout kGogLayout = {
    "GOG 1.77.9.0",
    {
        0xC3, 0x15, 0x0F, 0x9F, 0x2D, 0x9B, 0xF9, 0x67,
        0xD2, 0x3C, 0xA6, 0xA7, 0x9B, 0xB3, 0x27, 0x03,
        0xB9, 0x01, 0x16, 0x85, 0x4A, 0xAD, 0x98, 0x92,
        0xC7, 0xFC, 0x1F, 0x46, 0xA1, 0x06, 0x02, 0x93,
    },
    0x288D608,
    {0x1F02138, {0xA2F190, 0xA3EF00, 0xA3EEF0, 0xA38740}},
    0x288E958,
    0x359E228,
    0x3BF2FA8,
    // Inferred from the Steam registration order (com_timeScaler is constructed
    // 0x80 bytes before com_disableFrameSpinning); unverified on GOG, so the
    // runtime name check decides whether it is used.
    0x288E8B0,
    0x64A90,
    0xA395A6,
    {0x3ACD00, 19, {
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0xF3, 0x0F, 0x11, 0x54, 0x24, 0x18,
        0x57,
        0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00,
    }},
    {0x1E55208, {0x224400, 0x2243F0, 0x2243E0, 0x2DA6D0}},
    {0x1E55008, {0x224400, 0x2243F0, 0x2243E0, 0x2CF590}},
    {0x2D0C80, 17, {
        0x48, 0x89, 0x74, 0x24, 0x20,
        0x57,
        0x48, 0x83, 0xEC, 0x40,
        0x80, 0xB9, 0xB1, 0x1F, 0x00, 0x00, 0x00,
    }},
    false,
    true,
    {{
        {0x3CA3B0, 15, {
            0x4C, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10,
            0x48, 0x89, 0x4C, 0x24, 0x08,
        }},
        {0x3CACE0, 15, {
            0x4C, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10,
            0x48, 0x89, 0x4C, 0x24, 0x08,
        }},
    }},
};

// Steam build 17576867 (FileVersion 1.77.9.0, PE timestamp 0x67A50CDE). The
// executable is not SteamStub-wrapped; it is a separate link of the same
// source, so object layouts match GOG but code and data addresses do not.
constexpr GameBuildLayout kSteamLayout = {
    "Steam 1.77.9.0",
    {
        0xB6, 0x71, 0xF8, 0x24, 0x94, 0x22, 0x86, 0x2B,
        0xF5, 0x57, 0xD0, 0x0A, 0xAB, 0x2F, 0x4B, 0xB6,
        0x71, 0xED, 0x45, 0x15, 0xCC, 0x10, 0xAD, 0x8A,
        0x8A, 0x9D, 0xEC, 0xAD, 0x84, 0x51, 0x61, 0x80,
    },
    0x39A5290,
    {0x1C940A8, {0x8A5F60, 0x8A88E0, 0x8A88F0, 0x8ACDF0}},
    0x25B1EA8,
    0x32FA908,
    0x3992158,
    0x25B1E00,
    0x444C0,
    0x8AC8EF,
    {0x319560, 16, {
        0x48, 0x89, 0x5C, 0x24, 0x10,
        0x48, 0x89, 0x6C, 0x24, 0x18,
        0x48, 0x89, 0x74, 0x24, 0x20,
        0x57,
    }},
    {0x1B0DD88, {0x1BD8A0, 0x1BE8C0, 0x1BDD40, 0x2681F0}},
    {0x1B0D628, {0x1BD8A0, 0x1BE8C0, 0x1BDD40, 0x25D690}},
    {0x25F930, 17, {
        0x48, 0x89, 0x5C, 0x24, 0x10,
        0x57,
        0x48, 0x83, 0xEC, 0x20,
        0x80, 0xB9, 0xB1, 0x1F, 0x00, 0x00, 0x00,
    }},
    true,
    false,
    {},
    true,
    {0x1B08868, {0x238A50, 0x239790, 0x239120, 0x2396D0}},
    0xD8,
    0x239180,
    0x28,
    0x235880,
    0xC0,
    0x235680,
    {0x40, 0x57, 0x48, 0x83, 0xEC, 0x50, 0x48, 0xC7,
     0x44, 0x24, 0x20, 0xFE, 0xFF, 0xFF, 0xFF, 0x48},
    {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C,
     0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57},
    {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C,
     0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57},
    {0x1B03BC8, {0x1BD8A0, 0x1BE8C0, 0x1BDD40, 0x1BC810}},
    0x1BD1B0,
    {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C,
     0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x41},
    true,
    0x25AF110,
    0x1AC4D88,
    0x12D8,
    0x19A0,
};

constexpr std::array<const GameBuildLayout*, 2> kKnownLayouts = {
    &kGogLayout, &kSteamLayout,
};

constexpr std::uintptr_t kClockOffset = 0x2E7428;

constexpr std::size_t kCVarIntegerOffset = 0x28;
constexpr std::size_t kCVarFloatOffset = 0x2C;
constexpr std::size_t kCVarNameOffset = 0x30;
constexpr char kFrameLimiterCvarName[] = "com_timeScaler";
// com_timeScaler 1.0 is 30 FPS; the cvar is registered with range 0.1..10.
constexpr int kFrameLimiterBaseFps = 30;
constexpr int kMinimumMaxFps = 30;
constexpr int kMaximumMaxFps = 300;
constexpr std::uintptr_t kScaledTimeOffset = 0x68;
constexpr std::uintptr_t kSimulationTimeOffset = 0xB8;

constexpr unsigned char kExpectedCopyViewBytes[32] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74,
    0x24, 0x10, 0x48, 0x89, 0x7C, 0x24, 0x18, 0x41,
    0x56, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0x02, 0x4C,
    0x8B, 0xF2, 0x48, 0x8B, 0xF1, 0x89, 0x01, 0x0F,
};

constexpr std::size_t kRenderModelSize = 0x1CD0;
constexpr std::size_t kRenderModelMatrixOffset = 0x20;
constexpr std::size_t kRenderModelPreviousMatrixOffset = 0x60;
constexpr std::size_t kRenderModelInverseMatrixOffset = 0xA0;
constexpr std::size_t kRenderModelPreviousInverseMatrixOffset = 0xE0;
constexpr std::size_t kRenderModelViewMatrixOffset = 0x120;
constexpr std::size_t kRenderModelPreviousViewMatrixOffset = 0x160;
constexpr std::size_t kRenderModelMvpMatrixOffset = 0x1A0;
constexpr std::size_t kRenderModelPreviousMvpMatrixOffset = 0x1E0;
constexpr std::size_t kRenderModelDepthHackOffset = 0x18B8;
constexpr std::size_t kRenderModelOwnerOffset = 0x1C50;
constexpr std::size_t kRenderModelWorldOffset = 0x1BF8;
constexpr std::size_t kRenderModelHandleOffset = 0x1C18;
constexpr std::size_t kRenderWorldModelArrayOffset = 0x20538;
// idList count (low 24 bits) of the model-pointer array.
constexpr std::size_t kRenderWorldModelCountOffset = 0x20540;
// Model committed together with its owner by the flush (0x2395A0).
constexpr std::size_t kRenderModelLinkedModelOffset = 0x1930;
// Byte set to 1 by the arkRenderModelAssembly constructor on its parts.
constexpr std::size_t kRenderModelAssemblyPartOffset = 0x1C60;
constexpr std::uint32_t kRenderModelDirtyTransform = 0x01;
constexpr std::size_t kSourceTrackCapacity = 8192;
constexpr std::size_t kSourceTrackProbeLimit = 64;
constexpr std::size_t kSourceDirtyCapacity = 32768;
// Ticks a tracked model may go without a commit before its committed matrix is
// restored and the track is dropped.
constexpr std::uint32_t kSourceIdleTicksBeforeDrop = 3;
// Presentation frames a track may go unseen by its world's flush.
constexpr std::uint64_t kSourceStaleFrames = 600;

constexpr std::size_t kShadowCasterEntryStride = 0x30;
constexpr std::size_t kShadowCasterMatrixPointerOffset = 0x08;
constexpr std::size_t kShadowCasterProxyCapacity = 4096;

constexpr std::size_t kSkinnedModelSize = 0x2130;
constexpr std::size_t kSkinnedPoseUploadFlagsOffset = 0x1FB0;
constexpr std::size_t kSkinnedPosePendingOffset = 0x1FB1;
constexpr std::size_t kSkinnedTrueJointCountOffset = 0x1FE0;
constexpr std::size_t kSkinnedPoseCpuListOffset = 0x1FF8;
constexpr std::size_t kSkinnedPosePaddedCountOffset = 0x2000;
constexpr std::size_t kSkinnedModelAssetOffset = 0x1FE8;
constexpr std::size_t kSkeletalTrackCapacity = 1024;
constexpr std::size_t kSkeletalTrackProbeLimit = 32;
constexpr std::size_t kSkeletalTrackReportCapacity = 16;
constexpr std::size_t kOwnerlessSkeletalTrackCapacity = 512;
constexpr std::size_t kOwnerlessSkeletalTrackProbeLimit = 24;
constexpr std::size_t kOwnerlessSkeletalTrackReportCapacity = 16;
constexpr std::size_t kMaximumJointCount = 256;
constexpr std::uint32_t kMaximumCinematicJointCount = 64;
constexpr double kMaximumSkeletalStateInterval = 0.050;
constexpr double kMaximumJointTranslationJump = 16.0;
constexpr double kMaximumJointRotationJumpDegrees = 90.0;

constexpr double kNativeSimulationStep = 0.008333334;
constexpr double kMaximumWorldStateInterval = 0.050;
constexpr double kMaximumWorldPositionJump = 64.0;
constexpr double kMaximumWorldRotationJumpDegrees = 90.0;
constexpr std::size_t kWorldTransformCapacity = 8192;
constexpr std::size_t kWorldTransformProbeLimit = 64;
constexpr std::uint64_t kWorldTransformStaleFrames = 600;
constexpr std::size_t kWorldTrackReportCapacity = 16;
constexpr std::size_t kNonRigidTrackCapacity = 1024;
constexpr std::size_t kNonRigidTrackProbeLimit = 32;
constexpr std::size_t kNonRigidTrackReportCapacity = 8;
constexpr std::size_t kShadowCorrectionCapacity = 4096;
constexpr std::size_t kShadowCorrectionProbeLimit = 32;
constexpr std::uint64_t kShadowCorrectionMaximumAge = 2;

constexpr std::size_t kViewOriginOffset = 0xA8;
constexpr std::size_t kViewOriginDuplicateOffset = 0xC0;
constexpr std::size_t kViewAxisOffset = 0xCC;

constexpr double kTimeEpsilon = 1.0e-7;
constexpr double kMaximumStateInterval = 0.050;
constexpr double kMaximumPositionJump = 5.0;
constexpr double kMaximumRotationJumpDegrees = 45.0;
constexpr double kMinimumAlpha = -0.25;
constexpr double kMaximumAlpha = 2.0;
constexpr double kPi = 3.14159265358979323846;

HMODULE g_pluginModule = nullptr;
std::uintptr_t g_executableBase = 0;
const GameBuildLayout* g_layout = &kGogLayout;
void* g_relay = nullptr;
std::array<void*, 2> g_shadowCasterBuildTrampolines{};
void* g_renderModelGpuCopyTrampoline = nullptr;
void* g_skinnedPoseUploadTrampoline = nullptr;
std::atomic<bool> g_enabled{true};
std::atomic<bool> g_transformInterpolationRuntimeEnabled{true};
std::atomic<bool> g_skeletalInterpolationRuntimeEnabled{true};
std::atomic<bool> g_firstPersonHandsRuntimeEnabled{true};
std::atomic<bool> g_initializationStarted{false};
bool g_f10WasDown = false;
bool g_f11WasDown = false;
HANDLE g_telemetryMapping = nullptr;
bool g_unlockAbove120 = false;
int g_maxFps = 0;
bool g_stabilizeMouseSensitivity = false;
bool g_stabilizeFirstPersonHands = false;
bool g_interpolateWorldTransforms = false;
bool g_interpolateCinematicTransforms = false;
bool g_interpolateShadowTransforms = false;
bool g_interpolateFirstPersonSkeletons = false;
bool g_interpolateWorldSkeletons = false;
bool g_interpolateCinematicSkeletons = false;
bool g_enableAdaptiveInterpolation = false;
bool g_enableTelemetry = false;
bool g_enableInterpolationAbProbe = false;
bool g_toggleSounds = true;
bool g_overlay = false;
extern std::atomic<int> g_screenParticleMode;
void CycleScreenParticleMode();
bool InstallInlineHook(std::uintptr_t rva, const unsigned char* expected, std::size_t length,
                       const void* hook, void** original, const char* description);
void TryInstallOverlayPresentHook();
void UpdateForcedBloodEffect();
struct Transform;
void NoteCameraOrigins(const Transform& raw, const Transform& output);
void RefreshScreenParticlesForCamera(const Transform& predicted);
void ToggleForcedBloodEffect();
void ToggleDevGui();
void CloseDevGuiOnEscape();
void NoteSimulationTime(double simulationTime);
bool ClosePauseMenu();
bool g_crashLog = false;
bool g_devGuiEscapeFallback = true;
std::atomic<bool> g_forceBloodEffect{false};
int g_devGuiScale = 0;
bool g_autoContinueLoadScreen = false;
bool g_autoAbSchedule = false;
int g_autoAbSegmentSeconds = 20;
int g_autoAbRounds = 2;
bool g_autoAbQuitWhenDone = false;
bool g_sourceLevelTransforms = false;
bool g_sourceLevelWrites = false;
bool g_sourceLevelHands = false;
bool g_renderModelGpuCopyHookSkipped = false;
bool g_sourceLevelInstalled = false;
// AutoContinueLoadScreen without SourceLevelTransforms: only the render-world
// flush slot is hooked, and the hook does nothing but the load-screen check.
bool g_flushHookOnly = false;
std::atomic<bool> g_sourceLevelRuntimeEnabled{true};
std::atomic<std::uint64_t> g_abSourceFlushTicks{0};
std::atomic<std::uint64_t> g_abSourceFlushOriginalTicks{0};
std::atomic<std::uint64_t> g_abSourceWrites{0};
bool SourceLevelWritesSelected();
bool SourceHandsSelected();
void ObserveSourceLevelRendererCall();
std::atomic<bool> g_adaptiveInterpolationManualOverride{false};
std::atomic<int> g_unlockState{0};
// 0 = not resolved yet, 1 = engine limiter in use, 2 = unavailable.
std::atomic<int> g_frameLimiterState{0};
std::atomic<int> g_mouseStabilizationState{0};
std::atomic<int> g_firstPersonRenderState{0};
std::atomic<int> g_worldTransformRenderState{0};
std::atomic<std::uint64_t> g_worldTransformAdjustedCount{0};
std::atomic<std::uint64_t> g_worldTransformCapacityMissCount{0};
std::atomic<std::uint64_t> g_shadowMatrixCalls{0};
std::atomic<std::uint64_t> g_shadowCorrectionPublications{0};
std::atomic<std::uint64_t> g_shadowMatrixDirectMatches{0};
std::atomic<std::uint64_t> g_shadowMatrixContentMatches{0};
std::atomic<std::uint64_t> g_shadowMatrixAmbiguousMatches{0};
std::atomic<std::uint64_t> g_shadowMatrixAdjusted{0};
std::atomic<std::uint64_t> g_shadowMatrixCacheMisses{0};
std::atomic<std::uint64_t> g_shadowMatrixUnreadable{0};
std::atomic<std::uint64_t> g_shadowCorrectionPointerCapacityMisses{0};
std::atomic<std::uint64_t> g_shadowCorrectionContentCapacityMisses{0};
std::atomic<std::uint64_t> g_shadowCasterProxyCalls{0};
std::atomic<std::uint64_t> g_shadowCasterProxyLists{0};
std::atomic<std::uint64_t> g_shadowCasterProxyCapacityMisses{0};
std::atomic<int> g_worldSkeletalRenderState{0};
std::atomic<std::uint64_t> g_worldSkeletalAdjustedCount{0};
std::atomic<int> g_firstPersonSkeletalRenderState{0};
std::atomic<std::uint64_t> g_firstPersonSkeletalAdjustedCount{0};
std::atomic<std::uint64_t> g_abRenderModelHookCalls{0};
std::atomic<std::uint64_t> g_abFirstPersonRootCorrections{0};
std::atomic<std::uint64_t> g_abSkeletalHookCalls{0};
// QPC ticks spent in each hook in total and inside the original engine
// function; the difference is the plugin's own CPU cost. Probe-only.
std::atomic<std::uint64_t> g_abRenderModelHookTicks{0};
std::atomic<std::uint64_t> g_abRenderModelOriginalTicks{0};
std::atomic<std::uint64_t> g_abSkeletalHookTicks{0};
std::atomic<std::uint64_t> g_abSkeletalOriginalTicks{0};

struct WorldTransformDiagnostics {
    std::atomic<std::uint64_t> candidates{0};
    std::atomic<std::uint64_t> exactStaticType{0};
    std::atomic<std::uint64_t> exactSkinnedType{0};
    std::atomic<std::uint64_t> eligible{0};
    std::atomic<std::uint64_t> rigid{0};
    std::atomic<std::uint64_t> uniformScaled{0};
    std::atomic<std::uint64_t> reflectedRigid{0};
    std::atomic<std::uint64_t> reflectedMoving{0};
    std::atomic<std::uint64_t> reflectedAdjusted{0};
    std::atomic<std::uint64_t> cinematicEligible{0};
    std::atomic<std::uint64_t> cinematicAdjusted{0};
    std::atomic<std::uint64_t> moving{0};
    std::atomic<std::uint64_t> tracksCreated{0};
    std::atomic<std::uint64_t> samplePairs{0};
    std::atomic<std::uint64_t> vtableRejected{0};
    std::atomic<std::uint64_t> depthHackRejected{0};
    std::atomic<std::uint64_t> ownerRejected{0};
    std::atomic<std::uint64_t> nonRigidRejected{0};
    std::atomic<std::uint64_t> currentNonRigidRejected{0};
    std::atomic<std::uint64_t> previousNonRigidRejected{0};
    std::atomic<std::uint64_t> discontinuityRejected{0};
    std::atomic<std::uint64_t> sameTimeMutationRejected{0};
    std::atomic<std::uint64_t> jumpRejected{0};
    std::atomic<std::uint64_t> reflectionParityRejected{0};
    std::atomic<std::uint64_t> skinnedAdjusted{0};
};

struct ObservedWorldVtable {
    std::atomic<std::uintptr_t> rva{0};
    std::atomic<std::uint64_t> count{0};
};

WorldTransformDiagnostics g_worldDiagnostics;
std::array<ObservedWorldVtable, 8> g_observedWorldVtables{};
std::atomic<std::uint64_t> g_nextWorldDiagnosticsSerial{600};

struct SharedTelemetry {
    volatile LONG64 sequence;
    std::uint32_t version;
    std::uint32_t size;
    std::uint32_t enabled;
    std::uint32_t applied;
    double scaledTime;
    double simulationTime;
    double alpha;
    float rawOrigin[3];
    float outputOrigin[3];
    float rawAxis[9];
    float outputAxis[9];
};

static_assert(sizeof(SharedTelemetry) == 144, "Unexpected telemetry layout");
SharedTelemetry* g_telemetry = nullptr;
double g_lastAlpha = std::numeric_limits<double>::quiet_NaN();

using CopyViewFn = void*(__fastcall*)(void*, const void*);
CopyViewFn g_originalCopyView = nullptr;

using RenderModelGpuCopyFn = void(__fastcall*)(void*, void*, float, void*);
RenderModelGpuCopyFn g_originalRenderModelGpuCopy = nullptr;

using ShadowCasterBuildFnA = unsigned char(__fastcall*)(
    void*, void*, std::uint64_t*, float*, void*, float);
using ShadowCasterBuildFnB = unsigned char(__fastcall*)(
    void*, void*, std::uint64_t*, float*, void*, float, std::uint32_t, void*);
ShadowCasterBuildFnA g_originalShadowCasterBuildA = nullptr;
ShadowCasterBuildFnB g_originalShadowCasterBuildB = nullptr;

using SkinnedPoseUploadFn = std::uint64_t(__fastcall*)(void*, void*);
SkinnedPoseUploadFn g_originalSkinnedPoseUpload = nullptr;

struct Vec3 {
    double x;
    double y;
    double z;
};

struct Quaternion {
    double w;
    double x;
    double y;
    double z;
};

struct Transform {
    Vec3 origin;
    float axis[9];
};

struct PredictionState {
    bool initialized = false;
    const void* sourceView = nullptr;
    double previousTime = 0.0;
    double currentTime = 0.0;
    Transform previous{};
    Transform current{};
};

PredictionState g_prediction;

struct Matrix4 {
    float values[16]{};
};

struct ShadowCasterProxyStorage {
    alignas(16) std::array<unsigned char,
        kShadowCasterProxyCapacity * kShadowCasterEntryStride> entries{};
    alignas(16) std::array<Matrix4, kShadowCasterProxyCapacity> matrices{};
    std::array<unsigned char, kShadowCasterProxyCapacity> corrected{};
    bool active = false;
};

thread_local ShadowCasterProxyStorage g_shadowCasterProxyStorage;

struct RenderCorrectionState {
    Matrix4 currentDelta{};
    Matrix4 currentInverseDelta{};
    Matrix4 previousDelta{};
    Matrix4 previousInverseDelta{};
    bool currentValid = false;
    bool previousValid = false;
    std::uint64_t serial = 0;
};

SRWLOCK g_renderCorrectionLock = SRWLOCK_INIT;
RenderCorrectionState g_renderCorrection;

struct PresentationContext {
    double scaledTime = 0.0;
    double simulationTime = 0.0;
    std::uint64_t serial = 0;
    bool valid = false;
};

SRWLOCK g_presentationContextLock = SRWLOCK_INIT;
PresentationContext g_presentationContext;
std::atomic<std::uint64_t> g_presentationSerial{0};

void PublishPresentationContext();
bool ReadPresentationContext(PresentationContext& context);
bool RuntimeTransformInterpolationEnabled();
bool RuntimeSkeletalInterpolationEnabled();
bool RuntimeFirstPersonHandsEnabled();

struct WorldTransformTrack {
    const void* renderModel = nullptr;
    const void* owner = nullptr;
    const void* modelAsset = nullptr;
    std::uintptr_t vtable = 0;
    double previousTime = 0.0;
    double currentTime = 0.0;
    Matrix4 previous{};
    Matrix4 current{};
    Matrix4 previousPresented{};
    Matrix4 lastPresented{};
    std::uint64_t lastSeenSerial = 0;
    std::uint64_t lastPresentedSerial = 0;
    std::uint64_t diagnosticId = 0;
    std::uint64_t firstSeenSerial = 0;
    std::uint64_t firstMotionSerial = 0;
    std::uint64_t lastMotionSerial = 0;
    std::uint64_t lastCorrectionSerial = 0;
    std::uint64_t motionSamples = 0;
    std::uint64_t correctionBuilds = 0;
    std::uint64_t reportedMotionSamples = 0;
    std::uint64_t reportedCorrectionBuilds = 0;
    std::uint64_t discontinuities = 0;
    std::uint64_t currentMatrixHash = 0;
    bool hasPair = false;
    bool hasLastPresented = false;
    bool reflected = false;
};

struct NonRigidWorldTrack {
    const void* renderModel = nullptr;
    const void* owner = nullptr;
    double simulationTime = 0.0;
    Matrix4 current{};
    std::uint64_t diagnosticId = 0;
    std::uint64_t firstSeenSerial = 0;
    std::uint64_t lastSeenSerial = 0;
    std::uint64_t firstChangeSerial = 0;
    std::uint64_t lastChangeSerial = 0;
    std::uint64_t changes = 0;
    std::uint64_t reportedChanges = 0;
    bool currentRigid = false;
    bool previousRigid = false;
};

SRWLOCK g_worldTransformLock = SRWLOCK_INIT;
std::array<WorldTransformTrack, kWorldTransformCapacity> g_worldTransforms{};
std::atomic<std::uint64_t> g_nextWorldTrackId{1};
std::array<NonRigidWorldTrack, kNonRigidTrackCapacity> g_nonRigidWorldTracks{};
std::atomic<std::uint64_t> g_nextNonRigidTrackId{1};
std::atomic<std::uint64_t> g_nonRigidTrackCapacityMissCount{0};

struct ShadowCorrectionEntry {
    const void* matrix = nullptr;
    std::uint64_t matrixHash = 0;
    Matrix4 currentDelta{};
    std::uint64_t presentationSerial = 0;
};

SRWLOCK g_shadowCorrectionLock = SRWLOCK_INIT;
std::array<ShadowCorrectionEntry, kShadowCorrectionCapacity>
    g_shadowCorrectionsByPointer{};
std::array<ShadowCorrectionEntry, kShadowCorrectionCapacity>
    g_shadowCorrectionsByContent{};

struct SkeletalDiagnostics {
    std::atomic<std::uint64_t> calls{0};
    std::atomic<std::uint64_t> exactSkinnedType{0};
    std::atomic<std::uint64_t> worldEligible{0};
    std::atomic<std::uint64_t> firstPersonEligible{0};
    std::atomic<std::uint64_t> cinematicEligible{0};
    std::atomic<std::uint64_t> firstPersonDisabled{0};
    std::atomic<std::uint64_t> depthHackRejected{0};
    std::atomic<std::uint64_t> ownerRejected{0};
    std::atomic<std::uint64_t> firstPersonOwnerFallback{0};
    std::atomic<std::uint64_t> layoutRejected{0};
    std::atomic<std::uint64_t> pendingSamples{0};
    std::atomic<std::uint64_t> timeSamples{0};
    std::atomic<std::uint64_t> changedSamples{0};
    std::atomic<std::uint64_t> rigidPalettes{0};
    std::atomic<std::uint64_t> nonRigidPalettes{0};
    std::atomic<std::uint64_t> sameTimeChanges{0};
    std::atomic<std::uint64_t> tracksCreated{0};
    std::atomic<std::uint64_t> samplePairs{0};
    std::atomic<std::uint64_t> worldSamplePairs{0};
    std::atomic<std::uint64_t> firstPersonSamplePairs{0};
    std::atomic<std::uint64_t> cinematicSamplePairs{0};
    std::atomic<std::uint64_t> preparedUploads{0};
    std::atomic<std::uint64_t> worldPreparedUploads{0};
    std::atomic<std::uint64_t> firstPersonPreparedUploads{0};
    std::atomic<std::uint64_t> cinematicPreparedUploads{0};
    std::atomic<std::uint64_t> adjustedUploads{0};
    std::atomic<std::uint64_t> worldAdjustedUploads{0};
    std::atomic<std::uint64_t> firstPersonAdjustedUploads{0};
    std::atomic<std::uint64_t> cinematicAdjustedUploads{0};
    std::atomic<std::uint64_t> forcedUploads{0};
    std::atomic<std::uint64_t> worldForcedUploads{0};
    std::atomic<std::uint64_t> firstPersonForcedUploads{0};
    std::atomic<std::uint64_t> cinematicForcedUploads{0};
    std::atomic<std::uint64_t> forcedUploadFailures{0};
    std::atomic<std::uint64_t> preparedWithoutUpload{0};
    std::atomic<std::uint64_t> adjustedFrames{0};
    std::atomic<std::uint64_t> firstPersonAdjustedFrames{0};
    std::atomic<std::uint64_t> cinematicAdjustedFrames{0};
    std::atomic<std::uint64_t> sameFrameUploads{0};
    std::atomic<std::uint64_t> changedOutputs{0};
    std::atomic<std::uint64_t> repeatedOutputs{0};
    std::atomic<std::uint64_t> uploadGapOne{0};
    std::atomic<std::uint64_t> uploadGapTwo{0};
    std::atomic<std::uint64_t> uploadGapMore{0};
    std::atomic<std::uint64_t> firstPersonChangedOutputs{0};
    std::atomic<std::uint64_t> firstPersonRepeatedOutputs{0};
    std::atomic<std::uint64_t> firstPersonUploadGapOne{0};
    std::atomic<std::uint64_t> firstPersonUploadGapTwo{0};
    std::atomic<std::uint64_t> firstPersonUploadGapMore{0};
    std::array<std::atomic<std::uint64_t>, 5> alphaBuckets{};
    std::atomic<std::uint64_t> discontinuityRejected{0};
    std::atomic<std::uint64_t> interpolationRejected{0};
};

struct SkeletalObservationTrack {
    const void* renderModel = nullptr;
    const void* owner = nullptr;
    const void* modelAsset = nullptr;
    const void* cpuPalette = nullptr;
    std::uint32_t jointCount = 0;
    std::uint32_t paddedJointCount = 0;
    double previousTime = 0.0;
    double simulationTime = 0.0;
    std::uint64_t checksum = 0;
    std::uint64_t diagnosticId = 0;
    std::uint64_t firstSeenSerial = 0;
    std::uint64_t lastSeenSerial = 0;
    std::uint64_t firstChangeSerial = 0;
    std::uint64_t lastChangeSerial = 0;
    std::uint64_t samples = 0;
    std::uint64_t changes = 0;
    std::uint64_t rigidSamples = 0;
    std::uint64_t interpolationBuilds = 0;
    std::uint64_t reportedSamples = 0;
    std::uint64_t reportedChanges = 0;
    std::uint64_t reportedInterpolationBuilds = 0;
    float rootTranslation[3]{};
    std::uint32_t firstNonRigidJoint =
        std::numeric_limits<std::uint32_t>::max();
    double nonRigidRowLength[3]{};
    double nonRigidMaximumRowDot = 0.0;
    double nonRigidDeterminant = 0.0;
    bool lastPaletteRigid = false;
    bool firstPerson = false;
    bool cinematic = false;
    bool hasSnapshot = false;
    bool hasPair = false;
    bool hasPresentedOutput = false;
    std::uint64_t lastPresentedSerial = 0;
    std::uint64_t lastPresentedChecksum = 0;
    std::array<d2_pose::JointMatrix, kMaximumJointCount> previousPalette{};
    std::array<d2_pose::JointMatrix, kMaximumJointCount> currentPalette{};
};

struct OwnerlessSkeletalTrack {
    const void* renderModel = nullptr;
    const void* modelAsset = nullptr;
    const void* cpuPalette = nullptr;
    double simulationTime = 0.0;
    std::uint64_t checksum = 0;
    std::uint64_t diagnosticId = 0;
    std::uint64_t firstSeenSerial = 0;
    std::uint64_t lastSeenSerial = 0;
    std::uint64_t firstChangeSerial = 0;
    std::uint64_t lastChangeSerial = 0;
    std::uint64_t samples = 0;
    std::uint64_t changes = 0;
    std::uint64_t rigidSamples = 0;
    std::uint64_t reportedSamples = 0;
    std::uint64_t reportedChanges = 0;
    std::uint32_t jointCount = 0;
    std::uint32_t paddedJointCount = 0;
    std::uint32_t firstNonRigidJoint =
        std::numeric_limits<std::uint32_t>::max();
    float rootTranslation[3]{};
    signed char pending = 0;
    bool lastPaletteRigid = false;
};

SkeletalDiagnostics g_skeletalDiagnostics;
SRWLOCK g_skeletalObservationLock = SRWLOCK_INIT;
std::atomic<std::uint64_t> g_skeletalLockContended{0};

// Pose uploads run on several renderer worker threads; count how often the
// shared observation lock is already held.
void AcquireSkeletalObservationLock() {
    if (!TryAcquireSRWLockExclusive(&g_skeletalObservationLock)) {
        g_skeletalLockContended.fetch_add(1, std::memory_order_relaxed);
        AcquireSRWLockExclusive(&g_skeletalObservationLock);
    }
}
std::array<SkeletalObservationTrack, kSkeletalTrackCapacity>
    g_skeletalObservationTracks{};
std::array<OwnerlessSkeletalTrack, kOwnerlessSkeletalTrackCapacity>
    g_ownerlessSkeletalTracks{};
std::atomic<std::uint64_t> g_nextSkeletalTrackId{1};
std::atomic<std::uint64_t> g_skeletalTrackCapacityMissCount{0};
std::atomic<std::uint64_t> g_ownerlessSkeletalTrackCapacityMissCount{0};
std::atomic<std::uint64_t> g_nextSkeletalDiagnosticsSerial{600};

struct SkeletalPreparedUpload {
    const void* renderModel = nullptr;
    const void* owner = nullptr;
    std::uint64_t diagnosticId = 0;
    std::uint64_t presentationSerial = 0;
    std::uint64_t outputChecksum = 0;
    double alpha = 0.0;
    bool firstPerson = false;
    bool cinematic = false;
};

constexpr double kAbProbeWarmupSeconds = 2.0;
constexpr double kAbProbeHistogramBinMilliseconds = 0.25;
constexpr std::size_t kAbProbeHistogramBinCount = 401;

struct InterpolationAbCounterSnapshot {
    std::uint64_t renderModelHookCalls = 0;
    std::uint64_t firstPersonRootCorrections = 0;
    std::uint64_t worldCandidates = 0;
    std::uint64_t worldAdjustments = 0;
    std::uint64_t skeletalHookCalls = 0;
    std::uint64_t skeletalPrepareCalls = 0;
    std::uint64_t skeletalAdjustments = 0;
    std::uint64_t forcedUploads = 0;
    std::uint64_t renderModelHookTicks = 0;
    std::uint64_t renderModelOriginalTicks = 0;
    std::uint64_t skeletalHookTicks = 0;
    std::uint64_t skeletalOriginalTicks = 0;
    std::uint64_t sourceFlushTicks = 0;
    std::uint64_t sourceFlushOriginalTicks = 0;
    std::uint64_t sourceWrites = 0;
};

struct InterpolationAbProbeState {
    bool capturing = false;
    bool hasPreviousFrame = false;
    bool samplingStarted = false;
    bool transformInterpolationEnabled = true;
    bool skeletalInterpolationEnabled = true;
    bool firstPersonHandsEnabled = true;
    bool sourceLevelTransforms = false;
    std::uint64_t segmentId = 0;
    std::uint64_t startPresentationSerial = 0;
    std::uint64_t sampleStartPresentationSerial = 0;
    std::uint64_t lastPresentationSerial = 0;
    LARGE_INTEGER frequency{};
    LARGE_INTEGER segmentStartCounter{};
    LARGE_INTEGER previousFrameCounter{};
    double previousScaledTime = 0.0;
    double previousSimulationTime = 0.0;
    std::uint64_t warmupFrames = 0;
    std::uint64_t sampledFrames = 0;
    std::uint64_t cadenceFrames = 0;
    std::uint64_t zeroTickFrames = 0;
    std::uint64_t oneTickFrames = 0;
    std::uint64_t multipleTickFrames = 0;
    std::uint64_t invalidCadenceFrames = 0;
    double sampledSeconds = 0.0;
    double simulationTicks = 0.0;
    double minimumFrameMilliseconds = std::numeric_limits<double>::infinity();
    double maximumFrameMilliseconds = 0.0;
    std::array<std::uint64_t, kAbProbeHistogramBinCount> histogram{};
    InterpolationAbCounterSnapshot countersAtStart{};
};

InterpolationAbProbeState g_interpolationAbProbe;
std::uint64_t g_nextInterpolationAbSegmentId = 1;

enum class AdaptiveInterpolationMode {
    All,
    TransformsOnly,
    Off,
};

constexpr double kAdaptiveWindowSimulationTicks = 180.0;
constexpr double kAdaptiveAllMinimumFps = 130.0;
constexpr double kAdaptiveTransformsMinimumFps = 125.0;
constexpr double kAdaptiveAllRecoveryFps = 150.0;
constexpr double kAdaptiveTransformsRecoveryFps = 135.0;
constexpr double kAdaptiveAllCostRefreshMinimumFps = 200.0;
constexpr double kAdaptiveTransformCostRefreshMinimumFps = 180.0;
constexpr double kAdaptiveCostRefreshFrameTimeRatio = 0.75;
constexpr std::uint32_t kAdaptiveRecoveryWindowCount = 2;

struct AdaptiveInterpolationGateState {
    AdaptiveInterpolationMode mode = AdaptiveInterpolationMode::All;
    bool initialized = false;
    bool learnSkeletalPenalty = false;
    bool learnTransformPenalty = false;
    double previousScaledTime = 0.0;
    double previousSimulationTime = 0.0;
    double windowFrames = 0.0;
    double windowSimulationTicks = 0.0;
    double lastAllFrameSeconds = 0.0;
    double lastTransformFrameSeconds = 0.0;
    double skeletalPenaltySeconds = 0.0;
    double transformPenaltySeconds = 0.0;
    double skeletalPenaltyReferenceFrameSeconds = 0.0;
    double transformPenaltyReferenceFrameSeconds = 0.0;
    bool hasSkeletalPenalty = false;
    bool hasTransformPenalty = false;
    std::uint32_t recoveryWindows = 0;
};

AdaptiveInterpolationGateState g_adaptiveInterpolationGate;

void BuildSiblingPath(wchar_t* output, std::size_t capacity, const wchar_t* filename) {
    output[0] = L'\0';
    GetModuleFileNameW(g_pluginModule, output, static_cast<DWORD>(capacity));
    wchar_t* slash = wcsrchr(output, L'\\');
    if (slash != nullptr) {
        slash[1] = L'\0';
    }
    wcscat_s(output, capacity, filename);
}

void Log(const char* format, ...) {
    char message[1024]{};
    va_list arguments;
    va_start(arguments, format);
    vsnprintf_s(message, sizeof(message), _TRUNCATE, format, arguments);
    va_end(arguments);

    OutputDebugStringA(message);
    OutputDebugStringA("\n");

    wchar_t path[MAX_PATH]{};
    BuildSiblingPath(path, MAX_PATH, L"d2-high-fps-fix.log");
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(file, message, static_cast<DWORD>(strlen(message)), &written, nullptr);
        static constexpr char newline[] = "\r\n";
        WriteFile(file, newline, 2, &written, nullptr);
        CloseHandle(file);
    }
}

void LoadConfiguration() {
    wchar_t path[MAX_PATH]{};
    BuildSiblingPath(path, MAX_PATH, L"d2-high-fps-fix.ini");
    g_unlockAbove120 = GetPrivateProfileIntW(
        L"Fix", L"UnlockAbove120", 0, path) != 0;
    g_maxFps = static_cast<int>(GetPrivateProfileIntW(
        L"Fix", L"MaxFPS", 0, path));
    if (g_maxFps < 0) {
        g_maxFps = 0;
    } else if (g_maxFps > 0) {
        g_maxFps = std::max(kMinimumMaxFps, std::min(kMaximumMaxFps, g_maxFps));
    }
    g_stabilizeMouseSensitivity = GetPrivateProfileIntW(
        L"Fix", L"StabilizeMouseSensitivity", 1, path) != 0;
    g_stabilizeFirstPersonHands = GetPrivateProfileIntW(
        L"Fix", L"StabilizeFirstPersonHands", 0, path) != 0;
    g_interpolateWorldTransforms = GetPrivateProfileIntW(
        L"Interpolation", L"WorldTransforms", 0, path) != 0;
    g_interpolateCinematicTransforms = GetPrivateProfileIntW(
        L"Interpolation", L"CinematicTransforms", 0, path) != 0;
    g_interpolateShadowTransforms = GetPrivateProfileIntW(
        L"Interpolation", L"ShadowTransforms", 0, path) != 0;
    g_interpolateFirstPersonSkeletons = GetPrivateProfileIntW(
        L"Interpolation", L"FirstPersonSkeletons", 0, path) != 0;
    g_interpolateWorldSkeletons = GetPrivateProfileIntW(
        L"Interpolation", L"WorldSkeletons", 0, path) != 0;
    g_interpolateCinematicSkeletons = GetPrivateProfileIntW(
        L"Interpolation", L"CinematicSkeletons", 0, path) != 0;
    g_enableAdaptiveInterpolation = GetPrivateProfileIntW(
        L"Interpolation", L"AdaptivePerformanceGate", 1, path) != 0;
    g_sourceLevelTransforms = GetPrivateProfileIntW(
        L"Interpolation", L"SourceLevelTransforms", 0, path) != 0;
    g_sourceLevelWrites = g_sourceLevelTransforms &&
        GetPrivateProfileIntW(L"Interpolation", L"SourceLevelWrites", 0, path) != 0;
    g_sourceLevelHands = g_sourceLevelWrites &&
        GetPrivateProfileIntW(L"Interpolation", L"SourceLevelHands", 1, path) != 0;
    g_screenParticleMode.store(g_sourceLevelHands
        ? std::max(0, std::min(4, static_cast<int>(GetPrivateProfileIntW(
              L"Interpolation", L"ScreenParticleCorrection", 3, path))))
        : 0, std::memory_order_relaxed);
    g_enableTelemetry = GetPrivateProfileIntW(
        L"Diagnostics", L"Telemetry", 0, path) != 0;
    g_enableInterpolationAbProbe = GetPrivateProfileIntW(
        L"Diagnostics", L"InterpolationABProbe", 0, path) != 0;
    g_toggleSounds = GetPrivateProfileIntW(
        L"Diagnostics", L"ToggleSounds", 1, path) != 0;
    g_overlay = GetPrivateProfileIntW(
        L"Diagnostics", L"Overlay", 0, path) != 0;
    g_crashLog = GetPrivateProfileIntW(
        L"Diagnostics", L"CrashLog", 0, path) != 0;
    g_devGuiScale = std::max(0, std::min(4, static_cast<int>(
        GetPrivateProfileIntW(L"Diagnostics", L"DevGuiScale", 0, path))));
    g_devGuiEscapeFallback = GetPrivateProfileIntW(
        L"Diagnostics", L"DevGuiEscapeFallback", 1, path) != 0;
    g_forceBloodEffect.store(GetPrivateProfileIntW(
        L"Diagnostics", L"ForceBloodEffect", 0, path) != 0, std::memory_order_relaxed);
    g_autoContinueLoadScreen = GetPrivateProfileIntW(
        L"Diagnostics", L"AutoContinueLoadScreen", 0, path) != 0;
    if (g_autoContinueLoadScreen && !g_sourceLevelTransforms) {
        g_sourceLevelTransforms = true;
        g_flushHookOnly = true;
    }
    g_autoAbSchedule = GetPrivateProfileIntW(
        L"Diagnostics", L"AutoABSchedule", 0, path) != 0;
    g_autoAbSegmentSeconds = std::max(5, std::min(120, static_cast<int>(
        GetPrivateProfileIntW(L"Diagnostics", L"AutoABSegmentSeconds", 20, path))));
    g_autoAbRounds = std::max(1, std::min(10, static_cast<int>(
        GetPrivateProfileIntW(L"Diagnostics", L"AutoABRounds", 2, path))));
    g_autoAbQuitWhenDone = GetPrivateProfileIntW(
        L"Diagnostics", L"AutoABQuitWhenDone", 0, path) != 0;
    if (g_autoAbSchedule) {
        Log("Configuration: AutoABSchedule=1, AutoABSegmentSeconds=%d, "
            "AutoABRounds=%d, AutoABQuitWhenDone=%u.", g_autoAbSegmentSeconds,
            g_autoAbRounds, g_autoAbQuitWhenDone ? 1U : 0U);
    }
    Log("Configuration: UnlockAbove120=%u, MaxFPS=%d, StabilizeMouseSensitivity=%u, "
        "StabilizeFirstPersonHands=%u, WorldTransforms=%u, "
        "CinematicTransforms=%u, ShadowTransforms=%u, "
        "FirstPersonSkeletons=%u, WorldSkeletons=%u, "
        "CinematicSkeletons=%u, AdaptivePerformanceGate=%u, Telemetry=%u, "
        "InterpolationABProbe=%u.",
        g_unlockAbove120 ? 1U : 0U, g_maxFps,
        g_stabilizeMouseSensitivity ? 1U : 0U,
        g_stabilizeFirstPersonHands ? 1U : 0U,
        g_interpolateWorldTransforms ? 1U : 0U,
        g_interpolateCinematicTransforms ? 1U : 0U,
        g_interpolateShadowTransforms ? 1U : 0U,
        g_interpolateFirstPersonSkeletons ? 1U : 0U,
        g_interpolateWorldSkeletons ? 1U : 0U,
        g_interpolateCinematicSkeletons ? 1U : 0U,
        g_enableAdaptiveInterpolation ? 1U : 0U,
        g_enableTelemetry ? 1U : 0U,
        g_enableInterpolationAbProbe ? 1U : 0U);
    Log("Configuration: SourceLevelTransforms=%u, SourceLevelWrites=%u, "
        "SourceLevelHands=%u, ToggleSounds=%u, Overlay=%u, "
        "AutoContinueLoadScreen=%u.",
        g_sourceLevelTransforms ? 1U : 0U, g_sourceLevelWrites ? 1U : 0U,
        g_sourceLevelHands ? 1U : 0U, g_toggleSounds ? 1U : 0U,
        g_overlay ? 1U : 0U, g_autoContinueLoadScreen ? 1U : 0U);
    if (g_enableInterpolationAbProbe) {
        Log("A/B controls: Ctrl+F11 starts/stops a clean measurement segment; "
            "F11 toggles all configured interpolation; Alt+F11 cycles all, "
            "transforms-only, skeletons-only, and off; Shift+F11 toggles only "
            "first-person root stabilization. Camera prediction, mouse "
            "stabilization, and the FPS unlock remain unchanged.");
        if (g_sourceLevelWrites) {
            Log("A/B control: Ctrl+Shift+F11 switches world transforms between "
                "the source-level (render-world flush) and per-draw methods.");
        }
        if (g_enableAdaptiveInterpolation) {
            Log("Adaptive interpolation is suspended while "
                "InterpolationABProbe=1 so benchmark profiles remain fixed.");
        }
    } else if (g_enableAdaptiveInterpolation) {
        Log("Adaptive interpolation gate enabled: skeletal interpolation is "
            "shed before transform interpolation, with cadence hysteresis and "
            "measured-cost recovery.");
    }
}

bool ComputeFileSha256(const wchar_t* path, unsigned char output[32]) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD hashLength = 0;
    DWORD resultLength = 0;
    std::vector<unsigned char> hashObject;
    bool success = false;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength),
                          &resultLength, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                          reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength),
                          &resultLength, 0) < 0 ||
        hashLength != 32) {
        goto cleanup;
    }

    hashObject.resize(objectLength);
    if (BCryptCreateHash(algorithm, &hash, hashObject.data(), objectLength,
                         nullptr, 0, 0) < 0) {
        goto cleanup;
    }

    {
        std::vector<unsigned char> buffer(1024 * 1024);
        for (;;) {
            DWORD bytesRead = 0;
            if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr)) {
                goto cleanup;
            }
            if (bytesRead == 0) {
                break;
            }
            if (BCryptHashData(hash, buffer.data(), bytesRead, 0) < 0) {
                goto cleanup;
            }
        }
    }

    success = BCryptFinishHash(hash, output, 32, 0) >= 0;

cleanup:
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    if (algorithm != nullptr) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    CloseHandle(file);
    return success;
}

struct ExecutableImageLayout {
    const IMAGE_NT_HEADERS64* headers = nullptr;
    const IMAGE_SECTION_HEADER* sections = nullptr;
    std::uint16_t sectionCount = 0;
    std::uint32_t imageSize = 0;
};

const IMAGE_SECTION_HEADER* FindImageSection(
    const ExecutableImageLayout& image, std::uintptr_t rva,
    std::size_t size) {
    if (size == 0 || rva >= image.imageSize ||
        size > static_cast<std::size_t>(image.imageSize - rva)) {
        return nullptr;
    }

    for (std::uint16_t index = 0; index < image.sectionCount; ++index) {
        const IMAGE_SECTION_HEADER& section = image.sections[index];
        const std::uintptr_t start = section.VirtualAddress;
        const std::uintptr_t span = std::max<std::uintptr_t>(
            section.Misc.VirtualSize, section.SizeOfRawData);
        if (rva >= start && rva - start < span &&
            size <= span - static_cast<std::size_t>(rva - start)) {
            return &section;
        }
    }
    return nullptr;
}

bool ReadExecutableImageLayout(ExecutableImageLayout& image) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_executableBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        dos->e_lfanew > 0x100000) {
        Log("Executable does not have a valid DOS/PE header; patch not installed.");
        return false;
    }

    const auto* headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        g_executableBase + static_cast<std::uintptr_t>(dos->e_lfanew));
    if (headers->Signature != IMAGE_NT_SIGNATURE ||
        headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        headers->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        headers->FileHeader.NumberOfSections == 0 ||
        headers->FileHeader.NumberOfSections > 96 ||
        headers->OptionalHeader.SizeOfImage == 0) {
        Log("Executable is not a structurally valid PE32+ x64 image; patch not installed.");
        return false;
    }

    image.headers = headers;
    image.sections = IMAGE_FIRST_SECTION(headers);
    image.sectionCount = headers->FileHeader.NumberOfSections;
    image.imageSize = headers->OptionalHeader.SizeOfImage;
    return true;
}

bool ValidateImageRange(const ExecutableImageLayout& image,
                        std::uintptr_t rva, std::size_t size,
                        DWORD requiredCharacteristics,
                        DWORD forbiddenCharacteristics,
                        const char* description) {
    const IMAGE_SECTION_HEADER* section = FindImageSection(image, rva, size);
    if (section == nullptr ||
        (section->Characteristics & requiredCharacteristics) != requiredCharacteristics ||
        (section->Characteristics & forbiddenCharacteristics) != 0) {
        Log("Executable layout check failed for %s at RVA 0x%llX; patch not installed.",
            description, static_cast<unsigned long long>(rva));
        return false;
    }
    return true;
}

bool ValidateCodeRange(const ExecutableImageLayout& image,
                       std::uintptr_t rva, std::size_t size,
                       const char* description) {
    return ValidateImageRange(
        image, rva, size, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        IMAGE_SCN_MEM_WRITE, description);
}

bool ValidateMutableDataRange(const ExecutableImageLayout& image,
                              std::uintptr_t rva, std::size_t size,
                              const char* description) {
    return ValidateImageRange(
        image, rva, size, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        IMAGE_SCN_MEM_EXECUTE, description);
}

bool ValidateVtable(const ExecutableImageLayout& image,
                    const VtableLayout& vtable,
                    const char* description) {
    const std::size_t entriesToValidate = vtable.targets.size();
    if (!ValidateImageRange(image, vtable.rva,
                            entriesToValidate * sizeof(std::uintptr_t),
                            IMAGE_SCN_MEM_READ,
                            IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
                            description)) {
        return false;
    }

    const auto* entries = reinterpret_cast<const std::uintptr_t*>(
        g_executableBase + vtable.rva);
    for (std::size_t index = 0; index < entriesToValidate; ++index) {
        if (entries[index] < g_executableBase) {
            Log("Executable layout check failed for %s entry %llu; patch not installed.",
                description, static_cast<unsigned long long>(index));
            return false;
        }
        const std::uintptr_t targetRva = entries[index] - g_executableBase;
        if (targetRva != vtable.targets[index] ||
            !ValidateCodeRange(image, targetRva, 1, description)) {
            Log("Executable call relationship check failed for %s entry %llu; "
                "patch not installed.", description,
                static_cast<unsigned long long>(index));
            return false;
        }
    }
    return true;
}

bool ValidateHookSite(const ExecutableImageLayout& image,
                      const HookSiteLayout& site,
                      const char* description) {
    return site.length >= 14 && site.length <= site.bytes.size() &&
           ValidateCodeRange(image, site.rva, site.length, description) &&
           memcmp(reinterpret_cast<const void*>(g_executableBase + site.rva),
                  site.bytes.data(), site.length) == 0;
}

bool ValidateViewCopyCallRelationship(const ExecutableImageLayout& image) {
    if (!ValidateCodeRange(image, g_layout->copyCallsiteRva, 5,
                           "renderer view-copy call site") ||
        !ValidateCodeRange(image, g_layout->copyViewRva, sizeof(kExpectedCopyViewBytes),
                           "renderer view-copy target")) {
        return false;
    }

    const auto* callsite = reinterpret_cast<const unsigned char*>(
        g_executableBase + g_layout->copyCallsiteRva);
    if (callsite[0] != 0xE8) {
        Log("Renderer view-copy site is not a direct call; patch not installed.");
        return false;
    }
    std::int32_t displacement = 0;
    memcpy(&displacement, callsite + 1, sizeof(displacement));
    const std::uintptr_t target = static_cast<std::uintptr_t>(
        static_cast<std::int64_t>(g_executableBase + g_layout->copyCallsiteRva + 5) +
        displacement);
    if (target != g_executableBase + g_layout->copyViewRva ||
        memcmp(reinterpret_cast<const void*>(g_executableBase + g_layout->copyViewRva),
               kExpectedCopyViewBytes, sizeof(kExpectedCopyViewBytes)) != 0) {
        Log("Renderer view-copy call relationship does not match the supported layout; "
            "patch not installed.");
        return false;
    }
    return true;
}

bool ValidateVtableSlot(const ExecutableImageLayout& image,
                        std::uintptr_t vtableRva, std::size_t slotOffset,
                        std::uintptr_t expectedTarget,
                        const std::array<unsigned char, 16>& expectedBytes,
                        const char* description) {
    if (!ValidateImageRange(image, vtableRva + slotOffset, sizeof(std::uintptr_t),
                            IMAGE_SCN_MEM_READ,
                            IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
                            description)) {
        return false;
    }
    std::uintptr_t entry = 0;
    memcpy(&entry, reinterpret_cast<const void*>(g_executableBase + vtableRva + slotOffset),
           sizeof(entry));
    if (entry != g_executableBase + expectedTarget ||
        !ValidateCodeRange(image, expectedTarget, expectedBytes.size(), description) ||
        memcmp(reinterpret_cast<const void*>(g_executableBase + expectedTarget),
               expectedBytes.data(), expectedBytes.size()) != 0) {
        Log("Executable call relationship check failed for %s (vtable RVA 0x%llX "
            "slot 0x%llX); patch not installed.", description,
            static_cast<unsigned long long>(vtableRva),
            static_cast<unsigned long long>(slotOffset));
        return false;
    }
    return true;
}

bool ValidateCodeSignature(const ExecutableImageLayout& image, std::uintptr_t rva,
                           const std::array<unsigned char, 16>& bytes,
                           const char* description) {
    return ValidateCodeRange(image, rva, bytes.size(), description) &&
           memcmp(reinterpret_cast<const void*>(g_executableBase + rva), bytes.data(),
                  bytes.size()) == 0;
}

bool ValidateSourceLevelLayout(const ExecutableImageLayout& image) {
    const GameBuildLayout& layout = *g_layout;
    if (!ValidateVtable(image, layout.renderWorldVtable, "render-world vtable") ||
        !ValidateVtableSlot(image, layout.renderWorldVtable.rva,
                            layout.renderWorldFlushSlot, layout.renderWorldFlushRva,
                            layout.renderWorldFlushBytes, "render-world flush slot")) {
        return false;
    }
    for (const VtableLayout* vtable : {&layout.renderModelStaticVtable,
                                       &layout.skinnedModelVtable}) {
        if (!ValidateVtable(image, *vtable, "render-model vtable") ||
            !ValidateVtableSlot(image, vtable->rva, layout.renderModelMarkDirtySlot,
                                layout.renderModelMarkDirtyRva,
                                layout.renderModelMarkDirtyBytes,
                                "render-model MarkDirty slot") ||
            !ValidateVtableSlot(image, vtable->rva, layout.renderModelCommitSlot,
                                layout.renderModelCommitRva,
                                layout.renderModelCommitBytes,
                                "render-model Commit slot")) {
            return false;
        }
    }
    return ValidateVtable(image, layout.assemblyVtable, "assembly render-model vtable") &&
           ValidateVtableSlot(image, layout.assemblyVtable.rva,
                              layout.renderModelMarkDirtySlot,
                              layout.assemblyMarkDirtyRva,
                              layout.assemblyMarkDirtyBytes,
                              "assembly MarkDirty slot") &&
           ValidateVtableSlot(image, layout.assemblyVtable.rva,
                              layout.renderModelCommitSlot,
                              layout.renderModelCommitRva,
                              layout.renderModelCommitBytes,
                              "assembly Commit slot");
}

bool ValidateHookSignatures(const ExecutableImageLayout& image) {
    const bool rendererModelFeatures =
        g_stabilizeFirstPersonHands || g_interpolateWorldTransforms ||
        g_interpolateCinematicTransforms;
    const bool skeletalFeatures =
        g_interpolateWorldSkeletons || g_interpolateFirstPersonSkeletons ||
        g_interpolateCinematicSkeletons;

    if (rendererModelFeatures) {
        if (!ValidateHookSite(image, g_layout->renderModelGpuCopy,
                              "renderer model GPU-copy hook") ||
            !ValidateVtable(image, g_layout->renderModelStaticVtable,
                            "static render-model vtable") ||
            !ValidateVtable(image, g_layout->skinnedModelVtable,
                            "skinned render-model vtable")) {
            Log("Renderer model correction layout/signature validation failed; "
                "patch not installed.");
            return false;
        }
    }

    if (skeletalFeatures) {
        if (!ValidateHookSite(image, g_layout->skinnedPoseUpload,
                              "skinned-pose upload hook") ||
            !ValidateVtable(image, g_layout->skinnedModelVtable,
                            "skinned render-model vtable")) {
            Log("Skeletal correction layout/signature validation failed; "
                "patch not installed.");
            return false;
        }
    }

    if (g_interpolateShadowTransforms && g_layout->shadowCasterBuildSupported) {
        for (const HookSiteLayout& site : g_layout->shadowCasterBuild) {
            if (!ValidateHookSite(image, site, "shadow caster-build hook")) {
                Log("Shadow correction layout/signature validation failed; "
                    "patch not installed.");
                return false;
            }
        }
    }

    if (g_sourceLevelTransforms && g_layout->sourceLevelSupported &&
        !ValidateSourceLevelLayout(image)) {
        Log("Source-level transform layout/signature validation failed; "
            "patch not installed.");
        return false;
    }
    return true;
}

bool ValidateSelectedLayout(const ExecutableImageLayout& image) {
    return ValidateViewCopyCallRelationship(image) &&
           ValidateMutableDataRange(image, g_layout->gamePointerRva,
                                    sizeof(std::uintptr_t),
                                    "idGameLocal pointer") &&
           ValidateVtable(image, g_layout->gameVtable, "idGameLocal vtable") &&
           (!g_unlockAbove120 ||
            (ValidateMutableDataRange(image, g_layout->frameSpinningRva, sizeof(LONG),
                                      "frame-spinning cvar cache") &&
             ValidateMutableDataRange(image, g_layout->tripleBufferingRva, sizeof(LONG),
                                      "triple-buffering cvar cache"))) &&
           (!g_stabilizeMouseSensitivity ||
            ValidateMutableDataRange(image, g_layout->fixMouseSensibilityRva,
                                     sizeof(LONG),
                                     "mouse-sensitivity cvar cache")) &&
           ValidateHookSignatures(image);
}

// Returns the layout whose SHA-256 matches the executable, or nullptr when the
// hash is unknown or could not be computed.
const GameBuildLayout* IdentifyExecutableByHash(const wchar_t* path) {
    unsigned char actualHash[32]{};
    if (!ComputeFileSha256(path, actualHash)) {
        Log("Unable to hash Dishonored2.exe; continuing with runtime layout validation.");
        return nullptr;
    }

    for (const GameBuildLayout* layout : kKnownLayouts) {
        if (memcmp(actualHash, layout->sha256.data(), sizeof(actualHash)) == 0) {
            Log("Recognized the validated %s executable SHA-256.", layout->name);
            return layout;
        }
    }

    char hashText[65]{};
    for (std::size_t index = 0; index < sizeof(actualHash); ++index) {
        sprintf_s(hashText + index * 2, sizeof(hashText) - index * 2,
                  "%02X", actualHash[index]);
    }
    Log("Executable SHA-256 %s is not a reference hash; attempting strict "
        "runtime layout validation.", hashText);
    return nullptr;
}

bool VerifyExecutableLayout() {
    wchar_t path[MAX_PATH]{};
    const DWORD pathLength = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (pathLength == 0 || pathLength >= MAX_PATH) {
        Log("Unable to obtain the executable path; patch not installed.");
        return false;
    }

    const wchar_t* filename = wcsrchr(path, L'\\');
    filename = filename == nullptr ? path : filename + 1;
    if (_wcsicmp(filename, L"Dishonored2.exe") != 0) {
        Log("Host executable is not Dishonored2.exe; patch not installed.");
        return false;
    }

    const GameBuildLayout* recognized = IdentifyExecutableByHash(path);

    ExecutableImageLayout image{};
    if (!ReadExecutableImageLayout(image)) {
        return false;
    }

    // A recognized hash pins the layout. Otherwise every known layout is tried
    // in turn, and each must pass the full strict validation on its own.
    const GameBuildLayout* selected = nullptr;
    for (const GameBuildLayout* layout : kKnownLayouts) {
        if (recognized != nullptr && layout != recognized) {
            continue;
        }
        if (recognized == nullptr) {
            Log("Trying the %s layout.", layout->name);
        }
        g_layout = layout;
        if (ValidateSelectedLayout(image)) {
            selected = layout;
            break;
        }
    }
    if (selected == nullptr) {
        g_layout = &kGogLayout;
        return false;
    }

    if (g_interpolateShadowTransforms && !selected->shadowCasterBuildSupported) {
        g_interpolateShadowTransforms = false;
        Log("ShadowTransforms is not yet supported on the %s executable; "
            "shadow-transform interpolation was disabled.", selected->name);
    }
    if (g_autoContinueLoadScreen &&
        (!selected->autoContinueSupported || !g_sourceLevelTransforms ||
         !ValidateMutableDataRange(image, selected->commonObjectRva, 0x2000,
                                   "idCommonLocal object"))) {
        g_autoContinueLoadScreen = false;
        Log("AutoContinueLoadScreen is not supported on this executable; it was "
            "disabled.");
    }
    if (g_sourceLevelTransforms && !selected->sourceLevelSupported) {
        g_sourceLevelTransforms = false;
        g_sourceLevelWrites = false;
        g_sourceLevelHands = false;
        Log("SourceLevelTransforms is not supported on the %s executable; the "
            "source-level layer was disabled and the per-draw path is used.",
            selected->name);
    }

    Log("Executable passed strict runtime layout validation as %s; all enabled "
        "correction paths were validated before hook installation.",
        selected->name);
    return true;
}

double Clamp(double value, double minimum, double maximum) {
    return std::max(minimum, std::min(maximum, value));
}

bool IsFinite(const Transform& transform) {
    if (!std::isfinite(transform.origin.x) || !std::isfinite(transform.origin.y) ||
        !std::isfinite(transform.origin.z)) {
        return false;
    }
    for (float value : transform.axis) {
        if (!std::isfinite(value)) {
            return false;
        }
    }
    return true;
}

Quaternion Normalize(Quaternion value) {
    const double length = std::sqrt(value.w * value.w + value.x * value.x +
                                    value.y * value.y + value.z * value.z);
    if (!(length > 1.0e-12) || !std::isfinite(length)) {
        return {1.0, 0.0, 0.0, 0.0};
    }
    value.w /= length;
    value.x /= length;
    value.y /= length;
    value.z /= length;
    return value;
}

double QuaternionDot(const Quaternion& a, const Quaternion& b) {
    return a.w * b.w + a.x * b.x + a.y * b.y + a.z * b.z;
}

Quaternion MatrixToQuaternion(const float matrix[9]) {
    Quaternion result{};
    const double m00 = matrix[0];
    const double m01 = matrix[1];
    const double m02 = matrix[2];
    const double m10 = matrix[3];
    const double m11 = matrix[4];
    const double m12 = matrix[5];
    const double m20 = matrix[6];
    const double m21 = matrix[7];
    const double m22 = matrix[8];
    const double trace = m00 + m11 + m22;

    if (trace > 0.0) {
        const double scale = std::sqrt(trace + 1.0) * 2.0;
        result.w = 0.25 * scale;
        result.x = (m21 - m12) / scale;
        result.y = (m02 - m20) / scale;
        result.z = (m10 - m01) / scale;
    } else if (m00 > m11 && m00 > m22) {
        const double scale = std::sqrt(1.0 + m00 - m11 - m22) * 2.0;
        result.w = (m21 - m12) / scale;
        result.x = 0.25 * scale;
        result.y = (m01 + m10) / scale;
        result.z = (m02 + m20) / scale;
    } else if (m11 > m22) {
        const double scale = std::sqrt(1.0 + m11 - m00 - m22) * 2.0;
        result.w = (m02 - m20) / scale;
        result.x = (m01 + m10) / scale;
        result.y = 0.25 * scale;
        result.z = (m12 + m21) / scale;
    } else {
        const double scale = std::sqrt(1.0 + m22 - m00 - m11) * 2.0;
        result.w = (m10 - m01) / scale;
        result.x = (m02 + m20) / scale;
        result.y = (m12 + m21) / scale;
        result.z = 0.25 * scale;
    }
    return Normalize(result);
}

void QuaternionToMatrix(const Quaternion& input, float matrix[9]) {
    const Quaternion q = Normalize(input);
    const double xx = q.x * q.x;
    const double yy = q.y * q.y;
    const double zz = q.z * q.z;
    const double xy = q.x * q.y;
    const double xz = q.x * q.z;
    const double yz = q.y * q.z;
    const double wx = q.w * q.x;
    const double wy = q.w * q.y;
    const double wz = q.w * q.z;

    matrix[0] = static_cast<float>(1.0 - 2.0 * (yy + zz));
    matrix[1] = static_cast<float>(2.0 * (xy - wz));
    matrix[2] = static_cast<float>(2.0 * (xz + wy));
    matrix[3] = static_cast<float>(2.0 * (xy + wz));
    matrix[4] = static_cast<float>(1.0 - 2.0 * (xx + zz));
    matrix[5] = static_cast<float>(2.0 * (yz - wx));
    matrix[6] = static_cast<float>(2.0 * (xz - wy));
    matrix[7] = static_cast<float>(2.0 * (yz + wx));
    matrix[8] = static_cast<float>(1.0 - 2.0 * (xx + yy));
}

Quaternion SlerpUnclamped(Quaternion from, Quaternion to, double alpha) {
    from = Normalize(from);
    to = Normalize(to);
    double dot = QuaternionDot(from, to);
    if (dot < 0.0) {
        to = {-to.w, -to.x, -to.y, -to.z};
        dot = -dot;
    }
    dot = Clamp(dot, -1.0, 1.0);

    if (dot > 0.9995) {
        return Normalize({
            from.w + alpha * (to.w - from.w),
            from.x + alpha * (to.x - from.x),
            from.y + alpha * (to.y - from.y),
            from.z + alpha * (to.z - from.z),
        });
    }

    const double theta = std::acos(dot);
    const double sine = std::sin(theta);
    if (std::abs(sine) < 1.0e-12) {
        return from;
    }
    const double fromWeight = std::sin((1.0 - alpha) * theta) / sine;
    const double toWeight = std::sin(alpha * theta) / sine;
    return Normalize({
        from.w * fromWeight + to.w * toWeight,
        from.x * fromWeight + to.x * toWeight,
        from.y * fromWeight + to.y * toWeight,
        from.z * fromWeight + to.z * toWeight,
    });
}

double PositionDistance(const Transform& a, const Transform& b) {
    const double x = b.origin.x - a.origin.x;
    const double y = b.origin.y - a.origin.y;
    const double z = b.origin.z - a.origin.z;
    return std::sqrt(x * x + y * y + z * z);
}

double RotationDistanceDegrees(const Transform& a, const Transform& b) {
    const Quaternion qa = MatrixToQuaternion(a.axis);
    const Quaternion qb = MatrixToQuaternion(b.axis);
    const double dot = Clamp(std::abs(QuaternionDot(qa, qb)), 0.0, 1.0);
    return 2.0 * std::acos(dot) * 180.0 / kPi;
}

Transform ReadTransform(const void* view) {
    const auto* bytes = static_cast<const unsigned char*>(view);
    Transform result{};
    float origin[3]{};
    memcpy(origin, bytes + kViewOriginOffset, sizeof(origin));
    result.origin = {origin[0], origin[1], origin[2]};
    memcpy(result.axis, bytes + kViewAxisOffset, sizeof(result.axis));
    return result;
}

bool OriginsAreDuplicated(const void* view) {
    const auto* bytes = static_cast<const unsigned char*>(view);
    float primary[3]{};
    float duplicate[3]{};
    memcpy(primary, bytes + kViewOriginOffset, sizeof(primary));
    memcpy(duplicate, bytes + kViewOriginDuplicateOffset, sizeof(duplicate));
    return memcmp(primary, duplicate, sizeof(primary)) == 0;
}

void WriteTransform(void* view, const Transform& transform) {
    auto* bytes = static_cast<unsigned char*>(view);
    const float origin[3] = {
        static_cast<float>(transform.origin.x),
        static_cast<float>(transform.origin.y),
        static_cast<float>(transform.origin.z),
    };
    memcpy(bytes + kViewOriginOffset, origin, sizeof(origin));
    memcpy(bytes + kViewOriginDuplicateOffset, origin, sizeof(origin));
    memcpy(bytes + kViewAxisOffset, transform.axis, sizeof(transform.axis));
}

bool IsReadableMemory(const void* address, std::size_t size) {
    if (address == nullptr || size == 0) {
        return false;
    }
    const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(address);
    if (start > std::numeric_limits<std::uintptr_t>::max() - size) {
        return false;
    }
    MEMORY_BASIC_INFORMATION information{};
    if (VirtualQuery(address, &information, sizeof(information)) == 0 ||
        information.State != MEM_COMMIT ||
        (information.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
        return false;
    }
    const DWORD protection = information.Protect & 0xFF;
    const bool readable = protection == PAGE_READONLY || protection == PAGE_READWRITE ||
                          protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE_READ ||
                          protection == PAGE_EXECUTE_READWRITE ||
                          protection == PAGE_EXECUTE_WRITECOPY;
    const std::uintptr_t regionEnd =
        reinterpret_cast<std::uintptr_t>(information.BaseAddress) + information.RegionSize;
    return readable && start + size <= regionEnd;
}

// Hot hook paths validate the same few heap regions on every call. Each
// thread remembers recently validated committed, readable regions and accepts
// addresses inside them for a short presentation-frame window instead of
// issuing a VirtualQuery per check.
constexpr std::size_t kReadableRegionCacheSize = 8;
constexpr std::uint64_t kReadableRegionCacheFrames = 16;

struct ReadableRegionCacheEntry {
    std::uintptr_t start = 0;
    std::uintptr_t end = 0;
    std::uint64_t serial = 0;
};

thread_local std::array<ReadableRegionCacheEntry, kReadableRegionCacheSize>
    t_readableRegions{};
thread_local std::size_t t_readableRegionNext = 0;

bool IsReadableMemoryCached(const void* address, std::size_t size) {
    if (address == nullptr || size == 0) {
        return false;
    }
    const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(address);
    if (start > std::numeric_limits<std::uintptr_t>::max() - size) {
        return false;
    }
    const std::uintptr_t end = start + size;
    const std::uint64_t serial = g_presentationSerial.load(std::memory_order_relaxed);
    for (const ReadableRegionCacheEntry& entry : t_readableRegions) {
        if (start >= entry.start && end <= entry.end &&
            serial - entry.serial <= kReadableRegionCacheFrames) {
            return true;
        }
    }
    MEMORY_BASIC_INFORMATION information{};
    if (VirtualQuery(address, &information, sizeof(information)) == 0 ||
        information.State != MEM_COMMIT ||
        (information.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
        return false;
    }
    const DWORD protection = information.Protect & 0xFF;
    const bool readable = protection == PAGE_READONLY || protection == PAGE_READWRITE ||
                          protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE_READ ||
                          protection == PAGE_EXECUTE_READWRITE ||
                          protection == PAGE_EXECUTE_WRITECOPY;
    const std::uintptr_t regionStart =
        reinterpret_cast<std::uintptr_t>(information.BaseAddress);
    const std::uintptr_t regionEnd = regionStart + information.RegionSize;
    if (!readable || end > regionEnd) {
        return false;
    }
    ReadableRegionCacheEntry& slot =
        t_readableRegions[t_readableRegionNext++ % kReadableRegionCacheSize];
    slot.start = regionStart;
    slot.end = regionEnd;
    slot.serial = serial;
    return true;
}

bool IsExecutableMemory(const void* address) {
    MEMORY_BASIC_INFORMATION information{};
    if (address == nullptr || VirtualQuery(address, &information, sizeof(information)) == 0 ||
        information.State != MEM_COMMIT ||
        (information.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
        return false;
    }
    const DWORD protection = information.Protect & 0xFF;
    return protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
           protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
}

bool IsPlayerDepthHackObject(const void* object) {
    if (!IsReadableMemory(object, kRenderModelDepthHackOffset + sizeof(float))) {
        return false;
    }
    float depthHack = 0.0f;
    memcpy(&depthHack, static_cast<const unsigned char*>(object) +
                           kRenderModelDepthHackOffset, sizeof(depthHack));
    return std::isfinite(depthHack) && depthHack > 0.0f && depthHack < 100.0f;
}

Matrix4 MultiplyMatrices4(const Matrix4& left, const Matrix4& right) {
    Matrix4 result{};
    for (int row = 0; row < 4; ++row) {
        for (int column = 0; column < 4; ++column) {
            double value = 0.0;
            for (int inner = 0; inner < 4; ++inner) {
                value += static_cast<double>(left.values[row * 4 + inner]) *
                         static_cast<double>(right.values[inner * 4 + column]);
            }
            result.values[row * 4 + column] = static_cast<float>(value);
        }
    }
    return result;
}

bool IsFinite(const Matrix4& matrix) {
    for (float value : matrix.values) {
        if (!std::isfinite(value)) {
            return false;
        }
    }
    return true;
}

Matrix4 TransformMatrix(const Transform& transform) {
    Matrix4 result{};
    result.values[0] = transform.axis[0];
    result.values[1] = transform.axis[3];
    result.values[2] = transform.axis[6];
    result.values[3] = static_cast<float>(transform.origin.x);
    result.values[4] = transform.axis[1];
    result.values[5] = transform.axis[4];
    result.values[6] = transform.axis[7];
    result.values[7] = static_cast<float>(transform.origin.y);
    result.values[8] = transform.axis[2];
    result.values[9] = transform.axis[5];
    result.values[10] = transform.axis[8];
    result.values[11] = static_cast<float>(transform.origin.z);
    result.values[15] = 1.0f;
    return result;
}

Matrix4 InvertRigidTransform(const Matrix4& matrix) {
    Matrix4 result{};
    for (int row = 0; row < 3; ++row) {
        for (int column = 0; column < 3; ++column) {
            result.values[row * 4 + column] = matrix.values[column * 4 + row];
        }
        result.values[row * 4 + 3] =
            -(result.values[row * 4] * matrix.values[3] +
              result.values[row * 4 + 1] * matrix.values[7] +
              result.values[row * 4 + 2] * matrix.values[11]);
    }
    result.values[15] = 1.0f;
    return result;
}

bool BuildCameraCorrection(const Transform& rawCamera, const Transform& outputCamera,
                           Matrix4& delta, Matrix4& inverseDelta) {
    if (!IsFinite(rawCamera) || !IsFinite(outputCamera) ||
        PositionDistance(rawCamera, outputCamera) > kMaximumPositionJump ||
        RotationDistanceDegrees(rawCamera, outputCamera) > kMaximumRotationJumpDegrees) {
        return false;
    }
    const Matrix4 raw = TransformMatrix(rawCamera);
    const Matrix4 output = TransformMatrix(outputCamera);
    const Matrix4 inverseRaw = InvertRigidTransform(raw);
    const Matrix4 inverseOutput = InvertRigidTransform(output);
    delta = MultiplyMatrices4(output, inverseRaw);
    inverseDelta = MultiplyMatrices4(raw, inverseOutput);
    return IsFinite(delta) && IsFinite(inverseDelta);
}

void PublishRenderCorrection(const Transform& rawCamera, const Transform& outputCamera) {
    Matrix4 delta{};
    Matrix4 inverseDelta{};
    const bool valid = BuildCameraCorrection(rawCamera, outputCamera, delta, inverseDelta);

    AcquireSRWLockExclusive(&g_renderCorrectionLock);
    g_renderCorrection.previousDelta = g_renderCorrection.currentDelta;
    g_renderCorrection.previousInverseDelta = g_renderCorrection.currentInverseDelta;
    g_renderCorrection.previousValid = g_renderCorrection.currentValid;
    g_renderCorrection.currentDelta = delta;
    g_renderCorrection.currentInverseDelta = inverseDelta;
    g_renderCorrection.currentValid = valid;
    ++g_renderCorrection.serial;
    ReleaseSRWLockExclusive(&g_renderCorrectionLock);
}

bool ReadRenderCorrection(RenderCorrectionState& state) {
    AcquireSRWLockShared(&g_renderCorrectionLock);
    state = g_renderCorrection;
    ReleaseSRWLockShared(&g_renderCorrectionLock);
    if (!state.currentValid) {
        return false;
    }
    if (!state.previousValid) {
        state.previousDelta = state.currentDelta;
        state.previousInverseDelta = state.currentInverseDelta;
        state.previousValid = true;
    }
    return true;
}

Matrix4 ReadMatrix(const unsigned char* object, std::size_t offset) {
    Matrix4 result{};
    memcpy(&result, object + offset, sizeof(result));
    return result;
}

void WriteMatrix(unsigned char* object, std::size_t offset, const Matrix4& matrix) {
    memcpy(object + offset, &matrix, sizeof(matrix));
}

bool CorrectMatrixSet(unsigned char* object,
                      std::size_t modelOffset, std::size_t inverseModelOffset,
                      std::size_t modelViewOffset, std::size_t modelViewProjectionOffset,
                      const Matrix4& delta, const Matrix4& inverseDelta) {
    const Matrix4 model = ReadMatrix(object, modelOffset);
    const Matrix4 inverseModel = ReadMatrix(object, inverseModelOffset);
    const Matrix4 modelView = ReadMatrix(object, modelViewOffset);
    const Matrix4 modelViewProjection = ReadMatrix(object, modelViewProjectionOffset);
    if (!IsFinite(model) || !IsFinite(inverseModel) || !IsFinite(modelView) ||
        !IsFinite(modelViewProjection)) {
        return false;
    }

    const Matrix4 correctedModel = MultiplyMatrices4(delta, model);
    const Matrix4 correctedInverseModel = MultiplyMatrices4(inverseModel, inverseDelta);
    const Matrix4 modelToCorrectedModel = MultiplyMatrices4(inverseModel, correctedModel);
    const Matrix4 correctedModelView = MultiplyMatrices4(modelView, modelToCorrectedModel);
    const Matrix4 correctedModelViewProjection =
        MultiplyMatrices4(modelViewProjection, modelToCorrectedModel);
    if (!IsFinite(correctedModel) || !IsFinite(correctedInverseModel) ||
        !IsFinite(correctedModelView) || !IsFinite(correctedModelViewProjection)) {
        return false;
    }

    WriteMatrix(object, modelOffset, correctedModel);
    WriteMatrix(object, inverseModelOffset, correctedInverseModel);
    WriteMatrix(object, modelViewOffset, correctedModelView);
    WriteMatrix(object, modelViewProjectionOffset, correctedModelViewProjection);
    return true;
}

bool CorrectRenderModelClone(unsigned char* object, const RenderCorrectionState& state) {
    return CorrectMatrixSet(object,
                            kRenderModelMatrixOffset,
                            kRenderModelInverseMatrixOffset,
                            kRenderModelViewMatrixOffset,
                            kRenderModelMvpMatrixOffset,
                            state.currentDelta,
                            state.currentInverseDelta) &&
           CorrectMatrixSet(object,
                            kRenderModelPreviousMatrixOffset,
                            kRenderModelPreviousInverseMatrixOffset,
                            kRenderModelPreviousViewMatrixOffset,
                            kRenderModelPreviousMvpMatrixOffset,
                            state.previousDelta,
                            state.previousInverseDelta);
}

struct WorldMatrixCorrection {
    Matrix4 currentDelta{};
    Matrix4 currentInverseDelta{};
    Matrix4 previousDelta{};
    Matrix4 previousInverseDelta{};
    std::uint64_t presentationSerial = 0;
};

bool ReadRigidTransform(const Matrix4& matrix, Transform& transform) {
    if (!IsFinite(matrix) || std::abs(matrix.values[12]) > 1.0e-3f ||
        std::abs(matrix.values[13]) > 1.0e-3f ||
        std::abs(matrix.values[14]) > 1.0e-3f ||
        std::abs(matrix.values[15] - 1.0f) > 1.0e-3f) {
        return false;
    }

    const auto lengthSquared = [&](int row) {
        const double x = matrix.values[row * 4];
        const double y = matrix.values[row * 4 + 1];
        const double z = matrix.values[row * 4 + 2];
        return x * x + y * y + z * z;
    };
    const auto dotRows = [&](int left, int right) {
        return static_cast<double>(matrix.values[left * 4]) *
                   matrix.values[right * 4] +
               static_cast<double>(matrix.values[left * 4 + 1]) *
                   matrix.values[right * 4 + 1] +
               static_cast<double>(matrix.values[left * 4 + 2]) *
                   matrix.values[right * 4 + 2];
    };
    for (int row = 0; row < 3; ++row) {
        if (std::abs(lengthSquared(row) - 1.0) > 1.0e-2) {
            return false;
        }
    }
    if (std::abs(dotRows(0, 1)) > 1.0e-2 ||
        std::abs(dotRows(0, 2)) > 1.0e-2 ||
        std::abs(dotRows(1, 2)) > 1.0e-2) {
        return false;
    }
    const double determinant =
        matrix.values[0] * (matrix.values[5] * matrix.values[10] -
                            matrix.values[6] * matrix.values[9]) -
        matrix.values[1] * (matrix.values[4] * matrix.values[10] -
                            matrix.values[6] * matrix.values[8]) +
        matrix.values[2] * (matrix.values[4] * matrix.values[9] -
                            matrix.values[5] * matrix.values[8]);
    if (std::abs(determinant - 1.0) > 2.0e-2) {
        return false;
    }

    transform.origin = {matrix.values[3], matrix.values[7], matrix.values[11]};
    transform.axis[0] = matrix.values[0];
    transform.axis[1] = matrix.values[4];
    transform.axis[2] = matrix.values[8];
    transform.axis[3] = matrix.values[1];
    transform.axis[4] = matrix.values[5];
    transform.axis[5] = matrix.values[9];
    transform.axis[6] = matrix.values[2];
    transform.axis[7] = matrix.values[6];
    transform.axis[8] = matrix.values[10];
    return IsFinite(transform);
}

bool ReadWorldTransform(const Matrix4& matrix, Transform& transform,
                        double& uniformScale, bool& reflected) {
    reflected = false;
    if (ReadRigidTransform(matrix, transform)) {
        uniformScale = 1.0;
        return true;
    }
    if (!IsFinite(matrix) || std::abs(matrix.values[12]) > 1.0e-3f ||
        std::abs(matrix.values[13]) > 1.0e-3f ||
        std::abs(matrix.values[14]) > 1.0e-3f ||
        std::abs(matrix.values[15] - 1.0f) > 1.0e-3f) {
        return false;
    }

    double lengths[3]{};
    for (int row = 0; row < 3; ++row) {
        const double x = matrix.values[row * 4];
        const double y = matrix.values[row * 4 + 1];
        const double z = matrix.values[row * 4 + 2];
        lengths[row] = std::sqrt(x * x + y * y + z * z);
    }
    uniformScale = (lengths[0] + lengths[1] + lengths[2]) / 3.0;
    if (!(uniformScale > 1.0e-4) || uniformScale > 100.0 ||
        std::abs(lengths[0] - uniformScale) > uniformScale * 1.0e-3 ||
        std::abs(lengths[1] - uniformScale) > uniformScale * 1.0e-3 ||
        std::abs(lengths[2] - uniformScale) > uniformScale * 1.0e-3) {
        return false;
    }

    Matrix4 normalized = matrix;
    for (int row = 0; row < 3; ++row) {
        for (int column = 0; column < 3; ++column) {
            normalized.values[row * 4 + column] = static_cast<float>(
                normalized.values[row * 4 + column] / uniformScale);
        }
    }
    if (ReadRigidTransform(normalized, transform)) {
        return true;
    }

    // A transform with negative determinant is not representable by a
    // quaternion on its own. Factor a fixed local-X reflection out of the
    // matrix, interpolate the remaining proper rotation, then restore the
    // reflection when rebuilding the matrix. This admits rigid mirrored
    // render models without weakening the existing shear/non-uniform-scale
    // rejection.
    for (int row = 0; row < 3; ++row) {
        normalized.values[row * 4] = -normalized.values[row * 4];
    }
    if (!ReadRigidTransform(normalized, transform)) {
        return false;
    }
    reflected = true;
    return true;
}

Matrix4 TransformMatrixWithUniformScale(const Transform& transform,
                                         double uniformScale, bool reflected) {
    Matrix4 result = TransformMatrix(transform);
    for (int row = 0; row < 3; ++row) {
        for (int column = 0; column < 3; ++column) {
            result.values[row * 4 + column] = static_cast<float>(
                result.values[row * 4 + column] * uniformScale);
        }
    }
    if (reflected) {
        for (int row = 0; row < 3; ++row) {
            result.values[row * 4] = -result.values[row * 4];
        }
    }
    return result;
}

bool InvertAffineTransform(const Matrix4& matrix, Matrix4& inverse) {
    if (!IsFinite(matrix) || std::abs(matrix.values[12]) > 1.0e-3f ||
        std::abs(matrix.values[13]) > 1.0e-3f ||
        std::abs(matrix.values[14]) > 1.0e-3f ||
        std::abs(matrix.values[15] - 1.0f) > 1.0e-3f) {
        return false;
    }
    const double a = matrix.values[0];
    const double b = matrix.values[1];
    const double c = matrix.values[2];
    const double d = matrix.values[4];
    const double e = matrix.values[5];
    const double f = matrix.values[6];
    const double g = matrix.values[8];
    const double h = matrix.values[9];
    const double i = matrix.values[10];
    const double determinant =
        a * (e * i - f * h) - b * (d * i - f * g) +
        c * (d * h - e * g);
    if (!std::isfinite(determinant) || std::abs(determinant) < 1.0e-8) {
        return false;
    }
    const double reciprocal = 1.0 / determinant;
    inverse = {};
    inverse.values[0] = static_cast<float>((e * i - f * h) * reciprocal);
    inverse.values[1] = static_cast<float>((c * h - b * i) * reciprocal);
    inverse.values[2] = static_cast<float>((b * f - c * e) * reciprocal);
    inverse.values[4] = static_cast<float>((f * g - d * i) * reciprocal);
    inverse.values[5] = static_cast<float>((a * i - c * g) * reciprocal);
    inverse.values[6] = static_cast<float>((c * d - a * f) * reciprocal);
    inverse.values[8] = static_cast<float>((d * h - e * g) * reciprocal);
    inverse.values[9] = static_cast<float>((b * g - a * h) * reciprocal);
    inverse.values[10] = static_cast<float>((a * e - b * d) * reciprocal);
    inverse.values[3] =
        -(inverse.values[0] * matrix.values[3] +
          inverse.values[1] * matrix.values[7] +
          inverse.values[2] * matrix.values[11]);
    inverse.values[7] =
        -(inverse.values[4] * matrix.values[3] +
          inverse.values[5] * matrix.values[7] +
          inverse.values[6] * matrix.values[11]);
    inverse.values[11] =
        -(inverse.values[8] * matrix.values[3] +
          inverse.values[9] * matrix.values[7] +
          inverse.values[10] * matrix.values[11]);
    inverse.values[15] = 1.0f;
    return IsFinite(inverse);
}

bool InterpolateWorldMatrices(const Matrix4& previous, const Matrix4& current,
                              double alpha, Matrix4& result) {
    Transform from{};
    Transform to{};
    double fromScale = 1.0;
    double toScale = 1.0;
    bool fromReflected = false;
    bool toReflected = false;
    if (!ReadWorldTransform(previous, from, fromScale, fromReflected) ||
        !ReadWorldTransform(current, to, toScale, toReflected) ||
        fromReflected != toReflected) {
        return false;
    }
    Transform output{};
    output.origin = {
        from.origin.x + alpha * (to.origin.x - from.origin.x),
        from.origin.y + alpha * (to.origin.y - from.origin.y),
        from.origin.z + alpha * (to.origin.z - from.origin.z),
    };
    QuaternionToMatrix(SlerpUnclamped(MatrixToQuaternion(from.axis),
                                      MatrixToQuaternion(to.axis), alpha),
                       output.axis);
    const double outputScale = fromScale + alpha * (toScale - fromScale);
    result = TransformMatrixWithUniformScale(output, outputScale, fromReflected);
    return true;
}

bool WorldMatricesDiffer(const Matrix4& left, const Matrix4& right,
                         double positionEpsilon = 1.0e-4,
                         double rotationEpsilonDegrees = 1.0e-3,
                         double scaleEpsilon = 1.0e-4) {
    Transform leftTransform{};
    Transform rightTransform{};
    double leftScale = 1.0;
    double rightScale = 1.0;
    bool leftReflected = false;
    bool rightReflected = false;
    if (!ReadWorldTransform(left, leftTransform, leftScale, leftReflected) ||
        !ReadWorldTransform(right, rightTransform, rightScale, rightReflected)) {
        return true;
    }
    return leftReflected != rightReflected ||
           PositionDistance(leftTransform, rightTransform) > positionEpsilon ||
           RotationDistanceDegrees(leftTransform, rightTransform) >
               rotationEpsilonDegrees ||
           std::abs(leftScale - rightScale) > scaleEpsilon;
}

bool BuildWorldCorrection(const Matrix4& raw, const Matrix4& output,
                          Matrix4& delta, Matrix4& inverseDelta) {
    Transform rawTransform{};
    Transform outputTransform{};
    double rawScale = 1.0;
    double outputScale = 1.0;
    bool rawReflected = false;
    bool outputReflected = false;
    Matrix4 inverseRaw{};
    Matrix4 inverseOutput{};
    if (!ReadWorldTransform(raw, rawTransform, rawScale, rawReflected) ||
        !ReadWorldTransform(output, outputTransform, outputScale,
                            outputReflected) ||
        rawReflected != outputReflected ||
        !InvertAffineTransform(raw, inverseRaw) ||
        !InvertAffineTransform(output, inverseOutput)) {
        return false;
    }
    delta = MultiplyMatrices4(output, inverseRaw);
    inverseDelta = MultiplyMatrices4(raw, inverseOutput);
    return IsFinite(delta) && IsFinite(inverseDelta);
}

bool MatricesNearlyEqual(const Matrix4& left, const Matrix4& right,
                         double epsilon = 2.0e-5) {
    for (std::size_t index = 0; index < 16; ++index) {
        if (std::abs(static_cast<double>(left.values[index]) -
                     static_cast<double>(right.values[index])) > epsilon) {
            return false;
        }
    }
    return true;
}

bool ValidateWorldTransformInterpolationMath() {
    Transform from{};
    Transform to{};
    from.origin = {1.0, -2.0, 3.0};
    to.origin = {9.0, 6.0, -5.0};
    QuaternionToMatrix({0.984807753012208, 0.0, 0.0, 0.173648177666930},
                       from.axis);
    QuaternionToMatrix({0.642787609686539, 0.0, 0.0, 0.766044443118978},
                       to.axis);
    const Matrix4 mirroredFrom =
        TransformMatrixWithUniformScale(from, 1.0, true);
    const Matrix4 mirroredTo =
        TransformMatrixWithUniformScale(to, 1.5, true);

    Matrix4 atStart{};
    Matrix4 atEnd{};
    Matrix4 midpoint{};
    if (!InterpolateWorldMatrices(mirroredFrom, mirroredTo, 0.0, atStart) ||
        !InterpolateWorldMatrices(mirroredFrom, mirroredTo, 1.0, atEnd) ||
        !InterpolateWorldMatrices(mirroredFrom, mirroredTo, 0.5, midpoint) ||
        !MatricesNearlyEqual(atStart, mirroredFrom) ||
        !MatricesNearlyEqual(atEnd, mirroredTo)) {
        return false;
    }

    Transform midpointTransform{};
    double midpointScale = 1.0;
    bool midpointReflected = false;
    if (!ReadWorldTransform(midpoint, midpointTransform, midpointScale,
                            midpointReflected) ||
        !midpointReflected || std::abs(midpointScale - 1.25) > 2.0e-5) {
        return false;
    }

    Matrix4 correction{};
    Matrix4 inverseCorrection{};
    if (!BuildWorldCorrection(mirroredTo, midpoint, correction,
                              inverseCorrection)) {
        return false;
    }

    const Matrix4 properTo = TransformMatrixWithUniformScale(to, 1.5, false);
    Matrix4 rejectedOutput{};
    if (InterpolateWorldMatrices(mirroredFrom, properTo, 0.5,
                                 rejectedOutput)) {
        return false;
    }

    Transform identity{};
    QuaternionToMatrix({1.0, 0.0, 0.0, 0.0}, identity.axis);
    Matrix4 nonUniform = TransformMatrixWithUniformScale(identity, 1.0, false);
    nonUniform.values[0] = 1.25f;
    Transform rejectedTransform{};
    double rejectedScale = 1.0;
    bool rejectedReflected = false;
    return !ReadWorldTransform(nonUniform, rejectedTransform, rejectedScale,
                               rejectedReflected);
}

std::size_t WorldTransformHash(const void* renderModel, const void* owner) {
    std::uintptr_t value = reinterpret_cast<std::uintptr_t>(renderModel) >> 4;
    value ^= (reinterpret_cast<std::uintptr_t>(owner) >> 4) +
             static_cast<std::uintptr_t>(0x9E3779B97F4A7C15ULL) +
             (value << 6) + (value >> 2);
    return static_cast<std::size_t>(value) & (kWorldTransformCapacity - 1);
}

std::uint64_t MatrixContentHash(const Matrix4& matrix) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(&matrix);
    std::uint64_t hash = 1469598103934665603ULL;
    for (std::size_t index = 0; index < sizeof(matrix); ++index) {
        hash ^= bytes[index];
        hash *= 1099511628211ULL;
    }
    return hash == 0 ? 1 : hash;
}

std::size_t ShadowMatrixPointerHash(const void* matrix) {
    std::uintptr_t value = reinterpret_cast<std::uintptr_t>(matrix) >> 4;
    value ^= value >> 17;
    value *= static_cast<std::uintptr_t>(0x9E3779B97F4A7C15ULL);
    return static_cast<std::size_t>(value) &
           (kShadowCorrectionCapacity - 1);
}

std::size_t ShadowMatrixContentHash(std::uint64_t matrixHash) {
    matrixHash ^= matrixHash >> 33;
    matrixHash *= 0xff51afd7ed558ccdULL;
    matrixHash ^= matrixHash >> 33;
    return static_cast<std::size_t>(matrixHash) &
           (kShadowCorrectionCapacity - 1);
}

bool MatrixElementsDiffer(const Matrix4& left, const Matrix4& right,
                          float epsilon = 1.0e-4f) {
    for (std::size_t index = 0; index < 16; ++index) {
        if (std::abs(left.values[index] - right.values[index]) > epsilon) {
            return true;
        }
    }
    return false;
}

NonRigidWorldTrack* FindNonRigidWorldTrack(const void* renderModel,
                                           const void* owner,
                                           std::uint64_t presentationSerial,
                                           bool create) {
    static_assert((kNonRigidTrackCapacity & (kNonRigidTrackCapacity - 1)) == 0,
                  "Non-rigid track capacity must be a power of two");
    const std::size_t base =
        WorldTransformHash(renderModel, owner) & (kNonRigidTrackCapacity - 1);
    NonRigidWorldTrack* empty = nullptr;
    NonRigidWorldTrack* stale = nullptr;
    for (std::size_t probe = 0; probe < kNonRigidTrackProbeLimit; ++probe) {
        NonRigidWorldTrack& entry =
            g_nonRigidWorldTracks[(base + probe) & (kNonRigidTrackCapacity - 1)];
        if (entry.renderModel == renderModel && entry.owner == owner) {
            return &entry;
        }
        if (entry.renderModel == nullptr && empty == nullptr) {
            empty = &entry;
        } else if (entry.renderModel != nullptr && stale == nullptr &&
                   entry.lastSeenSerial + kWorldTransformStaleFrames <
                       presentationSerial) {
            stale = &entry;
        }
    }
    if (!create) {
        return nullptr;
    }
    NonRigidWorldTrack* result = empty != nullptr ? empty : stale;
    if (result == nullptr) {
        g_nonRigidTrackCapacityMissCount.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    *result = {};
    result->renderModel = renderModel;
    result->owner = owner;
    result->diagnosticId =
        g_nextNonRigidTrackId.fetch_add(1, std::memory_order_relaxed);
    result->firstSeenSerial = presentationSerial;
    return result;
}

void RecordNonRigidWorldModel(const void* renderModel, const void* owner,
                              const PresentationContext& context,
                              const Matrix4& current, bool currentRigid,
                              bool previousRigid) {
    AcquireSRWLockExclusive(&g_worldTransformLock);
    NonRigidWorldTrack* track =
        FindNonRigidWorldTrack(renderModel, owner, context.serial, false);
    if (track == nullptr) {
        track = FindNonRigidWorldTrack(renderModel, owner, context.serial, true);
        if (track != nullptr) {
            track->simulationTime = context.simulationTime;
            track->current = current;
        }
    } else if (context.simulationTime > track->simulationTime + kTimeEpsilon) {
        if (MatrixElementsDiffer(track->current, current)) {
            if (track->changes == 0) {
                track->firstChangeSerial = context.serial;
            }
            track->lastChangeSerial = context.serial;
            ++track->changes;
        }
        track->simulationTime = context.simulationTime;
        track->current = current;
    } else if (context.simulationTime < track->simulationTime - kTimeEpsilon) {
        track->simulationTime = context.simulationTime;
        track->current = current;
    }
    if (track != nullptr) {
        track->lastSeenSerial = context.serial;
        track->currentRigid = currentRigid;
        track->previousRigid = previousRigid;
    }
    ReleaseSRWLockExclusive(&g_worldTransformLock);
}

WorldTransformTrack* FindWorldTransformTrack(const void* renderModel, const void* owner,
                                             std::uint64_t presentationSerial,
                                             bool create) {
    static_assert((kWorldTransformCapacity & (kWorldTransformCapacity - 1)) == 0,
                  "World transform capacity must be a power of two");
    const std::size_t base = WorldTransformHash(renderModel, owner);
    WorldTransformTrack* empty = nullptr;
    WorldTransformTrack* stale = nullptr;
    for (std::size_t probe = 0; probe < kWorldTransformProbeLimit; ++probe) {
        WorldTransformTrack& entry =
            g_worldTransforms[(base + probe) & (kWorldTransformCapacity - 1)];
        if (entry.renderModel == renderModel && entry.owner == owner) {
            return &entry;
        }
        if (entry.renderModel == nullptr && empty == nullptr) {
            empty = &entry;
        } else if (entry.renderModel != nullptr && stale == nullptr &&
                   entry.lastSeenSerial + kWorldTransformStaleFrames <
                       presentationSerial) {
            stale = &entry;
        }
    }
    if (!create) {
        return nullptr;
    }
    WorldTransformTrack* result = empty != nullptr ? empty : stale;
    if (result == nullptr) {
        g_worldTransformCapacityMissCount.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    *result = {};
    result->renderModel = renderModel;
    result->owner = owner;
    result->diagnosticId =
        g_nextWorldTrackId.fetch_add(1, std::memory_order_relaxed);
    result->firstSeenSerial = presentationSerial;
    return result;
}

bool IsEligibleWorldRenderModel(const void* renderModel, const void*& owner,
                                 std::uintptr_t& vtable,
                                 const void*& modelAsset,
                                 bool& cinematic) {
    cinematic = false;
    g_worldDiagnostics.candidates.fetch_add(1, std::memory_order_relaxed);
    if (!IsReadableMemoryCached(renderModel, kRenderModelSize)) {
        return false;
    }
    memcpy(&vtable, renderModel, sizeof(vtable));
    const bool exactStatic =
        vtable == g_executableBase + g_layout->renderModelStaticVtable.rva;
    const bool exactSkinned =
        vtable == g_executableBase + g_layout->skinnedModelVtable.rva;
    if (!exactStatic && !exactSkinned) {
        g_worldDiagnostics.vtableRejected.fetch_add(1, std::memory_order_relaxed);
        if (vtable >= g_executableBase) {
            const std::uintptr_t rva = vtable - g_executableBase;
            for (ObservedWorldVtable& observation : g_observedWorldVtables) {
                std::uintptr_t observed = observation.rva.load(std::memory_order_relaxed);
                if (observed == rva) {
                    observation.count.fetch_add(1, std::memory_order_relaxed);
                    break;
                }
                if (observed == 0 &&
                    observation.rva.compare_exchange_strong(
                        observed, rva, std::memory_order_relaxed)) {
                    observation.count.store(1, std::memory_order_relaxed);
                    break;
                }
            }
        }
        return false;
    }
    std::uint32_t jointCount = 0;
    if (exactStatic) {
        if (!g_interpolateWorldTransforms) {
            return false;
        }
        g_worldDiagnostics.exactStaticType.fetch_add(
            1, std::memory_order_relaxed);
    } else {
        g_worldDiagnostics.exactSkinnedType.fetch_add(
            1, std::memory_order_relaxed);
        if ((!(g_interpolateWorldTransforms &&
                g_interpolateWorldSkeletons) &&
             !g_interpolateCinematicTransforms) ||
            !IsReadableMemoryCached(renderModel, kSkinnedModelSize)) {
            return false;
        }
        const auto* skinnedBytes =
            static_cast<const unsigned char*>(renderModel);
        std::uint32_t packedPaddedJointCount = 0;
        memcpy(&modelAsset, skinnedBytes + kSkinnedModelAssetOffset,
               sizeof(modelAsset));
        memcpy(&jointCount, skinnedBytes + kSkinnedTrueJointCountOffset,
               sizeof(jointCount));
        memcpy(&packedPaddedJointCount,
               skinnedBytes + kSkinnedPosePaddedCountOffset,
               sizeof(packedPaddedJointCount));
        const std::uint32_t paddedJointCount =
            packedPaddedJointCount & 0x00FFFFFFU;
        if (modelAsset == nullptr ||
            !IsReadableMemoryCached(modelAsset, sizeof(void*)) || jointCount == 0 ||
            jointCount > kMaximumJointCount ||
            paddedJointCount != ((jointCount + 7U) & ~7U) ||
            paddedJointCount > kMaximumJointCount) {
            return false;
        }
    }
    float depthHack = 0.0f;
    memcpy(&depthHack, static_cast<const unsigned char*>(renderModel) +
                           kRenderModelDepthHackOffset, sizeof(depthHack));
    if (!std::isfinite(depthHack) || std::abs(depthHack) > 1.0e-6f) {
        g_worldDiagnostics.depthHackRejected.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    memcpy(&owner, static_cast<const unsigned char*>(renderModel) +
                       kRenderModelOwnerOffset, sizeof(owner));
    if (owner == nullptr) {
        if (!exactSkinned || !g_interpolateCinematicTransforms ||
            jointCount > kMaximumCinematicJointCount) {
            g_worldDiagnostics.ownerRejected.fetch_add(
                1, std::memory_order_relaxed);
            return false;
        }
        owner = modelAsset;
        cinematic = true;
        g_worldDiagnostics.cinematicEligible.fetch_add(
            1, std::memory_order_relaxed);
    } else if (exactSkinned &&
               (!g_interpolateWorldTransforms ||
                !g_interpolateWorldSkeletons)) {
        return false;
    }
    g_worldDiagnostics.eligible.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool BuildWorldTransformCorrection(const void* renderModel,
                                   const PresentationContext& context,
                                   WorldMatrixCorrection& correction) {
    const void* owner = nullptr;
    const void* modelAsset = nullptr;
    std::uintptr_t vtable = 0;
    bool cinematic = false;
    if (!context.valid ||
        !IsEligibleWorldRenderModel(renderModel, owner, vtable, modelAsset,
                                    cinematic)) {
        return false;
    }
    const auto* bytes = static_cast<const unsigned char*>(renderModel);
    const Matrix4 rawCurrent = ReadMatrix(bytes, kRenderModelMatrixOffset);
    const Matrix4 rawPrevious = ReadMatrix(bytes, kRenderModelPreviousMatrixOffset);
    Transform rawCurrentTransform{};
    Transform rawPreviousTransform{};
    const bool currentRigid = ReadRigidTransform(rawCurrent, rawCurrentTransform);
    const bool previousRigid = ReadRigidTransform(rawPrevious, rawPreviousTransform);
    double currentScale = 1.0;
    double previousScale = 1.0;
    bool currentReflected = false;
    bool previousReflected = false;
    const bool currentSupported = currentRigid ||
        ReadWorldTransform(rawCurrent, rawCurrentTransform, currentScale,
                           currentReflected);
    const bool previousSupported = previousRigid ||
        ReadWorldTransform(rawPrevious, rawPreviousTransform, previousScale,
                           previousReflected);
    if (!currentSupported || !previousSupported) {
        g_worldDiagnostics.nonRigidRejected.fetch_add(1, std::memory_order_relaxed);
        if (!currentSupported) {
            g_worldDiagnostics.currentNonRigidRejected.fetch_add(
                1, std::memory_order_relaxed);
        }
        if (!previousSupported) {
            g_worldDiagnostics.previousNonRigidRejected.fetch_add(
                1, std::memory_order_relaxed);
        }
        RecordNonRigidWorldModel(renderModel, owner, context, rawCurrent,
                                 currentRigid, previousRigid);
        return false;
    }
    if (currentReflected != previousReflected) {
        g_worldDiagnostics.reflectionParityRejected.fetch_add(
            1, std::memory_order_relaxed);
        return false;
    }
    if (std::abs(currentScale - 1.0) > 1.0e-4 ||
        std::abs(previousScale - 1.0) > 1.0e-4) {
        g_worldDiagnostics.uniformScaled.fetch_add(1, std::memory_order_relaxed);
    }
    if (currentReflected || previousReflected) {
        g_worldDiagnostics.reflectedRigid.fetch_add(1, std::memory_order_relaxed);
    }
    g_worldDiagnostics.rigid.fetch_add(1, std::memory_order_relaxed);

    AcquireSRWLockExclusive(&g_worldTransformLock);
    WorldTransformTrack* track =
        FindWorldTransformTrack(renderModel, owner, context.serial, false);
    if (track == nullptr) {
        track = FindWorldTransformTrack(renderModel, owner, context.serial, true);
        if (track == nullptr) {
            ReleaseSRWLockExclusive(&g_worldTransformLock);
            return false;
        }
        track->currentTime = context.simulationTime;
        track->current = rawCurrent;
        track->currentMatrixHash = MatrixContentHash(rawCurrent);
        track->reflected = currentReflected;
        track->vtable = vtable;
        track->modelAsset = modelAsset;
        track->lastSeenSerial = context.serial;
        g_worldDiagnostics.tracksCreated.fetch_add(1, std::memory_order_relaxed);
        ReleaseSRWLockExclusive(&g_worldTransformLock);
        return false;
    }

    if (track->vtable != vtable || track->modelAsset != modelAsset) {
        const std::uint64_t diagnosticId =
            g_nextWorldTrackId.fetch_add(1, std::memory_order_relaxed);
        *track = {};
        track->renderModel = renderModel;
        track->owner = owner;
        track->modelAsset = modelAsset;
        track->vtable = vtable;
        track->diagnosticId = diagnosticId;
        track->firstSeenSerial = context.serial;
        track->currentTime = context.simulationTime;
        track->current = rawCurrent;
        track->currentMatrixHash = MatrixContentHash(rawCurrent);
        track->reflected = currentReflected;
        track->lastSeenSerial = context.serial;
        g_worldDiagnostics.tracksCreated.fetch_add(1,
                                                   std::memory_order_relaxed);
        ReleaseSRWLockExclusive(&g_worldTransformLock);
        return false;
    }

    track->lastSeenSerial = context.serial;
    if (context.simulationTime < track->currentTime - kTimeEpsilon ||
        context.simulationTime - track->currentTime > kMaximumWorldStateInterval) {
        g_worldDiagnostics.discontinuityRejected.fetch_add(1,
                                                           std::memory_order_relaxed);
        const void* savedModel = track->renderModel;
        const void* savedOwner = track->owner;
        const void* savedModelAsset = track->modelAsset;
        const std::uintptr_t savedVtable = track->vtable;
        const std::uint64_t savedDiagnosticId = track->diagnosticId;
        const std::uint64_t savedFirstSeenSerial = track->firstSeenSerial;
        const std::uint64_t savedFirstMotionSerial = track->firstMotionSerial;
        const std::uint64_t savedLastMotionSerial = track->lastMotionSerial;
        const std::uint64_t savedLastCorrectionSerial =
            track->lastCorrectionSerial;
        const std::uint64_t savedMotionSamples = track->motionSamples;
        const std::uint64_t savedCorrectionBuilds = track->correctionBuilds;
        const std::uint64_t savedReportedMotionSamples =
            track->reportedMotionSamples;
        const std::uint64_t savedReportedCorrectionBuilds =
            track->reportedCorrectionBuilds;
        const std::uint64_t savedDiscontinuities = track->discontinuities + 1;
        *track = {};
        track->renderModel = savedModel;
        track->owner = savedOwner;
        track->modelAsset = savedModelAsset;
        track->vtable = savedVtable;
        track->diagnosticId = savedDiagnosticId;
        track->firstSeenSerial = savedFirstSeenSerial;
        track->firstMotionSerial = savedFirstMotionSerial;
        track->lastMotionSerial = savedLastMotionSerial;
        track->lastCorrectionSerial = savedLastCorrectionSerial;
        track->motionSamples = savedMotionSamples;
        track->correctionBuilds = savedCorrectionBuilds;
        track->reportedMotionSamples = savedReportedMotionSamples;
        track->reportedCorrectionBuilds = savedReportedCorrectionBuilds;
        track->discontinuities = savedDiscontinuities;
        track->currentTime = context.simulationTime;
        track->current = rawCurrent;
        track->currentMatrixHash = MatrixContentHash(rawCurrent);
        track->reflected = currentReflected;
        track->lastSeenSerial = context.serial;
        ReleaseSRWLockExclusive(&g_worldTransformLock);
        return false;
    }

    if (context.simulationTime > track->currentTime + kTimeEpsilon) {
        const bool moved = WorldMatricesDiffer(track->current, rawCurrent);
        track->previousTime = track->currentTime;
        track->previous = track->current;
        track->currentTime = context.simulationTime;
        track->current = rawCurrent;
        track->currentMatrixHash = MatrixContentHash(rawCurrent);
        track->hasPair = true;
        g_worldDiagnostics.samplePairs.fetch_add(1, std::memory_order_relaxed);
        if (moved) {
            g_worldDiagnostics.moving.fetch_add(1, std::memory_order_relaxed);
            if (track->motionSamples == 0) {
                track->firstMotionSerial = context.serial;
            }
            track->lastMotionSerial = context.serial;
            ++track->motionSamples;
            if (currentReflected) {
                g_worldDiagnostics.reflectedMoving.fetch_add(
                    1, std::memory_order_relaxed);
            }
        }
    } else if (WorldMatricesDiffer(track->current, rawCurrent)) {
        // More than one root transform for the same model and simulation time
        // is ambiguous (for example a reused/transient renderer object).
        track->current = rawCurrent;
        track->currentMatrixHash = MatrixContentHash(rawCurrent);
        track->hasPair = false;
        track->hasLastPresented = false;
        g_worldDiagnostics.sameTimeMutationRejected.fetch_add(
            1, std::memory_order_relaxed);
        ReleaseSRWLockExclusive(&g_worldTransformLock);
        return false;
    }

    const double interval = track->currentTime - track->previousTime;
    Transform previousTransform{};
    Transform currentTransform{};
    double trackedPreviousScale = 1.0;
    double trackedCurrentScale = 1.0;
    bool trackedPreviousReflected = false;
    bool trackedCurrentReflected = false;
    const bool trackedPreviousSupported =
        ReadWorldTransform(track->previous, previousTransform,
                           trackedPreviousScale, trackedPreviousReflected);
    const bool trackedCurrentSupported =
        ReadWorldTransform(track->current, currentTransform,
                           trackedCurrentScale, trackedCurrentReflected);
    const bool reflectionParityMismatch =
        trackedPreviousSupported && trackedCurrentSupported &&
        trackedPreviousReflected != trackedCurrentReflected;
    const bool invalidPair = !track->hasPair || !(interval > kTimeEpsilon) ||
                             interval > kMaximumWorldStateInterval ||
                             !trackedPreviousSupported ||
                             !trackedCurrentSupported ||
                             reflectionParityMismatch;
    const bool excessiveJump =
        !invalidPair &&
        (PositionDistance(previousTransform, currentTransform) >
             kMaximumWorldPositionJump ||
         RotationDistanceDegrees(previousTransform, currentTransform) >
             kMaximumWorldRotationJumpDegrees ||
         trackedCurrentScale / trackedPreviousScale > 1.10 ||
         trackedPreviousScale / trackedCurrentScale > 1.10);
    if (invalidPair || excessiveJump) {
        if (reflectionParityMismatch) {
            g_worldDiagnostics.reflectionParityRejected.fetch_add(
                1, std::memory_order_relaxed);
        }
        if (excessiveJump) {
            g_worldDiagnostics.jumpRejected.fetch_add(1, std::memory_order_relaxed);
        }
        track->hasPair = false;
        track->hasLastPresented = false;
        ReleaseSRWLockExclusive(&g_worldTransformLock);
        return false;
    }

    const double targetTime = Clamp(context.scaledTime, track->previousTime,
                                    track->currentTime + kNativeSimulationStep);
    const double alpha = (targetTime - track->previousTime) / interval;
    Matrix4 target{};
    if (!InterpolateWorldMatrices(track->previous, track->current, alpha,
                                  target)) {
        track->hasPair = false;
        track->hasLastPresented = false;
        g_worldDiagnostics.reflectionParityRejected.fetch_add(
            1, std::memory_order_relaxed);
        ReleaseSRWLockExclusive(&g_worldTransformLock);
        return false;
    }

    if (track->lastPresentedSerial != context.serial) {
        if (track->hasLastPresented &&
            track->lastPresentedSerial + 1 == context.serial) {
            track->previousPresented = track->lastPresented;
        } else {
            track->previousPresented = target;
        }
        track->lastPresented = target;
        track->lastPresentedSerial = context.serial;
        track->hasLastPresented = true;
    }

    correction.presentationSerial = context.serial;
    const bool currentChanged = WorldMatricesDiffer(rawCurrent, target);
    const bool previousChanged =
        WorldMatricesDiffer(rawPrevious, track->previousPresented);
    const bool valid =
        BuildWorldCorrection(rawCurrent, target, correction.currentDelta,
                             correction.currentInverseDelta) &&
        BuildWorldCorrection(rawPrevious, track->previousPresented,
                             correction.previousDelta,
                             correction.previousInverseDelta);
    const bool corrected = valid && (currentChanged || previousChanged);
    if (corrected) {
        track->lastCorrectionSerial = context.serial;
        ++track->correctionBuilds;
        if (track->reflected) {
            g_worldDiagnostics.reflectedAdjusted.fetch_add(
                1, std::memory_order_relaxed);
        }
        if (cinematic) {
            g_worldDiagnostics.cinematicAdjusted.fetch_add(
                1, std::memory_order_relaxed);
        }
    }
    ReleaseSRWLockExclusive(&g_worldTransformLock);
    return corrected;
}

ShadowCorrectionEntry* FindShadowCorrectionByPointer(const void* matrix,
                                                     std::uint64_t serial,
                                                     bool create) {
    static_assert((kShadowCorrectionCapacity &
                   (kShadowCorrectionCapacity - 1)) == 0,
                  "Shadow correction capacity must be a power of two");
    const std::size_t base = ShadowMatrixPointerHash(matrix);
    ShadowCorrectionEntry* stale = nullptr;
    for (std::size_t probe = 0; probe < kShadowCorrectionProbeLimit; ++probe) {
        ShadowCorrectionEntry& entry =
            g_shadowCorrectionsByPointer[(base + probe) &
                                         (kShadowCorrectionCapacity - 1)];
        if (entry.matrix == matrix) {
            return &entry;
        }
        if (entry.matrix == nullptr) {
            if (!create) {
                return nullptr;
            }
            return &entry;
        }
        if (stale == nullptr &&
            entry.presentationSerial + kWorldTransformStaleFrames < serial) {
            stale = &entry;
        }
    }
    return create ? stale : nullptr;
}

ShadowCorrectionEntry* FindShadowCorrectionByContent(
    const void* matrix, std::uint64_t matrixHash, std::uint64_t serial,
    bool create) {
    const std::size_t base = ShadowMatrixContentHash(matrixHash);
    ShadowCorrectionEntry* stale = nullptr;
    for (std::size_t probe = 0; probe < kShadowCorrectionProbeLimit; ++probe) {
        ShadowCorrectionEntry& entry =
            g_shadowCorrectionsByContent[(base + probe) &
                                         (kShadowCorrectionCapacity - 1)];
        if (entry.matrix == matrix && entry.matrixHash == matrixHash) {
            return &entry;
        }
        if (entry.matrix == nullptr) {
            if (!create) {
                return nullptr;
            }
            return &entry;
        }
        if (stale == nullptr &&
            entry.presentationSerial + kWorldTransformStaleFrames < serial) {
            stale = &entry;
        }
    }
    return create ? stale : nullptr;
}

void PublishShadowCorrection(const void* renderModel,
                             const WorldMatrixCorrection& correction) {
    if (!RuntimeTransformInterpolationEnabled() ||
        !g_interpolateShadowTransforms ||
        renderModel == nullptr ||
        correction.presentationSerial == 0) {
        return;
    }
    const auto* matrix = static_cast<const unsigned char*>(renderModel) +
                         kRenderModelMatrixOffset;
    Matrix4 raw{};
    memcpy(&raw, matrix, sizeof(raw));
    const std::uint64_t matrixHash = MatrixContentHash(raw);

    bool pointerPublished = false;
    bool contentPublished = false;
    AcquireSRWLockExclusive(&g_shadowCorrectionLock);
    ShadowCorrectionEntry* pointerEntry = FindShadowCorrectionByPointer(
        matrix, correction.presentationSerial, true);
    ShadowCorrectionEntry* contentEntry = FindShadowCorrectionByContent(
        matrix, matrixHash, correction.presentationSerial, true);
    const ShadowCorrectionEntry value{
        matrix, matrixHash, correction.currentDelta,
        correction.presentationSerial};
    if (pointerEntry != nullptr) {
        *pointerEntry = value;
        pointerPublished = true;
    }
    if (contentEntry != nullptr) {
        *contentEntry = value;
        contentPublished = true;
    }
    ReleaseSRWLockExclusive(&g_shadowCorrectionLock);

    if (pointerPublished) {
        g_shadowCorrectionPublications.fetch_add(1,
                                                  std::memory_order_relaxed);
    } else {
        g_shadowCorrectionPointerCapacityMisses.fetch_add(
            1, std::memory_order_relaxed);
    }
    if (!contentPublished) {
        g_shadowCorrectionContentCapacityMisses.fetch_add(
            1, std::memory_order_relaxed);
    }
}

bool ReadShadowCorrection(const void* matrix, const Matrix4& raw,
                          std::uint64_t serial, Matrix4& delta) {
    bool direct = false;
    bool content = false;
    bool ambiguous = false;
    const std::uint64_t matrixHash = MatrixContentHash(raw);
    AcquireSRWLockShared(&g_shadowCorrectionLock);
    ShadowCorrectionEntry* pointerEntry =
        FindShadowCorrectionByPointer(matrix, serial, false);
    if (pointerEntry != nullptr &&
        pointerEntry->matrixHash == matrixHash &&
        pointerEntry->presentationSerial + kShadowCorrectionMaximumAge >= serial) {
        delta = pointerEntry->currentDelta;
        direct = true;
    } else {
        const std::size_t base = ShadowMatrixContentHash(matrixHash);
        const ShadowCorrectionEntry* match = nullptr;
        for (std::size_t probe = 0; probe < kShadowCorrectionProbeLimit; ++probe) {
            const ShadowCorrectionEntry& entry =
                g_shadowCorrectionsByContent[(base + probe) &
                                             (kShadowCorrectionCapacity - 1)];
            if (entry.matrix == nullptr) {
                break;
            }
            if (entry.matrixHash != matrixHash ||
                entry.presentationSerial + kShadowCorrectionMaximumAge < serial) {
                continue;
            }
            if (match == nullptr || match->matrix == entry.matrix) {
                match = &entry;
            } else {
                ambiguous = true;
                match = nullptr;
                break;
            }
        }
        if (match != nullptr) {
            delta = match->currentDelta;
            content = true;
        }
    }
    ReleaseSRWLockShared(&g_shadowCorrectionLock);

    if (direct) {
        g_shadowMatrixDirectMatches.fetch_add(1, std::memory_order_relaxed);
    } else if (content) {
        g_shadowMatrixContentMatches.fetch_add(1, std::memory_order_relaxed);
    } else if (ambiguous) {
        g_shadowMatrixAmbiguousMatches.fetch_add(1,
                                                  std::memory_order_relaxed);
    } else {
        g_shadowMatrixCacheMisses.fetch_add(1, std::memory_order_relaxed);
    }
    return direct || content;
}

bool BuildShadowMatrix(const float* source, Matrix4& corrected) {
    g_shadowMatrixCalls.fetch_add(1, std::memory_order_relaxed);
    if (!RuntimeTransformInterpolationEnabled() ||
        !g_interpolateShadowTransforms ||
        source == nullptr) {
        return false;
    }
    // The caster list can contain entries that the engine rejects before it
    // ever loads the full matrix.  The proxy builder examines entries before
    // those engine-side tests, so do not assume every non-null pointer is
    // currently readable merely because it occupies the matrix slot.
    if (!IsReadableMemory(source, sizeof(Matrix4))) {
        g_shadowMatrixUnreadable.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    Matrix4 raw{};
    memcpy(&raw, source, sizeof(raw));
    if (!IsFinite(raw)) {
        return false;
    }
    const std::uint64_t serial =
        g_presentationSerial.load(std::memory_order_acquire);
    if (serial == 0) {
        return false;
    }
    Matrix4 currentDelta{};
    if (!ReadShadowCorrection(source, raw, serial, currentDelta)) {
        return false;
    }
    corrected = MultiplyMatrices4(currentDelta, raw);
    if (!IsFinite(corrected)) {
        return false;
    }
    g_shadowMatrixAdjusted.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool BuildShadowCasterProxyList(std::uint64_t* sourceList,
                                std::uint64_t (&proxyList)[2]) {
    g_shadowCasterProxyCalls.fetch_add(1, std::memory_order_relaxed);
    if (!RuntimeTransformInterpolationEnabled() ||
        !g_interpolateShadowTransforms ||
        sourceList == nullptr) {
        return false;
    }
    const std::size_t count =
        static_cast<std::size_t>(sourceList[1] & 0x00FFFFFFULL);
    if (count == 0) {
        return false;
    }
    if (count > kShadowCasterProxyCapacity) {
        g_shadowCasterProxyCapacityMisses.fetch_add(
            1, std::memory_order_relaxed);
        return false;
    }
    const auto* sourceEntries = reinterpret_cast<const unsigned char*>(
        sourceList[0]);
    const std::size_t byteCount = count * kShadowCasterEntryStride;
    if (!IsReadableMemory(sourceEntries, byteCount)) {
        return false;
    }

    ShadowCasterProxyStorage& storage = g_shadowCasterProxyStorage;
    bool anyCorrected = false;
    for (std::size_t index = 0; index < count; ++index) {
        const unsigned char* sourceEntry =
            sourceEntries + index * kShadowCasterEntryStride;
        const float* matrix = nullptr;
        memcpy(&matrix, sourceEntry + kShadowCasterMatrixPointerOffset,
               sizeof(matrix));
        storage.corrected[index] = 0;
        if (matrix != nullptr &&
            BuildShadowMatrix(matrix, storage.matrices[index])) {
            storage.corrected[index] = 1;
            anyCorrected = true;
        }
    }
    if (!anyCorrected) {
        return false;
    }

    memcpy(storage.entries.data(), sourceEntries, byteCount);
    for (std::size_t index = 0; index < count; ++index) {
        if (storage.corrected[index] == 0) {
            continue;
        }
        unsigned char* proxyEntry =
            storage.entries.data() + index * kShadowCasterEntryStride;
        const float* correctedMatrix = storage.matrices[index].values;
        memcpy(proxyEntry + kShadowCasterMatrixPointerOffset,
               &correctedMatrix, sizeof(correctedMatrix));
    }
    proxyList[0] = reinterpret_cast<std::uint64_t>(storage.entries.data());
    proxyList[1] = sourceList[1];
    g_shadowCasterProxyLists.fetch_add(1, std::memory_order_relaxed);
    return true;
}

extern "C" unsigned char __fastcall HookShadowCasterBuildA(
    void* state, void* parameter, std::uint64_t* casterList, float* origin,
    void* viewMatrix, float clipDistance) {
    ShadowCasterProxyStorage& storage = g_shadowCasterProxyStorage;
    if (storage.active) {
        return g_originalShadowCasterBuildA(
            state, parameter, casterList, origin, viewMatrix, clipDistance);
    }
    storage.active = true;
    std::uint64_t proxyList[2]{};
    std::uint64_t* selectedList =
        BuildShadowCasterProxyList(casterList, proxyList) ? proxyList
                                                          : casterList;
    const unsigned char result = g_originalShadowCasterBuildA(
        state, parameter, selectedList, origin, viewMatrix, clipDistance);
    storage.active = false;
    return result;
}

extern "C" unsigned char __fastcall HookShadowCasterBuildB(
    void* state, void* parameter, std::uint64_t* casterList, float* origin,
    void* viewMatrix, float clipDistance, std::uint32_t maskIndex,
    void* maskContext) {
    ShadowCasterProxyStorage& storage = g_shadowCasterProxyStorage;
    if (storage.active) {
        return g_originalShadowCasterBuildB(
            state, parameter, casterList, origin, viewMatrix, clipDistance,
            maskIndex, maskContext);
    }
    storage.active = true;
    std::uint64_t proxyList[2]{};
    std::uint64_t* selectedList =
        BuildShadowCasterProxyList(casterList, proxyList) ? proxyList
                                                          : casterList;
    const unsigned char result = g_originalShadowCasterBuildB(
        state, parameter, selectedList, origin, viewMatrix, clipDistance,
        maskIndex, maskContext);
    storage.active = false;
    return result;
}

struct WorldTrackReport {
    const void* renderModel = nullptr;
    const void* owner = nullptr;
    const void* modelAsset = nullptr;
    std::uintptr_t vtableRva = 0;
    std::uint64_t diagnosticId = 0;
    std::uint64_t firstSeenSerial = 0;
    std::uint64_t firstMotionSerial = 0;
    std::uint64_t lastMotionSerial = 0;
    std::uint64_t lastCorrectionSerial = 0;
    std::uint64_t motionDelta = 0;
    std::uint64_t correctionDelta = 0;
    std::uint64_t motionTotal = 0;
    std::uint64_t correctionTotal = 0;
    std::uint64_t discontinuities = 0;
    Vec3 origin{};
    bool reflected = false;
};

struct NonRigidTrackReport {
    const void* renderModel = nullptr;
    const void* owner = nullptr;
    std::uint64_t diagnosticId = 0;
    std::uint64_t firstSeenSerial = 0;
    std::uint64_t firstChangeSerial = 0;
    std::uint64_t lastChangeSerial = 0;
    std::uint64_t changeDelta = 0;
    std::uint64_t changeTotal = 0;
    bool currentRigid = false;
    bool previousRigid = false;
    Matrix4 current{};
};

struct AffineMatrixMetrics {
    double rowLength[3]{};
    double maximumRowDot = 0.0;
    double determinant = 0.0;
    double bottomError = 0.0;
};

AffineMatrixMetrics MeasureAffineMatrix(const Matrix4& matrix) {
    AffineMatrixMetrics metrics{};
    const auto rowDot = [&](int left, int right) {
        return static_cast<double>(matrix.values[left * 4]) *
                   matrix.values[right * 4] +
               static_cast<double>(matrix.values[left * 4 + 1]) *
                   matrix.values[right * 4 + 1] +
               static_cast<double>(matrix.values[left * 4 + 2]) *
                   matrix.values[right * 4 + 2];
    };
    for (int row = 0; row < 3; ++row) {
        metrics.rowLength[row] = std::sqrt(std::max(0.0, rowDot(row, row)));
    }
    metrics.maximumRowDot = std::max({std::abs(rowDot(0, 1)),
                                      std::abs(rowDot(0, 2)),
                                      std::abs(rowDot(1, 2))});
    metrics.determinant =
        matrix.values[0] * (matrix.values[5] * matrix.values[10] -
                            matrix.values[6] * matrix.values[9]) -
        matrix.values[1] * (matrix.values[4] * matrix.values[10] -
                            matrix.values[6] * matrix.values[8]) +
        matrix.values[2] * (matrix.values[4] * matrix.values[9] -
                            matrix.values[5] * matrix.values[8]);
    metrics.bottomError =
        std::max({std::abs(static_cast<double>(matrix.values[12])),
                  std::abs(static_cast<double>(matrix.values[13])),
                  std::abs(static_cast<double>(matrix.values[14])),
                  std::abs(static_cast<double>(matrix.values[15] - 1.0f))});
    return metrics;
}

std::size_t CollectWorldTrackReports(
    std::array<WorldTrackReport, kWorldTrackReportCapacity>& reports,
    std::size_t& pendingCount) {
    std::size_t reportCount = 0;
    pendingCount = 0;
    AcquireSRWLockExclusive(&g_worldTransformLock);
    for (const WorldTransformTrack& track : g_worldTransforms) {
        if (track.renderModel == nullptr) {
            continue;
        }
        if (track.motionSamples != track.reportedMotionSamples ||
            track.correctionBuilds != track.reportedCorrectionBuilds) {
            ++pendingCount;
        }
    }

    // Report moving-but-uncorrected tracks first, then reflected moving tracks,
    // then all other activity. This keeps the vehicle diagnostic visible even
    // in scenes with hundreds of animated models.
    for (int pass = 0; pass < 3 && reportCount < reports.size(); ++pass) {
        for (WorldTransformTrack& track : g_worldTransforms) {
            if (track.renderModel == nullptr) {
                continue;
            }
            const std::uint64_t motionDelta =
                track.motionSamples - track.reportedMotionSamples;
            const std::uint64_t correctionDelta =
                track.correctionBuilds - track.reportedCorrectionBuilds;
            if (motionDelta == 0 && correctionDelta == 0) {
                continue;
            }
            const bool uncorrectedMotion = motionDelta != 0 && correctionDelta == 0;
            const bool reflectedMotion = track.reflected && motionDelta != 0;
            if ((pass == 0 && !uncorrectedMotion) ||
                (pass == 1 && (uncorrectedMotion || !reflectedMotion)) ||
                (pass == 2 && (uncorrectedMotion || reflectedMotion))) {
                continue;
            }

            WorldTrackReport& report = reports[reportCount++];
            report.renderModel = track.renderModel;
            report.owner = track.owner;
            report.modelAsset = track.modelAsset;
            report.vtableRva = track.vtable >= g_executableBase ?
                track.vtable - g_executableBase : track.vtable;
            report.diagnosticId = track.diagnosticId;
            report.firstSeenSerial = track.firstSeenSerial;
            report.firstMotionSerial = track.firstMotionSerial;
            report.lastMotionSerial = track.lastMotionSerial;
            report.lastCorrectionSerial = track.lastCorrectionSerial;
            report.motionDelta = motionDelta;
            report.correctionDelta = correctionDelta;
            report.motionTotal = track.motionSamples;
            report.correctionTotal = track.correctionBuilds;
            report.discontinuities = track.discontinuities;
            report.origin = {track.current.values[3], track.current.values[7],
                             track.current.values[11]};
            report.reflected = track.reflected;
            track.reportedMotionSamples = track.motionSamples;
            track.reportedCorrectionBuilds = track.correctionBuilds;
            if (reportCount == reports.size()) {
                break;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_worldTransformLock);
    return reportCount;
}

std::size_t CollectNonRigidTrackReports(
    std::array<NonRigidTrackReport, kNonRigidTrackReportCapacity>& reports,
    std::size_t& pendingCount) {
    std::size_t reportCount = 0;
    pendingCount = 0;
    AcquireSRWLockExclusive(&g_worldTransformLock);
    for (NonRigidWorldTrack& track : g_nonRigidWorldTracks) {
        if (track.renderModel == nullptr || track.changes == track.reportedChanges) {
            continue;
        }
        ++pendingCount;
        if (reportCount == reports.size()) {
            continue;
        }
        NonRigidTrackReport& report = reports[reportCount++];
        report.renderModel = track.renderModel;
        report.owner = track.owner;
        report.diagnosticId = track.diagnosticId;
        report.firstSeenSerial = track.firstSeenSerial;
        report.firstChangeSerial = track.firstChangeSerial;
        report.lastChangeSerial = track.lastChangeSerial;
        report.changeDelta = track.changes - track.reportedChanges;
        report.changeTotal = track.changes;
        report.currentRigid = track.currentRigid;
        report.previousRigid = track.previousRigid;
        report.current = track.current;
        track.reportedChanges = track.changes;
    }
    ReleaseSRWLockExclusive(&g_worldTransformLock);
    return reportCount;
}

void MaybeLogWorldTransformDiagnostics(const PresentationContext& context) {
    if ((!g_interpolateWorldTransforms &&
         !g_interpolateCinematicTransforms) || !context.valid) {
        return;
    }
    std::uint64_t next = g_nextWorldDiagnosticsSerial.load(std::memory_order_relaxed);
    if (context.serial < next ||
        !g_nextWorldDiagnosticsSerial.compare_exchange_strong(
            next, context.serial + 1200, std::memory_order_relaxed)) {
        return;
    }

    char observed[384]{};
    std::size_t offset = 0;
    for (const ObservedWorldVtable& observation : g_observedWorldVtables) {
        const std::uintptr_t rva = observation.rva.load(std::memory_order_relaxed);
        const std::uint64_t count = observation.count.load(std::memory_order_relaxed);
        if (rva == 0 || count == 0 || offset >= sizeof(observed)) {
            continue;
        }
        const int written = sprintf_s(
            observed + offset, sizeof(observed) - offset,
            "%s0x%llX:%llu", offset == 0 ? "" : ",",
            static_cast<unsigned long long>(rva),
            static_cast<unsigned long long>(count));
        if (written < 0) {
            break;
        }
        offset += static_cast<std::size_t>(written);
    }

    Log("World diagnostics frame=%llu: candidates=%llu, exactStatic=%llu, "
        "exactSkinned=%llu, "
        "eligible=%llu, supported=%llu, uniformScaled=%llu, "
        "reflected[supported=%llu moving=%llu adjusted=%llu], moving=%llu, "
        "tracks=%llu, pairs=%llu, "
        "adjusted=%llu(skinned=%llu), rejected[vtable=%llu depth=%llu owner=%llu "
        "nonRigid=%llu(current=%llu previous=%llu) discontinuity=%llu "
        "sameTime=%llu jump=%llu reflectionParity=%llu], capacityMiss=%llu "
        "nonRigidCapacityMiss=%llu, "
        "observedVtables=[%s].",
        static_cast<unsigned long long>(context.serial),
        static_cast<unsigned long long>(
            g_worldDiagnostics.candidates.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.exactStaticType.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.exactSkinnedType.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.eligible.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.rigid.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.uniformScaled.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.reflectedRigid.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.reflectedMoving.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.reflectedAdjusted.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.moving.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.tracksCreated.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.samplePairs.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldTransformAdjustedCount.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.skinnedAdjusted.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.vtableRejected.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.depthHackRejected.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.ownerRejected.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.nonRigidRejected.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.currentNonRigidRejected.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.previousNonRigidRejected.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.discontinuityRejected.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.sameTimeMutationRejected.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.jumpRejected.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.reflectionParityRejected.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldTransformCapacityMissCount.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_nonRigidTrackCapacityMissCount.load(std::memory_order_relaxed)),
        observed);

    Log("World cinematic frame=%llu: eligible=%llu adjusted=%llu.",
        static_cast<unsigned long long>(context.serial),
        static_cast<unsigned long long>(
            g_worldDiagnostics.cinematicEligible.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_worldDiagnostics.cinematicAdjusted.load(
                std::memory_order_relaxed)));

    if (g_interpolateShadowTransforms) {
        Log("Shadow transform frame=%llu: calls=%llu published=%llu "
            "matches[direct=%llu content=%llu ambiguous=%llu] adjusted=%llu "
            "cacheMiss=%llu unreadable=%llu "
            "proxy[calls=%llu lists=%llu capacityMiss=%llu] "
            "capacityMiss[pointer=%llu content=%llu].",
            static_cast<unsigned long long>(context.serial),
            static_cast<unsigned long long>(
                g_shadowMatrixCalls.load(std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowCorrectionPublications.load(std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowMatrixDirectMatches.load(std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowMatrixContentMatches.load(std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowMatrixAmbiguousMatches.load(std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowMatrixAdjusted.load(std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowMatrixCacheMisses.load(std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowMatrixUnreadable.load(std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowCasterProxyCalls.load(std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowCasterProxyLists.load(std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowCasterProxyCapacityMisses.load(
                    std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowCorrectionPointerCapacityMisses.load(
                    std::memory_order_relaxed)),
            static_cast<unsigned long long>(
                g_shadowCorrectionContentCapacityMisses.load(
                    std::memory_order_relaxed)));
    }

    std::array<WorldTrackReport, kWorldTrackReportCapacity> reports{};
    std::size_t pendingCount = 0;
    const std::size_t reportCount = CollectWorldTrackReports(reports, pendingCount);
    for (std::size_t index = 0; index < reportCount; ++index) {
        const WorldTrackReport& report = reports[index];
        Log("World track frame=%llu id=%llu model=%p owner=%p asset=%p "
            "vtableRva=0x%llX "
            "reflected=%u "
            "delta[motion=%llu corrected=%llu] total[motion=%llu corrected=%llu] "
            "serial[first=%llu firstMotion=%llu lastMotion=%llu "
            "lastCorrection=%llu] discontinuities=%llu origin=(%.3f,%.3f,%.3f).",
            static_cast<unsigned long long>(context.serial),
            static_cast<unsigned long long>(report.diagnosticId),
            report.renderModel, report.owner, report.modelAsset,
            static_cast<unsigned long long>(report.vtableRva),
            report.reflected ? 1U : 0U,
            static_cast<unsigned long long>(report.motionDelta),
            static_cast<unsigned long long>(report.correctionDelta),
            static_cast<unsigned long long>(report.motionTotal),
            static_cast<unsigned long long>(report.correctionTotal),
            static_cast<unsigned long long>(report.firstSeenSerial),
            static_cast<unsigned long long>(report.firstMotionSerial),
            static_cast<unsigned long long>(report.lastMotionSerial),
            static_cast<unsigned long long>(report.lastCorrectionSerial),
            static_cast<unsigned long long>(report.discontinuities),
            report.origin.x, report.origin.y, report.origin.z);
    }
    if (pendingCount > reportCount) {
        Log("World track frame=%llu: reported %llu of %llu changed tracks; "
            "remaining tracks carry forward to the next diagnostic window.",
            static_cast<unsigned long long>(context.serial),
            static_cast<unsigned long long>(reportCount),
            static_cast<unsigned long long>(pendingCount));
    }

    std::array<NonRigidTrackReport, kNonRigidTrackReportCapacity>
        nonRigidReports{};
    std::size_t nonRigidPendingCount = 0;
    const std::size_t nonRigidReportCount =
        CollectNonRigidTrackReports(nonRigidReports, nonRigidPendingCount);
    for (std::size_t index = 0; index < nonRigidReportCount; ++index) {
        const NonRigidTrackReport& report = nonRigidReports[index];
        const AffineMatrixMetrics metrics = MeasureAffineMatrix(report.current);
        Log("Non-rigid world track frame=%llu id=%llu model=%p owner=%p "
            "deltaChanges=%llu totalChanges=%llu rigid[current=%u previous=%u] "
            "serial[first=%llu firstChange=%llu lastChange=%llu] "
            "origin=(%.3f,%.3f,%.3f) rowLength=(%.5f,%.5f,%.5f) "
            "maxRowDot=%.6f determinant=%.6f bottomError=%.6f.",
            static_cast<unsigned long long>(context.serial),
            static_cast<unsigned long long>(report.diagnosticId),
            report.renderModel, report.owner,
            static_cast<unsigned long long>(report.changeDelta),
            static_cast<unsigned long long>(report.changeTotal),
            report.currentRigid ? 1U : 0U, report.previousRigid ? 1U : 0U,
            static_cast<unsigned long long>(report.firstSeenSerial),
            static_cast<unsigned long long>(report.firstChangeSerial),
            static_cast<unsigned long long>(report.lastChangeSerial),
            static_cast<double>(report.current.values[3]),
            static_cast<double>(report.current.values[7]),
            static_cast<double>(report.current.values[11]),
            metrics.rowLength[0], metrics.rowLength[1], metrics.rowLength[2],
            metrics.maximumRowDot, metrics.determinant, metrics.bottomError);
    }
    if (nonRigidPendingCount > nonRigidReportCount) {
        Log("Non-rigid world track frame=%llu: reported %llu of %llu changed "
            "tracks; remaining tracks carry forward.",
            static_cast<unsigned long long>(context.serial),
            static_cast<unsigned long long>(nonRigidReportCount),
            static_cast<unsigned long long>(nonRigidPendingCount));
    }
}

// Change detection for joint palettes. Processes eight bytes per step (a
// joint is 48 bytes) instead of one; only equality of hashes is ever used.
std::uint64_t HashJointPalette(const d2_pose::JointMatrix* palette,
                               std::size_t jointCount) {
    static_assert(sizeof(d2_pose::JointMatrix) % sizeof(std::uint64_t) == 0,
                  "Joint palettes are hashed in 64-bit words");
    const auto* bytes = reinterpret_cast<const unsigned char*>(palette);
    const std::size_t wordCount =
        jointCount * sizeof(d2_pose::JointMatrix) / sizeof(std::uint64_t);
    std::uint64_t hash = 1469598103934665603ULL ^ jointCount;
    for (std::size_t index = 0; index < wordCount; ++index) {
        std::uint64_t word = 0;
        memcpy(&word, bytes + index * sizeof(word), sizeof(word));
        hash = (hash ^ word) * 0x9E3779B97F4A7C15ULL;
        hash ^= hash >> 29;
    }
    return hash;
}

bool JointPalettesAreContinuous(const d2_pose::JointMatrix* previous,
                                const d2_pose::JointMatrix* current,
                                std::size_t jointCount) {
    for (std::size_t index = 0; index < jointCount; ++index) {
        const double deltaX = static_cast<double>(current[index].values[3]) -
                              previous[index].values[3];
        const double deltaY = static_cast<double>(current[index].values[7]) -
                              previous[index].values[7];
        const double deltaZ = static_cast<double>(current[index].values[11]) -
                              previous[index].values[11];
        const double translationDistance =
            std::sqrt(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
        if (!std::isfinite(translationDistance) ||
            translationDistance > kMaximumJointTranslationJump) {
            return false;
        }

        const d2_pose::Quaternion previousRotation =
            d2_pose::RotationToQuaternion(previous[index]);
        const d2_pose::Quaternion currentRotation =
            d2_pose::RotationToQuaternion(current[index]);
        const double dot = std::abs(
            previousRotation.w * currentRotation.w +
            previousRotation.x * currentRotation.x +
            previousRotation.y * currentRotation.y +
            previousRotation.z * currentRotation.z);
        const double angleDegrees =
            2.0 * std::acos(Clamp(dot, 0.0, 1.0)) * 180.0 / kPi;
        if (!std::isfinite(angleDegrees) ||
            angleDegrees > kMaximumJointRotationJumpDegrees) {
            return false;
        }
    }
    return true;
}

std::size_t OwnerlessSkeletalHash(const void* renderModel,
                                  const void* modelAsset) {
    std::uintptr_t value = reinterpret_cast<std::uintptr_t>(renderModel) >> 4;
    value ^= (reinterpret_cast<std::uintptr_t>(modelAsset) >> 4) +
             static_cast<std::uintptr_t>(0x9E3779B97F4A7C15ULL) +
             (value << 6) + (value >> 2);
    return static_cast<std::size_t>(value) &
           (kOwnerlessSkeletalTrackCapacity - 1);
}

OwnerlessSkeletalTrack* FindOwnerlessSkeletalTrack(
    const void* renderModel, const void* modelAsset, std::uint64_t serial,
    bool allowCreate) {
    static_assert((kOwnerlessSkeletalTrackCapacity &
                   (kOwnerlessSkeletalTrackCapacity - 1)) == 0,
                  "Ownerless skeletal track capacity must be a power of two");
    const std::size_t start = OwnerlessSkeletalHash(renderModel, modelAsset);
    OwnerlessSkeletalTrack* reusable = nullptr;
    for (std::size_t probe = 0; probe < kOwnerlessSkeletalTrackProbeLimit;
         ++probe) {
        OwnerlessSkeletalTrack& track =
            g_ownerlessSkeletalTracks[(start + probe) &
                                      (kOwnerlessSkeletalTrackCapacity - 1)];
        if (track.renderModel == renderModel && track.modelAsset == modelAsset) {
            return &track;
        }
        if (track.renderModel == nullptr ||
            serial > track.lastSeenSerial + kWorldTransformStaleFrames) {
            if (reusable == nullptr) {
                reusable = &track;
            }
        }
    }
    if (!allowCreate) {
        return nullptr;
    }
    if (reusable == nullptr) {
        g_ownerlessSkeletalTrackCapacityMissCount.fetch_add(
            1, std::memory_order_relaxed);
        return nullptr;
    }
    *reusable = {};
    reusable->renderModel = renderModel;
    reusable->modelAsset = modelAsset;
    reusable->diagnosticId =
        g_nextSkeletalTrackId.fetch_add(1, std::memory_order_relaxed);
    reusable->firstSeenSerial = serial;
    reusable->lastSeenSerial = serial;
    return reusable;
}

void ObserveOwnerlessSkeletalModel(
    const void* renderModel, const void* modelAsset,
    const d2_pose::JointMatrix* palette, std::uint32_t jointCount,
    std::uint32_t paddedJointCount, signed char pending,
    const PresentationContext& context) {
    AcquireSkeletalObservationLock();
    OwnerlessSkeletalTrack* track = FindOwnerlessSkeletalTrack(
        renderModel, modelAsset, context.serial, false);
    if (track == nullptr) {
        track = FindOwnerlessSkeletalTrack(renderModel, modelAsset,
                                           context.serial, true);
    }
    if (track == nullptr) {
        ReleaseSRWLockExclusive(&g_skeletalObservationLock);
        return;
    }
    track->lastSeenSerial = context.serial;
    track->cpuPalette = palette;
    track->jointCount = jointCount;
    track->paddedJointCount = paddedJointCount;
    track->pending = pending;
    if (track->samples != 0 &&
        context.simulationTime <= track->simulationTime + kTimeEpsilon) {
        ReleaseSRWLockExclusive(&g_skeletalObservationLock);
        return;
    }

    const std::uint64_t checksum = HashJointPalette(palette, jointCount);
    bool paletteRigid = true;
    std::uint32_t firstNonRigidJoint =
        std::numeric_limits<std::uint32_t>::max();
    for (std::uint32_t index = 0; index < jointCount; ++index) {
        if (!d2_pose::IsRigid(palette[index])) {
            paletteRigid = false;
            firstNonRigidJoint = index;
            break;
        }
    }
    const bool changed = track->samples != 0 && checksum != track->checksum;
    track->simulationTime = context.simulationTime;
    track->checksum = checksum;
    track->lastPaletteRigid = paletteRigid;
    track->firstNonRigidJoint = firstNonRigidJoint;
    track->rootTranslation[0] = palette[0].values[3];
    track->rootTranslation[1] = palette[0].values[7];
    track->rootTranslation[2] = palette[0].values[11];
    ++track->samples;
    if (paletteRigid) {
        ++track->rigidSamples;
    }
    if (changed) {
        if (track->changes == 0) {
            track->firstChangeSerial = context.serial;
        }
        track->lastChangeSerial = context.serial;
        ++track->changes;
    }
    ReleaseSRWLockExclusive(&g_skeletalObservationLock);
}

void MeasureNonRigidJoint(const d2_pose::JointMatrix& matrix,
                          SkeletalObservationTrack& track,
                          std::uint32_t jointIndex) {
    track.firstNonRigidJoint = jointIndex;
    const auto dotRows = [&](int left, int right) {
        return static_cast<double>(matrix.values[left * 4]) *
                   matrix.values[right * 4] +
               static_cast<double>(matrix.values[left * 4 + 1]) *
                   matrix.values[right * 4 + 1] +
               static_cast<double>(matrix.values[left * 4 + 2]) *
                   matrix.values[right * 4 + 2];
    };
    for (int row = 0; row < 3; ++row) {
        track.nonRigidRowLength[row] =
            std::sqrt(std::max(0.0, dotRows(row, row)));
    }
    track.nonRigidMaximumRowDot = std::max(
        std::abs(dotRows(0, 1)),
        std::max(std::abs(dotRows(0, 2)), std::abs(dotRows(1, 2))));
    track.nonRigidDeterminant =
        matrix.values[0] * (matrix.values[5] * matrix.values[10] -
                            matrix.values[6] * matrix.values[9]) -
        matrix.values[1] * (matrix.values[4] * matrix.values[10] -
                            matrix.values[6] * matrix.values[8]) +
        matrix.values[2] * (matrix.values[4] * matrix.values[9] -
                            matrix.values[5] * matrix.values[8]);
}

std::size_t SkeletalObservationHash(const void* renderModel, const void* owner) {
    std::uintptr_t value = reinterpret_cast<std::uintptr_t>(renderModel) >> 4;
    value ^= (reinterpret_cast<std::uintptr_t>(owner) >> 4) +
             static_cast<std::uintptr_t>(0x9E3779B97F4A7C15ULL) +
             (value << 6) + (value >> 2);
    return static_cast<std::size_t>(value) & (kSkeletalTrackCapacity - 1);
}

SkeletalObservationTrack* FindSkeletalObservationTrack(
    const void* renderModel, const void* owner, std::uint64_t serial,
    bool allowCreate) {
    const std::size_t start = SkeletalObservationHash(renderModel, owner);
    SkeletalObservationTrack* reusable = nullptr;
    for (std::size_t probe = 0; probe < kSkeletalTrackProbeLimit; ++probe) {
        SkeletalObservationTrack& track =
            g_skeletalObservationTracks[(start + probe) &
                                        (kSkeletalTrackCapacity - 1)];
        if (track.renderModel == renderModel && track.owner == owner) {
            return &track;
        }
        if (track.renderModel == nullptr ||
            serial > track.lastSeenSerial + kWorldTransformStaleFrames) {
            if (reusable == nullptr) {
                reusable = &track;
            }
        }
    }
    if (!allowCreate) {
        return nullptr;
    }
    if (reusable == nullptr) {
        g_skeletalTrackCapacityMissCount.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    *reusable = {};
    reusable->renderModel = renderModel;
    reusable->owner = owner;
    reusable->diagnosticId =
        g_nextSkeletalTrackId.fetch_add(1, std::memory_order_relaxed);
    reusable->firstSeenSerial = serial;
    reusable->lastSeenSerial = serial;
    g_skeletalDiagnostics.tracksCreated.fetch_add(1, std::memory_order_relaxed);
    return reusable;
}

constexpr std::size_t kPaletteRigidityCacheSize = 2048;

struct PaletteRigidityCacheEntry {
    const void* palette = nullptr;
    std::uint64_t checksum = 0;
    std::uint32_t jointCount = 0;
    std::uint32_t firstNonRigidJoint = 0;
    bool rigid = false;
};

SRWLOCK g_paletteRigidityLock = SRWLOCK_INIT;
std::array<PaletteRigidityCacheEntry, kPaletteRigidityCacheSize> g_paletteRigidity{};

bool PaletteIsRigid(const d2_pose::JointMatrix* palette, std::uint32_t jointCount,
                    std::uint64_t checksum, std::uint32_t& firstNonRigidJoint) {
    const std::size_t slot =
        (static_cast<std::size_t>(reinterpret_cast<std::uintptr_t>(palette) >> 4) ^
         static_cast<std::size_t>(checksum)) & (kPaletteRigidityCacheSize - 1);
    AcquireSRWLockShared(&g_paletteRigidityLock);
    const PaletteRigidityCacheEntry cached = g_paletteRigidity[slot];
    ReleaseSRWLockShared(&g_paletteRigidityLock);
    if (cached.palette == palette && cached.checksum == checksum &&
        cached.jointCount == jointCount) {
        firstNonRigidJoint = cached.firstNonRigidJoint;
        return cached.rigid;
    }
    bool rigid = true;
    firstNonRigidJoint = std::numeric_limits<std::uint32_t>::max();
    for (std::uint32_t index = 0; index < jointCount; ++index) {
        if (!d2_pose::IsRigid(palette[index])) {
            rigid = false;
            firstNonRigidJoint = index;
            break;
        }
    }
    AcquireSRWLockExclusive(&g_paletteRigidityLock);
    g_paletteRigidity[slot] = {palette, checksum, jointCount, firstNonRigidJoint, rigid};
    ReleaseSRWLockExclusive(&g_paletteRigidityLock);
    return rigid;
}

bool PrepareSkeletalPose(
    void* renderModel,
    std::array<d2_pose::JointMatrix, kMaximumJointCount>& output,
    SkeletalPreparedUpload& prepared) {
    g_skeletalDiagnostics.calls.fetch_add(1, std::memory_order_relaxed);
    if (!IsReadableMemoryCached(renderModel, kSkinnedModelSize)) {
        g_skeletalDiagnostics.layoutRejected.fetch_add(1,
                                                       std::memory_order_relaxed);
        return false;
    }

    std::uintptr_t vtable = 0;
    memcpy(&vtable, renderModel, sizeof(vtable));
    if (vtable != g_executableBase + g_layout->skinnedModelVtable.rva) {
        return false;
    }
    g_skeletalDiagnostics.exactSkinnedType.fetch_add(1,
                                                     std::memory_order_relaxed);

    const auto* bytes = static_cast<const unsigned char*>(renderModel);
    float depthHack = 0.0f;
    memcpy(&depthHack, bytes + kRenderModelDepthHackOffset, sizeof(depthHack));
    const bool firstPerson = std::isfinite(depthHack) && depthHack > 0.0f &&
                             depthHack < 100.0f;
    const bool world = std::isfinite(depthHack) &&
                       std::abs(depthHack) <= 1.0e-6f;
    if (firstPerson) {
        if (!g_interpolateFirstPersonSkeletons) {
            g_skeletalDiagnostics.firstPersonDisabled.fetch_add(
                1, std::memory_order_relaxed);
            return false;
        }
    } else if (!world) {
        g_skeletalDiagnostics.depthHackRejected.fetch_add(
            1, std::memory_order_relaxed);
        return false;
    }

    const void* owner = nullptr;
    const void* modelAsset = nullptr;
    const d2_pose::JointMatrix* palette = nullptr;
    std::uint32_t jointCount = 0;
    std::uint32_t packedPaddedJointCount = 0;
    signed char pending = 0;
    memcpy(&owner, bytes + kRenderModelOwnerOffset, sizeof(owner));
    memcpy(&modelAsset, bytes + kSkinnedModelAssetOffset, sizeof(modelAsset));
    memcpy(&palette, bytes + kSkinnedPoseCpuListOffset, sizeof(palette));
    memcpy(&jointCount, bytes + kSkinnedTrueJointCountOffset,
           sizeof(jointCount));
    memcpy(&packedPaddedJointCount, bytes + kSkinnedPosePaddedCountOffset,
           sizeof(packedPaddedJointCount));
    memcpy(&pending, bytes + kSkinnedPosePendingOffset, sizeof(pending));
    const std::uint32_t paddedJointCount =
        packedPaddedJointCount & 0x00FFFFFFU;
    const std::uint32_t expectedPaddedJointCount =
        (jointCount + 7U) & ~7U;
    const std::size_t paletteBytes =
        static_cast<std::size_t>(paddedJointCount) *
        sizeof(d2_pose::JointMatrix);
    if (modelAsset == nullptr ||
        !IsReadableMemoryCached(modelAsset, sizeof(void*)) || palette == nullptr ||
        jointCount == 0 ||
        jointCount > kMaximumJointCount ||
        paddedJointCount != expectedPaddedJointCount ||
        paddedJointCount > kMaximumJointCount ||
        !IsReadableMemoryCached(palette, paletteBytes)) {
        g_skeletalDiagnostics.layoutRejected.fetch_add(1,
                                                       std::memory_order_relaxed);
        return false;
    }

    const bool ownerReadable =
        owner != nullptr && IsReadableMemoryCached(owner, sizeof(void*));
    const void* trackOwner = owner;
    bool cinematic = false;
    if (!ownerReadable) {
        if (!firstPerson) {
            if (!g_interpolateCinematicSkeletons ||
                jointCount > kMaximumCinematicJointCount) {
                PresentationContext ownerlessContext{};
                if (ReadPresentationContext(ownerlessContext)) {
                    ObserveOwnerlessSkeletalModel(
                        renderModel, modelAsset, palette, jointCount,
                        paddedJointCount, pending, ownerlessContext);
                }
                g_skeletalDiagnostics.ownerRejected.fetch_add(
                    1, std::memory_order_relaxed);
                return false;
            }
            // Small exact-skinned cinematic attachments may be renderer-owned
            // and omit the ordinary world entity owner. Keep this separate
            // from WorldSkeletons, use the validated model asset as the second
            // identity component, and retain all palette/layout guards.
            trackOwner = modelAsset;
            cinematic = true;
            g_skeletalDiagnostics.cinematicEligible.fetch_add(
                1, std::memory_order_relaxed);
        } else {
            // Depth-hacked viewmodels are renderer-owned and may not expose the
            // world-entity owner used by ordinary skinned models. The validated
            // model asset is stable enough to complete the per-render-model key;
            // asset/palette/count changes still reset the history below.
            trackOwner = modelAsset;
            g_skeletalDiagnostics.firstPersonOwnerFallback.fetch_add(
                1, std::memory_order_relaxed);
        }
    } else if (world && !g_interpolateWorldSkeletons) {
        return false;
    }
    if (firstPerson) {
        g_skeletalDiagnostics.firstPersonEligible.fetch_add(
            1, std::memory_order_relaxed);
    } else if (!cinematic) {
        g_skeletalDiagnostics.worldEligible.fetch_add(
            1, std::memory_order_relaxed);
    }
    if (pending > 0) {
        g_skeletalDiagnostics.pendingSamples.fetch_add(
            1, std::memory_order_relaxed);
    }

    PresentationContext context{};
    if (!ReadPresentationContext(context)) {
        return false;
    }

    const std::uint64_t checksum = HashJointPalette(palette, jointCount);
    std::uint32_t firstNonRigidJoint = 0;
    const bool paletteRigid =
        PaletteIsRigid(palette, jointCount, checksum, firstNonRigidJoint);

    AcquireSkeletalObservationLock();
    SkeletalObservationTrack* track = FindSkeletalObservationTrack(
        renderModel, trackOwner, context.serial, false);
    if (track == nullptr) {
        track = FindSkeletalObservationTrack(renderModel, trackOwner,
                                             context.serial, true);
    }
    if (track == nullptr) {
        ReleaseSRWLockExclusive(&g_skeletalObservationLock);
        return false;
    }

    if ((track->samples != 0 &&
         (track->firstPerson != firstPerson ||
          track->cinematic != cinematic)) ||
        (track->modelAsset != nullptr && track->modelAsset != modelAsset) ||
        (track->cpuPalette != nullptr && track->cpuPalette != palette) ||
        (track->jointCount != 0 && track->jointCount != jointCount) ||
        (track->paddedJointCount != 0 &&
         track->paddedJointCount != paddedJointCount)) {
        const std::uint64_t diagnosticId =
            g_nextSkeletalTrackId.fetch_add(1, std::memory_order_relaxed);
        *track = {};
        track->renderModel = renderModel;
        track->owner = trackOwner;
        track->diagnosticId = diagnosticId;
        track->firstSeenSerial = context.serial;
        g_skeletalDiagnostics.tracksCreated.fetch_add(1,
                                                      std::memory_order_relaxed);
    }
    track->lastSeenSerial = context.serial;
    track->firstPerson = firstPerson;
    track->cinematic = cinematic;
    track->modelAsset = modelAsset;
    track->cpuPalette = palette;
    track->jointCount = jointCount;
    track->paddedJointCount = paddedJointCount;
    track->rootTranslation[0] = palette[0].values[3];
    track->rootTranslation[1] = palette[0].values[7];
    track->rootTranslation[2] = palette[0].values[11];
    track->lastPaletteRigid = paletteRigid;
    if (!paletteRigid) {
        MeasureNonRigidJoint(palette[firstNonRigidJoint], *track,
                             firstNonRigidJoint);
    }

    const bool firstSample = track->samples == 0;
    const bool laterTime = firstSample ||
        context.simulationTime > track->simulationTime + kTimeEpsilon;
    if (laterTime) {
        const bool changed = !firstSample && checksum != track->checksum;
        const double interval = context.simulationTime - track->simulationTime;

        if (paletteRigid && !track->hasSnapshot) {
            memcpy(track->currentPalette.data(), palette, paletteBytes);
            memcpy(track->previousPalette.data(), palette, paletteBytes);
            track->previousTime = context.simulationTime;
            track->simulationTime = context.simulationTime;
            track->hasSnapshot = true;
            track->hasPair = false;
        } else if (paletteRigid && track->hasSnapshot && !firstSample &&
                   interval > kTimeEpsilon &&
                   interval <= kMaximumSkeletalStateInterval &&
                   (!changed || JointPalettesAreContinuous(
                       track->currentPalette.data(), palette, jointCount))) {
            track->previousTime = track->simulationTime;
            track->simulationTime = context.simulationTime;
            if (changed) {
                memcpy(track->previousPalette.data(),
                       track->currentPalette.data(), paletteBytes);
                memcpy(track->currentPalette.data(), palette, paletteBytes);
                track->hasPair = true;
                g_skeletalDiagnostics.samplePairs.fetch_add(
                    1, std::memory_order_relaxed);
                (firstPerson ? g_skeletalDiagnostics.firstPersonSamplePairs
                             : g_skeletalDiagnostics.worldSamplePairs)
                    .fetch_add(1, std::memory_order_relaxed);
                if (cinematic) {
                    g_skeletalDiagnostics.cinematicSamplePairs.fetch_add(
                        1, std::memory_order_relaxed);
                }
            } else {
                track->hasPair = false;
            }
        } else {
            track->hasPair = false;
            track->hasSnapshot = paletteRigid;
            track->previousTime = context.simulationTime;
            track->simulationTime = context.simulationTime;
            if (paletteRigid) {
                memcpy(track->currentPalette.data(), palette, paletteBytes);
                memcpy(track->previousPalette.data(), palette, paletteBytes);
            }
            if (!firstSample) {
                g_skeletalDiagnostics.discontinuityRejected.fetch_add(
                    1, std::memory_order_relaxed);
            }
        }
        track->checksum = checksum;
        ++track->samples;
        if (paletteRigid) {
            ++track->rigidSamples;
        }
        if (changed) {
            if (track->changes == 0) {
                track->firstChangeSerial = context.serial;
            }
            track->lastChangeSerial = context.serial;
            ++track->changes;
        }
        g_skeletalDiagnostics.timeSamples.fetch_add(1,
                                                    std::memory_order_relaxed);
        if (changed) {
            g_skeletalDiagnostics.changedSamples.fetch_add(
                1, std::memory_order_relaxed);
        }
        if (paletteRigid) {
            g_skeletalDiagnostics.rigidPalettes.fetch_add(
                1, std::memory_order_relaxed);
        } else {
            g_skeletalDiagnostics.nonRigidPalettes.fetch_add(
                1, std::memory_order_relaxed);
        }
    } else if (context.simulationTime <
               track->simulationTime - kTimeEpsilon) {
        track->checksum = checksum;
        track->hasPair = false;
        track->hasSnapshot = paletteRigid;
        track->previousTime = context.simulationTime;
        track->simulationTime = context.simulationTime;
        if (paletteRigid) {
            memcpy(track->currentPalette.data(), palette, paletteBytes);
            memcpy(track->previousPalette.data(), palette, paletteBytes);
        }
        g_skeletalDiagnostics.discontinuityRejected.fetch_add(
            1, std::memory_order_relaxed);
    } else if (checksum != track->checksum) {
        track->checksum = checksum;
        track->hasPair = false;
        track->hasSnapshot = paletteRigid;
        track->previousTime = context.simulationTime;
        track->simulationTime = context.simulationTime;
        if (paletteRigid) {
            memcpy(track->currentPalette.data(), palette, paletteBytes);
            memcpy(track->previousPalette.data(), palette, paletteBytes);
        }
        g_skeletalDiagnostics.sameTimeChanges.fetch_add(
            1, std::memory_order_relaxed);
    }

    bool adjusted = false;
    const double pairInterval = track->simulationTime - track->previousTime;
    if (paletteRigid && track->hasPair &&
        (!track->hasPresentedOutput ||
         track->lastPresentedSerial != context.serial) &&
        pairInterval > kTimeEpsilon &&
        pairInterval <= kMaximumSkeletalStateInterval) {
        const double alpha = Clamp(
            (context.scaledTime - track->previousTime) / pairInterval,
            kMinimumAlpha, kMaximumAlpha);
        memcpy(output.data(), palette, paletteBytes);
        // Both stored palettes were accepted as rigid when they were sampled.
        adjusted = d2_pose::InterpolateJointPalettes(
            track->previousPalette.data(), track->currentPalette.data(),
            jointCount, alpha, output.data(), false);
        if (adjusted) {
            prepared.renderModel = renderModel;
            prepared.owner = trackOwner;
            prepared.diagnosticId = track->diagnosticId;
            prepared.presentationSerial = context.serial;
            prepared.outputChecksum = HashJointPalette(output.data(), jointCount);
            prepared.alpha = alpha;
            prepared.firstPerson = firstPerson;
            prepared.cinematic = cinematic;
            g_skeletalDiagnostics.preparedUploads.fetch_add(
                1, std::memory_order_relaxed);
            (firstPerson ? g_skeletalDiagnostics.firstPersonPreparedUploads
                         : g_skeletalDiagnostics.worldPreparedUploads)
                .fetch_add(1, std::memory_order_relaxed);
            if (cinematic) {
                g_skeletalDiagnostics.cinematicPreparedUploads.fetch_add(
                    1, std::memory_order_relaxed);
            }
        } else {
            track->hasPair = false;
            g_skeletalDiagnostics.interpolationRejected.fetch_add(
                1, std::memory_order_relaxed);
        }
    }
    ReleaseSRWLockExclusive(&g_skeletalObservationLock);
    return adjusted;
}

void RecordSkeletalUpload(const SkeletalPreparedUpload& prepared) {
    g_skeletalDiagnostics.adjustedUploads.fetch_add(1,
                                                     std::memory_order_relaxed);
    if (prepared.firstPerson) {
        g_skeletalDiagnostics.firstPersonAdjustedUploads.fetch_add(
            1, std::memory_order_relaxed);
        g_firstPersonSkeletalAdjustedCount.fetch_add(1,
                                                      std::memory_order_relaxed);
    } else {
        g_skeletalDiagnostics.worldAdjustedUploads.fetch_add(
            1, std::memory_order_relaxed);
        g_worldSkeletalAdjustedCount.fetch_add(1, std::memory_order_relaxed);
        if (prepared.cinematic) {
            g_skeletalDiagnostics.cinematicAdjustedUploads.fetch_add(
                1, std::memory_order_relaxed);
        }
    }

    AcquireSkeletalObservationLock();
    SkeletalObservationTrack* track = FindSkeletalObservationTrack(
        prepared.renderModel, prepared.owner, prepared.presentationSerial,
        false);
    if (track == nullptr || track->diagnosticId != prepared.diagnosticId) {
        ReleaseSRWLockExclusive(&g_skeletalObservationLock);
        return;
    }

    ++track->interpolationBuilds;
    if (track->hasPresentedOutput &&
        track->lastPresentedSerial == prepared.presentationSerial) {
        g_skeletalDiagnostics.sameFrameUploads.fetch_add(
            1, std::memory_order_relaxed);
        ReleaseSRWLockExclusive(&g_skeletalObservationLock);
        return;
    }

    g_skeletalDiagnostics.adjustedFrames.fetch_add(1,
                                                    std::memory_order_relaxed);
    if (prepared.firstPerson) {
        g_skeletalDiagnostics.firstPersonAdjustedFrames.fetch_add(
            1, std::memory_order_relaxed);
    } else if (prepared.cinematic) {
        g_skeletalDiagnostics.cinematicAdjustedFrames.fetch_add(
            1, std::memory_order_relaxed);
    }
    if (track->hasPresentedOutput) {
        if (prepared.outputChecksum == track->lastPresentedChecksum) {
            g_skeletalDiagnostics.repeatedOutputs.fetch_add(
                1, std::memory_order_relaxed);
            if (prepared.firstPerson) {
                g_skeletalDiagnostics.firstPersonRepeatedOutputs.fetch_add(
                    1, std::memory_order_relaxed);
            }
        } else {
            g_skeletalDiagnostics.changedOutputs.fetch_add(
                1, std::memory_order_relaxed);
            if (prepared.firstPerson) {
                g_skeletalDiagnostics.firstPersonChangedOutputs.fetch_add(
                    1, std::memory_order_relaxed);
            }
        }
        const std::uint64_t gap =
            prepared.presentationSerial - track->lastPresentedSerial;
        if (gap == 1) {
            g_skeletalDiagnostics.uploadGapOne.fetch_add(
                1, std::memory_order_relaxed);
            if (prepared.firstPerson) {
                g_skeletalDiagnostics.firstPersonUploadGapOne.fetch_add(
                    1, std::memory_order_relaxed);
            }
        } else if (gap == 2) {
            g_skeletalDiagnostics.uploadGapTwo.fetch_add(
                1, std::memory_order_relaxed);
            if (prepared.firstPerson) {
                g_skeletalDiagnostics.firstPersonUploadGapTwo.fetch_add(
                    1, std::memory_order_relaxed);
            }
        } else {
            g_skeletalDiagnostics.uploadGapMore.fetch_add(
                1, std::memory_order_relaxed);
            if (prepared.firstPerson) {
                g_skeletalDiagnostics.firstPersonUploadGapMore.fetch_add(
                    1, std::memory_order_relaxed);
            }
        }
    }

    std::size_t alphaBucket = 0;
    if (prepared.alpha > 0.0) {
        alphaBucket = prepared.alpha <= 0.5 ? 1 :
                      prepared.alpha <= 1.0 ? 2 :
                      prepared.alpha <= 1.5 ? 3 : 4;
    }
    g_skeletalDiagnostics.alphaBuckets[alphaBucket].fetch_add(
        1, std::memory_order_relaxed);
    track->hasPresentedOutput = true;
    track->lastPresentedSerial = prepared.presentationSerial;
    track->lastPresentedChecksum = prepared.outputChecksum;
    ReleaseSRWLockExclusive(&g_skeletalObservationLock);
}

struct SkeletalTrackReport {
    const void* renderModel = nullptr;
    const void* owner = nullptr;
    const void* modelAsset = nullptr;
    const void* cpuPalette = nullptr;
    std::uint64_t diagnosticId = 0;
    std::uint64_t firstSeenSerial = 0;
    std::uint64_t firstChangeSerial = 0;
    std::uint64_t lastChangeSerial = 0;
    std::uint64_t sampleDelta = 0;
    std::uint64_t changeDelta = 0;
    std::uint64_t sampleTotal = 0;
    std::uint64_t changeTotal = 0;
    std::uint64_t rigidSamples = 0;
    std::uint64_t interpolationDelta = 0;
    std::uint64_t interpolationTotal = 0;
    std::uint32_t jointCount = 0;
    std::uint32_t paddedJointCount = 0;
    float rootTranslation[3]{};
    std::uint32_t firstNonRigidJoint = 0;
    double nonRigidRowLength[3]{};
    double nonRigidMaximumRowDot = 0.0;
    double nonRigidDeterminant = 0.0;
    bool lastPaletteRigid = false;
    bool firstPerson = false;
    bool cinematic = false;
};

std::size_t CollectSkeletalTrackReports(
    std::array<SkeletalTrackReport, kSkeletalTrackReportCapacity>& reports,
    std::size_t& pendingCount) {
    std::size_t reportCount = 0;
    pendingCount = 0;
    AcquireSRWLockExclusive(&g_skeletalObservationLock);
    for (SkeletalObservationTrack& track : g_skeletalObservationTracks) {
        if (track.renderModel == nullptr ||
            (track.samples == track.reportedSamples &&
             track.changes == track.reportedChanges &&
             track.interpolationBuilds ==
                 track.reportedInterpolationBuilds)) {
            continue;
        }
        ++pendingCount;
        if (reportCount >= reports.size()) {
            continue;
        }
        SkeletalTrackReport& report = reports[reportCount++];
        report.renderModel = track.renderModel;
        report.owner = track.owner;
        report.modelAsset = track.modelAsset;
        report.cpuPalette = track.cpuPalette;
        report.diagnosticId = track.diagnosticId;
        report.firstSeenSerial = track.firstSeenSerial;
        report.firstChangeSerial = track.firstChangeSerial;
        report.lastChangeSerial = track.lastChangeSerial;
        report.sampleDelta = track.samples - track.reportedSamples;
        report.changeDelta = track.changes - track.reportedChanges;
        report.sampleTotal = track.samples;
        report.changeTotal = track.changes;
        report.rigidSamples = track.rigidSamples;
        report.interpolationDelta =
            track.interpolationBuilds - track.reportedInterpolationBuilds;
        report.interpolationTotal = track.interpolationBuilds;
        report.jointCount = track.jointCount;
        report.paddedJointCount = track.paddedJointCount;
        memcpy(report.rootTranslation, track.rootTranslation,
               sizeof(report.rootTranslation));
        report.firstNonRigidJoint = track.firstNonRigidJoint;
        memcpy(report.nonRigidRowLength, track.nonRigidRowLength,
               sizeof(report.nonRigidRowLength));
        report.nonRigidMaximumRowDot = track.nonRigidMaximumRowDot;
        report.nonRigidDeterminant = track.nonRigidDeterminant;
        report.lastPaletteRigid = track.lastPaletteRigid;
        report.firstPerson = track.firstPerson;
        report.cinematic = track.cinematic;
        track.reportedSamples = track.samples;
        track.reportedChanges = track.changes;
        track.reportedInterpolationBuilds = track.interpolationBuilds;
    }
    ReleaseSRWLockExclusive(&g_skeletalObservationLock);
    return reportCount;
}

struct OwnerlessSkeletalReport {
    const void* renderModel = nullptr;
    const void* modelAsset = nullptr;
    const void* cpuPalette = nullptr;
    std::uint64_t diagnosticId = 0;
    std::uint64_t firstSeenSerial = 0;
    std::uint64_t firstChangeSerial = 0;
    std::uint64_t lastChangeSerial = 0;
    std::uint64_t sampleDelta = 0;
    std::uint64_t changeDelta = 0;
    std::uint64_t sampleTotal = 0;
    std::uint64_t changeTotal = 0;
    std::uint64_t rigidSamples = 0;
    std::uint32_t jointCount = 0;
    std::uint32_t paddedJointCount = 0;
    std::uint32_t firstNonRigidJoint = 0;
    float rootTranslation[3]{};
    signed char pending = 0;
    bool lastPaletteRigid = false;
};

std::size_t CollectOwnerlessSkeletalReports(
    std::array<OwnerlessSkeletalReport,
               kOwnerlessSkeletalTrackReportCapacity>& reports,
    std::size_t& pendingCount) {
    std::size_t reportCount = 0;
    pendingCount = 0;
    AcquireSRWLockExclusive(&g_skeletalObservationLock);
    for (const OwnerlessSkeletalTrack& track : g_ownerlessSkeletalTracks) {
        if (track.renderModel != nullptr &&
            (track.samples != track.reportedSamples ||
             track.changes != track.reportedChanges)) {
            ++pendingCount;
        }
    }
    // Moving palettes first; static ownerless models are useful only after all
    // changing candidates have been attributed.
    for (int pass = 0; pass < 2 && reportCount < reports.size(); ++pass) {
        for (OwnerlessSkeletalTrack& track : g_ownerlessSkeletalTracks) {
            if (track.renderModel == nullptr) {
                continue;
            }
            const std::uint64_t sampleDelta =
                track.samples - track.reportedSamples;
            const std::uint64_t changeDelta =
                track.changes - track.reportedChanges;
            if (sampleDelta == 0 && changeDelta == 0) {
                continue;
            }
            const bool changed = changeDelta != 0;
            if ((pass == 0) != changed) {
                continue;
            }
            OwnerlessSkeletalReport& report = reports[reportCount++];
            report.renderModel = track.renderModel;
            report.modelAsset = track.modelAsset;
            report.cpuPalette = track.cpuPalette;
            report.diagnosticId = track.diagnosticId;
            report.firstSeenSerial = track.firstSeenSerial;
            report.firstChangeSerial = track.firstChangeSerial;
            report.lastChangeSerial = track.lastChangeSerial;
            report.sampleDelta = sampleDelta;
            report.changeDelta = changeDelta;
            report.sampleTotal = track.samples;
            report.changeTotal = track.changes;
            report.rigidSamples = track.rigidSamples;
            report.jointCount = track.jointCount;
            report.paddedJointCount = track.paddedJointCount;
            report.firstNonRigidJoint = track.firstNonRigidJoint;
            memcpy(report.rootTranslation, track.rootTranslation,
                   sizeof(report.rootTranslation));
            report.pending = track.pending;
            report.lastPaletteRigid = track.lastPaletteRigid;
            track.reportedSamples = track.samples;
            track.reportedChanges = track.changes;
            if (reportCount == reports.size()) {
                break;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_skeletalObservationLock);
    return reportCount;
}

void MaybeLogSkeletalDiagnostics(const PresentationContext& context) {
    if ((!g_interpolateWorldSkeletons &&
         !g_interpolateFirstPersonSkeletons &&
         !g_interpolateCinematicSkeletons) || !context.valid) {
        return;
    }
    std::uint64_t next =
        g_nextSkeletalDiagnosticsSerial.load(std::memory_order_relaxed);
    if (context.serial < next ||
        !g_nextSkeletalDiagnosticsSerial.compare_exchange_strong(
            next, context.serial + 1200, std::memory_order_relaxed)) {
        return;
    }

    Log("Skeletal diagnostics frame=%llu: calls=%llu exactSkinned=%llu "
        "eligible[world=%llu firstPerson=%llu] pending=%llu "
        "timeSamples=%llu changed=%llu "
        "palettes[rigid=%llu nonRigid=%llu] tracks=%llu pairs=%llu "
        "upload[prepared=%llu adjusted=%llu forced=%llu skipped=%llu "
        "forceFailed=%llu frames=%llu "
        "sameFrame=%llu changed=%llu repeated=%llu gap1=%llu gap2=%llu "
        "gapMore=%llu alpha=%llu/%llu/%llu/%llu/%llu] "
        "discontinuity=%llu interpolationRejected=%llu "
        "rejected[firstPersonDisabled=%llu depthHack=%llu owner=%llu "
        "layout=%llu sameTime=%llu] ownerFallback[firstPerson=%llu] "
        "capacityMiss=%llu.",
        static_cast<unsigned long long>(context.serial),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.calls.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.exactSkinnedType.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.worldEligible.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonEligible.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.pendingSamples.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.timeSamples.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.changedSamples.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.rigidPalettes.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.nonRigidPalettes.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.tracksCreated.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.samplePairs.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.preparedUploads.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.adjustedUploads.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.forcedUploads.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.preparedWithoutUpload.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.forcedUploadFailures.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.adjustedFrames.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.sameFrameUploads.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.changedOutputs.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.repeatedOutputs.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.uploadGapOne.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.uploadGapTwo.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.uploadGapMore.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.alphaBuckets[0].load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.alphaBuckets[1].load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.alphaBuckets[2].load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.alphaBuckets[3].load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.alphaBuckets[4].load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.discontinuityRejected.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.interpolationRejected.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonDisabled.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.depthHackRejected.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.ownerRejected.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.layoutRejected.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.sameTimeChanges.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonOwnerFallback.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalTrackCapacityMissCount.load(std::memory_order_relaxed)));

    Log("Skeletal scope frame=%llu: pairs[world=%llu firstPerson=%llu] "
        "prepared[world=%llu firstPerson=%llu] "
        "adjusted[world=%llu firstPerson=%llu] "
        "forced[world=%llu firstPerson=%llu] "
        "firstPersonOutput[frames=%llu changed=%llu repeated=%llu "
        "gap1=%llu gap2=%llu gapMore=%llu].",
        static_cast<unsigned long long>(context.serial),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.worldSamplePairs.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonSamplePairs.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.worldPreparedUploads.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonPreparedUploads.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.worldAdjustedUploads.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonAdjustedUploads.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.worldForcedUploads.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonForcedUploads.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonAdjustedFrames.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonChangedOutputs.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonRepeatedOutputs.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonUploadGapOne.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonUploadGapTwo.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.firstPersonUploadGapMore.load(
                std::memory_order_relaxed)));

    Log("Skeletal cinematic frame=%llu: eligible=%llu pairs=%llu "
        "prepared=%llu adjusted=%llu forced=%llu frames=%llu.",
        static_cast<unsigned long long>(context.serial),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.cinematicEligible.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.cinematicSamplePairs.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.cinematicPreparedUploads.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.cinematicAdjustedUploads.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.cinematicForcedUploads.load(
                std::memory_order_relaxed)),
        static_cast<unsigned long long>(
            g_skeletalDiagnostics.cinematicAdjustedFrames.load(
                std::memory_order_relaxed)));

    std::array<SkeletalTrackReport, kSkeletalTrackReportCapacity> reports{};
    std::size_t pendingCount = 0;
    const std::size_t reportCount =
        CollectSkeletalTrackReports(reports, pendingCount);
    for (std::size_t index = 0; index < reportCount; ++index) {
        const SkeletalTrackReport& report = reports[index];
        Log("Skeletal track frame=%llu scope=%s id=%llu model=%p ownerKey=%p "
            "asset=%p "
            "palette=%p joints=%u padded=%u delta[samples=%llu changes=%llu] "
            "interpolated[delta=%llu total=%llu] "
            "total[samples=%llu changes=%llu rigid=%llu] "
            "serial[first=%llu firstChange=%llu lastChange=%llu] "
            "root=(%.3f,%.3f,%.3f) rigid=%u nonRigid[joint=%u "
            "rowLength=(%.5f,%.5f,%.5f) maxRowDot=%.6f det=%.6f].",
            static_cast<unsigned long long>(context.serial),
            report.firstPerson ? "firstPerson" :
            report.cinematic ? "cinematic" : "world",
            static_cast<unsigned long long>(report.diagnosticId),
            report.renderModel, report.owner, report.modelAsset,
            report.cpuPalette, report.jointCount, report.paddedJointCount,
            static_cast<unsigned long long>(report.sampleDelta),
            static_cast<unsigned long long>(report.changeDelta),
            static_cast<unsigned long long>(report.interpolationDelta),
            static_cast<unsigned long long>(report.interpolationTotal),
            static_cast<unsigned long long>(report.sampleTotal),
            static_cast<unsigned long long>(report.changeTotal),
            static_cast<unsigned long long>(report.rigidSamples),
            static_cast<unsigned long long>(report.firstSeenSerial),
            static_cast<unsigned long long>(report.firstChangeSerial),
            static_cast<unsigned long long>(report.lastChangeSerial),
            report.rootTranslation[0], report.rootTranslation[1],
            report.rootTranslation[2], report.lastPaletteRigid ? 1U : 0U,
            report.firstNonRigidJoint,
            report.nonRigidRowLength[0], report.nonRigidRowLength[1],
            report.nonRigidRowLength[2], report.nonRigidMaximumRowDot,
            report.nonRigidDeterminant);
    }
    if (pendingCount > reportCount) {
        Log("Skeletal track frame=%llu: reported %llu of %llu changed tracks; "
            "remaining tracks carry forward.",
            static_cast<unsigned long long>(context.serial),
            static_cast<unsigned long long>(reportCount),
            static_cast<unsigned long long>(pendingCount));
    }

    std::array<OwnerlessSkeletalReport,
               kOwnerlessSkeletalTrackReportCapacity> ownerlessReports{};
    std::size_t ownerlessPendingCount = 0;
    const std::size_t ownerlessReportCount =
        CollectOwnerlessSkeletalReports(ownerlessReports,
                                        ownerlessPendingCount);
    for (std::size_t index = 0; index < ownerlessReportCount; ++index) {
        const OwnerlessSkeletalReport& report = ownerlessReports[index];
        Log("Ownerless skeletal track frame=%llu id=%llu model=%p asset=%p "
            "palette=%p joints=%u padded=%u pending=%d "
            "delta[samples=%llu changes=%llu] "
            "total[samples=%llu changes=%llu rigid=%llu] "
            "serial[first=%llu firstChange=%llu lastChange=%llu] "
            "root=(%.3f,%.3f,%.3f) rigid=%u firstNonRigidJoint=%u.",
            static_cast<unsigned long long>(context.serial),
            static_cast<unsigned long long>(report.diagnosticId),
            report.renderModel, report.modelAsset, report.cpuPalette,
            report.jointCount, report.paddedJointCount,
            static_cast<int>(report.pending),
            static_cast<unsigned long long>(report.sampleDelta),
            static_cast<unsigned long long>(report.changeDelta),
            static_cast<unsigned long long>(report.sampleTotal),
            static_cast<unsigned long long>(report.changeTotal),
            static_cast<unsigned long long>(report.rigidSamples),
            static_cast<unsigned long long>(report.firstSeenSerial),
            static_cast<unsigned long long>(report.firstChangeSerial),
            static_cast<unsigned long long>(report.lastChangeSerial),
            report.rootTranslation[0], report.rootTranslation[1],
            report.rootTranslation[2], report.lastPaletteRigid ? 1U : 0U,
            report.firstNonRigidJoint);
    }
    if (ownerlessPendingCount > ownerlessReportCount) {
        Log("Ownerless skeletal track frame=%llu: reported %llu of %llu "
            "changed tracks; remaining tracks carry forward. capacityMiss=%llu.",
            static_cast<unsigned long long>(context.serial),
            static_cast<unsigned long long>(ownerlessReportCount),
            static_cast<unsigned long long>(ownerlessPendingCount),
            static_cast<unsigned long long>(
                g_ownerlessSkeletalTrackCapacityMissCount.load(
                    std::memory_order_relaxed)));
    }
}

bool CorrectWorldRenderModelClone(unsigned char* object,
                                  const WorldMatrixCorrection& correction) {
    return CorrectMatrixSet(object,
                            kRenderModelMatrixOffset,
                            kRenderModelInverseMatrixOffset,
                            kRenderModelViewMatrixOffset,
                            kRenderModelMvpMatrixOffset,
                            correction.currentDelta,
                            correction.currentInverseDelta) &&
           CorrectMatrixSet(object,
                            kRenderModelPreviousMatrixOffset,
                            kRenderModelPreviousInverseMatrixOffset,
                            kRenderModelPreviousViewMatrixOffset,
                            kRenderModelPreviousMvpMatrixOffset,
                            correction.previousDelta,
                            correction.previousInverseDelta);
}

std::uint64_t ReadPerformanceCounter() {
    LARGE_INTEGER counter{};
    QueryPerformanceCounter(&counter);
    return static_cast<std::uint64_t>(counter.QuadPart);
}

void CallOriginalRenderModelGpuCopy(void* state, void* renderContext,
                                    float parameter, void* drawSurface) {
    if (!g_enableInterpolationAbProbe) {
        g_originalRenderModelGpuCopy(state, renderContext, parameter, drawSurface);
        return;
    }
    const std::uint64_t start = ReadPerformanceCounter();
    g_originalRenderModelGpuCopy(state, renderContext, parameter, drawSurface);
    g_abRenderModelOriginalTicks.fetch_add(ReadPerformanceCounter() - start,
                                           std::memory_order_relaxed);
}

std::uint64_t CallOriginalSkinnedPoseUpload(void* renderModel,
                                            void* renderContext) {
    if (!g_enableInterpolationAbProbe) {
        return g_originalSkinnedPoseUpload(renderModel, renderContext);
    }
    const std::uint64_t start = ReadPerformanceCounter();
    const std::uint64_t result =
        g_originalSkinnedPoseUpload(renderModel, renderContext);
    g_abSkeletalOriginalTicks.fetch_add(ReadPerformanceCounter() - start,
                                        std::memory_order_relaxed);
    return result;
}

void HookRenderModelGpuCopyBody(
    void* state, void* renderContext, float parameter, void* drawSurface) {
    if (g_enableInterpolationAbProbe) {
        g_abRenderModelHookCalls.fetch_add(1, std::memory_order_relaxed);
    }
    if (g_sourceLevelInstalled) {
        ObserveSourceLevelRendererCall();
    }
    // Source mode corrects first-person models after the render-world flush.
    const bool firstPersonHandsEnabled =
        RuntimeFirstPersonHandsEnabled() && !SourceHandsSelected();
    // The source-level layer already wrote presentation matrices into the
    // render models; the per-draw world path would treat them as raw input.
    const bool transformInterpolationEnabled =
        RuntimeTransformInterpolationEnabled() &&
        (g_interpolateWorldTransforms || g_interpolateCinematicTransforms) &&
        !SourceLevelWritesSelected();
    if ((!firstPersonHandsEnabled && !transformInterpolationEnabled) ||
        g_renderModelGpuCopyTrampoline == nullptr ||
        !IsReadableMemoryCached(drawSurface, 16)) {
        CallOriginalRenderModelGpuCopy(state, renderContext, parameter, drawSurface);
        return;
    }

    void* renderModel = nullptr;
    memcpy(&renderModel, static_cast<unsigned char*>(drawSurface) + 8, sizeof(renderModel));
    if (!IsReadableMemoryCached(renderModel, kRenderModelSize)) {
        CallOriginalRenderModelGpuCopy(state, renderContext, parameter, drawSurface);
        return;
    }

    std::uintptr_t renderModelVtable = 0;
    memcpy(&renderModelVtable, renderModel, sizeof(renderModelVtable));
    const bool exactSkinned =
        renderModelVtable == g_executableBase + g_layout->skinnedModelVtable.rva;
    bool correctedFirstPerson = false;
    std::uint64_t correctionSerial = 0;
    RenderCorrectionState firstPersonCorrection{};
    WorldMatrixCorrection worldCorrection{};
    bool hasCorrection = false;

    if (firstPersonHandsEnabled && IsPlayerDepthHackObject(renderModel)) {
        if (ReadRenderCorrection(firstPersonCorrection)) {
            hasCorrection = true;
            correctedFirstPerson = true;
            correctionSerial = firstPersonCorrection.serial;
        }
    } else if (transformInterpolationEnabled) {
        PresentationContext context{};
        if (ReadPresentationContext(context) &&
            BuildWorldTransformCorrection(renderModel, context,
                                          worldCorrection)) {
            hasCorrection = true;
            correctionSerial = worldCorrection.presentationSerial;
        }
    }

    if (!hasCorrection) {
        CallOriginalRenderModelGpuCopy(state, renderContext, parameter, drawSurface);
        return;
    }

    const std::size_t renderModelCloneSize =
        exactSkinned ? kSkinnedModelSize : kRenderModelSize;
    if (!IsReadableMemoryCached(renderModel, renderModelCloneSize)) {
        CallOriginalRenderModelGpuCopy(state, renderContext, parameter,
                                     drawSurface);
        return;
    }
    alignas(16) unsigned char renderModelClone[kSkinnedModelSize];
    memcpy(renderModelClone, renderModel, renderModelCloneSize);
    const bool corrected = correctedFirstPerson
        ? CorrectRenderModelClone(renderModelClone, firstPersonCorrection)
        : CorrectWorldRenderModelClone(renderModelClone, worldCorrection);
    if (!corrected) {
        CallOriginalRenderModelGpuCopy(state, renderContext, parameter,
                                     drawSurface);
        return;
    }
    if (!correctedFirstPerson) {
        PublishShadowCorrection(renderModel, worldCorrection);
    }

    alignas(16) unsigned char drawSurfaceProxy[16]{};
    memcpy(drawSurfaceProxy, drawSurface, sizeof(drawSurfaceProxy));
    void* renderModelClonePointer = renderModelClone;
    memcpy(drawSurfaceProxy + 8, &renderModelClonePointer, sizeof(renderModelClonePointer));
    CallOriginalRenderModelGpuCopy(state, renderContext, parameter, drawSurfaceProxy);

    // The original function caches the source pointer in its renderer-local state.
    // Keep that cache tied to the real model rather than this stack-only clone.
    memcpy(state, &renderModel, sizeof(renderModel));

    if (correctedFirstPerson) {
        if (g_enableInterpolationAbProbe) {
            g_abFirstPersonRootCorrections.fetch_add(
                1, std::memory_order_relaxed);
        }
        int expected = 0;
        if (g_firstPersonRenderState.compare_exchange_strong(expected, 1)) {
            Log("Applied first-person correction at the renderer GPU-parameter boundary "
                "(camera serial %llu).",
                static_cast<unsigned long long>(correctionSerial));
        }
    } else {
        g_worldTransformAdjustedCount.fetch_add(1, std::memory_order_relaxed);
        if (exactSkinned) {
            g_worldDiagnostics.skinnedAdjusted.fetch_add(
                1, std::memory_order_relaxed);
        }
        int expected = 0;
        if (g_worldTransformRenderState.compare_exchange_strong(expected, 1)) {
            Log("Applied experimental world-transform interpolation at the renderer "
                "GPU-parameter boundary (presentation serial %llu).",
                static_cast<unsigned long long>(correctionSerial));
        }
    }
}

bool SkinnedPoseUploaded(std::uint64_t result) {
    return g_layout->skinnedPoseUploadReturnsByte ? (result & 0xFFU) != 0
                                                  : result != 0;
}

std::uint64_t HookSkinnedPoseUploadBody(
    void* renderModel, void* renderContext) {
    if (g_enableInterpolationAbProbe) {
        g_abSkeletalHookCalls.fetch_add(1, std::memory_order_relaxed);
    }
    if (!RuntimeSkeletalInterpolationEnabled() ||
        (!g_interpolateWorldSkeletons &&
         !g_interpolateFirstPersonSkeletons &&
         !g_interpolateCinematicSkeletons) ||
        g_skinnedPoseUploadTrampoline == nullptr) {
        return CallOriginalSkinnedPoseUpload(renderModel, renderContext);
    }

    // PrepareSkeletalPose initializes every byte that can be consumed when it
    // succeeds; avoid zeroing this 12 KiB buffer on every rejected hook call.
    std::array<d2_pose::JointMatrix, kMaximumJointCount> interpolatedPalette;
    SkeletalPreparedUpload prepared{};
    if (PrepareSkeletalPose(renderModel, interpolatedPalette, prepared)) {
        auto* bytes = static_cast<unsigned char*>(renderModel);
        void* sourcePalette = nullptr;
        memcpy(&sourcePalette, bytes + kSkinnedPoseCpuListOffset,
               sizeof(sourcePalette));
        void* replacementPalette = interpolatedPalette.data();
        memcpy(bytes + kSkinnedPoseCpuListOffset, &replacementPalette,
               sizeof(replacementPalette));
        unsigned char savedUploadFlags = 0;
        signed char savedPending = 0;
        memcpy(&savedUploadFlags, bytes + kSkinnedPoseUploadFlagsOffset,
               sizeof(savedUploadFlags));
        memcpy(&savedPending, bytes + kSkinnedPosePendingOffset,
               sizeof(savedPending));

        std::uint64_t result =
            CallOriginalSkinnedPoseUpload(renderModel, renderContext);
        bool forced = false;
        if (!SkinnedPoseUploaded(result)) {
            // The native path commonly consumes its two pending uploads on
            // alternating presentation frames. For a valid moving pair, map
            // only the currently selected buffer once on the intervening
            // frame. Restore the engine-owned scheduler bytes immediately.
            const unsigned char forcedUploadFlags =
                static_cast<unsigned char>(savedUploadFlags & ~0x06U);
            const signed char forcedPending = 1;
            memcpy(bytes + kSkinnedPoseUploadFlagsOffset, &forcedUploadFlags,
                   sizeof(forcedUploadFlags));
            memcpy(bytes + kSkinnedPosePendingOffset, &forcedPending,
                   sizeof(forcedPending));
            result = CallOriginalSkinnedPoseUpload(renderModel, renderContext);
            memcpy(bytes + kSkinnedPoseUploadFlagsOffset, &savedUploadFlags,
                   sizeof(savedUploadFlags));
            memcpy(bytes + kSkinnedPosePendingOffset, &savedPending,
                   sizeof(savedPending));
            forced = SkinnedPoseUploaded(result);
        }
        memcpy(bytes + kSkinnedPoseCpuListOffset, &sourcePalette,
               sizeof(sourcePalette));

        if (SkinnedPoseUploaded(result)) {
            RecordSkeletalUpload(prepared);
            if (forced) {
                g_skeletalDiagnostics.forcedUploads.fetch_add(
                    1, std::memory_order_relaxed);
                (prepared.firstPerson
                     ? g_skeletalDiagnostics.firstPersonForcedUploads
                     : g_skeletalDiagnostics.worldForcedUploads)
                    .fetch_add(1, std::memory_order_relaxed);
                if (prepared.cinematic) {
                    g_skeletalDiagnostics.cinematicForcedUploads.fetch_add(
                        1, std::memory_order_relaxed);
                }
            }
            if (prepared.firstPerson) {
                int expected = 0;
                if (g_firstPersonSkeletalRenderState.compare_exchange_strong(
                        expected, 1)) {
                    Log("Applied experimental first-person skeletal "
                        "interpolation at the renderer palette-upload boundary; "
                        "the hand-root correction remains independent.");
                }
            } else {
                int expected = 0;
                if (g_worldSkeletalRenderState.compare_exchange_strong(expected,
                                                                        1)) {
                    Log("Applied experimental %s skeletal interpolation at "
                        "the renderer palette-upload boundary.",
                        prepared.cinematic ? "cinematic" : "world");
                }
            }
        } else {
            g_skeletalDiagnostics.preparedWithoutUpload.fetch_add(
                1, std::memory_order_relaxed);
            g_skeletalDiagnostics.forcedUploadFailures.fetch_add(
                1, std::memory_order_relaxed);
        }
        return result;
    }
    return CallOriginalSkinnedPoseUpload(renderModel, renderContext);
}

extern "C" void __fastcall HookRenderModelGpuCopy(
    void* state, void* renderContext, float parameter, void* drawSurface) {
    if (!g_enableInterpolationAbProbe) {
        HookRenderModelGpuCopyBody(state, renderContext, parameter, drawSurface);
        return;
    }
    const std::uint64_t start = ReadPerformanceCounter();
    HookRenderModelGpuCopyBody(state, renderContext, parameter, drawSurface);
    g_abRenderModelHookTicks.fetch_add(ReadPerformanceCounter() - start,
                                       std::memory_order_relaxed);
}

extern "C" std::uint64_t __fastcall HookSkinnedPoseUpload(
    void* renderModel, void* renderContext) {
    if (!g_enableInterpolationAbProbe) {
        return HookSkinnedPoseUploadBody(renderModel, renderContext);
    }
    const std::uint64_t start = ReadPerformanceCounter();
    const std::uint64_t result =
        HookSkinnedPoseUploadBody(renderModel, renderContext);
    g_abSkeletalHookTicks.fetch_add(ReadPerformanceCounter() - start,
                                    std::memory_order_relaxed);
    return result;
}

bool InitializeTelemetry() {
    wchar_t name[96]{};
    swprintf_s(name, L"Local\\D2HighFpsFixTelemetry-%lu", GetCurrentProcessId());
    g_telemetryMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
                                            PAGE_READWRITE, 0,
                                            sizeof(SharedTelemetry), name);
    if (g_telemetryMapping == nullptr) {
        Log("Unable to create the camera telemetry mapping (Win32 %lu).", GetLastError());
        return false;
    }
    g_telemetry = static_cast<SharedTelemetry*>(
        MapViewOfFile(g_telemetryMapping, FILE_MAP_WRITE, 0, 0, sizeof(SharedTelemetry)));
    if (g_telemetry == nullptr) {
        Log("Unable to map the camera telemetry block (Win32 %lu).", GetLastError());
        CloseHandle(g_telemetryMapping);
        g_telemetryMapping = nullptr;
        return false;
    }
    ZeroMemory(g_telemetry, sizeof(*g_telemetry));
    g_telemetry->version = 1;
    g_telemetry->size = sizeof(SharedTelemetry);
    return true;
}

void PublishTelemetry(const void* source, const void* destination) {
    if (g_telemetry == nullptr) {
        return;
    }

    const Transform raw = ReadTransform(source);
    const Transform output = ReadTransform(destination);
    double scaledTime = std::numeric_limits<double>::quiet_NaN();
    double simulationTime = std::numeric_limits<double>::quiet_NaN();
    auto* game = *reinterpret_cast<unsigned char**>(g_executableBase + g_layout->gamePointerRva);
    if (game != nullptr && *reinterpret_cast<std::uintptr_t*>(game) ==
                               g_executableBase + g_layout->gameVtable.rva) {
        unsigned char* clock = game + kClockOffset;
        memcpy(&scaledTime, clock + kScaledTimeOffset, sizeof(scaledTime));
        memcpy(&simulationTime, clock + kSimulationTimeOffset, sizeof(simulationTime));
    }

    const bool applied = memcmp(&raw.origin, &output.origin, sizeof(raw.origin)) != 0 ||
                         memcmp(raw.axis, output.axis, sizeof(raw.axis)) != 0;
    InterlockedIncrement64(&g_telemetry->sequence);
    MemoryBarrier();
    g_telemetry->enabled = g_enabled.load(std::memory_order_relaxed) ? 1U : 0U;
    g_telemetry->applied = applied ? 1U : 0U;
    g_telemetry->scaledTime = scaledTime;
    g_telemetry->simulationTime = simulationTime;
    g_telemetry->alpha = g_lastAlpha;
    for (int index = 0; index < 3; ++index) {
        const double rawValue = index == 0 ? raw.origin.x :
                                index == 1 ? raw.origin.y : raw.origin.z;
        const double outputValue = index == 0 ? output.origin.x :
                                   index == 1 ? output.origin.y : output.origin.z;
        g_telemetry->rawOrigin[index] = static_cast<float>(rawValue);
        g_telemetry->outputOrigin[index] = static_cast<float>(outputValue);
    }
    memcpy(g_telemetry->rawAxis, raw.axis, sizeof(raw.axis));
    memcpy(g_telemetry->outputAxis, output.axis, sizeof(output.axis));
    MemoryBarrier();
    InterlockedIncrement64(&g_telemetry->sequence);
}

void PublishPresentationContext() {
    PresentationContext context{};
    auto* game = *reinterpret_cast<unsigned char**>(g_executableBase + g_layout->gamePointerRva);
    if (game != nullptr && *reinterpret_cast<std::uintptr_t*>(game) ==
                               g_executableBase + g_layout->gameVtable.rva) {
        unsigned char* clock = game + kClockOffset;
        memcpy(&context.scaledTime, clock + kScaledTimeOffset, sizeof(context.scaledTime));
        memcpy(&context.simulationTime, clock + kSimulationTimeOffset,
               sizeof(context.simulationTime));
        context.valid = std::isfinite(context.scaledTime) &&
                        std::isfinite(context.simulationTime);
    }

    AcquireSRWLockExclusive(&g_presentationContextLock);
    context.serial = g_presentationContext.serial + 1;
    g_presentationContext = context;
    ReleaseSRWLockExclusive(&g_presentationContextLock);
    g_presentationSerial.store(context.serial, std::memory_order_release);
    MaybeLogWorldTransformDiagnostics(context);
    MaybeLogSkeletalDiagnostics(context);
}

bool ReadPresentationContext(PresentationContext& context) {
    AcquireSRWLockShared(&g_presentationContextLock);
    context = g_presentationContext;
    ReleaseSRWLockShared(&g_presentationContextLock);
    return context.valid && context.serial != 0;
}

bool HasConfiguredTransformInterpolationLayers() {
    return g_interpolateWorldTransforms ||
           g_interpolateCinematicTransforms ||
           g_interpolateShadowTransforms;
}

bool HasConfiguredSkeletalInterpolationLayers() {
    return g_interpolateFirstPersonSkeletons ||
           g_interpolateWorldSkeletons ||
           g_interpolateCinematicSkeletons;
}

bool HasConfiguredInterpolationLayers() {
    return HasConfiguredTransformInterpolationLayers() ||
           HasConfiguredSkeletalInterpolationLayers();
}

bool RuntimeTransformInterpolationEnabled() {
    return HasConfiguredTransformInterpolationLayers() &&
           g_transformInterpolationRuntimeEnabled.load(
               std::memory_order_relaxed);
}

bool RuntimeSkeletalInterpolationEnabled() {
    return HasConfiguredSkeletalInterpolationLayers() &&
           g_skeletalInterpolationRuntimeEnabled.load(
               std::memory_order_relaxed);
}

bool RuntimeFirstPersonHandsEnabled() {
    return g_stabilizeFirstPersonHands &&
           g_firstPersonHandsRuntimeEnabled.load(std::memory_order_relaxed);
}

const char* AdaptiveInterpolationModeName(AdaptiveInterpolationMode mode) {
    switch (mode) {
        case AdaptiveInterpolationMode::All:
            return "all";
        case AdaptiveInterpolationMode::TransformsOnly:
            return "transforms-only";
        case AdaptiveInterpolationMode::Off:
            return "off";
    }
    return "unknown";
}

void SetAdaptiveInterpolationMode(AdaptiveInterpolationMode mode,
                                  double measuredFps,
                                  double predictedFps,
                                  const char* reason) {
    g_adaptiveInterpolationGate.mode = mode;
    g_adaptiveInterpolationGate.recoveryWindows = 0;
    g_transformInterpolationRuntimeEnabled.store(
        mode != AdaptiveInterpolationMode::Off,
        std::memory_order_relaxed);
    g_skeletalInterpolationRuntimeEnabled.store(
        mode == AdaptiveInterpolationMode::All,
        std::memory_order_relaxed);
    if (std::isfinite(predictedFps)) {
        Log("Adaptive interpolation -> %s: measured cadence %.2f FPS, "
            "predicted next-profile cadence %.2f FPS (%s).",
            AdaptiveInterpolationModeName(mode), measuredFps, predictedFps,
            reason);
    } else {
        Log("Adaptive interpolation -> %s: measured cadence %.2f FPS (%s).",
            AdaptiveInterpolationModeName(mode), measuredFps, reason);
    }
}

void ResetAdaptiveInterpolationWindow() {
    g_adaptiveInterpolationGate.windowFrames = 0.0;
    g_adaptiveInterpolationGate.windowSimulationTicks = 0.0;
}

void SuspendAdaptiveInterpolationForManualControl() {
    if (g_enableAdaptiveInterpolation && !g_enableInterpolationAbProbe &&
        !g_adaptiveInterpolationManualOverride.exchange(
            true, std::memory_order_relaxed)) {
        Log("Adaptive interpolation suspended until the next game launch "
            "because a manual interpolation profile was selected.");
    }
}

void UpdateAdaptiveInterpolationGate(const PresentationContext& context) {
    if (!g_enableAdaptiveInterpolation || g_enableInterpolationAbProbe ||
        g_adaptiveInterpolationManualOverride.load(std::memory_order_relaxed) ||
        !context.valid) {
        return;
    }

    AdaptiveInterpolationGateState& gate = g_adaptiveInterpolationGate;
    if (!gate.initialized) {
        gate.initialized = true;
        gate.previousScaledTime = context.scaledTime;
        gate.previousSimulationTime = context.simulationTime;
        gate.mode = AdaptiveInterpolationMode::All;
        return;
    }

    const double scaledDelta = context.scaledTime - gate.previousScaledTime;
    const double simulationDelta =
        context.simulationTime - gate.previousSimulationTime;
    gate.previousScaledTime = context.scaledTime;
    gate.previousSimulationTime = context.simulationTime;
    if (!(scaledDelta > kTimeEpsilon) || scaledDelta > 0.25 ||
        simulationDelta < -kTimeEpsilon || simulationDelta > 0.10) {
        ResetAdaptiveInterpolationWindow();
        gate.recoveryWindows = 0;
        return;
    }

    gate.windowFrames += 1.0;
    gate.windowSimulationTicks +=
        std::max(0.0, simulationDelta) / kNativeSimulationStep;
    if (gate.windowSimulationTicks < kAdaptiveWindowSimulationTicks) {
        return;
    }

    const double cadenceFps = (1.0 / kNativeSimulationStep) *
        gate.windowFrames / gate.windowSimulationTicks;
    ResetAdaptiveInterpolationWindow();
    if (!(cadenceFps > 1.0) || !std::isfinite(cadenceFps)) {
        gate.recoveryWindows = 0;
        return;
    }
    const double frameSeconds = 1.0 / cadenceFps;

    if (gate.mode == AdaptiveInterpolationMode::All) {
        gate.recoveryWindows = 0;
        if (cadenceFps < kAdaptiveAllMinimumFps) {
            gate.lastAllFrameSeconds = frameSeconds;
            gate.learnSkeletalPenalty = true;
            SetAdaptiveInterpolationMode(
                AdaptiveInterpolationMode::TransformsOnly, cadenceFps,
                std::numeric_limits<double>::quiet_NaN(),
                "full interpolation lacks useful native-rate headroom");
        }
        return;
    }

    if (gate.mode == AdaptiveInterpolationMode::TransformsOnly) {
        if (gate.learnSkeletalPenalty) {
            gate.skeletalPenaltySeconds = std::max(
                0.0, gate.lastAllFrameSeconds - frameSeconds);
            gate.skeletalPenaltyReferenceFrameSeconds = frameSeconds;
            gate.hasSkeletalPenalty = true;
            gate.learnSkeletalPenalty = false;
            Log("Adaptive interpolation learned skeletal cost %.3f ms/frame.",
                gate.skeletalPenaltySeconds * 1000.0);
        }
        if (cadenceFps < kAdaptiveTransformsMinimumFps) {
            gate.lastTransformFrameSeconds = frameSeconds;
            gate.learnTransformPenalty = true;
            SetAdaptiveInterpolationMode(
                AdaptiveInterpolationMode::Off, cadenceFps,
                std::numeric_limits<double>::quiet_NaN(),
                "transform-only interpolation remains below native-rate guard");
            return;
        }

        const double predictedAllFps = gate.hasSkeletalPenalty
            ? 1.0 / (frameSeconds + gate.skeletalPenaltySeconds)
            : cadenceFps >= 200.0 ? cadenceFps
                                  : std::numeric_limits<double>::quiet_NaN();
        const bool predictedAllHasHeadroom =
            std::isfinite(predictedAllFps) &&
            predictedAllFps >= kAdaptiveAllRecoveryFps;
        const bool skeletalCostContextChanged = gate.hasSkeletalPenalty &&
            gate.skeletalPenaltyReferenceFrameSeconds > kTimeEpsilon &&
            frameSeconds <= gate.skeletalPenaltyReferenceFrameSeconds *
                kAdaptiveCostRefreshFrameTimeRatio &&
            cadenceFps >= kAdaptiveAllCostRefreshMinimumFps;
        if (predictedAllHasHeadroom || skeletalCostContextChanged) {
            if (++gate.recoveryWindows >= kAdaptiveRecoveryWindowCount) {
                SetAdaptiveInterpolationMode(
                    AdaptiveInterpolationMode::All, cadenceFps,
                    predictedAllFps,
                    predictedAllHasHeadroom
                        ? "measured headroom supports full interpolation"
                        : "scene cadence improved enough to refresh skeletal cost");
            }
        } else {
            gate.recoveryWindows = 0;
        }
        return;
    }

    if (gate.learnTransformPenalty) {
        gate.transformPenaltySeconds = std::max(
            0.0, gate.lastTransformFrameSeconds - frameSeconds);
        gate.transformPenaltyReferenceFrameSeconds = frameSeconds;
        gate.hasTransformPenalty = true;
        gate.learnTransformPenalty = false;
        Log("Adaptive interpolation learned transform cost %.3f ms/frame.",
            gate.transformPenaltySeconds * 1000.0);
    }
    const double predictedTransformFps = gate.hasTransformPenalty
        ? 1.0 / (frameSeconds + gate.transformPenaltySeconds)
        : cadenceFps >= 180.0 ? cadenceFps
                              : std::numeric_limits<double>::quiet_NaN();
    const bool predictedTransformsHaveHeadroom =
        std::isfinite(predictedTransformFps) &&
        predictedTransformFps >= kAdaptiveTransformsRecoveryFps;
    const bool transformCostContextChanged = gate.hasTransformPenalty &&
        gate.transformPenaltyReferenceFrameSeconds > kTimeEpsilon &&
        frameSeconds <= gate.transformPenaltyReferenceFrameSeconds *
            kAdaptiveCostRefreshFrameTimeRatio &&
        cadenceFps >= kAdaptiveTransformCostRefreshMinimumFps;
    if (predictedTransformsHaveHeadroom || transformCostContextChanged) {
        if (++gate.recoveryWindows >= kAdaptiveRecoveryWindowCount) {
            SetAdaptiveInterpolationMode(
                AdaptiveInterpolationMode::TransformsOnly, cadenceFps,
                predictedTransformFps,
                predictedTransformsHaveHeadroom
                    ? "measured headroom supports transform interpolation"
                    : "scene cadence improved enough to refresh transform cost");
        }
    } else {
        gate.recoveryWindows = 0;
    }
}

InterpolationAbCounterSnapshot CaptureInterpolationAbCounters() {
    InterpolationAbCounterSnapshot counters{};
    counters.renderModelHookCalls =
        g_abRenderModelHookCalls.load(std::memory_order_relaxed);
    counters.firstPersonRootCorrections =
        g_abFirstPersonRootCorrections.load(std::memory_order_relaxed);
    counters.worldCandidates =
        g_worldDiagnostics.candidates.load(std::memory_order_relaxed);
    counters.worldAdjustments =
        g_worldTransformAdjustedCount.load(std::memory_order_relaxed);
    counters.skeletalHookCalls =
        g_abSkeletalHookCalls.load(std::memory_order_relaxed);
    counters.skeletalPrepareCalls =
        g_skeletalDiagnostics.calls.load(std::memory_order_relaxed);
    counters.skeletalAdjustments =
        g_skeletalDiagnostics.adjustedUploads.load(std::memory_order_relaxed);
    counters.forcedUploads =
        g_skeletalDiagnostics.forcedUploads.load(std::memory_order_relaxed);
    counters.renderModelHookTicks =
        g_abRenderModelHookTicks.load(std::memory_order_relaxed);
    counters.renderModelOriginalTicks =
        g_abRenderModelOriginalTicks.load(std::memory_order_relaxed);
    counters.skeletalHookTicks =
        g_abSkeletalHookTicks.load(std::memory_order_relaxed);
    counters.skeletalOriginalTicks =
        g_abSkeletalOriginalTicks.load(std::memory_order_relaxed);
    counters.sourceFlushTicks =
        g_abSourceFlushTicks.load(std::memory_order_relaxed);
    counters.sourceFlushOriginalTicks =
        g_abSourceFlushOriginalTicks.load(std::memory_order_relaxed);
    counters.sourceWrites = g_abSourceWrites.load(std::memory_order_relaxed);
    return counters;
}

std::uint64_t CounterDelta(std::uint64_t current, std::uint64_t previous) {
    return current >= previous ? current - previous : 0;
}

double InterpolationAbPercentile(double percentile) {
    const std::uint64_t sampleCount = g_interpolationAbProbe.sampledFrames;
    if (sampleCount == 0) {
        return std::numeric_limits<double>::quiet_NaN();
    }
    const std::uint64_t target = static_cast<std::uint64_t>(
        std::ceil(percentile * static_cast<double>(sampleCount)));
    std::uint64_t cumulative = 0;
    for (std::size_t index = 0;
         index < g_interpolationAbProbe.histogram.size(); ++index) {
        cumulative += g_interpolationAbProbe.histogram[index];
        if (cumulative >= target) {
            return (static_cast<double>(index) + 0.5) *
                   kAbProbeHistogramBinMilliseconds;
        }
    }
    return (static_cast<double>(kAbProbeHistogramBinCount) - 0.5) *
           kAbProbeHistogramBinMilliseconds;
}

void LogInterpolationAbTiming(const InterpolationAbCounterSnapshot& current,
                              double averageFrameMilliseconds) {
    const InterpolationAbCounterSnapshot& start =
        g_interpolationAbProbe.countersAtStart;
    const double frames = static_cast<double>(
        g_interpolationAbProbe.sampledFrames);
    const double ticksPerMillisecond =
        static_cast<double>(g_interpolationAbProbe.frequency.QuadPart) / 1000.0;
    if (!(frames > 0.0) || !(ticksPerMillisecond > 0.0)) {
        return;
    }
    const auto perFrame = [&](std::uint64_t now, std::uint64_t then) {
        return static_cast<double>(CounterDelta(now, then)) /
               ticksPerMillisecond / frames;
    };
    const double modelTotal =
        perFrame(current.renderModelHookTicks, start.renderModelHookTicks);
    const double modelEngine =
        perFrame(current.renderModelOriginalTicks, start.renderModelOriginalTicks);
    const double poseTotal =
        perFrame(current.skeletalHookTicks, start.skeletalHookTicks);
    const double poseEngine =
        perFrame(current.skeletalOriginalTicks, start.skeletalOriginalTicks);
    const double flushTotal =
        perFrame(current.sourceFlushTicks, start.sourceFlushTicks);
    const double flushEngine =
        perFrame(current.sourceFlushOriginalTicks, start.sourceFlushOriginalTicks);
    const double modelPlugin = std::max(0.0, modelTotal - modelEngine);
    const double posePlugin = std::max(0.0, poseTotal - poseEngine);
    const double flushPlugin = std::max(0.0, flushTotal - flushEngine);
    const double pluginTotal = modelPlugin + posePlugin + flushPlugin;
    Log("A/B segment %llu hook CPU per sampled frame (all threads): "
        "modelHook plugin=%.3fms engine=%.3fms calls=%.1f; poseHook "
        "plugin=%.3fms engine=%.3fms calls=%.1f; sourceFlush plugin=%.3fms "
        "engine=%.3fms writes=%.1f; plugin total=%.3fms "
        "(%.1f%% of the %.3fms average frame).",
        static_cast<unsigned long long>(g_interpolationAbProbe.segmentId),
        modelPlugin, modelEngine,
        static_cast<double>(CounterDelta(current.renderModelHookCalls,
                                         start.renderModelHookCalls)) / frames,
        posePlugin, poseEngine,
        static_cast<double>(CounterDelta(current.skeletalHookCalls,
                                         start.skeletalHookCalls)) / frames,
        flushPlugin, flushEngine,
        static_cast<double>(CounterDelta(current.sourceWrites,
                                         start.sourceWrites)) / frames,
        pluginTotal,
        averageFrameMilliseconds > 0.0
            ? 100.0 * pluginTotal / averageFrameMilliseconds : 0.0,
        averageFrameMilliseconds);
}

void ReportInterpolationAbSegment(const char* reason) {
    if (!g_interpolationAbProbe.capturing) {
        return;
    }

    const InterpolationAbCounterSnapshot current =
        CaptureInterpolationAbCounters();
    if (g_interpolationAbProbe.sampledFrames == 0 ||
        !(g_interpolationAbProbe.sampledSeconds > 0.0)) {
        Log("A/B segment %llu ended (%s): transforms=%s(%s) skeletons=%s hands=%s, "
            "serial=%llu..%llu; no post-warm-up samples were captured.",
            static_cast<unsigned long long>(g_interpolationAbProbe.segmentId),
            reason,
            g_interpolationAbProbe.transformInterpolationEnabled ? "on" : "off",
            g_interpolationAbProbe.sourceLevelTransforms ? "source" : "per-draw",
            g_interpolationAbProbe.skeletalInterpolationEnabled ? "on" : "off",
            g_interpolationAbProbe.firstPersonHandsEnabled ? "on" : "off",
            static_cast<unsigned long long>(
                g_interpolationAbProbe.startPresentationSerial),
            static_cast<unsigned long long>(
                g_interpolationAbProbe.lastPresentationSerial));
        return;
    }

    const double averageFrameMilliseconds =
        1000.0 * g_interpolationAbProbe.sampledSeconds /
        static_cast<double>(g_interpolationAbProbe.sampledFrames);
    const double averageFps =
        static_cast<double>(g_interpolationAbProbe.sampledFrames) /
        g_interpolationAbProbe.sampledSeconds;
    const double cadenceFps =
        g_interpolationAbProbe.simulationTicks > kTimeEpsilon
            ? (1.0 / kNativeSimulationStep) *
                  static_cast<double>(g_interpolationAbProbe.cadenceFrames) /
                  g_interpolationAbProbe.simulationTicks
            : std::numeric_limits<double>::quiet_NaN();

    Log("A/B segment %llu ended (%s): transforms=%s(%s) skeletons=%s hands=%s, "
        "serial=%llu..%llu, warmup=%.1fs/%llu frames, sample=%.3fs/%llu "
        "frames; avg=%.3fms %.2fFPS, p50=%.3fms p95=%.3fms p99=%.3fms "
        "min=%.3fms max=%.3fms; cadence=%.2fFPS ticks[zero=%llu one=%llu "
        "multi=%llu invalid=%llu]; work[modelHooks=%llu fpRoots=%llu "
        "worldCandidates=%llu worldAdjusted=%llu poseHooks=%llu "
        "posePrepareCalls=%llu poseAdjusted=%llu forcedUploads=%llu].",
        static_cast<unsigned long long>(g_interpolationAbProbe.segmentId),
        reason,
        g_interpolationAbProbe.transformInterpolationEnabled ? "on" : "off",
        g_interpolationAbProbe.sourceLevelTransforms ? "source" : "per-draw",
        g_interpolationAbProbe.skeletalInterpolationEnabled ? "on" : "off",
        g_interpolationAbProbe.firstPersonHandsEnabled ? "on" : "off",
        static_cast<unsigned long long>(
            g_interpolationAbProbe.sampleStartPresentationSerial),
        static_cast<unsigned long long>(
            g_interpolationAbProbe.lastPresentationSerial),
        kAbProbeWarmupSeconds,
        static_cast<unsigned long long>(g_interpolationAbProbe.warmupFrames),
        g_interpolationAbProbe.sampledSeconds,
        static_cast<unsigned long long>(g_interpolationAbProbe.sampledFrames),
        averageFrameMilliseconds, averageFps,
        InterpolationAbPercentile(0.50),
        InterpolationAbPercentile(0.95),
        InterpolationAbPercentile(0.99),
        g_interpolationAbProbe.minimumFrameMilliseconds,
        g_interpolationAbProbe.maximumFrameMilliseconds,
        cadenceFps,
        static_cast<unsigned long long>(g_interpolationAbProbe.zeroTickFrames),
        static_cast<unsigned long long>(g_interpolationAbProbe.oneTickFrames),
        static_cast<unsigned long long>(
            g_interpolationAbProbe.multipleTickFrames),
        static_cast<unsigned long long>(
            g_interpolationAbProbe.invalidCadenceFrames),
        static_cast<unsigned long long>(CounterDelta(
            current.renderModelHookCalls,
            g_interpolationAbProbe.countersAtStart.renderModelHookCalls)),
        static_cast<unsigned long long>(CounterDelta(
            current.firstPersonRootCorrections,
            g_interpolationAbProbe.countersAtStart.firstPersonRootCorrections)),
        static_cast<unsigned long long>(CounterDelta(
            current.worldCandidates,
            g_interpolationAbProbe.countersAtStart.worldCandidates)),
        static_cast<unsigned long long>(CounterDelta(
            current.worldAdjustments,
            g_interpolationAbProbe.countersAtStart.worldAdjustments)),
        static_cast<unsigned long long>(CounterDelta(
            current.skeletalHookCalls,
            g_interpolationAbProbe.countersAtStart.skeletalHookCalls)),
        static_cast<unsigned long long>(CounterDelta(
            current.skeletalPrepareCalls,
            g_interpolationAbProbe.countersAtStart.skeletalPrepareCalls)),
        static_cast<unsigned long long>(CounterDelta(
            current.skeletalAdjustments,
            g_interpolationAbProbe.countersAtStart.skeletalAdjustments)),
        static_cast<unsigned long long>(CounterDelta(
            current.forcedUploads,
            g_interpolationAbProbe.countersAtStart.forcedUploads)));
    LogInterpolationAbTiming(current, averageFrameMilliseconds);
}

void StartInterpolationAbSegment() {
    g_interpolationAbProbe = {};
    if (!QueryPerformanceFrequency(&g_interpolationAbProbe.frequency) ||
        g_interpolationAbProbe.frequency.QuadPart <= 0 ||
        !QueryPerformanceCounter(&g_interpolationAbProbe.segmentStartCounter)) {
        Log("A/B probe could not initialize the performance counter.");
        return;
    }
    g_interpolationAbProbe.capturing = true;
    g_interpolationAbProbe.transformInterpolationEnabled =
        RuntimeTransformInterpolationEnabled();
    g_interpolationAbProbe.skeletalInterpolationEnabled =
        RuntimeSkeletalInterpolationEnabled();
    g_interpolationAbProbe.firstPersonHandsEnabled =
        RuntimeFirstPersonHandsEnabled();
    g_interpolationAbProbe.sourceLevelTransforms = SourceLevelWritesSelected();
    g_interpolationAbProbe.segmentId = g_nextInterpolationAbSegmentId++;
    g_interpolationAbProbe.startPresentationSerial =
        g_presentationSerial.load(std::memory_order_acquire);
    g_interpolationAbProbe.lastPresentationSerial =
        g_interpolationAbProbe.startPresentationSerial;
    Log("A/B segment %llu started: transforms=%s(%s) skeletons=%s hands=%s at "
        "presentation serial %llu; first %.1f seconds are warm-up.",
        static_cast<unsigned long long>(g_interpolationAbProbe.segmentId),
        g_interpolationAbProbe.transformInterpolationEnabled ? "on" : "off",
        g_interpolationAbProbe.sourceLevelTransforms ? "source" : "per-draw",
        g_interpolationAbProbe.skeletalInterpolationEnabled ? "on" : "off",
        g_interpolationAbProbe.firstPersonHandsEnabled ? "on" : "off",
        static_cast<unsigned long long>(
            g_interpolationAbProbe.startPresentationSerial),
        kAbProbeWarmupSeconds);
    QueryPerformanceCounter(&g_interpolationAbProbe.segmentStartCounter);
}

void StopInterpolationAbSegment(const char* reason) {
    ReportInterpolationAbSegment(reason);
    g_interpolationAbProbe.capturing = false;
    g_interpolationAbProbe.hasPreviousFrame = false;
}

void RecordInterpolationAbFrame(const PresentationContext& context) {
    if (!g_enableInterpolationAbProbe ||
        !g_interpolationAbProbe.capturing || !context.valid) {
        return;
    }

    LARGE_INTEGER now{};
    if (!QueryPerformanceCounter(&now)) {
        return;
    }
    g_interpolationAbProbe.lastPresentationSerial = context.serial;
    if (!g_interpolationAbProbe.hasPreviousFrame) {
        g_interpolationAbProbe.previousFrameCounter = now;
        g_interpolationAbProbe.previousScaledTime = context.scaledTime;
        g_interpolationAbProbe.previousSimulationTime = context.simulationTime;
        g_interpolationAbProbe.hasPreviousFrame = true;
        return;
    }

    const double counterFrequency = static_cast<double>(
        g_interpolationAbProbe.frequency.QuadPart);
    const double elapsedSeconds = static_cast<double>(
        now.QuadPart - g_interpolationAbProbe.previousFrameCounter.QuadPart) /
        counterFrequency;
    const double sinceSegmentStart = static_cast<double>(
        now.QuadPart - g_interpolationAbProbe.segmentStartCounter.QuadPart) /
        counterFrequency;
    const double scaledDelta =
        context.scaledTime - g_interpolationAbProbe.previousScaledTime;
    const double simulationDelta =
        context.simulationTime - g_interpolationAbProbe.previousSimulationTime;
    g_interpolationAbProbe.previousFrameCounter = now;
    g_interpolationAbProbe.previousScaledTime = context.scaledTime;
    g_interpolationAbProbe.previousSimulationTime = context.simulationTime;

    if (sinceSegmentStart < kAbProbeWarmupSeconds) {
        ++g_interpolationAbProbe.warmupFrames;
        return;
    }
    if (!g_interpolationAbProbe.samplingStarted) {
        g_interpolationAbProbe.samplingStarted = true;
        g_interpolationAbProbe.sampleStartPresentationSerial = context.serial;
        g_interpolationAbProbe.countersAtStart = CaptureInterpolationAbCounters();
        return;
    }
    if (!(elapsedSeconds > 0.0) || elapsedSeconds > 0.5) {
        ++g_interpolationAbProbe.invalidCadenceFrames;
        return;
    }

    const double frameMilliseconds = elapsedSeconds * 1000.0;
    ++g_interpolationAbProbe.sampledFrames;
    g_interpolationAbProbe.sampledSeconds += elapsedSeconds;
    g_interpolationAbProbe.minimumFrameMilliseconds = std::min(
        g_interpolationAbProbe.minimumFrameMilliseconds, frameMilliseconds);
    g_interpolationAbProbe.maximumFrameMilliseconds = std::max(
        g_interpolationAbProbe.maximumFrameMilliseconds, frameMilliseconds);
    const std::size_t histogramIndex = std::min<std::size_t>(
        static_cast<std::size_t>(frameMilliseconds /
                                 kAbProbeHistogramBinMilliseconds),
        kAbProbeHistogramBinCount - 1);
    ++g_interpolationAbProbe.histogram[histogramIndex];

    if (scaledDelta > kTimeEpsilon && scaledDelta <= 0.5 &&
        simulationDelta >= -kTimeEpsilon && simulationDelta <= 0.5) {
        const double ticks = std::max(0.0, simulationDelta) /
                             kNativeSimulationStep;
        g_interpolationAbProbe.simulationTicks += ticks;
        ++g_interpolationAbProbe.cadenceFrames;
        if (ticks < 0.5) {
            ++g_interpolationAbProbe.zeroTickFrames;
        } else if (ticks < 1.5) {
            ++g_interpolationAbProbe.oneTickFrames;
        } else {
            ++g_interpolationAbProbe.multipleTickFrames;
        }
    } else {
        ++g_interpolationAbProbe.invalidCadenceFrames;
    }
}


// ---------------------------------------------------------------------------
// Audible toggle feedback (Diagnostics/ToggleSounds). Beep() blocks for the
// tone's duration, so tones are queued to a dedicated worker thread and the
// game thread only appends to the queue.
// ---------------------------------------------------------------------------

struct ToggleTone {
    DWORD frequency;  // 0 = silence
    DWORD milliseconds;
};

enum class ToggleCue {
    On,
    Off,
    Unavailable,
    SegmentStart,
    SegmentStop,
    MethodSource,
    MethodPerDraw,
};

SRWLOCK g_toggleToneLock = SRWLOCK_INIT;
CONDITION_VARIABLE g_toggleToneReady = CONDITION_VARIABLE_INIT;
std::vector<ToggleTone> g_toggleTones;
std::atomic<bool> g_toggleToneThreadStarted{false};

DWORD WINAPI ToggleToneThread(void*) {
    std::vector<ToggleTone> tones;
    for (;;) {
        AcquireSRWLockExclusive(&g_toggleToneLock);
        while (g_toggleTones.empty()) {
            SleepConditionVariableSRW(&g_toggleToneReady, &g_toggleToneLock,
                                      INFINITE, 0);
        }
        tones.swap(g_toggleTones);
        ReleaseSRWLockExclusive(&g_toggleToneLock);
        for (const ToggleTone& tone : tones) {
            if (tone.frequency == 0) {
                Sleep(tone.milliseconds);
            } else {
                Beep(tone.frequency, tone.milliseconds);
            }
        }
        tones.clear();
    }
}

void QueueToggleTones(std::initializer_list<ToggleTone> tones) {
    if (!g_toggleSounds) {
        return;
    }
    if (!g_toggleToneThreadStarted.exchange(true, std::memory_order_acq_rel)) {
        HANDLE thread = CreateThread(nullptr, 0, ToggleToneThread, nullptr, 0, nullptr);
        if (thread == nullptr) {
            g_toggleSounds = false;
            return;
        }
        CloseHandle(thread);
    }
    AcquireSRWLockExclusive(&g_toggleToneLock);
    // A held key or rapid presses must not build up a backlog.
    if (g_toggleTones.size() < 32) {
        g_toggleTones.insert(g_toggleTones.end(), tones.begin(), tones.end());
    }
    ReleaseSRWLockExclusive(&g_toggleToneLock);
    WakeConditionVariable(&g_toggleToneReady);
}

// Rising = on, falling = off, a low buzz = not available, a single click =
// segment start, a double click = segment stop, high two-tone = source-level
// method, low two-tone = per-draw method.
void PlayToggleCue(ToggleCue cue) {
    switch (cue) {
        case ToggleCue::On:
            QueueToggleTones({{600, 70}, {900, 90}});
            break;
        case ToggleCue::Off:
            QueueToggleTones({{900, 70}, {600, 90}});
            break;
        case ToggleCue::Unavailable:
            QueueToggleTones({{220, 180}});
            break;
        case ToggleCue::SegmentStart:
            QueueToggleTones({{1800, 25}});
            break;
        case ToggleCue::SegmentStop:
            QueueToggleTones({{1800, 25}, {0, 60}, {1800, 25}});
            break;
        case ToggleCue::MethodSource:
            QueueToggleTones({{1200, 80}, {1500, 110}});
            break;
        case ToggleCue::MethodPerDraw:
            QueueToggleTones({{450, 80}, {330, 110}});
            break;
    }
}

// Alt+F11 profile index: 1 = all, 2 = transforms only, 3 = skeletons only,
// 4 = off; one short beep per index.
void PlayProfileCue(int index) {
    switch (index) {
        case 1:
            QueueToggleTones({{800, 60}});
            break;
        case 2:
            QueueToggleTones({{800, 60}, {0, 70}, {800, 60}});
            break;
        case 3:
            QueueToggleTones({{800, 60}, {0, 70}, {800, 60}, {0, 70}, {800, 60}});
            break;
        default:
            QueueToggleTones({{800, 60}, {0, 70}, {800, 60}, {0, 70}, {800, 60},
                              {0, 70}, {800, 60}});
            break;
    }
}

void HandleInterpolationAbControls() {
    const bool f11IsDown = (GetAsyncKeyState(VK_F11) & 0x8000) != 0;
    if (f11IsDown && !g_f11WasDown) {
        const bool controlIsDown =
            (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        const bool altIsDown =
            (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
        const bool shiftIsDown =
            (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        if (controlIsDown && shiftIsDown) {
            if (g_renderModelGpuCopyHookSkipped) {
                PlayToggleCue(ToggleCue::Unavailable);
                Log("Ctrl+Shift+F11: the per-draw hook is not installed in source "
                    "mode; set Diagnostics/InterpolationABProbe=1 to compare methods.");
            } else if (!g_sourceLevelInstalled || !g_sourceLevelWrites) {
                PlayToggleCue(ToggleCue::Unavailable);
                Log("Ctrl+Shift+F11: the source-level transform method is not "
                    "available (requires SourceLevelTransforms=1 and "
                    "SourceLevelWrites=1 on a supported executable).");
            } else {
                const bool wasCapturing = g_interpolationAbProbe.capturing;
                if (wasCapturing) {
                    StopInterpolationAbSegment("Ctrl+Shift+F11 method change");
                }
                const bool nowSource = !g_sourceLevelRuntimeEnabled.load(
                    std::memory_order_relaxed);
                g_sourceLevelRuntimeEnabled.store(nowSource,
                                                  std::memory_order_relaxed);
                PlayToggleCue(nowSource ? ToggleCue::MethodSource
                                        : ToggleCue::MethodPerDraw);
                Log("Ctrl+Shift+F11: world-transform method is now %s%s.",
                    nowSource ? "source-level (render-world flush)" : "per-draw",
                    wasCapturing ? "; the running A/B segment was restarted" : "");
                if (wasCapturing) {
                    StartInterpolationAbSegment();
                }
            }
        } else if (controlIsDown) {
            if (!g_enableInterpolationAbProbe) {
                PlayToggleCue(ToggleCue::Unavailable);
                Log("Ctrl+F11: A/B measurement is unavailable because "
                    "Diagnostics/InterpolationABProbe is disabled.");
            } else if (g_interpolationAbProbe.capturing) {
                PlayToggleCue(ToggleCue::SegmentStop);
                StopInterpolationAbSegment("Ctrl+F11 stop");
                Log("Ctrl+F11: A/B measurement stopped; travel frames will "
                    "not be sampled.");
            } else {
                PlayToggleCue(ToggleCue::SegmentStart);
                StartInterpolationAbSegment();
            }
        } else if (altIsDown) {
            if (!HasConfiguredInterpolationLayers()) {
                PlayToggleCue(ToggleCue::Unavailable);
                Log("Alt+F11: no interpolation layers are enabled by "
                    "configuration.");
            } else {
                SuspendAdaptiveInterpolationForManualControl();
                const bool transformsEnabled =
                    g_transformInterpolationRuntimeEnabled.load(
                        std::memory_order_relaxed);
                const bool skeletonsEnabled =
                    g_skeletalInterpolationRuntimeEnabled.load(
                        std::memory_order_relaxed);
                bool nextTransforms = true;
                bool nextSkeletons = true;
                if (transformsEnabled && skeletonsEnabled) {
                    nextTransforms = true;
                    nextSkeletons = false;
                } else if (transformsEnabled) {
                    nextTransforms = false;
                    nextSkeletons = true;
                } else if (skeletonsEnabled) {
                    nextTransforms = false;
                    nextSkeletons = false;
                }
                const bool wasCapturing = g_interpolationAbProbe.capturing;
                if (wasCapturing) {
                    StopInterpolationAbSegment("Alt+F11 profile change");
                }
                g_transformInterpolationRuntimeEnabled.store(
                    nextTransforms, std::memory_order_relaxed);
                g_skeletalInterpolationRuntimeEnabled.store(
                    nextSkeletons, std::memory_order_relaxed);
                const int profileIndex = nextTransforms
                    ? (nextSkeletons ? 1 : 2)
                    : (nextSkeletons ? 3 : 4);
                PlayProfileCue(profileIndex);
                Log("Alt+F11: interpolation profile %d/4 transforms=%s "
                    "skeletons=%s; first-person root remains unchanged.",
                    profileIndex, nextTransforms ? "on" : "off",
                    nextSkeletons ? "on" : "off");
                if (wasCapturing) {
                    StartInterpolationAbSegment();
                }
            }
        } else if (shiftIsDown) {
            if (!g_stabilizeFirstPersonHands) {
                PlayToggleCue(ToggleCue::Unavailable);
                Log("Shift+F11: first-person root stabilization is disabled "
                    "by configuration.");
            } else {
                const bool nowEnabled =
                    !g_firstPersonHandsRuntimeEnabled.load(
                        std::memory_order_relaxed);
                const bool wasCapturing = g_interpolationAbProbe.capturing;
                if (wasCapturing) {
                    StopInterpolationAbSegment("Shift+F11 mode change");
                }
                g_firstPersonHandsRuntimeEnabled.store(
                    nowEnabled, std::memory_order_relaxed);
                PlayToggleCue(nowEnabled ? ToggleCue::On : ToggleCue::Off);
                Log("Shift+F11: first-person root stabilization %s; camera "
                    "prediction remains unchanged.",
                    nowEnabled ? "enabled" : "disabled");
                if (wasCapturing) {
                    StartInterpolationAbSegment();
                }
            }
        } else if (!HasConfiguredInterpolationLayers()) {
            PlayToggleCue(ToggleCue::Unavailable);
            Log("F11: no interpolation layers are enabled by configuration.");
        } else {
            SuspendAdaptiveInterpolationForManualControl();
            const bool anyEnabled =
                g_transformInterpolationRuntimeEnabled.load(
                    std::memory_order_relaxed) ||
                g_skeletalInterpolationRuntimeEnabled.load(
                    std::memory_order_relaxed);
            const bool nowEnabled = !anyEnabled;
            const bool wasCapturing = g_interpolationAbProbe.capturing;
            if (wasCapturing) {
                StopInterpolationAbSegment("F11 mode change");
            }
            g_transformInterpolationRuntimeEnabled.store(
                nowEnabled, std::memory_order_relaxed);
            g_skeletalInterpolationRuntimeEnabled.store(
                nowEnabled, std::memory_order_relaxed);
            PlayToggleCue(nowEnabled ? ToggleCue::On : ToggleCue::Off);
            Log("F11: configured world/skeletal/cinematic interpolation %s; "
                "camera, mouse, unlock, and first-person root settings remain "
                "unchanged.", nowEnabled ? "enabled" : "disabled");
            if (wasCapturing) {
                StartInterpolationAbSegment();
            }
        }
    }
    g_f11WasDown = f11IsDown;
}

void ResetPrediction(const void* source, double simulationTime, const Transform& transform) {
    g_prediction.initialized = true;
    g_prediction.sourceView = source;
    g_prediction.previousTime = simulationTime;
    g_prediction.currentTime = simulationTime;
    g_prediction.previous = transform;
    g_prediction.current = transform;
}

bool IsWritableMemory(const void* address, std::size_t size) {
    if (!IsReadableMemory(address, size)) {
        return false;
    }
    MEMORY_BASIC_INFORMATION information{};
    if (VirtualQuery(address, &information, sizeof(information)) == 0) {
        return false;
    }
    const DWORD protection = information.Protect & 0xFF;
    return protection == PAGE_READWRITE || protection == PAGE_WRITECOPY;
}

// Drives the game's own frame spinner (the menu "Framerate Limiter") at
// MaxFPS instead of disabling it. The value is re-asserted every frame so the
// INI stays authoritative if the config load or the menu slider rewrites it;
// the saved config keeps its own string value.
void TryApplyEngineFrameLimiter() {
    if (g_maxFps <= 0 ||
        g_frameLimiterState.load(std::memory_order_relaxed) == 2) {
        return;
    }

    auto* cvar = reinterpret_cast<unsigned char*>(
        g_executableBase + g_layout->frameLimiterCvarRva);
    if (g_frameLimiterState.load(std::memory_order_relaxed) == 0) {
        const char* name = nullptr;
        if (g_layout->frameLimiterCvarRva != 0 &&
            IsReadableMemory(cvar + kCVarNameOffset, sizeof(name))) {
            memcpy(&name, cvar + kCVarNameOffset, sizeof(name));
            if (name == nullptr) {
                return;  // The cvar constructor has not run yet.
            }
        }
        if (name == nullptr ||
            !IsReadableMemory(name, sizeof(kFrameLimiterCvarName)) ||
            memcmp(name, kFrameLimiterCvarName, sizeof(kFrameLimiterCvarName)) != 0 ||
            !IsWritableMemory(cvar + kCVarIntegerOffset, 2 * sizeof(LONG))) {
            g_frameLimiterState.store(2, std::memory_order_relaxed);
            Log("The engine frame limiter (%s) was not found on the %s "
                "executable; MaxFPS was not applied and UnlockAbove120 "
                "behaves as configured.", kFrameLimiterCvarName, g_layout->name);
            return;
        }
        g_frameLimiterState.store(1, std::memory_order_relaxed);
        Log("Driving the engine frame limiter at MaxFPS=%d (%s=%.4f); "
            "com_disableFrameSpinning is left enabled. The limiter is skipped "
            "while V-Sync is on.", g_maxFps, kFrameLimiterCvarName,
            static_cast<double>(g_maxFps) / kFrameLimiterBaseFps);
    }

    const float target = static_cast<float>(g_maxFps) / kFrameLimiterBaseFps;
    auto* value = reinterpret_cast<volatile float*>(cvar + kCVarFloatOffset);
    if (*value != target) {
        *value = target;
        InterlockedExchange(reinterpret_cast<volatile LONG*>(cvar + kCVarIntegerOffset),
                            static_cast<LONG>(target));
    }
}

void TryUnlockAbove120() {
    if (!g_unlockAbove120 || g_unlockState.load(std::memory_order_relaxed) != 0) {
        return;
    }
    // The engine limiter needs the frame spinner; only fall back to disabling
    // it once MaxFPS is known to be unavailable.
    if (g_maxFps > 0 &&
        g_frameLimiterState.load(std::memory_order_relaxed) != 2) {
        return;
    }

    auto* frameSpinning = reinterpret_cast<volatile LONG*>(
        g_executableBase + g_layout->frameSpinningRva);
    auto* tripleBuffering = reinterpret_cast<volatile LONG*>(
        g_executableBase + g_layout->tripleBufferingRva);
    const LONG frameSpinningValue = *frameSpinning;
    const LONG tripleBufferingValue = *tripleBuffering;

    // Wait until both cvars contain their established initialized values.
    if ((frameSpinningValue != 0 && frameSpinningValue != 1) ||
        (tripleBufferingValue != 0 && tripleBufferingValue != 1)) {
        return;
    }
    if (tripleBufferingValue != 0) {
        int expected = 0;
        if (g_unlockState.compare_exchange_strong(expected, 2)) {
            Log("UnlockAbove120 was not applied because Triple Buffering is enabled.");
        }
        return;
    }

    InterlockedExchange(frameSpinning, 1);
    int expected = 0;
    if (g_unlockState.compare_exchange_strong(expected, 1)) {
        Log("Applied com_disableFrameSpinning=1; the external/driver limiter now controls FPS.");
    }
}

void TryStabilizeMouseSensitivity() {
    if (!g_stabilizeMouseSensitivity ||
        g_mouseStabilizationState.load(std::memory_order_relaxed) != 0) {
        return;
    }

    auto* fixMouseSensibility = reinterpret_cast<volatile LONG*>(
        g_executableBase + g_layout->fixMouseSensibilityRva);
    const LONG value = *fixMouseSensibility;

    // The game initializes this cached cvar to either 0 or 1. Do not write an
    // unexpected value: it may mean the cvar constructor has not run yet.
    if (value != 0 && value != 1) {
        return;
    }

    int expected = 0;
    if (value == 0) {
        if (g_mouseStabilizationState.compare_exchange_strong(expected, 2)) {
            Log("Mouse sensitivity is already stable: g_fixMouseSensibility=0.");
        }
        return;
    }

    if (g_mouseStabilizationState.compare_exchange_strong(expected, 1)) {
        InterlockedExchange(fixMouseSensibility, 0);
        Log("Stabilized mouse sensitivity by applying g_fixMouseSensibility=0.");
    }
}

void ApplyPrediction(void* destination, const void* source) {
    g_lastAlpha = std::numeric_limits<double>::quiet_NaN();
    TryApplyEngineFrameLimiter();
    TryUnlockAbove120();
    TryStabilizeMouseSensitivity();
    TryInstallOverlayPresentHook();
    UpdateForcedBloodEffect();
    const bool f10IsDown = (GetAsyncKeyState(VK_F10) & 0x8000) != 0;
    const bool controlIsDown = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
    const bool altIsDown = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
    if (f10IsDown && !g_f10WasDown && controlIsDown && altIsDown) {
        CycleScreenParticleMode();
    } else if (f10IsDown && !g_f10WasDown && controlIsDown && g_overlay) {
        ToggleDevGui();
    } else if (f10IsDown && !g_f10WasDown && altIsDown) {
        ToggleForcedBloodEffect();
    } else if (f10IsDown && !g_f10WasDown) {
        const bool nowEnabled = !g_enabled.load(std::memory_order_relaxed);
        g_enabled.store(nowEnabled, std::memory_order_relaxed);
        g_prediction.initialized = false;
        PlayToggleCue(nowEnabled ? ToggleCue::On : ToggleCue::Off);
        Log("F10: high-FPS camera and first-person prediction %s.",
            nowEnabled ? "enabled" : "disabled");
    }
    g_f10WasDown = f10IsDown;
    CloseDevGuiOnEscape();
    HandleInterpolationAbControls();
    if (!g_enabled.load(std::memory_order_relaxed)) {
        return;
    }

    auto* game = *reinterpret_cast<unsigned char**>(g_executableBase + g_layout->gamePointerRva);
    if (game == nullptr || *reinterpret_cast<std::uintptr_t*>(game) !=
                               g_executableBase + g_layout->gameVtable.rva) {
        g_prediction.initialized = false;
        return;
    }

    unsigned char* clock = game + kClockOffset;
    double scaledTime = 0.0;
    double simulationTime = 0.0;
    memcpy(&scaledTime, clock + kScaledTimeOffset, sizeof(scaledTime));
    memcpy(&simulationTime, clock + kSimulationTimeOffset, sizeof(simulationTime));

    const Transform raw = ReadTransform(destination);
    if (!std::isfinite(scaledTime) || !std::isfinite(simulationTime) ||
        !IsFinite(raw) || !OriginsAreDuplicated(destination)) {
        g_prediction.initialized = false;
        return;
    }

    if (!g_prediction.initialized || g_prediction.sourceView != source ||
        simulationTime < g_prediction.currentTime - kTimeEpsilon) {
        ResetPrediction(source, simulationTime, raw);
        return;
    }

    if (simulationTime > g_prediction.currentTime + kTimeEpsilon) {
        const double interval = simulationTime - g_prediction.currentTime;
        if (interval > kMaximumStateInterval ||
            PositionDistance(g_prediction.current, raw) > kMaximumPositionJump ||
            RotationDistanceDegrees(g_prediction.current, raw) > kMaximumRotationJumpDegrees) {
            ResetPrediction(source, simulationTime, raw);
            return;
        }
        g_prediction.previousTime = g_prediction.currentTime;
        g_prediction.previous = g_prediction.current;
        g_prediction.currentTime = simulationTime;
        g_prediction.current = raw;
    }

    const double interval = g_prediction.currentTime - g_prediction.previousTime;
    if (!(interval > kTimeEpsilon) || interval > kMaximumStateInterval) {
        return;
    }

    const double alpha = Clamp((scaledTime - g_prediction.previousTime) / interval,
                               kMinimumAlpha, kMaximumAlpha);
    g_lastAlpha = alpha;
    Transform predicted{};
    predicted.origin = {
        g_prediction.previous.origin.x +
            alpha * (g_prediction.current.origin.x - g_prediction.previous.origin.x),
        g_prediction.previous.origin.y +
            alpha * (g_prediction.current.origin.y - g_prediction.previous.origin.y),
        g_prediction.previous.origin.z +
            alpha * (g_prediction.current.origin.z - g_prediction.previous.origin.z),
    };
    const Quaternion previousRotation = MatrixToQuaternion(g_prediction.previous.axis);
    const Quaternion currentRotation = MatrixToQuaternion(g_prediction.current.axis);
    QuaternionToMatrix(SlerpUnclamped(previousRotation, currentRotation, alpha), predicted.axis);

    if (IsFinite(predicted)) {
        WriteTransform(destination, predicted);
    }
}


// ---------------------------------------------------------------------------
// Automated A/B schedule (Diagnostics/AutoABSchedule). Once gameplay has been
// ticking for a warm-up period it cycles through fixed interpolation profiles,
// records one probe segment per profile and round (interleaved so drift
// cancels), logs a summary table, and can close the game window. It only
// flips the same runtime switches the F11 hotkeys use; no input is simulated.
// ---------------------------------------------------------------------------

struct AutoAbProfile {
    const char* name;
    bool transforms;
    bool skeletons;
    bool source;
    bool camera;
    bool hands;
};

// "unlock only" also turns off camera prediction (F10) and the first-person
// root correction (Shift+F11), leaving the FPS unlock and measurement.
constexpr std::array<AutoAbProfile, 7> kAutoAbProfiles = {{
    {"off", false, false, true, true, true},
    {"transforms source", true, false, true, true, true},
    {"transforms per-draw", true, false, false, true, true},
    {"skeletons only", false, true, true, true, true},
    {"all source", true, true, true, true, true},
    {"all per-draw", true, true, false, true, true},
    {"unlock only", false, false, true, false, false},
}};
constexpr std::size_t kAutoAbDefaultProfileCount = 6;
std::vector<std::size_t> g_autoAbProfileOrder;
constexpr double kAutoAbGameplayWarmupSeconds = 10.0;
constexpr double kAutoAbSettleSeconds = 1.0;

struct AutoAbResult {
    std::size_t profile = 0;
    int round = 0;
    double fps = 0.0;
    double p50 = 0.0;
    double p95 = 0.0;
    double p99 = 0.0;
    double modelMs = 0.0;
    double poseMs = 0.0;
    double flushMs = 0.0;
    double writesPerFrame = 0.0;
    std::uint64_t frames = 0;
};

enum class AutoAbPhase { WaitingForGameplay, Settling, Recording, Done };

struct AutoAbState {
    AutoAbPhase phase = AutoAbPhase::WaitingForGameplay;
    std::uint64_t phaseStart = 0;
    std::uint64_t gameplayStart = 0;
    double lastSimulationTime = 0.0;
    std::size_t step = 0;
    std::vector<AutoAbResult> results;
};

AutoAbState g_autoAb;

double AutoAbSeconds(std::uint64_t from, std::uint64_t to) {
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    return static_cast<double>(to - from) / static_cast<double>(frequency.QuadPart);
}

void ApplyAutoAbProfile(const AutoAbProfile& profile) {
    g_enabled.store(profile.camera, std::memory_order_relaxed);
    if (!profile.camera) {
        g_prediction.initialized = false;
    }
    g_firstPersonHandsRuntimeEnabled.store(profile.hands, std::memory_order_relaxed);
    g_transformInterpolationRuntimeEnabled.store(profile.transforms,
                                                 std::memory_order_relaxed);
    g_skeletalInterpolationRuntimeEnabled.store(profile.skeletons,
                                                std::memory_order_relaxed);
    if (g_sourceLevelInstalled && g_sourceLevelWrites) {
        g_sourceLevelRuntimeEnabled.store(profile.source, std::memory_order_relaxed);
    }
}

AutoAbResult CaptureAutoAbResult(std::size_t profile, int round) {
    AutoAbResult result{};
    result.profile = profile;
    result.round = round;
    const InterpolationAbProbeState& probe = g_interpolationAbProbe;
    result.frames = probe.sampledFrames;
    if (probe.sampledFrames == 0 || !(probe.sampledSeconds > 0.0)) {
        return result;
    }
    const double frames = static_cast<double>(probe.sampledFrames);
    result.fps = frames / probe.sampledSeconds;
    result.p50 = InterpolationAbPercentile(0.50);
    result.p95 = InterpolationAbPercentile(0.95);
    result.p99 = InterpolationAbPercentile(0.99);
    const InterpolationAbCounterSnapshot now = CaptureInterpolationAbCounters();
    const InterpolationAbCounterSnapshot& start = probe.countersAtStart;
    const double ticksPerMs = static_cast<double>(probe.frequency.QuadPart) / 1000.0;
    const auto plugin = [&](std::uint64_t total, std::uint64_t totalStart,
                            std::uint64_t engine, std::uint64_t engineStart) {
        const double value = static_cast<double>(CounterDelta(total, totalStart)) -
                             static_cast<double>(CounterDelta(engine, engineStart));
        return std::max(0.0, value) / ticksPerMs / frames;
    };
    result.modelMs = plugin(now.renderModelHookTicks, start.renderModelHookTicks,
                            now.renderModelOriginalTicks, start.renderModelOriginalTicks);
    result.poseMs = plugin(now.skeletalHookTicks, start.skeletalHookTicks,
                           now.skeletalOriginalTicks, start.skeletalOriginalTicks);
    result.flushMs = plugin(now.sourceFlushTicks, start.sourceFlushTicks,
                            now.sourceFlushOriginalTicks, start.sourceFlushOriginalTicks);
    result.writesPerFrame =
        static_cast<double>(CounterDelta(now.sourceWrites, start.sourceWrites)) / frames;
    return result;
}

BOOL CALLBACK AutoAbCloseWindow(HWND window, LPARAM) {
    DWORD processId = 0;
    GetWindowThreadProcessId(window, &processId);
    if (processId == GetCurrentProcessId() && IsWindowVisible(window) &&
        GetWindow(window, GW_OWNER) == nullptr) {
        PostMessageW(window, WM_CLOSE, 0, 0);
    }
    return TRUE;
}

void LogAutoAbSummary() {
    Log("Auto A/B summary (%d rounds x %zu profiles, %d s segments; plugin ms are "
        "per frame across all threads):", g_autoAbRounds, g_autoAbProfileOrder.size(),
        g_autoAbSegmentSeconds);
    Log("  %-20s round  frames     FPS   p50ms  p95ms  p99ms  model   pose  flush  "
        "writes/f", "profile");
    for (const AutoAbResult& r : g_autoAb.results) {
        Log("  %-20s %5d %7llu %7.1f %7.3f %6.3f %6.3f %6.3f %6.3f %6.3f %8.1f",
            kAutoAbProfiles[r.profile].name, r.round,
            static_cast<unsigned long long>(r.frames), r.fps, r.p50, r.p95, r.p99,
            r.modelMs, r.poseMs, r.flushMs, r.writesPerFrame);
    }
    for (std::size_t profile : g_autoAbProfileOrder) {
        double fps = 0.0, p99 = 0.0, model = 0.0, pose = 0.0, flush = 0.0;
        int count = 0;
        for (const AutoAbResult& r : g_autoAb.results) {
            if (r.profile == profile && r.frames != 0) {
                fps += r.fps; p99 += r.p99; model += r.modelMs; pose += r.poseMs;
                flush += r.flushMs; ++count;
            }
        }
        if (count != 0) {
            Log("  mean %-15s FPS %7.1f  p99 %6.3f ms  plugin model %.3f pose %.3f "
                "flush %.3f ms", kAutoAbProfiles[profile].name, fps / count,
                p99 / count, model / count, pose / count, flush / count);
        }
    }
}

void BuildAutoAbProfileOrder() {
    wchar_t path[MAX_PATH]{};
    BuildSiblingPath(path, MAX_PATH, L"d2-high-fps-fix.ini");
    wchar_t list[512]{};
    GetPrivateProfileStringW(L"Diagnostics", L"AutoABProfiles", L"", list, 512, path);
    char narrow[512]{};
    WideCharToMultiByte(CP_UTF8, 0, list, -1, narrow, sizeof(narrow), nullptr, nullptr);
    char* context = nullptr;
    for (char* token = strtok_s(narrow, ",", &context); token != nullptr;
         token = strtok_s(nullptr, ",", &context)) {
        while (*token == ' ') {
            ++token;
        }
        std::size_t length = strlen(token);
        while (length != 0 && token[length - 1] == ' ') {
            token[--length] = '\0';
        }
        bool found = false;
        for (std::size_t index = 0; index < kAutoAbProfiles.size(); ++index) {
            if (_stricmp(token, kAutoAbProfiles[index].name) == 0) {
                g_autoAbProfileOrder.push_back(index);
                found = true;
                break;
            }
        }
        if (!found && length != 0) {
            Log("Auto A/B: unknown profile '%s' in AutoABProfiles was ignored.", token);
        }
    }
    if (g_autoAbProfileOrder.empty()) {
        for (std::size_t index = 0; index < kAutoAbDefaultProfileCount; ++index) {
            g_autoAbProfileOrder.push_back(index);
        }
    }
    char names[512]{};
    for (std::size_t index : g_autoAbProfileOrder) {
        strcat_s(names, kAutoAbProfiles[index].name);
        strcat_s(names, "; ");
    }
    Log("Auto A/B profiles per round: %s", names);
}

void UpdateAutoAbSchedule(const PresentationContext& context) {
    if (!g_autoAbSchedule || !g_enableInterpolationAbProbe ||
        g_autoAb.phase == AutoAbPhase::Done || !context.valid) {
        return;
    }
    if (g_autoAbProfileOrder.empty()) {
        BuildAutoAbProfileOrder();
    }
    const std::uint64_t now = ReadPerformanceCounter();
    const std::size_t totalSteps =
        g_autoAbProfileOrder.size() * static_cast<std::size_t>(g_autoAbRounds);
    switch (g_autoAb.phase) {
        case AutoAbPhase::WaitingForGameplay: {
            const bool ticking = context.simulationTime > g_autoAb.lastSimulationTime;
            g_autoAb.lastSimulationTime = context.simulationTime;
            if (!ticking) {
                return;
            }
            if (g_autoAb.gameplayStart == 0) {
                g_autoAb.gameplayStart = now;
                Log("Auto A/B: gameplay detected; starting in %.0f s.",
                    kAutoAbGameplayWarmupSeconds);
                return;
            }
            if (AutoAbSeconds(g_autoAb.gameplayStart, now) < kAutoAbGameplayWarmupSeconds) {
                return;
            }
            if (g_interpolationAbProbe.capturing) {
                StopInterpolationAbSegment("Auto A/B takeover");
            }
            g_autoAb.step = 0;
            ApplyAutoAbProfile(kAutoAbProfiles[g_autoAbProfileOrder[0]]);
            g_autoAb.phase = AutoAbPhase::Settling;
            g_autoAb.phaseStart = now;
            return;
        }
        case AutoAbPhase::Settling:
            if (AutoAbSeconds(g_autoAb.phaseStart, now) < kAutoAbSettleSeconds) {
                return;
            }
            Log("Auto A/B step %zu/%zu: %s (round %zu).", g_autoAb.step + 1, totalSteps,
                kAutoAbProfiles[g_autoAbProfileOrder[g_autoAb.step %
                                                     g_autoAbProfileOrder.size()]].name,
                g_autoAb.step / g_autoAbProfileOrder.size() + 1);
            StartInterpolationAbSegment();
            g_autoAb.phase = AutoAbPhase::Recording;
            g_autoAb.phaseStart = now;
            return;
        case AutoAbPhase::Recording: {
            if (AutoAbSeconds(g_autoAb.phaseStart, now) <
                kAbProbeWarmupSeconds + static_cast<double>(g_autoAbSegmentSeconds)) {
                return;
            }
            const std::size_t profile =
                g_autoAbProfileOrder[g_autoAb.step % g_autoAbProfileOrder.size()];
            g_autoAb.results.push_back(CaptureAutoAbResult(
                profile, static_cast<int>(g_autoAb.step / g_autoAbProfileOrder.size()) + 1));
            StopInterpolationAbSegment("Auto A/B step complete");
            ++g_autoAb.step;
            if (g_autoAb.step >= totalSteps) {
                ApplyAutoAbProfile(kAutoAbProfiles[4]);  // everything back on
                g_autoAb.phase = AutoAbPhase::Done;
                LogAutoAbSummary();
                if (g_autoAbQuitWhenDone) {
                    Log("Auto A/B: done; closing the game window.");
                    EnumWindows(AutoAbCloseWindow, 0);
                }
                return;
            }
            ApplyAutoAbProfile(kAutoAbProfiles[
                g_autoAbProfileOrder[g_autoAb.step % g_autoAbProfileOrder.size()]]);
            g_autoAb.phase = AutoAbPhase::Settling;
            g_autoAb.phaseStart = now;
            return;
        }
        case AutoAbPhase::Done:
            return;
    }
}

extern "C" void* __fastcall HookCopyView(void* destination, const void* source) {
    void* result = g_originalCopyView(destination, source);
    const Transform rawCamera = ReadTransform(destination);
    ApplyPrediction(destination, source);
    PublishRenderCorrection(rawCamera, ReadTransform(destination));
    NoteCameraOrigins(rawCamera, ReadTransform(destination));
    RefreshScreenParticlesForCamera(ReadTransform(destination));
    PublishPresentationContext();
    PresentationContext probeContext{};
    if (ReadPresentationContext(probeContext)) {
        NoteSimulationTime(probeContext.simulationTime);
        UpdateAdaptiveInterpolationGate(probeContext);
        RecordInterpolationAbFrame(probeContext);
        UpdateAutoAbSchedule(probeContext);
    }
    PublishTelemetry(source, destination);
    return result;
}

std::uintptr_t AlignUp(std::uintptr_t value, std::uintptr_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

void* AllocateRelayNear(std::uintptr_t callsite) {
    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);
    const std::uintptr_t allocationGranularity = systemInfo.dwAllocationGranularity;
    const std::uintptr_t systemMinimum =
        reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    const std::uintptr_t systemMaximum =
        reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);
    const std::uintptr_t reach = 0x70000000ULL;
    const std::uintptr_t minimum = std::max(systemMinimum, callsite > reach ? callsite - reach : 0);
    const std::uintptr_t maximum = std::min(systemMaximum, callsite + reach);

    std::uintptr_t cursor = minimum;
    while (cursor < maximum) {
        MEMORY_BASIC_INFORMATION information{};
        if (VirtualQuery(reinterpret_cast<void*>(cursor), &information,
                         sizeof(information)) == 0) {
            break;
        }
        const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(information.BaseAddress);
        const std::uintptr_t regionEnd = regionBase + information.RegionSize;
        if (information.State == MEM_FREE) {
            const std::uintptr_t candidate = AlignUp(regionBase, allocationGranularity);
            if (candidate < regionEnd && candidate + 0x1000 <= maximum) {
                void* allocation = VirtualAlloc(reinterpret_cast<void*>(candidate), 0x1000,
                                                MEM_RESERVE | MEM_COMMIT,
                                                PAGE_EXECUTE_READWRITE);
                if (allocation != nullptr) {
                    return allocation;
                }
            }
        }
        if (regionEnd <= cursor) {
            break;
        }
        cursor = regionEnd;
    }
    return nullptr;
}

void WriteAbsoluteIndirectJump(unsigned char* destination, const void* target) {
    destination[0] = 0xFF;
    destination[1] = 0x25;
    memset(destination + 2, 0, 4);
    const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(target);
    memcpy(destination + 6, &address, sizeof(address));
}

// ---------------------------------------------------------------------------
// Source-level world-transform layer (SourceLevelTransforms).
//
// The game thread writes each entity's origin/axis/scale into its render model
// and calls MarkDirty (render-model vtable +0x28) once per 120 Hz tick. Once
// per rendered frame the render-world flush (idRenderWorldLocal vtable +0xD8)
// runs Commit for every dirty model, rebuilding the world matrix at +0x20 and
// its inverse at +0xA0. The per-view cull job then copies +0x20 into the
// previous-matrix slot +0x60 and builds the view/MVP matrices from it.
//
// Phase A (SourceLevelWrites=0) only observes MarkDirty and the flush. Phase B
// (SourceLevelWrites=1) samples each committed matrix after the flush returns
// and, before any view job runs, overwrites +0x20/+0xA0 with the presentation
// blend. The cull job then derives +0x60 and the MVP from it, so no per-draw
// correction is needed. Entity transforms, origin/axis/scale fields, and the
// bounds that gameplay reads back are never modified.
// ---------------------------------------------------------------------------

using RenderWorldFlushFn = void(__fastcall*)(void*, std::uintptr_t);
using RenderModelMarkDirtyFn = void(__fastcall*)(void*, std::uintptr_t);
RenderWorldFlushFn g_originalRenderWorldFlush = nullptr;
RenderModelMarkDirtyFn g_originalRenderModelMarkDirty = nullptr;

struct SourceLevelDiagnostics {
    std::atomic<std::uint64_t> markDirtyCalls{0};
    std::atomic<std::uint64_t> markDirtyTransform{0};
    std::atomic<std::uint64_t> markDirtyOffFlushThread{0};
    std::atomic<std::uint64_t> dirtyOverflows{0};
    std::atomic<std::uint64_t> rendererFirstAfterFlush{0};
    std::atomic<std::uint64_t> rendererFirstBeforeFlush{0};
    std::atomic<std::uint64_t> rendererCallsDuringFlush{0};
    std::atomic<std::uint64_t> assemblyMarkDirty{0};
    std::atomic<std::uint64_t> assemblyMarkDirtyTransform{0};
    std::atomic<std::uint64_t> partMarkDirtyTransform{0};
    std::atomic<std::uint64_t> dirtyLockContended{0};
};

// Counters only touched by the flush thread.
struct SourceLevelCounters {
    std::uint64_t flushCalls = 0;
    std::uint64_t flushesWithTick = 0;
    std::uint64_t uniqueDirty = 0;
    std::uint64_t foreignWorldDirty = 0;
    std::uint64_t flushEngineTicks = 0;
    std::uint64_t flushPluginTicks = 0;
    std::uint64_t tracksCreated = 0;
    std::uint64_t samples = 0;
    std::uint64_t holds = 0;
    std::uint64_t writes = 0;
    std::uint64_t restores = 0;
    std::uint64_t drops = 0;
    std::uint64_t deadTracks = 0;
    std::uint64_t staleTracks = 0;
    std::uint64_t ineligible = 0;
    std::uint64_t capacityMisses = 0;
    std::uint64_t jumpSnaps = 0;
    std::uint64_t intervalSnaps = 0;
    std::uint64_t sameTimeSnaps = 0;
    std::uint64_t timeResets = 0;
    std::uint64_t nonRigid = 0;
    std::uint64_t activeTracks = 0;
    std::uint64_t activePartTracks = 0;
    std::uint64_t linkedCandidates = 0;
    std::uint64_t linkedTracksCreated = 0;
    std::uint64_t handsDirty = 0;
    std::uint64_t firstCommits = 0;
    std::uint64_t handsTracksCreated = 0;
    std::uint64_t handsWrites = 0;
    std::uint64_t activeHandsTracks = 0;
};

SourceLevelDiagnostics g_sourceDiagnostics;
SourceLevelCounters g_sourceCounters;

struct SourceLevelDiagnosticsSnapshot {
    std::uint64_t serial = 0;
    std::uint64_t markDirtyCalls = 0;
    std::uint64_t markDirtyTransform = 0;
    std::uint64_t markDirtyOffFlushThread = 0;
    std::uint64_t dirtyOverflows = 0;
    std::uint64_t rendererFirstAfterFlush = 0;
    std::uint64_t rendererFirstBeforeFlush = 0;
    std::uint64_t rendererCallsDuringFlush = 0;
    std::uint64_t assemblyMarkDirty = 0;
    std::uint64_t assemblyMarkDirtyTransform = 0;
    std::uint64_t partMarkDirtyTransform = 0;
    std::uint64_t dirtyLockContended = 0;
    std::uint64_t poseLockContended = 0;
    SourceLevelCounters plain{};
};

std::atomic<DWORD> g_sourceFlushThreadId{0};
std::atomic<DWORD> g_sourceRendererThreadId{0};
std::atomic<std::uint64_t> g_sourceLastFlushSerial{0};
std::atomic<std::uint64_t> g_sourceLastRendererSerial{0};
std::atomic<bool> g_sourceFlushInProgress{false};
double g_sourceLastFlushSimulationTime = std::numeric_limits<double>::quiet_NaN();
std::uint64_t g_sourceLastLogCounter = 0;
SourceLevelDiagnosticsSnapshot g_sourceLastLogSnapshot{};
bool g_sourceHasLogSnapshot = false;

SRWLOCK g_sourceDirtyLock = SRWLOCK_INIT;
// Each entry records the world the model belonged to at MarkDirty time, while
// the model was certainly alive, so the flush never reads a model that may
// have been deleted since.
struct SourceDirtyEntry {
    void* model;
    void* world;
    std::uint32_t deferrals;
};
// Entries waiting for a world that is never flushed again (unloaded) are
// discarded after this many foreign flushes.
constexpr std::uint32_t kSourceMaximumDirtyDeferrals = 600;
std::vector<SourceDirtyEntry> g_sourceDirty;
std::vector<SourceDirtyEntry> g_sourceDirtyPending;
std::vector<SourceDirtyEntry> g_sourceDirtyDeferred;
std::vector<void*> g_sourceDirtyScratch;
bool g_sourceDirtyOverflowed = false;

struct SourceTrack {
    void* model = nullptr;
    void* world = nullptr;
    const void* owner = nullptr;
    const void* modelAsset = nullptr;
    std::uintptr_t vtable = 0;
    std::uint16_t handle = 0;
    double previousTime = 0.0;
    double currentTime = 0.0;
    Matrix4 previous{};
    Matrix4 current{};
    Matrix4 currentInverse{};
    // What the model's +0x20 holds unless the engine committed it again.
    Matrix4 expected{};
    std::uint64_t lastFlushSerial = 0;
    std::uint32_t idleTicks = 0;
    bool hasPair = false;
    bool dirty = false;
    bool fresh = false;
    bool assemblyPart = false;
    // First-person (depth-hacked) model corrected to the predicted camera.
    bool hands = false;
    // Screen particle (camera blood and similar): its particles are emitted
    // in world space at the tick camera, so like the hands it is moved by the
    // camera correction instead of being interpolated.
    bool screenParticle = false;
    // Mode 2: the emitter pose (+0x1860 origin, +0x186C axis) the engine last
    // placed, and what this track wrote there.
    std::array<float, 12> poseBase{};
    std::array<float, 12> poseExpected{};
    int screenMode = 0;
};

std::array<SourceTrack, kSourceTrackCapacity> g_sourceTracks{};

bool SourceLevelWritesSelected() {
    return g_sourceLevelInstalled && g_sourceLevelWrites &&
           g_sourceLevelRuntimeEnabled.load(std::memory_order_relaxed);
}

bool SourceLevelWritesActive() {
    return SourceLevelWritesSelected() && RuntimeTransformInterpolationEnabled() &&
           (g_interpolateWorldTransforms || g_interpolateCinematicTransforms);
}

void ObserveSourceLevelRendererCall() {
    if (g_sourceFlushInProgress.load(std::memory_order_acquire)) {
        g_sourceDiagnostics.rendererCallsDuringFlush.fetch_add(
            1, std::memory_order_relaxed);
    }
    const std::uint64_t serial = g_presentationSerial.load(std::memory_order_acquire);
    std::uint64_t last = g_sourceLastRendererSerial.load(std::memory_order_relaxed);
    if (serial == last ||
        !g_sourceLastRendererSerial.compare_exchange_strong(
            last, serial, std::memory_order_relaxed)) {
        return;
    }
    g_sourceRendererThreadId.store(GetCurrentThreadId(), std::memory_order_relaxed);
    if (g_sourceLastFlushSerial.load(std::memory_order_acquire) == serial) {
        g_sourceDiagnostics.rendererFirstAfterFlush.fetch_add(
            1, std::memory_order_relaxed);
    } else {
        g_sourceDiagnostics.rendererFirstBeforeFlush.fetch_add(
            1, std::memory_order_relaxed);
    }
}

std::size_t SourceTrackHash(const void* model) {
    std::uintptr_t value = reinterpret_cast<std::uintptr_t>(model) >> 4;
    value ^= value >> 17;
    value *= static_cast<std::uintptr_t>(0x9E3779B97F4A7C15ULL);
    return static_cast<std::size_t>(value >> 7) & (kSourceTrackCapacity - 1);
}

SourceTrack* FindSourceTrack(const void* model) {
    const std::size_t base = SourceTrackHash(model);
    for (std::size_t probe = 0; probe < kSourceTrackProbeLimit; ++probe) {
        SourceTrack& track = g_sourceTracks[(base + probe) & (kSourceTrackCapacity - 1)];
        if (track.model == model) {
            return &track;
        }
    }
    return nullptr;
}

// Occupied slots, so per-flush work scales with tracked models instead of the
// table capacity. A slot is listed at most once; dropped tracks are removed
// lazily by CompactSourceTrackList.
std::vector<std::uint32_t> g_sourceActive;
std::array<bool, kSourceTrackCapacity> g_sourceListed{};

SourceTrack* CreateSourceTrack(void* model) {
    const std::size_t base = SourceTrackHash(model);
    for (std::size_t probe = 0; probe < kSourceTrackProbeLimit; ++probe) {
        const std::size_t index = (base + probe) & (kSourceTrackCapacity - 1);
        SourceTrack& track = g_sourceTracks[index];
        if (track.model == nullptr) {
            track = {};
            track.model = model;
            if (!g_sourceListed[index]) {
                g_sourceListed[index] = true;
                g_sourceActive.push_back(static_cast<std::uint32_t>(index));
            }
            return &track;
        }
    }
    return nullptr;
}

void CompactSourceTrackList() {
    std::size_t kept = 0;
    for (std::uint32_t index : g_sourceActive) {
        if (g_sourceTracks[index].model != nullptr) {
            g_sourceActive[kept++] = index;
        } else {
            g_sourceListed[index] = false;
        }
    }
    g_sourceActive.resize(kept);
}

// Resolves the world's model-pointer array once per flush. A model is alive
// and owned by this world exactly when array[handle] still points at it.
struct SourceWorldView {
    void* world = nullptr;
    void* const* models = nullptr;
    std::uint32_t modelCount = 0;
};

bool SourceModelRegistered(const SourceWorldView& view, const void* model,
                           std::uint16_t handle) {
    if (view.models == nullptr) {
        return false;
    }
    return handle < view.modelCount && view.models[handle] == model;
}

void WriteSourceMatrices(SourceTrack& track, const Matrix4& matrix,
                         const Matrix4& inverse) {
    auto* bytes = static_cast<unsigned char*>(track.model);
    WriteMatrix(bytes, kRenderModelMatrixOffset, matrix);
    WriteMatrix(bytes, kRenderModelInverseMatrixOffset, inverse);
    track.expected = matrix;
}

bool MatricesBitwiseEqual(const Matrix4& left, const Matrix4& right) {
    return memcmp(&left, &right, sizeof(left)) == 0;
}

bool SourceHandsSelected() {
    return SourceLevelWritesSelected() && g_sourceLevelHands;
}

bool SourceHandsActive() {
    return SourceHandsSelected() && RuntimeFirstPersonHandsEnabled();
}

// Writes the engine's committed matrices back (when ours are still in place)
// and forgets the track.
void RestoreScreenParticlePose(SourceTrack& track);

void RestoreAndDropSourceTrack(SourceTrack& track, bool registered) {
    if (registered && track.screenParticle && track.screenMode == 2) {
        RestoreScreenParticlePose(track);
        track = {};
        ++g_sourceCounters.drops;
        return;
    }
    if (registered && !track.fresh) {
        const Matrix4 raw = ReadMatrix(static_cast<const unsigned char*>(track.model),
                                       kRenderModelMatrixOffset);
        if (MatricesBitwiseEqual(raw, track.expected) &&
            !MatricesBitwiseEqual(raw, track.current)) {
            WriteSourceMatrices(track, track.current, track.currentInverse);
            ++g_sourceCounters.restores;
        }
    }
    track = {};
    ++g_sourceCounters.drops;
}

void CollectSourceDirtyModels(void* world, std::vector<void*>& output, bool& overflowed) {
    g_sourceDirtyPending.clear();
    AcquireSRWLockExclusive(&g_sourceDirtyLock);
    g_sourceDirtyPending.swap(g_sourceDirty);
    overflowed = g_sourceDirtyOverflowed;
    g_sourceDirtyOverflowed = false;
    ReleaseSRWLockExclusive(&g_sourceDirtyLock);

    // Models of another world wait for that world's flush.
    g_sourceDirtyDeferred.clear();
    output.clear();
    for (const SourceDirtyEntry& entry : g_sourceDirtyPending) {
        if (entry.world == world) {
            output.push_back(entry.model);
        } else if (entry.world != nullptr &&
                   entry.deferrals < kSourceMaximumDirtyDeferrals) {
            g_sourceDirtyDeferred.push_back({entry.model, entry.world,
                                             entry.deferrals + 1});
        }
    }
    std::sort(output.begin(), output.end());
    output.erase(std::unique(output.begin(), output.end()), output.end());
    g_sourceCounters.foreignWorldDirty += g_sourceDirtyDeferred.size();
    if (!g_sourceDirtyDeferred.empty()) {
        AcquireSRWLockExclusive(&g_sourceDirtyLock);
        for (const SourceDirtyEntry& entry : g_sourceDirtyDeferred) {
            if (g_sourceDirty.size() < kSourceDirtyCapacity) {
                g_sourceDirty.push_back(entry);
            }
        }
        ReleaseSRWLockExclusive(&g_sourceDirtyLock);
    }
}

bool ResolveSourceWorldView(void* world, SourceWorldView& view) {
    view.world = world;
    view.models = nullptr;
    void* const* models = nullptr;
    if (!IsReadableMemory(static_cast<unsigned char*>(world) + kRenderWorldModelArrayOffset,
                          sizeof(models))) {
        return false;
    }
    memcpy(&models, static_cast<unsigned char*>(world) + kRenderWorldModelArrayOffset,
           sizeof(models));
    std::uint32_t packedCount = 0;
    memcpy(&packedCount, static_cast<unsigned char*>(world) + kRenderWorldModelCountOffset,
           sizeof(packedCount));
    const std::uint32_t count =
        std::min<std::uint32_t>(packedCount & 0x00FFFFFFU, 0x10000U);
    if (count == 0 || !IsReadableMemory(models, sizeof(void*) * count)) {
        return false;
    }
    view.models = models;
    view.modelCount = count;
    return true;
}

// Same test as IsPlayerDepthHackObject without the VirtualQuery; only used on
// models known to be alive (registered or dirtied this tick).
bool SourceModelIsFirstPerson(const void* model) {
    float depthHack = 0.0f;
    memcpy(&depthHack, static_cast<const unsigned char*>(model) + kRenderModelDepthHackOffset,
           sizeof(depthHack));
    return std::isfinite(depthHack) && depthHack > 0.0f && depthHack < 100.0f;
}

bool IsSourceExactModelType(const void* model, std::uintptr_t& vtable) {
    memcpy(&vtable, model, sizeof(vtable));
    return vtable == g_executableBase + g_layout->renderModelStaticVtable.rva ||
           vtable == g_executableBase + g_layout->skinnedModelVtable.rva;
}

// A model is only tracked once it commits a second time within this many
// flushes. Level loads commit every model once; without this they would fill
// the track table for a few ticks and push moving models out.
constexpr std::size_t kSourcePendingCapacity = 16384;
constexpr std::uint64_t kSourcePendingWindowFlushes = 120;

struct SourcePendingEntry {
    const void* model = nullptr;
    std::uint64_t flush = 0;
};

std::array<SourcePendingEntry, kSourcePendingCapacity> g_sourcePending{};
std::uint64_t g_sourceFlushSerial = 0;

// Returns true when the model has committed before within the window.
bool SourceModelCommittedRecently(const void* model) {
    SourcePendingEntry& entry =
        g_sourcePending[SourceTrackHash(model) & (kSourcePendingCapacity - 1)];
    const bool recent = entry.model == model &&
                        g_sourceFlushSerial - entry.flush <= kSourcePendingWindowFlushes;
    entry.model = model;
    entry.flush = g_sourceFlushSerial;
    return recent;
}

SourceTrack* RegisterSourceDirtyModel(const SourceWorldView& view, void* model,
                                      bool worldActive, bool handsActive) {
    SourceTrack* existing = FindSourceTrack(model);
    if (existing != nullptr) {
        existing->dirty = true;
        return existing;
    }
    if (!SourceModelCommittedRecently(model)) {
        ++g_sourceCounters.firstCommits;
        return nullptr;
    }
    if (!IsReadableMemory(model, kRenderModelSize)) {
        return nullptr;
    }
    std::uint16_t handle = 0;
    memcpy(&handle, static_cast<unsigned char*>(model) + kRenderModelHandleOffset,
           sizeof(handle));
    if (!SourceModelRegistered(view, model, handle)) {
        ++g_sourceCounters.ineligible;
        return nullptr;
    }
    const void* owner = nullptr;
    const void* modelAsset = nullptr;
    std::uintptr_t vtable = 0;
    bool hands = false;
    if (SourceModelIsFirstPerson(model)) {
        // First-person (depth-hacked) models follow the predicted camera
        // instead of being interpolated between ticks.
        if (!handsActive || !IsSourceExactModelType(model, vtable)) {
            ++g_sourceCounters.ineligible;
            return nullptr;
        }
        hands = true;
    } else {
        bool cinematic = false;
        if (!worldActive ||
            !IsEligibleWorldRenderModel(model, owner, vtable, modelAsset, cinematic)) {
            ++g_sourceCounters.ineligible;
            return nullptr;
        }
    }
    SourceTrack* track = CreateSourceTrack(model);
    if (track == nullptr) {
        ++g_sourceCounters.capacityMisses;
        return nullptr;
    }
    track->world = view.world;
    track->handle = handle;
    track->vtable = vtable;
    track->owner = owner;
    track->modelAsset = modelAsset;
    track->fresh = true;
    track->dirty = true;
    track->hands = hands;
    track->assemblyPart =
        static_cast<const unsigned char*>(model)[kRenderModelAssemblyPartOffset] == 1;
    ++g_sourceCounters.tracksCreated;
    if (hands) {
        ++g_sourceCounters.handsTracksCreated;
    }
    return track;
}

void RegisterSourceDirtyModels(const SourceWorldView& view,
                               const std::vector<void*>& dirty,
                               bool worldActive, bool handsActive) {
    for (void* model : dirty) {
        if (SourceModelIsFirstPerson(model)) {
            ++g_sourceCounters.handsDirty;
        }
        if (RegisterSourceDirtyModel(view, model, worldActive, handsActive) == nullptr) {
            continue;
        }
        // The flush commits the linked model with its owner's flags without
        // a MarkDirty of its own, so it is offered here as a candidate. A
        // linked model the engine did not recommit only produces a hold.
        void* linked = nullptr;
        memcpy(&linked, static_cast<unsigned char*>(model) + kRenderModelLinkedModelOffset,
               sizeof(linked));
        if (linked == nullptr || linked == model) {
            continue;
        }
        ++g_sourceCounters.linkedCandidates;
        const bool known = FindSourceTrack(linked) != nullptr;
        if (RegisterSourceDirtyModel(view, linked, worldActive, handsActive) != nullptr &&
            !known) {
            ++g_sourceCounters.linkedTracksCreated;
        }
    }
}

// Returns false when the pair must not be blended (interval, rigidity, jump).
bool SourcePairBlendable(const SourceTrack& track) {
    const double interval = track.currentTime - track.previousTime;
    if (!(interval > kTimeEpsilon) || interval > kMaximumWorldStateInterval) {
        ++g_sourceCounters.intervalSnaps;
        return false;
    }
    Transform previousTransform{};
    Transform currentTransform{};
    double previousScale = 1.0;
    double currentScale = 1.0;
    bool previousReflected = false;
    bool currentReflected = false;
    if (!ReadWorldTransform(track.previous, previousTransform, previousScale,
                            previousReflected) ||
        !ReadWorldTransform(track.current, currentTransform, currentScale,
                            currentReflected) ||
        previousReflected != currentReflected) {
        ++g_sourceCounters.nonRigid;
        return false;
    }
    if (PositionDistance(previousTransform, currentTransform) > kMaximumWorldPositionJump ||
        RotationDistanceDegrees(previousTransform, currentTransform) >
            kMaximumWorldRotationJumpDegrees ||
        currentScale / previousScale > 1.10 || previousScale / currentScale > 1.10) {
        ++g_sourceCounters.jumpSnaps;
        return false;
    }
    return true;
}

void UpdateSourceTrack(SourceTrack& track, const PresentationContext& context,
                       std::uint64_t& writes) {
    auto* bytes = static_cast<unsigned char*>(track.model);
    const Matrix4 raw = ReadMatrix(bytes, kRenderModelMatrixOffset);
    const bool committed = track.dirty || track.fresh ||
                           !MatricesBitwiseEqual(raw, track.expected);
    track.dirty = false;
    track.lastFlushSerial = context.serial;

    if (track.fresh) {
        track.fresh = false;
        track.previous = raw;
        track.current = raw;
        track.currentInverse = ReadMatrix(bytes, kRenderModelInverseMatrixOffset);
        track.expected = raw;
        track.previousTime = context.simulationTime;
        track.currentTime = context.simulationTime;
        track.hasPair = false;
        track.idleTicks = 0;
        return;
    }

    if (context.simulationTime < track.currentTime - kTimeEpsilon) {
        // Time went backwards (load or restart): start over from what the
        // model holds now.
        if (committed) {
            track.current = raw;
            track.currentInverse = ReadMatrix(bytes, kRenderModelInverseMatrixOffset);
        }
        track.previous = track.current;
        track.previousTime = context.simulationTime;
        track.currentTime = context.simulationTime;
        track.hasPair = false;
        ++g_sourceCounters.timeResets;
    } else if (context.simulationTime > track.currentTime + kTimeEpsilon) {
        track.previous = track.current;
        track.previousTime = track.currentTime;
        if (committed) {
            track.current = raw;
            track.currentInverse = ReadMatrix(bytes, kRenderModelInverseMatrixOffset);
            track.idleTicks = 0;
            ++g_sourceCounters.samples;
        } else {
            // Not committed this tick: the entity's committed state is still
            // the last committed matrix.
            ++track.idleTicks;
            ++g_sourceCounters.holds;
        }
        track.currentTime = context.simulationTime;
        track.hasPair = true;
    } else if (committed && !MatricesBitwiseEqual(raw, track.current)) {
        // A second commit for the same simulation time is a discontinuity.
        track.current = raw;
        track.currentInverse = ReadMatrix(bytes, kRenderModelInverseMatrixOffset);
        track.previous = raw;
        track.hasPair = false;
        track.idleTicks = 0;
        ++g_sourceCounters.sameTimeSnaps;
    }
    if (committed) {
        track.expected = raw;
    }

    Matrix4 output = track.current;
    Matrix4 outputInverse = track.currentInverse;
    bool blended = false;
    if (track.hasPair) {
        if (!SourcePairBlendable(track)) {
            track.hasPair = false;
        } else {
            const double interval = track.currentTime - track.previousTime;
            const double targetTime = Clamp(context.scaledTime, track.previousTime,
                                            track.currentTime + kNativeSimulationStep);
            const double alpha = (targetTime - track.previousTime) / interval;
            Matrix4 target{};
            Matrix4 targetInverse{};
            if (InterpolateWorldMatrices(track.previous, track.current, alpha, target) &&
                InvertAffineTransform(target, targetInverse) &&
                WorldMatricesDiffer(target, track.current)) {
                output = target;
                outputInverse = targetInverse;
                blended = true;
            }
        }
    }

    // The model currently holds `raw`. Write only when the presentation
    // matrix differs from it.
    if (!MatricesBitwiseEqual(raw, output)) {
        WriteSourceMatrices(track, output, outputInverse);
        ++writes;
        if (blended) {
            ++g_sourceCounters.writes;
        } else {
            ++g_sourceCounters.restores;
        }
    }

    if (!blended && track.idleTicks >= kSourceIdleTicksBeforeDrop) {
        // The model holds its committed matrix; nothing remains to restore.
        track = {};
        ++g_sourceCounters.drops;
    }
}

// First-person models: the committed matrix is attached to the raw camera of
// the last tick; the camera-correction delta published by the view-copy hook
// re-attaches it to the predicted camera, exactly as the per-draw path did.
// The cull job then copies last frame's corrected matrix into +0x60.
void UpdateSourceHandsTrack(SourceTrack& track, const PresentationContext& context,
                            std::uint64_t& writes) {
    auto* bytes = static_cast<unsigned char*>(track.model);
    const Matrix4 raw = ReadMatrix(bytes, kRenderModelMatrixOffset);
    const bool committed = track.dirty || track.fresh ||
                           !MatricesBitwiseEqual(raw, track.expected);
    track.dirty = false;
    track.fresh = false;
    track.lastFlushSerial = context.serial;
    if (committed) {
        track.current = raw;
        track.currentInverse = ReadMatrix(bytes, kRenderModelInverseMatrixOffset);
        track.expected = raw;
    }

    Matrix4 output = track.current;
    Matrix4 outputInverse = track.currentInverse;
    RenderCorrectionState correction{};
    bool corrected = false;
    if (ReadRenderCorrection(correction)) {
        const Matrix4 candidate = MultiplyMatrices4(correction.currentDelta, track.current);
        const Matrix4 candidateInverse =
            MultiplyMatrices4(track.currentInverse, correction.currentInverseDelta);
        if (IsFinite(candidate) && IsFinite(candidateInverse)) {
            output = candidate;
            outputInverse = candidateInverse;
            corrected = true;
        }
    }
    if (!MatricesBitwiseEqual(raw, output)) {
        WriteSourceMatrices(track, output, outputInverse);
        ++writes;
        if (corrected) {
            ++g_sourceCounters.handsWrites;
        } else {
            ++g_sourceCounters.restores;
        }
    }
}

// Screen particles (Interpolation/ScreenParticleCorrection). A particle
// system flagged as a screen particle (flag 0x40 at +0x24; camera blood uses
// it) is placed every tick by 0x227190 at the game camera plus
// pm_screenParticleOffset along its forward axis, by writing that pose into its
// render model's +0x1860/+0x186C; the particles are emitted in world space and
// the model's +0x20 commits as identity. With the predicted camera they would
// lag the view by the prediction and snap every tick, and their motion vectors
// would follow the camera, so after the flush the model's +0x20/+0xA0 take the
// camera correction (predicted * inverse(tick)), exactly as the first-person
// hands do. 0x227190 is wrapped to collect the models of such systems.
constexpr std::uintptr_t kSteamParticleUpdateRva = 0x227190;
constexpr std::size_t kSteamParticleUpdateHookLength = 18;
constexpr unsigned char kSteamParticleUpdateBytes[kSteamParticleUpdateHookLength] = {
    0x48, 0x89, 0x74, 0x24, 0x10,
    0x57,
    0x48, 0x83, 0xEC, 0x60,
    0x41, 0x0F, 0xB6, 0x81, 0x54, 0x01, 0x00, 0x00,
};
constexpr std::size_t kParticleSystemModelOffset = 0x08;
constexpr std::size_t kParticleSystemFlagsOffset = 0x24;
constexpr unsigned char kParticleSystemScreenFlag = 0x40;
constexpr std::size_t kScreenParticleCapacity = 32;
using ParticleUpdateFn = std::uint64_t(__fastcall*)(void*, float, void*, void*);
ParticleUpdateFn g_originalParticleUpdate = nullptr;
std::atomic<int> g_screenParticleMode{3};
bool g_screenParticleHookInstalled = false;

struct ScreenParticleEntry {
    void* model = nullptr;
    std::uint64_t seenCounter = 0;
};
SRWLOCK g_screenParticleLock = SRWLOCK_INIT;
std::array<ScreenParticleEntry, kScreenParticleCapacity> g_screenParticles{};

void CorrectEmitterPoseNow(unsigned char* model, void* placementContext);

// Diagnostics for screen particles: where the placement puts the emitter
// relative to the raw (tick) and the predicted camera, how often, and on which
// thread, logged once a second while one is active.
SRWLOCK g_cameraOriginLock = SRWLOCK_INIT;
float g_rawCameraOrigin[3]{};
float g_outputCameraOrigin[3]{};
std::uint64_t g_cameraOriginSerial = 0;
Transform g_outputCamera{};
bool g_outputCameraValid = false;
Transform g_previousOutputCamera{};
bool g_previousOutputCameraValid = false;

void NoteCameraOrigins(const Transform& raw, const Transform& output) {
    AcquireSRWLockExclusive(&g_cameraOriginLock);
    g_rawCameraOrigin[0] = static_cast<float>(raw.origin.x);
    g_rawCameraOrigin[1] = static_cast<float>(raw.origin.y);
    g_rawCameraOrigin[2] = static_cast<float>(raw.origin.z);
    g_outputCameraOrigin[0] = static_cast<float>(output.origin.x);
    g_outputCameraOrigin[1] = static_cast<float>(output.origin.y);
    g_outputCameraOrigin[2] = static_cast<float>(output.origin.z);
    g_previousOutputCamera = g_outputCamera;
    g_previousOutputCameraValid = g_outputCameraValid;
    g_outputCamera = output;
    g_outputCameraValid = IsFinite(output);
    ++g_cameraOriginSerial;
    ReleaseSRWLockExclusive(&g_cameraOriginLock);
}

struct ScreenParticleDiagnostics {
    std::uint64_t windowStart = 0;
    std::uint64_t calls = 0;
    std::uint64_t distinctFrames = 0;
    std::uint64_t lastFrame = 0;
    double rawDistanceSum = 0.0;
    double outputDistanceSum = 0.0;
    double emitterStepSum = 0.0;
    float lastEmitter[3]{};
    DWORD thread = 0;
};
ScreenParticleDiagnostics g_screenParticleDiagnostics;
SRWLOCK g_screenParticleDiagnosticsLock = SRWLOCK_INIT;

void NoteScreenParticlePlacement(const unsigned char* model) {
    // Emitter = camera origin + forward * offset; compare the emitter with
    // both camera origins (the offset adds the same ~3.2 to either).
    float emitter[3]{};
    memcpy(emitter, model + 0x1860, sizeof(emitter));
    float raw[3]{};
    float output[3]{};
    std::uint64_t frame = 0;
    AcquireSRWLockShared(&g_cameraOriginLock);
    memcpy(raw, g_rawCameraOrigin, sizeof(raw));
    memcpy(output, g_outputCameraOrigin, sizeof(output));
    frame = g_cameraOriginSerial;
    ReleaseSRWLockShared(&g_cameraOriginLock);
    const auto distance = [](const float* a, const float* b) {
        const double dx = a[0] - b[0], dy = a[1] - b[1], dz = a[2] - b[2];
        return std::sqrt(dx * dx + dy * dy + dz * dz);
    };
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    const std::uint64_t now = ReadPerformanceCounter();
    AcquireSRWLockExclusive(&g_screenParticleDiagnosticsLock);
    ScreenParticleDiagnostics& d = g_screenParticleDiagnostics;
    if (d.windowStart == 0) {
        d.windowStart = now;
    }
    ++d.calls;
    if (frame != d.lastFrame) {
        ++d.distinctFrames;
        d.lastFrame = frame;
    }
    d.rawDistanceSum += distance(emitter, raw);
    d.outputDistanceSum += distance(emitter, output);
    d.emitterStepSum += distance(emitter, d.lastEmitter);
    memcpy(d.lastEmitter, emitter, sizeof(emitter));
    d.thread = GetCurrentThreadId();
    if (now - d.windowStart >= static_cast<std::uint64_t>(frequency.QuadPart)) {
        const double calls = static_cast<double>(d.calls);
        Log("Screen particles: %llu placements in %.2fs over %llu rendered frames on thread "
            "%lu; mean emitter distance to raw camera %.4f, to predicted camera %.4f, "
            "mean emitter step %.4f.",
            static_cast<unsigned long long>(d.calls),
            static_cast<double>(now - d.windowStart) / static_cast<double>(frequency.QuadPart),
            static_cast<unsigned long long>(d.distinctFrames), d.thread,
            d.rawDistanceSum / calls, d.outputDistanceSum / calls, d.emitterStepSum / calls);
        d = ScreenParticleDiagnostics{};
    }
    ReleaseSRWLockExclusive(&g_screenParticleDiagnosticsLock);
}

extern "C" std::uint64_t __fastcall HookParticleUpdate(void* system, float deltaTime,
                                                       void* third, void* fourth) {
    const std::uint64_t result = g_originalParticleUpdate(system, deltaTime, third, fourth);
    const auto* bytes = static_cast<const unsigned char*>(system);
    if ((bytes[kParticleSystemFlagsOffset] & kParticleSystemScreenFlag) == 0) {
        return result;
    }
    void* model = nullptr;
    memcpy(&model, bytes + kParticleSystemModelOffset, sizeof(model));
    if (model == nullptr) {
        return result;
    }
    NoteScreenParticlePlacement(static_cast<const unsigned char*>(model));
    if (g_screenParticleMode.load(std::memory_order_relaxed) >= 3 && SourceHandsActive()) {
        CorrectEmitterPoseNow(static_cast<unsigned char*>(model), fourth);
    }
    const std::uint64_t now = ReadPerformanceCounter();
    AcquireSRWLockExclusive(&g_screenParticleLock);
    ScreenParticleEntry* slot = nullptr;
    ScreenParticleEntry* oldest = &g_screenParticles[0];
    for (ScreenParticleEntry& entry : g_screenParticles) {
        if (entry.model == model) {
            slot = &entry;
            break;
        }
        if (entry.seenCounter < oldest->seenCounter) {
            oldest = &entry;
        }
    }
    if (slot == nullptr) {
        slot = oldest;
        slot->model = model;
    }
    slot->seenCounter = now;
    ReleaseSRWLockExclusive(&g_screenParticleLock);
    return result;
}

// True when the particle update placed this model as a screen particle within
// the last quarter second.
bool ScreenParticleSeenRecently(const void* model) {
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    const std::uint64_t now = ReadPerformanceCounter();
    bool seen = false;
    AcquireSRWLockShared(&g_screenParticleLock);
    for (const ScreenParticleEntry& entry : g_screenParticles) {
        if (entry.model == model) {
            seen = now - entry.seenCounter < static_cast<std::uint64_t>(frequency.QuadPart / 4);
            break;
        }
    }
    ReleaseSRWLockShared(&g_screenParticleLock);
    return seen;
}

// Creates hands-style tracks for this world's recently placed screen
// particles (the flush only offers models that were marked dirty).
void RegisterScreenParticleModels(const SourceWorldView& view) {
    void* models[kScreenParticleCapacity]{};
    std::size_t count = 0;
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    const std::uint64_t now = ReadPerformanceCounter();
    AcquireSRWLockShared(&g_screenParticleLock);
    for (const ScreenParticleEntry& entry : g_screenParticles) {
        if (entry.model != nullptr &&
            now - entry.seenCounter < static_cast<std::uint64_t>(frequency.QuadPart / 4)) {
            models[count++] = entry.model;
        }
    }
    ReleaseSRWLockShared(&g_screenParticleLock);
    for (std::size_t index = 0; index < count; ++index) {
        void* model = models[index];
        SourceTrack* existing = FindSourceTrack(model);
        if (existing != nullptr) {
            if (!existing->screenParticle) {
                // Previously tracked as something else: hand it over.
                RestoreAndDropSourceTrack(*existing, true);
            } else {
                continue;
            }
        }
        if (!IsReadableMemory(model, kRenderModelSize)) {
            continue;
        }
        std::uint16_t handle = 0;
        memcpy(&handle, static_cast<unsigned char*>(model) + kRenderModelHandleOffset,
               sizeof(handle));
        if (!SourceModelRegistered(view, model, handle)) {
            continue;  // Another world, or not registered yet.
        }
        SourceTrack* track = CreateSourceTrack(model);
        if (track == nullptr) {
            ++g_sourceCounters.capacityMisses;
            continue;
        }
        std::uintptr_t vtable = 0;
        memcpy(&vtable, model, sizeof(vtable));
        track->world = view.world;
        track->handle = handle;
        track->vtable = vtable;
        track->fresh = true;
        track->dirty = true;
        track->hands = true;
        track->screenParticle = true;
        track->screenMode = g_screenParticleMode.load(std::memory_order_relaxed);
        static bool logged = false;
        if (!logged) {
            logged = true;
            Log("Screen particles: correcting a screen-particle model to the predicted "
                "camera (first seen at serial %llu).",
                static_cast<unsigned long long>(g_presentationSerial.load()));
        }
    }
}

constexpr std::size_t kRenderModelOriginOffset = 0x1860;
constexpr std::size_t kRenderModelAxisOffset = 0x186C;

void ReadEmitterPose(const unsigned char* model, std::array<float, 12>& pose) {
    memcpy(pose.data(), model + kRenderModelOriginOffset, 3 * sizeof(float));
    memcpy(pose.data() + 3, model + kRenderModelAxisOffset, 9 * sizeof(float));
}

void WriteEmitterPose(unsigned char* model, const std::array<float, 12>& pose) {
    memcpy(model + kRenderModelOriginOffset, pose.data(), 3 * sizeof(float));
    memcpy(model + kRenderModelAxisOffset, pose.data() + 3, 9 * sizeof(float));
}

void RestoreScreenParticlePose(SourceTrack& track) {
    auto* bytes = static_cast<unsigned char*>(track.model);
    std::array<float, 12> raw{};
    ReadEmitterPose(bytes, raw);
    if (raw == track.poseExpected && raw != track.poseBase) {
        WriteEmitterPose(bytes, track.poseBase);
        ++g_sourceCounters.restores;
    }
}

// Mode 2: moves the particle system's emitter pose (origin/axis, from which the
// particle geometry is built) by the camera correction. The pose is laid out
// as Commit (0x1095F0) uses it: matrix column j is axis row j, column 3 the
// origin.
void UpdateScreenParticlePoseTrack(SourceTrack& track, std::uint64_t& writes) {
    auto* bytes = static_cast<unsigned char*>(track.model);
    std::array<float, 12> raw{};
    ReadEmitterPose(bytes, raw);
    if (track.fresh || raw != track.poseExpected) {
        track.poseBase = raw;  // placed again by the particle update
    }
    track.fresh = false;
    track.dirty = false;
    RenderCorrectionState correction{};
    if (!ReadRenderCorrection(correction)) {
        if (raw != track.poseBase) {
            WriteEmitterPose(bytes, track.poseBase);
            ++g_sourceCounters.restores;
        }
        track.poseExpected = track.poseBase;
        return;
    }
    const std::array<float, 12>& base = track.poseBase;
    Matrix4 pose{};
    for (int row = 0; row < 3; ++row) {
        for (int column = 0; column < 3; ++column) {
            pose.values[row * 4 + column] = base[3 + column * 3 + row];
        }
        pose.values[row * 4 + 3] = base[row];
    }
    pose.values[15] = 1.0f;
    const Matrix4 corrected = MultiplyMatrices4(correction.currentDelta, pose);
    if (!IsFinite(corrected)) {
        return;
    }
    std::array<float, 12> output{};
    for (int row = 0; row < 3; ++row) {
        output[row] = corrected.values[row * 4 + 3];
        for (int column = 0; column < 3; ++column) {
            output[3 + column * 3 + row] = corrected.values[row * 4 + column];
        }
    }
    if (output != raw) {
        WriteEmitterPose(bytes, output);
        ++writes;
        ++g_sourceCounters.handsWrites;
    }
    track.poseExpected = output;
}

// Mode 3: the placement (0x227190) runs once per rendered frame on a job
// thread and rewrites the emitter pose from the unpredicted camera, after the
// flush, so the pose is corrected right after the placement instead.
struct ScreenParticlePlacement {
    void* model = nullptr;
    Transform used{};
    std::array<float, 12> base{};
    std::array<float, 12> written{};
};
SRWLOCK g_screenPlacementLock = SRWLOCK_INIT;
std::array<ScreenParticlePlacement, 8> g_screenPlacements{};

bool WriteCorrectedEmitterPose(unsigned char* model, const std::array<float, 12>& base,
                               const Matrix4& delta, std::array<float, 12>* written = nullptr);

// The placement reads its camera from [context+0x128] (origin via vtable
// +0x20, axis via +0x30; 0x21DC00) on the same call, and it runs on a job
// thread at a point in the frame that does not line up with the camera hook,
// so a published "predicted * inverse(raw)" delta can belong to another tick.
// Instead the pose is re-expressed relative to the camera the placement used
// and put on the latest predicted camera: pose' = predicted * inverse(used) * pose.
void CorrectEmitterPoseNow(unsigned char* model, void* placementContext) {
    if (placementContext == nullptr) {
        return;
    }
    void* camera = nullptr;
    memcpy(&camera, static_cast<unsigned char*>(placementContext) + 0x128, sizeof(camera));
    if (camera == nullptr) {
        return;
    }
    using VectorGetter = const float*(__fastcall*)(void*);
    void** vtable = *static_cast<void***>(camera);
    const float* usedOrigin = reinterpret_cast<VectorGetter>(vtable[0x20 / sizeof(void*)])(camera);
    const float* usedAxis = reinterpret_cast<VectorGetter>(vtable[0x30 / sizeof(void*)])(camera);
    if (usedOrigin == nullptr || usedAxis == nullptr) {
        return;
    }
    Transform used{};
    used.origin = {usedOrigin[0], usedOrigin[1], usedOrigin[2]};
    memcpy(used.axis, usedAxis, sizeof(used.axis));
    Transform predicted{};
    Transform previousPredicted{};
    bool havePredicted = false;
    bool havePrevious = false;
    AcquireSRWLockShared(&g_cameraOriginLock);
    predicted = g_outputCamera;
    havePredicted = g_outputCameraValid;
    previousPredicted = g_previousOutputCamera;
    havePrevious = g_previousOutputCameraValid;
    ReleaseSRWLockShared(&g_cameraOriginLock);
    Matrix4 delta{};
    Matrix4 inverseDelta{};
    if (!havePredicted || !BuildCameraCorrection(used, predicted, delta, inverseDelta)) {
        return;
    }
    // Mode 4: the frame this placement is drawn in has not published its
    // camera yet, so extrapolate one frame: step = latest * inverse(previous),
    // next = step * latest, delta = next * inverse(used) = step * delta.
    if (g_screenParticleMode.load(std::memory_order_relaxed) == 4 && havePrevious) {
        Matrix4 step{};
        Matrix4 inverseStep{};
        if (BuildCameraCorrection(previousPredicted, predicted, step, inverseStep)) {
            const Matrix4 extrapolated = MultiplyMatrices4(step, delta);
            if (IsFinite(extrapolated)) {
                delta = extrapolated;
            }
        }
    }
    std::array<float, 12> base{};
    ReadEmitterPose(model, base);
    std::array<float, 12> written = base;
    WriteCorrectedEmitterPose(model, base, delta, &written);
    AcquireSRWLockExclusive(&g_screenPlacementLock);
    ScreenParticlePlacement* slot = nullptr;
    for (ScreenParticlePlacement& placement : g_screenPlacements) {
        if (placement.model == model) {
            slot = &placement;
            break;
        }
        if (slot == nullptr && placement.model == nullptr) {
            slot = &placement;
        }
    }
    if (slot == nullptr) {
        slot = &g_screenPlacements[0];
    }
    slot->model = model;
    slot->used = used;
    slot->base = base;
    slot->written = written;
    ReleaseSRWLockExclusive(&g_screenPlacementLock);
}

// Applies delta to an emitter pose laid out as Commit (0x1095F0) uses it and
// writes it.
bool WriteCorrectedEmitterPose(unsigned char* model, const std::array<float, 12>& base,
                               const Matrix4& delta, std::array<float, 12>* written) {
    Matrix4 pose{};
    for (int row = 0; row < 3; ++row) {
        for (int column = 0; column < 3; ++column) {
            pose.values[row * 4 + column] = base[3 + column * 3 + row];
        }
        pose.values[row * 4 + 3] = base[row];
    }
    pose.values[15] = 1.0f;
    const Matrix4 corrected = MultiplyMatrices4(delta, pose);
    if (!IsFinite(corrected)) {
        return false;
    }
    std::array<float, 12> output{};
    for (int row = 0; row < 3; ++row) {
        output[row] = corrected.values[row * 4 + 3];
        for (int column = 0; column < 3; ++column) {
            output[3 + column * 3 + row] = corrected.values[row * 4 + column];
        }
    }
    WriteEmitterPose(model, output);
    if (written != nullptr) {
        *written = output;
    }
    return true;
}

// The placement runs before the camera hook of the frame it is drawn in, so a
// pose put on the latest predicted camera trails by one frame. The camera hook
// calls this after publishing the new predicted camera: each screen particle
// placed since is moved again from the camera it was placed with onto the
// camera now being rendered, unless the engine has placed it again meanwhile.
void RefreshScreenParticlesForCamera(const Transform& predicted) {
    if (g_screenParticleMode.load(std::memory_order_relaxed) < 3 || !SourceHandsActive()) {
        return;
    }
    AcquireSRWLockExclusive(&g_screenPlacementLock);
    for (ScreenParticlePlacement& placement : g_screenPlacements) {
        if (placement.model == nullptr) {
            continue;
        }
        auto* model = static_cast<unsigned char*>(placement.model);
        std::array<float, 12> current{};
        ReadEmitterPose(model, current);
        if (current != placement.written) {
            placement = ScreenParticlePlacement{};  // placed again, or reused
            continue;
        }
        Matrix4 delta{};
        Matrix4 inverseDelta{};
        if (BuildCameraCorrection(placement.used, predicted, delta, inverseDelta)) {
            WriteCorrectedEmitterPose(model, placement.base, delta, &placement.written);
        }
    }
    ReleaseSRWLockExclusive(&g_screenPlacementLock);
}

// Ctrl+Alt+F10 cycles ScreenParticleCorrection: off, model matrix, emitter
// pose after the flush, emitter pose at placement.
void CycleScreenParticleMode() {
    if (!g_screenParticleHookInstalled) {
        PlayToggleCue(ToggleCue::Unavailable);
        return;
    }
    const int next = (g_screenParticleMode.load(std::memory_order_relaxed) + 1) % 5;
    g_screenParticleMode.store(next, std::memory_order_relaxed);
    if (next == 0) {
        PlayToggleCue(ToggleCue::Off);
    } else {
        PlayProfileCue(next);
    }
    static const char* const kNames[] = {"off", "model matrix (+0x20)",
                                         "emitter pose after the flush",
                                         "emitter pose at placement",
                                         "emitter pose at placement, extrapolated one frame"};
    Log("Ctrl+Alt+F10: screen-particle correction %s.", kNames[next]);
}

bool InstallScreenParticleHook() {
    if (g_screenParticleMode.load(std::memory_order_relaxed) == 0 ||
        g_layout != &kSteamLayout) {
        return false;
    }
    void* original = nullptr;
    if (!InstallInlineHook(kSteamParticleUpdateRva, kSteamParticleUpdateBytes,
                           kSteamParticleUpdateHookLength,
                           reinterpret_cast<const void*>(&HookParticleUpdate), &original,
                           "screen-particle update")) {
        g_screenParticleMode.store(0, std::memory_order_relaxed);
        return false;
    }
    g_originalParticleUpdate = reinterpret_cast<ParticleUpdateFn>(original);
    g_screenParticleHookInstalled = true;
    return true;
}

void ProcessSourceLevelTracks(void* world, const PresentationContext& context,
                              bool hasContext, const std::vector<void*>& dirty) {
    SourceWorldView view{};
    if (!ResolveSourceWorldView(world, view)) {
        // Without the model array nothing can be validated; forget this
        // world's tracks without touching their models.
        for (std::uint32_t index : g_sourceActive) {
            SourceTrack& track = g_sourceTracks[index];
            if (track.model != nullptr && track.world == world) {
                track = {};
                ++g_sourceCounters.deadTracks;
            }
        }
        CompactSourceTrackList();
        return;
    }
    const bool worldActive = hasContext && SourceLevelWritesActive();
    const bool handsActive = hasContext && SourceHandsActive();

    ++g_sourceFlushSerial;
    RegisterSourceDirtyModels(view, dirty, worldActive, handsActive);
    if (handsActive && (g_screenParticleMode.load(std::memory_order_relaxed) == 1 ||
                        g_screenParticleMode.load(std::memory_order_relaxed) == 2)) {
        RegisterScreenParticleModels(view);
    }
    std::uint64_t writes = 0;
    std::uint64_t active = 0;
    std::uint64_t activeParts = 0;
    std::uint64_t activeHands = 0;
    for (std::uint32_t index : g_sourceActive) {
        SourceTrack& track = g_sourceTracks[index];
        if (track.model == nullptr) {
            continue;
        }
        if (track.world != world) {
            if (hasContext && track.lastFlushSerial != 0 &&
                track.lastFlushSerial + kSourceStaleFrames < context.serial) {
                track = {};
                ++g_sourceCounters.staleTracks;
            }
            continue;
        }
        std::uintptr_t vtable = 0;
        if (!SourceModelRegistered(view, track.model, track.handle) ||
            (memcpy(&vtable, track.model, sizeof(vtable)), vtable != track.vtable)) {
            // Deleted or replaced in this flush: never write to it again.
            track = {};
            ++g_sourceCounters.deadTracks;
            continue;
        }
        if (track.screenParticle &&
            (!ScreenParticleSeenRecently(track.model) ||
             track.screenMode != g_screenParticleMode.load(std::memory_order_relaxed))) {
            // The particle system stopped or the model went back to the pool.
            RestoreAndDropSourceTrack(track, true);
            continue;
        }
        if (!track.screenParticle && SourceModelIsFirstPerson(track.model) != track.hands) {
            // Switched between first-person and world rendering.
            RestoreAndDropSourceTrack(track, true);
            ++g_sourceCounters.ineligible;
            continue;
        }
        if (!(track.hands ? handsActive : worldActive)) {
            RestoreAndDropSourceTrack(track, true);
            continue;
        }
        // A lost dirty notification (overflow) is still caught by the
        // expected-matrix comparison in the update.
        if (track.screenParticle && track.screenMode == 2) {
            UpdateScreenParticlePoseTrack(track, writes);
        } else if (track.hands) {
            UpdateSourceHandsTrack(track, context, writes);
        } else {
            UpdateSourceTrack(track, context, writes);
        }
        if (track.model != nullptr) {
            ++active;
            if (track.assemblyPart) {
                ++activeParts;
            }
            if (track.hands) {
                ++activeHands;
            }
        }
    }
    CompactSourceTrackList();
    g_sourceCounters.activeTracks = active;
    g_sourceCounters.activePartTracks = activeParts;
    g_sourceCounters.activeHandsTracks = activeHands;
    if (writes != 0) {
        if (g_enableInterpolationAbProbe) {
            g_abSourceWrites.fetch_add(writes, std::memory_order_relaxed);
        }
        int expected = 0;
        if (g_worldTransformRenderState.compare_exchange_strong(expected, 2)) {
            Log("Applied source-level transforms after the render-world flush "
                "(presentation serial %llu).",
                static_cast<unsigned long long>(context.serial));
        }
    }
}

SourceLevelDiagnosticsSnapshot CaptureSourceLevelDiagnostics(std::uint64_t serial) {
    SourceLevelDiagnosticsSnapshot snapshot{};
    snapshot.serial = serial;
    snapshot.markDirtyCalls =
        g_sourceDiagnostics.markDirtyCalls.load(std::memory_order_relaxed);
    snapshot.markDirtyTransform =
        g_sourceDiagnostics.markDirtyTransform.load(std::memory_order_relaxed);
    snapshot.markDirtyOffFlushThread =
        g_sourceDiagnostics.markDirtyOffFlushThread.load(std::memory_order_relaxed);
    snapshot.dirtyOverflows =
        g_sourceDiagnostics.dirtyOverflows.load(std::memory_order_relaxed);
    snapshot.rendererFirstAfterFlush =
        g_sourceDiagnostics.rendererFirstAfterFlush.load(std::memory_order_relaxed);
    snapshot.rendererFirstBeforeFlush =
        g_sourceDiagnostics.rendererFirstBeforeFlush.load(std::memory_order_relaxed);
    snapshot.rendererCallsDuringFlush =
        g_sourceDiagnostics.rendererCallsDuringFlush.load(std::memory_order_relaxed);
    snapshot.assemblyMarkDirty =
        g_sourceDiagnostics.assemblyMarkDirty.load(std::memory_order_relaxed);
    snapshot.assemblyMarkDirtyTransform =
        g_sourceDiagnostics.assemblyMarkDirtyTransform.load(std::memory_order_relaxed);
    snapshot.partMarkDirtyTransform =
        g_sourceDiagnostics.partMarkDirtyTransform.load(std::memory_order_relaxed);
    snapshot.dirtyLockContended =
        g_sourceDiagnostics.dirtyLockContended.load(std::memory_order_relaxed);
    snapshot.poseLockContended = g_skeletalLockContended.load(std::memory_order_relaxed);
    snapshot.plain = g_sourceCounters;
    return snapshot;
}

void MaybeLogSourceLevelDiagnostics(std::uint64_t serial) {
    LARGE_INTEGER frequency{};
    LARGE_INTEGER now{};
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 ||
        !QueryPerformanceCounter(&now)) {
        return;
    }
    const std::uint64_t counter = static_cast<std::uint64_t>(now.QuadPart);
    if (!g_sourceHasLogSnapshot) {
        g_sourceLastLogSnapshot = CaptureSourceLevelDiagnostics(serial);
        g_sourceLastLogCounter = counter;
        g_sourceHasLogSnapshot = true;
        return;
    }
    if (counter - g_sourceLastLogCounter <
        static_cast<std::uint64_t>(frequency.QuadPart)) {
        return;
    }
    const SourceLevelDiagnosticsSnapshot current = CaptureSourceLevelDiagnostics(serial);
    const SourceLevelDiagnosticsSnapshot& last = g_sourceLastLogSnapshot;
    const auto delta = [](std::uint64_t later, std::uint64_t earlier) {
        return static_cast<unsigned long long>(CounterDelta(later, earlier));
    };
    const double seconds = static_cast<double>(counter - g_sourceLastLogCounter) /
                           static_cast<double>(frequency.QuadPart);
    const double ticksPerMillisecond = static_cast<double>(frequency.QuadPart) / 1000.0;
    const unsigned long long frames = delta(current.serial, last.serial);
    const unsigned long long flushes =
        delta(current.plain.flushCalls, last.plain.flushCalls);
    const double perFlush = flushes != 0 ? 1.0 / static_cast<double>(flushes) : 0.0;
    Log("Source-level %.2fs: frames=%llu flushes=%llu (%.2f/frame, with tick=%llu) "
        "markDirty=%llu transform=%llu offFlushThread=%llu uniqueDirty/flush=%.1f "
        "foreignWorld=%llu overflows=%llu lockContended=%llu poseLockContended=%llu; renderer first call after-flush=%llu "
        "before-flush=%llu during-flush=%llu; threads flush=%lu renderer=%lu; per flush "
        "engine=%.3fms plugin=%.3fms; tracks active=%llu created=%llu samples=%llu "
        "holds=%llu writes=%llu restores=%llu drops=%llu dead=%llu stale=%llu "
        "ineligible=%llu capMiss=%llu snaps[jump=%llu interval=%llu sameTime=%llu "
        "timeReset=%llu nonRigid=%llu]; assemblies markDirty=%llu transform=%llu "
        "partTransform=%llu partTracks=%llu linked candidates=%llu created=%llu; "
        "hands dirty=%llu created=%llu tracks=%llu writes=%llu; firstCommits=%llu; "
        "per-draw hook %s; "
        "writes %s.",
        seconds, frames, flushes,
        frames != 0 ? static_cast<double>(flushes) / static_cast<double>(frames) : 0.0,
        delta(current.plain.flushesWithTick, last.plain.flushesWithTick),
        delta(current.markDirtyCalls, last.markDirtyCalls),
        delta(current.markDirtyTransform, last.markDirtyTransform),
        delta(current.markDirtyOffFlushThread, last.markDirtyOffFlushThread),
        static_cast<double>(delta(current.plain.uniqueDirty, last.plain.uniqueDirty)) *
            perFlush,
        delta(current.plain.foreignWorldDirty, last.plain.foreignWorldDirty),
        delta(current.dirtyOverflows, last.dirtyOverflows),
        delta(current.dirtyLockContended, last.dirtyLockContended),
        delta(current.poseLockContended, last.poseLockContended),
        delta(current.rendererFirstAfterFlush, last.rendererFirstAfterFlush),
        delta(current.rendererFirstBeforeFlush, last.rendererFirstBeforeFlush),
        delta(current.rendererCallsDuringFlush, last.rendererCallsDuringFlush),
        static_cast<unsigned long>(g_sourceFlushThreadId.load(std::memory_order_relaxed)),
        static_cast<unsigned long>(g_sourceRendererThreadId.load(std::memory_order_relaxed)),
        static_cast<double>(delta(current.plain.flushEngineTicks,
                                  last.plain.flushEngineTicks)) /
            ticksPerMillisecond * perFlush,
        static_cast<double>(delta(current.plain.flushPluginTicks,
                                  last.plain.flushPluginTicks)) /
            ticksPerMillisecond * perFlush,
        static_cast<unsigned long long>(current.plain.activeTracks),
        delta(current.plain.tracksCreated, last.plain.tracksCreated),
        delta(current.plain.samples, last.plain.samples),
        delta(current.plain.holds, last.plain.holds),
        delta(current.plain.writes, last.plain.writes),
        delta(current.plain.restores, last.plain.restores),
        delta(current.plain.drops, last.plain.drops),
        delta(current.plain.deadTracks, last.plain.deadTracks),
        delta(current.plain.staleTracks, last.plain.staleTracks),
        delta(current.plain.ineligible, last.plain.ineligible),
        delta(current.plain.capacityMisses, last.plain.capacityMisses),
        delta(current.plain.jumpSnaps, last.plain.jumpSnaps),
        delta(current.plain.intervalSnaps, last.plain.intervalSnaps),
        delta(current.plain.sameTimeSnaps, last.plain.sameTimeSnaps),
        delta(current.plain.timeResets, last.plain.timeResets),
        delta(current.plain.nonRigid, last.plain.nonRigid),
        delta(current.assemblyMarkDirty, last.assemblyMarkDirty),
        delta(current.assemblyMarkDirtyTransform, last.assemblyMarkDirtyTransform),
        delta(current.partMarkDirtyTransform, last.partMarkDirtyTransform),
        static_cast<unsigned long long>(current.plain.activePartTracks),
        delta(current.plain.linkedCandidates, last.plain.linkedCandidates),
        delta(current.plain.linkedTracksCreated, last.plain.linkedTracksCreated),
        delta(current.plain.handsDirty, last.plain.handsDirty),
        delta(current.plain.handsTracksCreated, last.plain.handsTracksCreated),
        static_cast<unsigned long long>(current.plain.activeHandsTracks),
        delta(current.plain.handsWrites, last.plain.handsWrites),
        delta(current.plain.firstCommits, last.plain.firstCommits),
        g_renderModelGpuCopyHookSkipped ? "not installed" :
            (g_renderModelGpuCopyTrampoline != nullptr ? "installed" : "off"),
        SourceLevelWritesActive() ? "active" :
            (g_sourceLevelWrites ? "configured but inactive" : "disabled (Phase A)"));
    g_sourceLastLogSnapshot = current;
    g_sourceLastLogCounter = counter;
}

extern "C" void __fastcall HookRenderModelMarkDirty(void* model, std::uintptr_t flags) {
    g_originalRenderModelMarkDirty(model, flags);
    g_sourceDiagnostics.markDirtyCalls.fetch_add(1, std::memory_order_relaxed);
    if ((flags & kRenderModelDirtyTransform) == 0) {
        return;
    }
    g_sourceDiagnostics.markDirtyTransform.fetch_add(1, std::memory_order_relaxed);
    if (static_cast<const unsigned char*>(model)[kRenderModelAssemblyPartOffset] == 1) {
        g_sourceDiagnostics.partMarkDirtyTransform.fetch_add(1, std::memory_order_relaxed);
    }
    if (GetCurrentThreadId() != g_sourceFlushThreadId.load(std::memory_order_relaxed)) {
        g_sourceDiagnostics.markDirtyOffFlushThread.fetch_add(
            1, std::memory_order_relaxed);
    }
    void* world = nullptr;
    memcpy(&world, static_cast<unsigned char*>(model) + kRenderModelWorldOffset,
           sizeof(world));
    if (!TryAcquireSRWLockExclusive(&g_sourceDirtyLock)) {
        g_sourceDiagnostics.dirtyLockContended.fetch_add(1, std::memory_order_relaxed);
        AcquireSRWLockExclusive(&g_sourceDirtyLock);
    }
    if (g_sourceDirty.size() < kSourceDirtyCapacity) {
        g_sourceDirty.push_back({model, world, 0});
    } else if (!g_sourceDirtyOverflowed) {
        g_sourceDirtyOverflowed = true;
        g_sourceDiagnostics.dirtyOverflows.fetch_add(1, std::memory_order_relaxed);
    }
    ReleaseSRWLockExclusive(&g_sourceDirtyLock);
}

RenderModelMarkDirtyFn g_originalAssemblyMarkDirty = nullptr;

extern "C" void __fastcall HookAssemblyMarkDirty(void* model, std::uintptr_t flags) {
    // The original propagates to every part through the part's (hooked)
    // static MarkDirty slot, so parts reach the dirty list on their own.
    g_originalAssemblyMarkDirty(model, flags);
    g_sourceDiagnostics.assemblyMarkDirty.fetch_add(1, std::memory_order_relaxed);
    if ((flags & kRenderModelDirtyTransform) != 0) {
        g_sourceDiagnostics.assemblyMarkDirtyTransform.fetch_add(
            1, std::memory_order_relaxed);
    }
}


// Diagnostics/AutoContinueLoadScreen: when a level finishes loading with the
// "press a key to continue" prompt armed, the loading loop (0x4B190) waits for
// bit 1 of idCommonLocal+0x19A0, which the prompt's input callback (0x47D70)
// sets. This sets the same bit, once, half a second after the prompt is armed.
// Runs from the render-world flush hook, which keeps running on the main
// thread while the load screen is shown.
void TryAutoContinueLoadScreen() {
    if (!g_autoContinueLoadScreen) {
        return;
    }
    static std::uint64_t armedCounter = 0;
    static bool continued = false;
    auto* common = reinterpret_cast<unsigned char*>(
        g_executableBase + g_layout->commonObjectRva);
    std::uintptr_t vtable = 0;
    memcpy(&vtable, common, sizeof(vtable));
    if (vtable != g_executableBase + g_layout->commonVtableRva) {
        return;
    }
    std::int32_t promptHandle = 0;
    memcpy(&promptHandle, common + g_layout->commonLoadPromptHandleOffset,
           sizeof(promptHandle));
    if (promptHandle == -1) {
        armedCounter = 0;
        continued = false;
        return;
    }
    const std::uint64_t now = ReadPerformanceCounter();
    if (armedCounter == 0) {
        armedCounter = now;
        return;
    }
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    if (continued || now - armedCounter <
                         static_cast<std::uint64_t>(frequency.QuadPart / 2)) {
        return;
    }
    continued = true;
    InterlockedOr8(reinterpret_cast<volatile char*>(
                       common + g_layout->commonLoadFlagsOffset), 2);
    Log("AutoContinueLoadScreen: the load-screen prompt was armed; continued "
        "without a key press.");
}

extern "C" void __fastcall HookRenderWorldFlush(void* world, std::uintptr_t argument) {
    if (g_sourceFlushInProgress.exchange(true, std::memory_order_acq_rel)) {
        // Nested or concurrent flush: the track table is single-threaded.
        g_originalRenderWorldFlush(world, argument);
        return;
    }
    TryAutoContinueLoadScreen();
    if (g_flushHookOnly) {
        g_originalRenderWorldFlush(world, argument);
        g_sourceFlushInProgress.store(false, std::memory_order_release);
        return;
    }
    const std::uint64_t start = ReadPerformanceCounter();
    g_sourceFlushThreadId.store(GetCurrentThreadId(), std::memory_order_relaxed);
    PresentationContext context{};
    const bool hasContext = ReadPresentationContext(context);

    const std::uint64_t engineStart = ReadPerformanceCounter();
    g_originalRenderWorldFlush(world, argument);
    const std::uint64_t engineEnd = ReadPerformanceCounter();
    if (hasContext) {
        g_sourceLastFlushSerial.store(context.serial, std::memory_order_release);
    }

    ++g_sourceCounters.flushCalls;
    if (hasContext) {
        if (!(context.simulationTime <= g_sourceLastFlushSimulationTime + kTimeEpsilon)) {
            ++g_sourceCounters.flushesWithTick;
        }
        g_sourceLastFlushSimulationTime = context.simulationTime;
    }

    bool overflowed = false;
    g_sourceDirtyScratch.clear();
    CollectSourceDirtyModels(world, g_sourceDirtyScratch, overflowed);
    g_sourceCounters.uniqueDirty += g_sourceDirtyScratch.size();
    if (g_sourceLevelWrites) {
        ProcessSourceLevelTracks(world, context, hasContext, g_sourceDirtyScratch);
    }
    g_sourceDirtyScratch.clear();

    const std::uint64_t end = ReadPerformanceCounter();
    g_sourceCounters.flushEngineTicks += engineEnd - engineStart;
    g_sourceCounters.flushPluginTicks +=
        (end - start) - (engineEnd - engineStart);
    if (g_enableInterpolationAbProbe) {
        g_abSourceFlushTicks.fetch_add(end - start, std::memory_order_relaxed);
        g_abSourceFlushOriginalTicks.fetch_add(engineEnd - engineStart,
                                               std::memory_order_relaxed);
    }
    MaybeLogSourceLevelDiagnostics(hasContext ? context.serial
                                              : g_presentationSerial.load(
                                                    std::memory_order_acquire));
    // Covers the engine flush and the matrix writes that follow it.
    g_sourceFlushInProgress.store(false, std::memory_order_release);
}

bool ReplaceVtableSlot(std::uintptr_t slotAddress, std::uintptr_t expected,
                       const void* replacement) {
    auto* slot = reinterpret_cast<volatile LONG64*>(slotAddress);
    DWORD oldProtection = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(slotAddress), sizeof(std::uintptr_t),
                        PAGE_READWRITE, &oldProtection)) {
        return false;
    }
    const LONG64 previous = InterlockedCompareExchange64(
        slot, static_cast<LONG64>(reinterpret_cast<std::uintptr_t>(replacement)),
        static_cast<LONG64>(expected));
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void*>(slotAddress), sizeof(std::uintptr_t),
                   oldProtection, &ignored);
    return static_cast<std::uintptr_t>(previous) == expected;
}

bool InstallSourceLevelHooks() {
    if (!g_sourceLevelTransforms) {
        Log("Source-level transforms are disabled by configuration.");
        return false;
    }
    const GameBuildLayout& layout = *g_layout;
    if (!layout.sourceLevelSupported) {
        return false;
    }
    const std::uintptr_t flushTarget = g_executableBase + layout.renderWorldFlushRva;
    const std::uintptr_t markDirtyTarget = g_executableBase + layout.renderModelMarkDirtyRva;
    const std::uintptr_t flushSlot =
        g_executableBase + layout.renderWorldVtable.rva + layout.renderWorldFlushSlot;
    const std::array<std::uintptr_t, 2> markDirtySlots = {
        g_executableBase + layout.renderModelStaticVtable.rva +
            layout.renderModelMarkDirtySlot,
        g_executableBase + layout.skinnedModelVtable.rva + layout.renderModelMarkDirtySlot,
    };
    if (memcmp(reinterpret_cast<const void*>(flushTarget),
               layout.renderWorldFlushBytes.data(),
               layout.renderWorldFlushBytes.size()) != 0 ||
        memcmp(reinterpret_cast<const void*>(markDirtyTarget),
               layout.renderModelMarkDirtyBytes.data(),
               layout.renderModelMarkDirtyBytes.size()) != 0) {
        Log("Source-level hook entry bytes changed after preflight; source-level "
            "transforms were not installed.");
        return false;
    }

    if (g_flushHookOnly) {
        g_originalRenderWorldFlush = reinterpret_cast<RenderWorldFlushFn>(flushTarget);
        if (!ReplaceVtableSlot(flushSlot, flushTarget,
                               reinterpret_cast<const void*>(&HookRenderWorldFlush))) {
            g_autoContinueLoadScreen = false;
            Log("Unable to replace the render-world flush vtable slot; "
                "AutoContinueLoadScreen was not installed.");
            return false;
        }
        Log("Installed the render-world flush hook for AutoContinueLoadScreen only "
            "(source-level transforms are off).");
        return true;
    }
    g_sourceDirty.reserve(kSourceDirtyCapacity);
    g_sourceDirtyScratch.reserve(kSourceDirtyCapacity);
    g_sourceDirtyDeferred.reserve(kSourceDirtyCapacity);
    g_sourceDirtyPending.reserve(kSourceDirtyCapacity);
    g_originalRenderWorldFlush = reinterpret_cast<RenderWorldFlushFn>(flushTarget);
    g_originalRenderModelMarkDirty =
        reinterpret_cast<RenderModelMarkDirtyFn>(markDirtyTarget);

    std::size_t patched = 0;
    for (; patched < markDirtySlots.size(); ++patched) {
        if (!ReplaceVtableSlot(markDirtySlots[patched], markDirtyTarget,
                               reinterpret_cast<const void*>(&HookRenderModelMarkDirty))) {
            break;
        }
    }
    if (patched != markDirtySlots.size()) {
        for (std::size_t index = 0; index < patched; ++index) {
            ReplaceVtableSlot(markDirtySlots[index],
                              reinterpret_cast<std::uintptr_t>(&HookRenderModelMarkDirty),
                              reinterpret_cast<const void*>(markDirtyTarget));
        }
        Log("Unable to replace the render-model MarkDirty vtable slots; "
            "source-level transforms were not installed.");
        return false;
    }
    // Writes are enabled before the flush slot goes live so the first flush
    // already sees a consistent configuration.
    g_sourceLevelInstalled = true;
    if (!ReplaceVtableSlot(flushSlot, flushTarget,
                           reinterpret_cast<const void*>(&HookRenderWorldFlush))) {
        g_sourceLevelInstalled = false;
        for (std::uintptr_t slot : markDirtySlots) {
            ReplaceVtableSlot(slot,
                              reinterpret_cast<std::uintptr_t>(&HookRenderModelMarkDirty),
                              reinterpret_cast<const void*>(markDirtyTarget));
        }
        Log("Unable to replace the render-world flush vtable slot; source-level "
            "transforms were not installed.");
        return false;
    }

    // Diagnostic-only: parts are covered through their own static slot.
    const std::uintptr_t assemblyTarget = g_executableBase + layout.assemblyMarkDirtyRva;
    const std::uintptr_t assemblySlot = g_executableBase + layout.assemblyVtable.rva +
                                        layout.renderModelMarkDirtySlot;
    g_originalAssemblyMarkDirty = reinterpret_cast<RenderModelMarkDirtyFn>(assemblyTarget);
    if (memcmp(reinterpret_cast<const void*>(assemblyTarget),
               layout.assemblyMarkDirtyBytes.data(),
               layout.assemblyMarkDirtyBytes.size()) != 0 ||
        !ReplaceVtableSlot(assemblySlot, assemblyTarget,
                           reinterpret_cast<const void*>(&HookAssemblyMarkDirty))) {
        Log("Assembly MarkDirty diagnostics were not installed; assembly parts "
            "remain covered through the static render-model slot.");
    }

    Log("Installed source-level transform hooks: render-world flush slot RVA 0x%llX "
        "(target 0x%llX) and render-model MarkDirty slots RVA 0x%llX/0x%llX "
        "(target 0x%llX); writes=%s. %s",
        static_cast<unsigned long long>(layout.renderWorldVtable.rva +
                                        layout.renderWorldFlushSlot),
        static_cast<unsigned long long>(layout.renderWorldFlushRva),
        static_cast<unsigned long long>(layout.renderModelStaticVtable.rva +
                                        layout.renderModelMarkDirtySlot),
        static_cast<unsigned long long>(layout.skinnedModelVtable.rva +
                                        layout.renderModelMarkDirtySlot),
        static_cast<unsigned long long>(layout.renderModelMarkDirtyRva),
        g_sourceLevelWrites ? "on (per-draw world transforms are skipped)"
                            : "off (logging only)",
        g_sourceLevelWrites && !(g_interpolateWorldTransforms ||
                                 g_interpolateCinematicTransforms)
            ? "WorldTransforms/CinematicTransforms are both 0, so no model is "
              "eligible for source-level writes."
            : "");
    return true;
}


// ---------------------------------------------------------------------------
// Diagnostics overlay (Diagnostics/Overlay). The retail engine's debug text is
// compiled out (its DrawString only parses color codes), so the status lines
// are drawn with Direct3D 11 right before the game presents: the
// IDXGISwapChain::Present vtable slot is replaced, and each frame the lines are
// drawn into the back buffer under a private device-context state
// (SwapDeviceContextState), so none of the game's pipeline state is touched.
// The font atlas is rendered once from Consolas with GDI.
// ---------------------------------------------------------------------------

constexpr std::size_t kSwapChainPresentSlot = 8;
constexpr std::size_t kSwapChainPresent1Slot = 22;
constexpr int kOverlayFirstChar = 32;
constexpr int kOverlayCharCount = 96;  // 32..127; 127 is a solid cell
constexpr int kOverlayAtlasColumns = 16;
constexpr int kOverlayAtlasRows = kOverlayCharCount / kOverlayAtlasColumns;
constexpr UINT kOverlayMaxVertices = 6 * 1024;

using PresentFn = HRESULT(STDMETHODCALLTYPE*)(IDXGISwapChain*, UINT, UINT);
using Present1Fn = HRESULT(STDMETHODCALLTYPE*)(IDXGISwapChain1*, UINT, UINT,
                                               const DXGI_PRESENT_PARAMETERS*);
using D3D11CreateDeviceAndSwapChainFn = decltype(&D3D11CreateDeviceAndSwapChain);
using D3DCompileFn = HRESULT(WINAPI*)(LPCVOID, SIZE_T, LPCSTR, const void*, void*,
                                      LPCSTR, LPCSTR, UINT, UINT, ID3DBlob**, ID3DBlob**);

PresentFn g_originalPresent = nullptr;
Present1Fn g_originalPresent1 = nullptr;

struct OverlayVertex {
    float x, y, u, v;
    std::uint32_t color;
};

struct OverlayFont {
    ID3D11ShaderResourceView* atlas = nullptr;
    int pixelHeight = 0;
    int cellWidth = 0;
    int cellHeight = 0;
};

// DevGUI draws with the engine's 48-pixel courier font at a scale; each scale
// used gets its own Courier New atlas at the matching pixel height.
constexpr std::size_t kDevGuiFontSlots = 4;

struct OverlayRenderer {
    bool failed = false;
    bool ready = false;
    IDXGISwapChain* swapChain = nullptr;  // not owned; the one being drawn on
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext1* context = nullptr;
    ID3DDeviceContextState* state = nullptr;
    ID3D11VertexShader* vertexShader = nullptr;
    ID3D11PixelShader* pixelShader = nullptr;
    ID3D11InputLayout* inputLayout = nullptr;
    ID3D11Buffer* vertexBuffer = nullptr;
    std::array<OverlayFont, kDevGuiFontSlots> devGuiFonts{};
    ID3D11SamplerState* sampler = nullptr;
    ID3D11BlendState* blend = nullptr;
    ID3D11RasterizerState* rasterizer = nullptr;
    ID3D11DepthStencilState* depth = nullptr;
    std::uint64_t frames = 0;
    std::uint64_t lastBoundPresent = 0;
    bool targetFailureLogged = false;
};

OverlayRenderer g_overlayRenderer;

struct OverlayStatistics {
    bool initialized = false;
    std::uint64_t lastCounter = 0;
    std::uint64_t lastSerial = 0;
    InterpolationAbCounterSnapshot lastCounters{};
    double fps = 0.0;
    double modelMs = 0.0;
    double poseMs = 0.0;
    double flushMs = 0.0;
    double writesPerFrame = 0.0;
};

OverlayStatistics g_overlayStatistics;

void UpdateOverlayStatistics() {
    OverlayStatistics& stats = g_overlayStatistics;
    const std::uint64_t now = ReadPerformanceCounter();
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    const std::uint64_t serial = g_presentationSerial.load(std::memory_order_acquire);
    if (!stats.initialized) {
        stats.initialized = true;
        stats.lastCounter = now;
        stats.lastSerial = serial;
        stats.lastCounters = CaptureInterpolationAbCounters();
        return;
    }
    const double seconds = static_cast<double>(now - stats.lastCounter) /
                           static_cast<double>(frequency.QuadPart);
    if (seconds < 0.5) {
        return;
    }
    const InterpolationAbCounterSnapshot counters = CaptureInterpolationAbCounters();
    const double frames = static_cast<double>(CounterDelta(serial, stats.lastSerial));
    const double ticksPerMs = static_cast<double>(frequency.QuadPart) / 1000.0;
    const auto perFrameMs = [&](std::uint64_t total, std::uint64_t engine,
                                std::uint64_t totalBefore, std::uint64_t engineBefore) {
        if (!(frames > 0.0)) {
            return 0.0;
        }
        const double plugin =
            static_cast<double>(CounterDelta(total, totalBefore)) -
            static_cast<double>(CounterDelta(engine, engineBefore));
        return std::max(0.0, plugin) / ticksPerMs / frames;
    };
    stats.fps = frames / seconds;
    stats.modelMs = perFrameMs(counters.renderModelHookTicks,
                               counters.renderModelOriginalTicks,
                               stats.lastCounters.renderModelHookTicks,
                               stats.lastCounters.renderModelOriginalTicks);
    stats.poseMs = perFrameMs(counters.skeletalHookTicks, counters.skeletalOriginalTicks,
                              stats.lastCounters.skeletalHookTicks,
                              stats.lastCounters.skeletalOriginalTicks);
    stats.flushMs = perFrameMs(counters.sourceFlushTicks, counters.sourceFlushOriginalTicks,
                               stats.lastCounters.sourceFlushTicks,
                               stats.lastCounters.sourceFlushOriginalTicks);
    stats.writesPerFrame = frames > 0.0
        ? static_cast<double>(CounterDelta(counters.sourceWrites,
                                           stats.lastCounters.sourceWrites)) / frames
        : 0.0;
    stats.lastCounter = now;
    stats.lastSerial = serial;
    stats.lastCounters = counters;
}

// Rows of the FPSFix column added to DevGUI: {label, value}. Labels name the
// hotkey that changes each state.
struct FpsFixColumnRow {
    char label[64];
    char value[48];
};

int FormatFpsFixColumn(FpsFixColumnRow (&rows)[16]) {
    UpdateOverlayStatistics();
    const OverlayStatistics& stats = g_overlayStatistics;
    const bool transforms = RuntimeTransformInterpolationEnabled();
    int count = 0;
    const auto row = [&](const char* label, const char* format, auto... values) {
        if (count < 16) {
            strcpy_s(rows[count].label, label);
            sprintf_s(rows[count].value, format, values...);
            ++count;
        }
    };
    const auto box = [](bool on) { return on ? "[X]" : "[ ]"; };
    row("Camera Prediction (F10)", "%s", box(g_enabled.load(std::memory_order_relaxed)));
    row("World Transforms (Alt+F11)", "%s", box(transforms));
    row("Transform Method (Ctrl+Shift+F11)", "%s",
        SourceLevelWritesSelected() ? "<source>" : "<per-draw>");
    row("Skeletons (Alt+F11)", "%s", box(RuntimeSkeletalInterpolationEnabled()));
    row("First-Person Hands (Shift+F11)", "%s", box(RuntimeFirstPersonHandsEnabled()));
    row("Force Blood Effect (Alt+F10)", "%s",
        box(g_forceBloodEffect.load(std::memory_order_relaxed)));
    static const char* const kScreenModes[] = {"<off>", "<matrix>", "<pose>", "<placement>",
                                               "<extrapolated>"};
    row("Screen Particle Fix (Ctrl+Alt+F10)", "%s",
        kScreenModes[std::max(0, std::min(4, g_screenParticleMode.load(std::memory_order_relaxed)))]);
    if (g_enableInterpolationAbProbe) {
        if (g_interpolationAbProbe.capturing) {
            LARGE_INTEGER now{};
            QueryPerformanceCounter(&now);
            const double elapsed = static_cast<double>(
                now.QuadPart - g_interpolationAbProbe.segmentStartCounter.QuadPart) /
                static_cast<double>(g_interpolationAbProbe.frequency.QuadPart);
            row("A/B Recording (Ctrl+F11)", "[X] %.0fs%s", elapsed,
                elapsed < kAbProbeWarmupSeconds ? " warm-up" : "");
        } else {
            row("A/B Recording (Ctrl+F11)", "%s", "[ ]");
        }
        row("Plugin ms/frame: model", "%.2f", stats.modelMs);
        row("Plugin ms/frame: pose", "%.2f", stats.poseMs);
        row("Plugin ms/frame: flush", "%.2f", stats.flushMs);
    }
    row("Frames/s", "%.0f", stats.fps);
    row("Source Tracks", "%llu", static_cast<unsigned long long>(g_sourceCounters.activeTracks));
    row("Source Writes/frame", "%.1f", stats.writesPerFrame);
    return count;
}

template <typename T>
void ReleaseOverlayObject(T*& object) {
    if (object != nullptr) {
        object->Release();
        object = nullptr;
    }
}

void ReleaseOverlayRenderer(OverlayRenderer& renderer) {
    ReleaseOverlayObject(renderer.depth);
    ReleaseOverlayObject(renderer.rasterizer);
    ReleaseOverlayObject(renderer.blend);
    ReleaseOverlayObject(renderer.sampler);
    for (OverlayFont& font : renderer.devGuiFonts) {
        ReleaseOverlayObject(font.atlas);
        font = OverlayFont{};
    }
    ReleaseOverlayObject(renderer.vertexBuffer);
    ReleaseOverlayObject(renderer.inputLayout);
    ReleaseOverlayObject(renderer.pixelShader);
    ReleaseOverlayObject(renderer.vertexShader);
    ReleaseOverlayObject(renderer.state);
    ReleaseOverlayObject(renderer.context);
    ReleaseOverlayObject(renderer.device);
    renderer.ready = false;
}

constexpr char kOverlayShaderSource[] = R"(
struct VertexInput { float2 position : POSITION; float2 uv : TEXCOORD; float4 color : COLOR; };
struct PixelInput { float4 position : SV_Position; float2 uv : TEXCOORD; float4 color : COLOR; };
PixelInput VSMain(VertexInput input) {
    PixelInput output;
    output.position = float4(input.position, 0.0, 1.0);
    output.uv = input.uv;
    output.color = input.color;
    return output;
}
Texture2D fontTexture : register(t0);
SamplerState fontSampler : register(s0);
float4 PSMain(PixelInput input) : SV_Target {
    return float4(input.color.rgb, input.color.a * fontTexture.Sample(fontSampler, input.uv).r);
}
)";

// Renders characters 32..126 of a monospaced font into an R8 atlas; cell 127
// is filled solid for background quads.
bool CreateOverlayFontAtlas(ID3D11Device* device, const wchar_t* face, int weight,
                            int pixelHeight, OverlayFont& output) {
    HDC dc = CreateCompatibleDC(nullptr);
    if (dc == nullptr) {
        return false;
    }
    HFONT font = CreateFontW(-pixelHeight, 0, 0, 0, weight, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
                             ANTIALIASED_QUALITY, FIXED_PITCH | FF_MODERN, face);
    HGDIOBJ previousFont = SelectObject(dc, font);
    SIZE glyph{};
    GetTextExtentPoint32W(dc, L"M", 1, &glyph);
    output.pixelHeight = pixelHeight;
    output.cellWidth = std::max(1, static_cast<int>(glyph.cx));
    output.cellHeight = std::max(1, static_cast<int>(glyph.cy));
    const int width = output.cellWidth * kOverlayAtlasColumns;
    const int height = output.cellHeight * kOverlayAtlasRows;

    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = width;
    info.bmiHeader.biHeight = -height;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HBITMAP bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &bits, nullptr, 0);
    bool created = false;
    if (bitmap != nullptr && bits != nullptr) {
        HGDIOBJ previousBitmap = SelectObject(dc, bitmap);
        memset(bits, 0, static_cast<std::size_t>(width) * height * 4);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(255, 255, 255));
        for (int index = 0; index < kOverlayCharCount - 1; ++index) {
            const char character = static_cast<char>(kOverlayFirstChar + index);
            TextOutA(dc, (index % kOverlayAtlasColumns) * output.cellWidth,
                     (index / kOverlayAtlasColumns) * output.cellHeight, &character, 1);
        }
        GdiFlush();
        std::vector<unsigned char> alpha(static_cast<std::size_t>(width) * height);
        const auto* pixels = static_cast<const std::uint32_t*>(bits);
        for (std::size_t pixel = 0; pixel < alpha.size(); ++pixel) {
            alpha[pixel] = static_cast<unsigned char>((pixels[pixel] >> 16) & 0xFF);
        }
        const int solid = kOverlayCharCount - 1;
        for (int y = 0; y < output.cellHeight; ++y) {
            for (int x = 0; x < output.cellWidth; ++x) {
                alpha[static_cast<std::size_t>((solid / kOverlayAtlasColumns) *
                                               output.cellHeight + y) * width +
                      (solid % kOverlayAtlasColumns) * output.cellWidth + x] = 0xFF;
            }
        }
        SelectObject(dc, previousBitmap);

        D3D11_TEXTURE2D_DESC description{};
        description.Width = static_cast<UINT>(width);
        description.Height = static_cast<UINT>(height);
        description.MipLevels = 1;
        description.ArraySize = 1;
        description.Format = DXGI_FORMAT_R8_UNORM;
        description.SampleDesc.Count = 1;
        description.Usage = D3D11_USAGE_IMMUTABLE;
        description.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        D3D11_SUBRESOURCE_DATA data{};
        data.pSysMem = alpha.data();
        data.SysMemPitch = static_cast<UINT>(width);
        ID3D11Texture2D* texture = nullptr;
        if (SUCCEEDED(device->CreateTexture2D(&description, &data, &texture))) {
            created = SUCCEEDED(device->CreateShaderResourceView(
                texture, nullptr, &output.atlas));
            texture->Release();
        }
    }
    if (bitmap != nullptr) {
        DeleteObject(bitmap);
    }
    SelectObject(dc, previousFont);
    DeleteObject(font);
    DeleteDC(dc);
    return created;
}

bool InitializeOverlayRenderer(OverlayRenderer& renderer, IDXGISwapChain* swapChain) {
    DXGI_SWAP_CHAIN_DESC swapDescription{};
    ID3D11Device* device = nullptr;
    if (FAILED(swapChain->GetDesc(&swapDescription)) ||
        FAILED(swapChain->GetDevice(__uuidof(ID3D11Device),
                                    reinterpret_cast<void**>(&device)))) {
        Log("Diagnostics overlay: the presenting swap chain has no D3D11 device; the "
            "overlay is off.");
        return false;
    }
    renderer.device = device;
    ID3D11DeviceContext* immediate = nullptr;
    device->GetImmediateContext(&immediate);
    const HRESULT contextResult = immediate->QueryInterface(
        __uuidof(ID3D11DeviceContext1), reinterpret_cast<void**>(&renderer.context));
    immediate->Release();
    const D3D_FEATURE_LEVEL level = device->GetFeatureLevel();
    ID3D11Device1* device1 = nullptr;
    if (FAILED(contextResult) ||
        FAILED(device->QueryInterface(__uuidof(ID3D11Device1),
                                      reinterpret_cast<void**>(&device1)))) {
        Log("Diagnostics overlay: D3D11.1 is unavailable; the overlay is off.");
        return false;
    }
    const HRESULT stateResult = device1->CreateDeviceContextState(
        0, &level, 1, D3D11_SDK_VERSION, __uuidof(ID3D11Device), nullptr,
        &renderer.state);
    device1->Release();
    if (FAILED(stateResult)) {
        Log("Diagnostics overlay: CreateDeviceContextState failed (0x%08lX); the overlay "
            "is off.", static_cast<unsigned long>(stateResult));
        return false;
    }

    HMODULE compiler = LoadLibraryW(L"d3dcompiler_47.dll");
    const auto compile = compiler != nullptr
        ? reinterpret_cast<D3DCompileFn>(GetProcAddress(compiler, "D3DCompile"))
        : nullptr;
    if (compile == nullptr) {
        Log("Diagnostics overlay: d3dcompiler_47.dll is unavailable; the overlay is off.");
        return false;
    }
    ID3DBlob* vertexCode = nullptr;
    ID3DBlob* pixelCode = nullptr;
    ID3DBlob* errors = nullptr;
    HRESULT result = compile(kOverlayShaderSource, sizeof(kOverlayShaderSource) - 1,
                             "overlay", nullptr, nullptr, "VSMain", "vs_4_0", 0, 0,
                             &vertexCode, &errors);
    ReleaseOverlayObject(errors);
    if (SUCCEEDED(result)) {
        result = compile(kOverlayShaderSource, sizeof(kOverlayShaderSource) - 1, "overlay",
                         nullptr, nullptr, "PSMain", "ps_4_0", 0, 0, &pixelCode, &errors);
        ReleaseOverlayObject(errors);
    }
    bool ok = SUCCEEDED(result);
    if (ok) {
        static const D3D11_INPUT_ELEMENT_DESC elements[] = {
            {"POSITION", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
            {"TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 8, D3D11_INPUT_PER_VERTEX_DATA, 0},
            {"COLOR", 0, DXGI_FORMAT_R8G8B8A8_UNORM, 0, 16, D3D11_INPUT_PER_VERTEX_DATA, 0},
        };
        ok = SUCCEEDED(device->CreateVertexShader(vertexCode->GetBufferPointer(),
                                                  vertexCode->GetBufferSize(), nullptr,
                                                  &renderer.vertexShader)) &&
             SUCCEEDED(device->CreatePixelShader(pixelCode->GetBufferPointer(),
                                                 pixelCode->GetBufferSize(), nullptr,
                                                 &renderer.pixelShader)) &&
             SUCCEEDED(device->CreateInputLayout(elements, 3,
                                                 vertexCode->GetBufferPointer(),
                                                 vertexCode->GetBufferSize(),
                                                 &renderer.inputLayout));
    }
    ReleaseOverlayObject(vertexCode);
    ReleaseOverlayObject(pixelCode);
    if (!ok) {
        Log("Diagnostics overlay: shader setup failed; the overlay is off.");
        return false;
    }

    D3D11_BUFFER_DESC bufferDescription{};
    bufferDescription.ByteWidth = kOverlayMaxVertices * sizeof(OverlayVertex);
    bufferDescription.Usage = D3D11_USAGE_DYNAMIC;
    bufferDescription.BindFlags = D3D11_BIND_VERTEX_BUFFER;
    bufferDescription.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    D3D11_SAMPLER_DESC samplerDescription{};
    samplerDescription.Filter = D3D11_FILTER_MIN_MAG_MIP_POINT;
    samplerDescription.AddressU = D3D11_TEXTURE_ADDRESS_CLAMP;
    samplerDescription.AddressV = D3D11_TEXTURE_ADDRESS_CLAMP;
    samplerDescription.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
    samplerDescription.MaxLOD = D3D11_FLOAT32_MAX;
    D3D11_BLEND_DESC blendDescription{};
    blendDescription.RenderTarget[0].BlendEnable = TRUE;
    blendDescription.RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA;
    blendDescription.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
    blendDescription.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
    blendDescription.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
    blendDescription.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA;
    blendDescription.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
    blendDescription.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    D3D11_RASTERIZER_DESC rasterizerDescription{};
    rasterizerDescription.FillMode = D3D11_FILL_SOLID;
    rasterizerDescription.CullMode = D3D11_CULL_NONE;
    rasterizerDescription.DepthClipEnable = TRUE;
    D3D11_DEPTH_STENCIL_DESC depthDescription{};
    depthDescription.DepthEnable = FALSE;
    depthDescription.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
    depthDescription.DepthFunc = D3D11_COMPARISON_ALWAYS;
    ok = SUCCEEDED(device->CreateBuffer(&bufferDescription, nullptr,
                                        &renderer.vertexBuffer)) &&
         SUCCEEDED(device->CreateSamplerState(&samplerDescription, &renderer.sampler)) &&
         SUCCEEDED(device->CreateBlendState(&blendDescription, &renderer.blend)) &&
         SUCCEEDED(device->CreateRasterizerState(&rasterizerDescription,
                                                 &renderer.rasterizer)) &&
         SUCCEEDED(device->CreateDepthStencilState(&depthDescription, &renderer.depth));
    if (!ok) {
        Log("Diagnostics overlay: resource setup failed; the overlay is off.");
        return false;
    }
    renderer.swapChain = swapChain;
    renderer.ready = true;
    Log("Diagnostics overlay: bound to swap chain %p on device %p.",
        static_cast<void*>(swapChain), static_cast<void*>(device));
    Log("Diagnostics overlay: D3D11 renderer ready (back buffer %ux%u format %u).",
        swapDescription.BufferDesc.Width, swapDescription.BufferDesc.Height,
        static_cast<unsigned>(swapDescription.BufferDesc.Format));
    return true;
}

void AppendOverlayQuad(OverlayVertex* vertices, UINT& count, float x0, float y0, float x1,
                       float y1, float u0, float v0, float u1, float v1,
                       std::uint32_t color) {
    if (count + 6 > kOverlayMaxVertices) {
        return;
    }
    const OverlayVertex quad[6] = {
        {x0, y0, u0, v0, color}, {x1, y0, u1, v0, color}, {x0, y1, u0, v1, color},
        {x0, y1, u0, v1, color}, {x1, y0, u1, v0, color}, {x1, y1, u1, v1, color},
    };
    memcpy(vertices + count, quad, sizeof(quad));
    count += 6;
}


// DevGUI replay. The DevGUI pass (0x8989F0) runs once per game frame; while it
// runs, every string handed to DevGUI's text drawer is recorded with its
// position, scale, color and alignment, and when the pass returns the list is
// published for the Present hook, which draws it at the same coordinates.
struct DevGuiTextEntry {
    float x = 0.0f;
    float y = 0.0f;
    float scale = 0.0f;
    std::uint32_t color = 0;
    int alignment = 0;
    char text[128]{};
};

constexpr std::size_t kDevGuiMaxEntries = 1024;
SRWLOCK g_devGuiTextLock = SRWLOCK_INIT;
std::vector<DevGuiTextEntry> g_devGuiCapture;
std::vector<DevGuiTextEntry> g_devGuiPublished;
std::uint64_t g_devGuiPublishedCounter = 0;
thread_local bool g_inDevGuiPass = false;
bool g_devGuiBacking = true;

std::uint32_t PackOverlayColor(const float* color) {
    if (color == nullptr || !IsReadableMemoryCached(color, 4 * sizeof(float))) {
        return 0xFFFFFFFFu;
    }
    const auto channel = [](float value) {
        const float clamped = std::isfinite(value) ? std::min(1.0f, std::max(0.0f, value)) : 1.0f;
        return static_cast<std::uint32_t>(clamped * 255.0f + 0.5f);
    };
    return channel(color[0]) | (channel(color[1]) << 8) | (channel(color[2]) << 16) |
           (channel(color[3]) << 24);
}

void RecordDevGuiText(float x, float y, float scale, const float* color, const char* text,
                      int alignment) {
    if (!g_inDevGuiPass || text == nullptr || !IsReadableMemoryCached(text, 1)) {
        return;
    }
    DevGuiTextEntry entry{};
    entry.x = x;
    entry.y = y;
    entry.scale = scale;
    entry.color = PackOverlayColor(color);
    entry.alignment = alignment;
    std::size_t length = 0;
    for (const char* character = text;
         *character != '\0' && length + 1 < sizeof(entry.text) &&
         IsReadableMemoryCached(character + 1, 1);
         ++character) {
        if (*character == '^' && character[1] != '\0') {
            ++character;  // id color escape such as ^1
            continue;
        }
        entry.text[length++] = (*character >= 32 && *character < 127) ? *character : '?';
    }
    if (length == 0 || g_devGuiCapture.size() >= kDevGuiMaxEntries) {
        return;
    }
    g_devGuiCapture.push_back(entry);
}

// Adds an "- FPSFIX -" block at DevGUI's bottom-left (the key legend is at the
// bottom-right), in DevGUI's own colors (the most common header and row colors
// this frame), text scale, left margin, and row spacing.
std::atomic<int> g_overlayBackBufferHeight{0};
void AppendFpsFixColumn(std::vector<DevGuiTextEntry>& entries) {
    float scale = 0.0f;
    float left = 1.0e9f;
    std::uint32_t headerColor = 0xFFFFFFFFu;
    std::uint32_t rowColor = 0xFFFFFFFFu;
    std::vector<std::pair<std::uint32_t, int>> headerColors;
    std::vector<std::pair<std::uint32_t, int>> rowColors;
    const auto tally = [](std::vector<std::pair<std::uint32_t, int>>& tallies,
                          std::uint32_t color) {
        for (auto& tallyEntry : tallies) {
            if (tallyEntry.first == color) {
                ++tallyEntry.second;
                return;
            }
        }
        tallies.emplace_back(color, 1);
    };
    for (const DevGuiTextEntry& entry : entries) {
        const std::size_t length = strlen(entry.text);
        if (length > 4 && entry.text[0] == '-' && entry.text[length - 1] == '-') {
            scale = entry.scale;
            left = std::min(left, entry.x);
            tally(headerColors, entry.color);
        } else {
            tally(rowColors, entry.color);
        }
    }
    const int screenHeight = g_overlayBackBufferHeight.load(std::memory_order_relaxed);
    if (scale <= 0.0f || screenHeight <= 0) {
        return;
    }
    const auto mostCommon = [](const std::vector<std::pair<std::uint32_t, int>>& tallies,
                               std::uint32_t fallback) {
        int best = 0;
        for (const auto& tallyEntry : tallies) {
            if (tallyEntry.second > best) {
                best = tallyEntry.second;
                fallback = tallyEntry.first;
            }
        }
        return fallback;
    };
    headerColor = mostCommon(headerColors, headerColor);
    rowColor = mostCommon(rowColors, rowColor);
    // Courier advance is 0.6 em of the 48 px font.
    const float lineHeight = 48.0f * scale;
    const float x = left;
    const float valueX = x + 36.0f * 28.8f * scale;
    const auto add = [&](float atX, float atY, std::uint32_t color, const char* text) {
        if (entries.size() >= kDevGuiMaxEntries) {
            return;
        }
        DevGuiTextEntry entry{};
        entry.x = atX;
        entry.y = atY;
        entry.scale = scale;
        entry.color = color;
        strncpy_s(entry.text, text, _TRUNCATE);
        entries.push_back(entry);
    };
    FpsFixColumnRow rows[16]{};
    const int count = FormatFpsFixColumn(rows);
    const float headerY = static_cast<float>(screenHeight) -
                          lineHeight * (2.0f + 1.4f + static_cast<float>(count));
    add(x, headerY, headerColor, "- FPSFIX -");
    float y = headerY + lineHeight * 1.4f;
    for (int index = 0; index < count; ++index) {
        add(x, y, rowColor, rows[index].label);
        add(valueX, y, rowColor, rows[index].value);
        y += lineHeight;
    }
}

void PublishDevGuiText() {
    if (!g_devGuiCapture.empty()) {
        AppendFpsFixColumn(g_devGuiCapture);
    }
    AcquireSRWLockExclusive(&g_devGuiTextLock);
    g_devGuiPublished.swap(g_devGuiCapture);
    g_devGuiPublishedCounter = ReadPerformanceCounter();
    ReleaseSRWLockExclusive(&g_devGuiTextLock);
    g_devGuiCapture.clear();
}

void CopyPublishedDevGuiText(std::vector<DevGuiTextEntry>& output) {
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    AcquireSRWLockShared(&g_devGuiTextLock);
    // A stale list (the game view stopped running, e.g. a load screen) is dropped.
    if (ReadPerformanceCounter() - g_devGuiPublishedCounter <
        static_cast<std::uint64_t>(frequency.QuadPart / 2)) {
        output = g_devGuiPublished;
    }
    ReleaseSRWLockShared(&g_devGuiTextLock);
}

const OverlayFont* AcquireDevGuiFont(OverlayRenderer& renderer, float scale) {
    // The engine font is 48 pixels tall; DevGUI draws it at scale 0.25 (12 px).
    const int pixelHeight = std::max(8, std::min(64, static_cast<int>(48.0f * scale + 0.5f)));
    for (OverlayFont& font : renderer.devGuiFonts) {
        if (font.atlas != nullptr && font.pixelHeight == pixelHeight) {
            return &font;
        }
    }
    for (OverlayFont& font : renderer.devGuiFonts) {
        if (font.atlas == nullptr) {
            if (CreateOverlayFontAtlas(renderer.device, L"Courier New", FW_BOLD, pixelHeight,
                                       font)) {
                Log("Diagnostics overlay: DevGUI font %d px (cell %dx%d).", pixelHeight,
                    font.cellWidth, font.cellHeight);
                return &font;
            }
            font = OverlayFont{};
            return nullptr;
        }
    }
    return nullptr;
}

void DrawOverlayFrame(IDXGISwapChain* swapChain);

void DrawOverlay(IDXGISwapChain* swapChain) {
    static thread_local bool inside = false;
    if (inside) {
        return;  // Present1 may forward to Present.
    }
    inside = true;
    DrawOverlayFrame(swapChain);
    inside = false;
}

#define OVERLAY_TRACE(step)                                                            do {                                                                                   if (g_overlayRenderer.frames < 3) {                                                    Log("Diagnostics overlay: frame %llu %s.",                                             static_cast<unsigned long long>(g_overlayRenderer.frames), step);          }                                                                              } while (false)

void DrawOverlayFrame(IDXGISwapChain* swapChain) {
    OverlayRenderer& renderer = g_overlayRenderer;
    if (!g_overlay || renderer.failed) {
        return;
    }
    if (!renderer.ready) {
        if (!InitializeOverlayRenderer(renderer, swapChain)) {
            ReleaseOverlayRenderer(renderer);
            renderer.failed = true;
            return;
        }
    }
    if (swapChain != renderer.swapChain) {
        // Another swap chain: a capture tool, or the game recreated its own. Move
        // to it once the bound one has not presented for two seconds.
        const std::uint64_t now = ReadPerformanceCounter();
        LARGE_INTEGER frequency{};
        QueryPerformanceFrequency(&frequency);
        if (now - renderer.lastBoundPresent < static_cast<std::uint64_t>(frequency.QuadPart) * 2) {
            return;
        }
        ID3D11Device* device = nullptr;
        const bool sameDevice =
            SUCCEEDED(swapChain->GetDevice(__uuidof(ID3D11Device),
                                           reinterpret_cast<void**>(&device))) &&
            device == renderer.device;
        ReleaseOverlayObject(device);
        if (!sameDevice) {
            ReleaseOverlayRenderer(renderer);
            return;  // Re-initialized on the next Present.
        }
        renderer.swapChain = swapChain;
        Log("Diagnostics overlay: moved to a new swap chain on the same device.");
    }
    renderer.lastBoundPresent = ReadPerformanceCounter();
    ID3D11Texture2D* backBuffer = nullptr;
    if (FAILED(swapChain->GetBuffer(0, __uuidof(ID3D11Texture2D),
                                    reinterpret_cast<void**>(&backBuffer)))) {
        return;
    }
    D3D11_TEXTURE2D_DESC backDescription{};
    backBuffer->GetDesc(&backDescription);
    ID3D11RenderTargetView* target = nullptr;
    HRESULT targetResult =
        renderer.device->CreateRenderTargetView(backBuffer, nullptr, &target);
    if (FAILED(targetResult)) {
        // Typeless back buffers need an explicit view format.
        D3D11_RENDER_TARGET_VIEW_DESC view{};
        view.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;
        switch (backDescription.Format) {
            case DXGI_FORMAT_R8G8B8A8_TYPELESS: view.Format = DXGI_FORMAT_R8G8B8A8_UNORM; break;
            case DXGI_FORMAT_B8G8R8A8_TYPELESS: view.Format = DXGI_FORMAT_B8G8R8A8_UNORM; break;
            case DXGI_FORMAT_R10G10B10A2_TYPELESS:
                view.Format = DXGI_FORMAT_R10G10B10A2_UNORM;
                break;
            case DXGI_FORMAT_R16G16B16A16_TYPELESS:
                view.Format = DXGI_FORMAT_R16G16B16A16_FLOAT;
                break;
            default: break;
        }
        if (view.Format != DXGI_FORMAT_UNKNOWN) {
            targetResult = renderer.device->CreateRenderTargetView(backBuffer, &view, &target);
        }
    }
    backBuffer->Release();
    if (FAILED(targetResult)) {
        if (!renderer.targetFailureLogged) {
            renderer.targetFailureLogged = true;
            Log("Diagnostics overlay: unable to create a render target for back-buffer "
                "format %u; nothing is drawn.", static_cast<unsigned>(backDescription.Format));
        }
        return;
    }

    const float width = static_cast<float>(backDescription.Width);
    const float height = static_cast<float>(backDescription.Height);
    g_overlayBackBufferHeight.store(static_cast<int>(backDescription.Height),
                                    std::memory_order_relaxed);
    const auto ndcX = [&](float x) { return x / width * 2.0f - 1.0f; };
    const auto ndcY = [&](float y) { return 1.0f - y / height * 2.0f; };

    // Each batch is a vertex range drawn with one font atlas.
    struct Batch {
        const OverlayFont* font;
        UINT first;
        UINT count;
    };
    Batch batches[1 + kDevGuiFontSlots]{};
    std::size_t batchCount = 0;
    OverlayVertex* vertices = nullptr;
    UINT count = 0;
    const auto beginBatch = [&](const OverlayFont* font) {
        if (batchCount != 0 && batches[batchCount - 1].font == font) {
            return;
        }
        if (batchCount < std::size(batches)) {
            batches[batchCount++] = {font, count, 0};
        }
    };
    const auto endBatch = [&]() {
        if (batchCount != 0) {
            batches[batchCount - 1].count = count - batches[batchCount - 1].first;
        }
    };
    const auto cellUv = [](const OverlayFont& font, int index, float& u0, float& v0,
                           float& u1, float& v1) {
        u0 = static_cast<float>(index % kOverlayAtlasColumns) / kOverlayAtlasColumns;
        v0 = static_cast<float>(index / kOverlayAtlasColumns) / kOverlayAtlasRows;
        u1 = u0 + 1.0f / kOverlayAtlasColumns;
        v1 = v0 + 1.0f / kOverlayAtlasRows;
        (void)font;
    };
    const auto appendBox = [&](const OverlayFont& font, float left, float top, float right,
                               float bottom, std::uint32_t color) {
        float u0 = 0, v0 = 0, u1 = 0, v1 = 0;
        cellUv(font, kOverlayCharCount - 1, u0, v0, u1, v1);
        const float su = (u0 + u1) * 0.5f;
        const float sv = (v0 + v1) * 0.5f;
        AppendOverlayQuad(vertices, count, ndcX(left), ndcY(top), ndcX(right), ndcY(bottom),
                          su, sv, su, sv, color);
    };
    const auto appendText = [&](const OverlayFont& font, float x, float y, const char* text,
                                std::uint32_t color) {
        const float cellWidth = static_cast<float>(font.cellWidth);
        const float cellHeight = static_cast<float>(font.cellHeight);
        float u0 = 0, v0 = 0, u1 = 0, v1 = 0;
        for (const char* character = text; *character != '\0'; ++character) {
            const int code = static_cast<unsigned char>(*character);
            if (code > kOverlayFirstChar && code < kOverlayFirstChar + kOverlayCharCount - 1) {
                cellUv(font, code - kOverlayFirstChar, u0, v0, u1, v1);
                AppendOverlayQuad(vertices, count, ndcX(x), ndcY(y), ndcX(x + cellWidth),
                                  ndcY(y + cellHeight), u0, v0, u1, v1, color);
            }
            x += cellWidth;
        }
    };

    std::vector<DevGuiTextEntry> devGui;
    CopyPublishedDevGuiText(devGui);

    D3D11_MAPPED_SUBRESOURCE mapped{};
    ID3DDeviceContextState* previous = nullptr;
    OVERLAY_TRACE("swapping in the overlay state");
    renderer.context->SwapDeviceContextState(renderer.state, &previous);
    OVERLAY_TRACE("mapping vertices");
    if (SUCCEEDED(renderer.context->Map(renderer.vertexBuffer, 0, D3D11_MAP_WRITE_DISCARD,
                                        0, &mapped))) {
        vertices = static_cast<OverlayVertex*>(mapped.pData);

        // DevGUI lays itself out in screen pixels at a fixed 12 px text size,
        // which is tiny at high resolutions. It is enlarged by an integer factor
        // (DevGuiScale, 0 = height / 720): entries in the left/top half grow
        // from the top-left corner, the rest (the key legend) from the
        // bottom-right corner, so both stay on screen.
        const float devGuiScale = static_cast<float>(
            g_devGuiScale > 0 ? g_devGuiScale
                              : std::max(1, static_cast<int>(height / 720.0f + 0.25f)));
        for (const DevGuiTextEntry& entry : devGui) {
            const OverlayFont* font = AcquireDevGuiFont(renderer, entry.scale * devGuiScale);
            if (font == nullptr) {
                continue;
            }
            beginBatch(font);
            const float textWidth =
                static_cast<float>(strlen(entry.text)) * static_cast<float>(font->cellWidth);
            float x = entry.x < width * 0.5f ? entry.x * devGuiScale
                                             : width - (width - entry.x) * devGuiScale;
            const float y = entry.y < height * 0.5f ? entry.y * devGuiScale
                                                    : height - (height - entry.y) * devGuiScale;
            if (entry.alignment == 1) {
                x -= textWidth;
            } else if (entry.alignment == 2) {
                x -= textWidth * 0.5f;
            }
            if (g_devGuiBacking) {
                appendBox(*font, x - 2.0f, y - 1.0f, x + textWidth + 2.0f,
                          y + static_cast<float>(font->cellHeight) + 1.0f, 0x90000000u);
            }
            appendText(*font, x, y, entry.text, entry.color);
            endBatch();
        }
        renderer.context->Unmap(renderer.vertexBuffer, 0);

        D3D11_VIEWPORT viewport{0.0f, 0.0f, width, height, 0.0f, 1.0f};
        const UINT stride = sizeof(OverlayVertex);
        const UINT offset = 0;
        const float blendFactor[4] = {0.0f, 0.0f, 0.0f, 0.0f};
        renderer.context->OMSetRenderTargets(1, &target, nullptr);
        renderer.context->OMSetBlendState(renderer.blend, blendFactor, 0xFFFFFFFFu);
        renderer.context->OMSetDepthStencilState(renderer.depth, 0);
        renderer.context->RSSetState(renderer.rasterizer);
        renderer.context->RSSetViewports(1, &viewport);
        renderer.context->IASetInputLayout(renderer.inputLayout);
        renderer.context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
        renderer.context->IASetVertexBuffers(0, 1, &renderer.vertexBuffer, &stride, &offset);
        renderer.context->VSSetShader(renderer.vertexShader, nullptr, 0);
        renderer.context->PSSetShader(renderer.pixelShader, nullptr, 0);
        renderer.context->PSSetSamplers(0, 1, &renderer.sampler);
        OVERLAY_TRACE("drawing");
        for (std::size_t batch = 0; batch < batchCount; ++batch) {
            if (batches[batch].count == 0) {
                continue;
            }
            renderer.context->PSSetShaderResources(0, 1, &batches[batch].font->atlas);
            renderer.context->Draw(batches[batch].count, batches[batch].first);
        }
        ID3D11RenderTargetView* none = nullptr;
        renderer.context->OMSetRenderTargets(1, &none, nullptr);
    }
    OVERLAY_TRACE("restoring the game state");
    renderer.context->SwapDeviceContextState(previous, nullptr);
    ReleaseOverlayObject(previous);
    target->Release();
    OVERLAY_TRACE("done");
    if (renderer.frames++ == 0) {
        Log("Diagnostics overlay: first frame drawn with D3D11.");
    }
}

HRESULT STDMETHODCALLTYPE HookPresent(IDXGISwapChain* swapChain, UINT syncInterval,
                                      UINT flags) {
    if ((flags & DXGI_PRESENT_TEST) == 0) {
        DrawOverlay(swapChain);
    }
    const HRESULT result = g_originalPresent(swapChain, syncInterval, flags);
    static std::atomic<int> failures{0};
    if (FAILED(result) && failures.fetch_add(1) < 4) {
        Log("Diagnostics overlay: Present returned 0x%08lX.", static_cast<unsigned long>(result));
    }
    return result;
}

HRESULT STDMETHODCALLTYPE HookPresent1(IDXGISwapChain1* swapChain, UINT syncInterval,
                                       UINT flags,
                                       const DXGI_PRESENT_PARAMETERS* parameters) {
    if ((flags & DXGI_PRESENT_TEST) == 0) {
        DrawOverlay(swapChain);
    }
    return g_originalPresent1(swapChain, syncInterval, flags, parameters);
}

bool ReplaceSwapChainSlot(void** vtable, std::size_t slot, const void* replacement,
                          void** original) {
    DWORD oldProtection = 0;
    if (!VirtualProtect(&vtable[slot], sizeof(void*), PAGE_READWRITE, &oldProtection)) {
        return false;
    }
    *original = InterlockedExchangePointer(&vtable[slot], const_cast<void*>(replacement));
    DWORD ignored = 0;
    VirtualProtect(&vtable[slot], sizeof(void*), oldProtection, &ignored);
    return true;
}

// Startup recreates the device, so the Present hook (and its probe device) is
// installed only once the game has presented rendered views for a while; it
// runs on its own thread so the frame that triggers it is not delayed.
DWORD WINAPI OverlayPresentHookThread(void*);

void TryInstallOverlayPresentHook() {
    static bool started = false;
    if (!g_overlay || started ||
        g_presentationSerial.load(std::memory_order_acquire) < 240) {
        return;
    }
    started = true;
    HANDLE thread = CreateThread(nullptr, 0, OverlayPresentHookThread, nullptr, 0, nullptr);
    if (thread != nullptr) {
        CloseHandle(thread);
    }
}

// Creates a throwaway device and swap chain to find the DXGI swap-chain vtable,
// which every swap chain in the process shares, and replaces Present/Present1.
bool InstallOverlayPresentHook() {
    HMODULE d3d11 = LoadLibraryW(L"d3d11.dll");
    const auto create = d3d11 != nullptr
        ? reinterpret_cast<D3D11CreateDeviceAndSwapChainFn>(
              GetProcAddress(d3d11, "D3D11CreateDeviceAndSwapChain"))
        : nullptr;
    if (create == nullptr) {
        Log("Diagnostics overlay: d3d11.dll is unavailable; the overlay was not installed.");
        return false;
    }
    HWND window = CreateWindowExW(0, L"STATIC", L"d2-high-fps-fix overlay probe",
                                  WS_POPUP, 0, 0, 64, 64, nullptr, nullptr, nullptr,
                                  nullptr);
    if (window == nullptr) {
        Log("Diagnostics overlay: unable to create the probe window; the overlay was not "
            "installed.");
        return false;
    }
    DXGI_SWAP_CHAIN_DESC description{};
    description.BufferDesc.Width = 64;
    description.BufferDesc.Height = 64;
    description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    description.SampleDesc.Count = 1;
    description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    description.BufferCount = 1;
    description.OutputWindow = window;
    description.Windowed = TRUE;
    description.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    IDXGISwapChain* swapChain = nullptr;
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;
    const HRESULT result = create(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0,
                                  D3D11_SDK_VERSION, &description, &swapChain, &device,
                                  nullptr, &context);
    bool installed = false;
    if (SUCCEEDED(result) && swapChain != nullptr) {
        void** vtable = *reinterpret_cast<void***>(swapChain);
        void* original = nullptr;
        installed = ReplaceSwapChainSlot(vtable, kSwapChainPresentSlot,
                                         reinterpret_cast<const void*>(&HookPresent),
                                         &original);
        if (installed) {
            g_originalPresent = reinterpret_cast<PresentFn>(original);
            IDXGISwapChain1* swapChain1 = nullptr;
            if (SUCCEEDED(swapChain->QueryInterface(__uuidof(IDXGISwapChain1),
                                                    reinterpret_cast<void**>(&swapChain1)))) {
                void** vtable1 = *reinterpret_cast<void***>(swapChain1);
                void* original1 = nullptr;
                if (ReplaceSwapChainSlot(vtable1, kSwapChainPresent1Slot,
                                         reinterpret_cast<const void*>(&HookPresent1),
                                         &original1)) {
                    g_originalPresent1 = reinterpret_cast<Present1Fn>(original1);
                }
                swapChain1->Release();
            }
        }
    }
    ReleaseOverlayObject(context);
    ReleaseOverlayObject(device);
    ReleaseOverlayObject(swapChain);
    DestroyWindow(window);
    if (!installed) {
        Log("Diagnostics overlay: unable to hook IDXGISwapChain::Present (0x%08lX); the "
            "overlay was not installed.", static_cast<unsigned long>(result));
        return false;
    }
    Log("Diagnostics overlay: hooked IDXGISwapChain::Present%s; DevGUI is drawn "
        "through it.", g_originalPresent1 != nullptr ? " and Present1" : "");
    return true;
}

DWORD WINAPI OverlayPresentHookThread(void*) {
    InstallOverlayPresentHook();
    return 0;
}

bool InstallShadowCasterBuildHooks() {
    if (!g_interpolateShadowTransforms) {
        Log("Shadow-transform interpolation is disabled by configuration.");
        return false;
    }
    const std::array<HookSiteLayout, 2>& sites = g_layout->shadowCasterBuild;
    std::array<unsigned char*, 2> entries{};
    const std::array<const void*, 2> hooks = {
        reinterpret_cast<const void*>(&HookShadowCasterBuildA),
        reinterpret_cast<const void*>(&HookShadowCasterBuildB),
    };
    constexpr std::size_t kAbsoluteJumpLength = 14;
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const HookSiteLayout& site = sites[index];
        entries[index] = reinterpret_cast<unsigned char*>(
            g_executableBase + site.rva);
        if (memcmp(entries[index], site.bytes.data(), site.length) != 0) {
            Log("Shadow caster-build entry %llu bytes do not match; shadow "
                "transforms were not installed.",
                static_cast<unsigned long long>(index));
            return false;
        }
        auto* trampoline = static_cast<unsigned char*>(VirtualAlloc(
            nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE));
        if (trampoline == nullptr) {
            for (void* allocation : g_shadowCasterBuildTrampolines) {
                if (allocation != nullptr) {
                    VirtualFree(allocation, 0, MEM_RELEASE);
                }
            }
            g_shadowCasterBuildTrampolines = {};
            Log("Unable to allocate shadow caster-build trampolines; shadow "
                "transforms were not installed.");
            return false;
        }
        memcpy(trampoline, entries[index], site.length);
        WriteAbsoluteIndirectJump(trampoline + site.length,
                                  entries[index] + site.length);
        FlushInstructionCache(GetCurrentProcess(), trampoline,
                              site.length + kAbsoluteJumpLength);
        g_shadowCasterBuildTrampolines[index] = trampoline;
    }

    const std::size_t protectedLength = static_cast<std::size_t>(
        entries.back() - entries.front()) + sites.back().length;
    DWORD oldProtection = 0;
    if (!VirtualProtect(entries.front(), protectedLength,
                        PAGE_EXECUTE_READWRITE, &oldProtection)) {
        for (void* allocation : g_shadowCasterBuildTrampolines) {
            VirtualFree(allocation, 0, MEM_RELEASE);
        }
        g_shadowCasterBuildTrampolines = {};
        Log("VirtualProtect failed for shadow caster-build entries; shadow "
            "transforms were not installed.");
        return false;
    }
    g_originalShadowCasterBuildA = reinterpret_cast<ShadowCasterBuildFnA>(
        g_shadowCasterBuildTrampolines[0]);
    g_originalShadowCasterBuildB = reinterpret_cast<ShadowCasterBuildFnB>(
        g_shadowCasterBuildTrampolines[1]);
    for (std::size_t index = 0; index < entries.size(); ++index) {
        unsigned char patch[kMaximumHookLength]{};
        memset(patch, 0x90, sizeof(patch));
        WriteAbsoluteIndirectJump(patch, hooks[index]);
        memcpy(entries[index], patch, sites[index].length);
    }
    FlushInstructionCache(GetCurrentProcess(), entries.front(),
                          protectedLength);
    DWORD ignored = 0;
    VirtualProtect(entries.front(), protectedLength, oldProtection, &ignored);

    Log("Installed coherent renderer-only shadow caster-list proxies at build "
        "RVAs 0x%llX and 0x%llX.",
        static_cast<unsigned long long>(sites[0].rva),
        static_cast<unsigned long long>(sites[1].rva));
    return true;
}

bool InstallRenderModelGpuCopyHook() {
    if (!g_stabilizeFirstPersonHands && !g_interpolateWorldTransforms &&
        !g_interpolateCinematicTransforms) {
        Log("Renderer model GPU-copy features are disabled by configuration.");
        return false;
    }

    const HookSiteLayout& site = g_layout->renderModelGpuCopy;
    auto* entry = reinterpret_cast<unsigned char*>(g_executableBase + site.rva);
    if (memcmp(entry, site.bytes.data(), site.length) != 0) {
        Log("Renderer GPU-copy bytes do not match; renderer model features were not installed.");
        return false;
    }

    constexpr std::size_t kAbsoluteJumpLength = 14;
    auto* trampoline = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (trampoline == nullptr) {
        Log("Unable to allocate the renderer GPU-copy trampoline; "
            "hands stabilization was not installed.");
        return false;
    }
    memcpy(trampoline, entry, site.length);
    WriteAbsoluteIndirectJump(trampoline + site.length, entry + site.length);
    FlushInstructionCache(GetCurrentProcess(), trampoline,
                          site.length + kAbsoluteJumpLength);

    unsigned char patch[kMaximumHookLength]{};
    memset(patch, 0x90, sizeof(patch));
    WriteAbsoluteIndirectJump(patch,
                              reinterpret_cast<const void*>(&HookRenderModelGpuCopy));

    DWORD oldProtection = 0;
    if (!VirtualProtect(entry, site.length, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        Log("VirtualProtect failed at the renderer GPU-copy boundary; "
            "renderer model features were not installed.");
        return false;
    }
    g_originalRenderModelGpuCopy = reinterpret_cast<RenderModelGpuCopyFn>(trampoline);
    g_renderModelGpuCopyTrampoline = trampoline;
    memcpy(entry, patch, site.length);
    FlushInstructionCache(GetCurrentProcess(), entry, site.length);
    DWORD ignored = 0;
    VirtualProtect(entry, site.length, oldProtection, &ignored);

    Log("Installed renderer model GPU-copy hook at RVA 0x%llX "
        "(first-person roots=%u, world transforms=%u, cinematic transforms=%u).",
        static_cast<unsigned long long>(g_layout->renderModelGpuCopy.rva),
        g_stabilizeFirstPersonHands ? 1U : 0U,
        g_interpolateWorldTransforms ? 1U : 0U,
        g_interpolateCinematicTransforms ? 1U : 0U);
    return true;
}

bool InstallSkinnedPoseUploadHook() {
    if (!g_interpolateWorldSkeletons &&
        !g_interpolateFirstPersonSkeletons &&
        !g_interpolateCinematicSkeletons) {
        Log("Skeletal interpolation is disabled by configuration.");
        return false;
    }

    const HookSiteLayout& site = g_layout->skinnedPoseUpload;
    auto* entry = reinterpret_cast<unsigned char*>(g_executableBase + site.rva);
    if (memcmp(entry, site.bytes.data(), site.length) != 0) {
        Log("Skinned-pose upload bytes do not match; skeletal interpolation "
            "was not installed.");
        return false;
    }

    constexpr std::size_t kAbsoluteJumpLength = 14;
    auto* trampoline = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT,
                     PAGE_EXECUTE_READWRITE));
    if (trampoline == nullptr) {
        Log("Unable to allocate the skinned-pose upload trampoline; skeletal "
            "interpolation was not installed.");
        return false;
    }
    memcpy(trampoline, entry, site.length);
    WriteAbsoluteIndirectJump(trampoline + site.length, entry + site.length);
    FlushInstructionCache(GetCurrentProcess(), trampoline,
                          site.length + kAbsoluteJumpLength);

    unsigned char patch[kMaximumHookLength]{};
    memset(patch, 0x90, sizeof(patch));
    WriteAbsoluteIndirectJump(patch,
                              reinterpret_cast<const void*>(&HookSkinnedPoseUpload));

    DWORD oldProtection = 0;
    if (!VirtualProtect(entry, site.length, PAGE_EXECUTE_READWRITE,
                        &oldProtection)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        Log("VirtualProtect failed at the skinned-pose upload boundary; skeletal "
            "interpolation was not installed.");
        return false;
    }
    g_originalSkinnedPoseUpload =
        reinterpret_cast<SkinnedPoseUploadFn>(trampoline);
    g_skinnedPoseUploadTrampoline = trampoline;
    memcpy(entry, patch, site.length);
    FlushInstructionCache(GetCurrentProcess(), entry, site.length);
    DWORD ignored = 0;
    VirtualProtect(entry, site.length, oldProtection, &ignored);

    Log("Installed experimental skeletal hook at pose-upload RVA 0x%llX "
        "(first-person=%u, world=%u, cinematic=%u); CPU poses remain unmodified and "
        "presentation palettes are substituted only during synchronous GPU "
        "upload.",
        static_cast<unsigned long long>(g_layout->skinnedPoseUpload.rva),
        g_interpolateFirstPersonSkeletons ? 1U : 0U,
        g_interpolateWorldSkeletons ? 1U : 0U,
        g_interpolateCinematicSkeletons ? 1U : 0U);
    return true;
}

bool InstallHook() {
    ExecutableImageLayout image{};
    if (!ReadExecutableImageLayout(image) ||
        !ValidateViewCopyCallRelationship(image)) {
        Log("Renderer view-copy site changed after preflight; patch not installed.");
        return false;
    }

    auto* callsite = reinterpret_cast<unsigned char*>(g_executableBase + g_layout->copyCallsiteRva);
    g_originalCopyView = reinterpret_cast<CopyViewFn>(g_executableBase + g_layout->copyViewRva);
    g_relay = AllocateRelayNear(reinterpret_cast<std::uintptr_t>(callsite));
    if (g_relay == nullptr) {
        Log("Unable to allocate a relay within rel32 range; patch not installed.");
        return false;
    }

    unsigned char relayCode[12] = {0x48, 0xB8};
    const std::uintptr_t hookAddress = reinterpret_cast<std::uintptr_t>(&HookCopyView);
    memcpy(relayCode + 2, &hookAddress, sizeof(hookAddress));
    relayCode[10] = 0xFF;
    relayCode[11] = 0xE0;
    memcpy(g_relay, relayCode, sizeof(relayCode));
    FlushInstructionCache(GetCurrentProcess(), g_relay, sizeof(relayCode));

    const std::int64_t displacement64 =
        reinterpret_cast<std::uintptr_t>(g_relay) -
        (reinterpret_cast<std::uintptr_t>(callsite) + 5);
    if (displacement64 < std::numeric_limits<std::int32_t>::min() ||
        displacement64 > std::numeric_limits<std::int32_t>::max()) {
        Log("Allocated relay is outside rel32 range; patch not installed.");
        return false;
    }
    const std::int32_t displacement = static_cast<std::int32_t>(displacement64);
    unsigned char patch[5] = {0xE8};
    memcpy(patch + 1, &displacement, sizeof(displacement));

    DWORD oldProtection = 0;
    if (!VirtualProtect(callsite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtection)) {
        Log("VirtualProtect failed at the view-copy call site; patch not installed.");
        return false;
    }
    memcpy(callsite, patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), callsite, sizeof(patch));
    DWORD ignored = 0;
    VirtualProtect(callsite, sizeof(patch), oldProtection, &ignored);

    Log("Installed Dishonored 2 high-FPS camera hook at RVA 0x%llX; F10 toggles it.",
        static_cast<unsigned long long>(g_layout->copyCallsiteRva));
    return true;
}

// Diagnostics: DevGUI keeps its own text drawer (0x784A0: this, x, y, scale,
// const float* color, const char* text, int alignment), separate from the stripped debug
// DrawString. While the overlay is on, the first distinct strings it is asked
// to draw are logged, to see whether DevGUI's menu data exists.
constexpr std::uintptr_t kSteamDevGuiTextRva = 0x784A0;
constexpr std::size_t kSteamDevGuiTextHookLength = 18;
constexpr unsigned char kSteamDevGuiTextBytes[kSteamDevGuiTextHookLength] = {
    0x48, 0x8B, 0xC4,
    0xF3, 0x0F, 0x11, 0x50, 0x18,
    0x55, 0x56, 0x57,
    0x48, 0x81, 0xEC, 0x20, 0x01, 0x00, 0x00,
};
// Two extra stack arguments are forwarded untouched in case a caller passes more.
using DevGuiTextFn = std::uint64_t(__fastcall*)(void*, float, float, float, const float*,
                                                const char*, std::uint64_t, std::uint64_t,
                                                std::uint64_t);
DevGuiTextFn g_originalDevGuiText = nullptr;
std::atomic<int> g_devGuiTextLogged{0};

extern "C" std::uint64_t __fastcall HookDevGuiText(void* self, float x, float y, float scale,
                                                   const float* color, const char* text,
                                                   std::uint64_t seventh, std::uint64_t eighth,
                                                   std::uint64_t ninth) {
    if (g_devGuiTextLogged.load(std::memory_order_relaxed) < 24) {
        char sample[96]{};
        if (text != nullptr && IsReadableMemory(text, 1)) {
            std::size_t length = 0;
            while (length + 1 < sizeof(sample) && IsReadableMemory(text + length, 1) &&
                   text[length] != '\0') {
                const char character = text[length];
                sample[length] = (character >= 32 && character < 127) ? character : '?';
                ++length;
            }
        }
        static char last[96]{};
        if (strcmp(sample, last) != 0) {
            strcpy_s(last, sample);
            g_devGuiTextLogged.fetch_add(1, std::memory_order_relaxed);
            Log("DevGUI text: (%.0f, %.0f) scale %.2f \"%s\"", x, y, scale, sample);
        }
    }
    RecordDevGuiText(x, y, scale, color, text, static_cast<int>(seventh));
    return g_originalDevGuiText(self, x, y, scale, color, text, seventh, eighth, ninth);
}

// The DevGUI pass, hooked only to mark DevGUI frames for the replay above.
constexpr std::uintptr_t kSteamDevGuiPassRva = 0x8989F0;
constexpr std::size_t kSteamDevGuiPassHookLength = 18;
constexpr unsigned char kSteamDevGuiPassBytes[kSteamDevGuiPassHookLength] = {
    0x40, 0x57,
    0x48, 0x81, 0xEC, 0x60, 0x05, 0x00, 0x00,
    0x48, 0xC7, 0x44, 0x24, 0x30, 0xFE, 0xFF, 0xFF, 0xFF,
};
using DevGuiPassFn = void*(__fastcall*)(void*);
DevGuiPassFn g_originalDevGuiPass = nullptr;

extern "C" void* __fastcall HookDevGuiPass(void* self) {
    g_inDevGuiPass = true;
    void* context = g_originalDevGuiPass(self);
    g_inDevGuiPass = false;
    PublishDevGuiText();
    return context;
}

// The devgui cvar (Steam): 0 off, 1 on, 2 on with the key legend.
constexpr std::uintptr_t kSteamDevGuiCvarRva = 0x39A4FE0;
constexpr char kDevGuiCvarName[] = "devgui";

// Returns the devgui cvar after checking its name, or null.
unsigned char* FindDevGuiCvar() {
    if (g_layout != &kSteamLayout || g_originalDevGuiPass == nullptr) {
        return nullptr;
    }
    auto* cvar = reinterpret_cast<unsigned char*>(g_executableBase + kSteamDevGuiCvarRva);
    const char* name = nullptr;
    memcpy(&name, cvar + kCVarNameOffset, sizeof(name));
    if (name == nullptr || !IsReadableMemory(name, sizeof(kDevGuiCvarName)) ||
        memcmp(name, kDevGuiCvarName, sizeof(kDevGuiCvarName)) != 0) {
        return nullptr;
    }
    return cvar;
}

void SetDevGuiCvar(unsigned char* cvar, LONG value) {
    *reinterpret_cast<volatile float*>(cvar + kCVarFloatOffset) = static_cast<float>(value);
    InterlockedExchange(reinterpret_cast<volatile LONG*>(cvar + kCVarIntegerOffset), value);
}

// DevGUI closes itself on Esc (and = and a pad button) once it has input
// focus (handler 0x899050 sets devgui 0). As a fallback, also covering the
// frames before it takes focus, an Esc press while devgui is above 0 sets it
// to 0 here (Diagnostics/DevGuiEscapeFallback).
void CloseDevGuiOnEscape() {
    if (!g_devGuiEscapeFallback) {
        return;
    }
    static bool escapeWasDown = false;
    const bool escapeIsDown = (GetAsyncKeyState(VK_ESCAPE) & 0x8000) != 0;
    const bool pressed = escapeIsDown && !escapeWasDown;
    escapeWasDown = escapeIsDown;
    if (!pressed) {
        return;
    }
    unsigned char* cvar = FindDevGuiCvar();
    if (cvar == nullptr) {
        return;
    }
    LONG current = 0;
    memcpy(&current, cvar + kCVarIntegerOffset, sizeof(current));
    if (current <= 0) {
        return;
    }
    SetDevGuiCvar(cvar, 0);
    PlayToggleCue(ToggleCue::Off);
    Log("Esc: DevGUI closed (devgui 0).");
}

void ToggleDevGui() {
    unsigned char* cvar = FindDevGuiCvar();
    if (cvar == nullptr) {
        PlayToggleCue(ToggleCue::Unavailable);
        Log("Ctrl+F10: the devgui cvar was not found.");
        return;
    }
    LONG current = 0;
    memcpy(&current, cvar + kCVarIntegerOffset, sizeof(current));
    const LONG value = current > 0 ? 0 : 2;
    if (value != 0 && ClosePauseMenu()) {
        Log("Ctrl+F10: closed the pause menu for DevGUI.");
    }
    SetDevGuiCvar(cvar, value);
    PlayToggleCue(value != 0 ? ToggleCue::On : ToggleCue::Off);
    Log("Ctrl+F10: DevGUI %s.", value != 0 ? "opened (devgui 2)" : "closed (devgui 0)");
}

bool InstallInlineHook(std::uintptr_t rva, const unsigned char* expected, std::size_t length,
                       const void* hook, void** original, const char* description) {
    auto* entry = reinterpret_cast<unsigned char*>(g_executableBase + rva);
    if (memcmp(entry, expected, length) != 0) {
        Log("%s hook bytes do not match; not installed.", description);
        return false;
    }
    auto* trampoline = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (trampoline == nullptr) {
        return false;
    }
    memcpy(trampoline, entry, length);
    WriteAbsoluteIndirectJump(trampoline + length, entry + length);
    FlushInstructionCache(GetCurrentProcess(), trampoline, length + 14);
    unsigned char patch[kMaximumHookLength];
    memset(patch, 0x90, sizeof(patch));
    WriteAbsoluteIndirectJump(patch, hook);
    DWORD oldProtection = 0;
    if (!VirtualProtect(entry, length, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return false;
    }
    *original = trampoline;
    memcpy(entry, patch, length);
    FlushInstructionCache(GetCurrentProcess(), entry, length);
    DWORD ignored = 0;
    VirtualProtect(entry, length, oldProtection, &ignored);
    Log("Installed the %s hook at RVA 0x%llX.", description,
        static_cast<unsigned long long>(rva));
    return true;
}

// Pause menu. Its DevGUI button is gone from the retail ActionScript, but the
// exe's "DevGUI" callback (0x78F140) still closes the pause state and runs
// devgui 1. The pause state's show method (vtable slot 0x1C61678 -> 0x78F170)
// is wrapped to remember the state object, and the game counts as sitting in
// the pause menu when it was shown after the last simulation tick. Ctrl+F10
// there closes the pause menu the same way the callback does
// (0x7885B0(state+8, 1)) and opens DevGUI.
constexpr std::uintptr_t kSteamPauseShowSlotRva = 0x1C61678;
constexpr std::uintptr_t kSteamPauseShowRva = 0x78F170;
constexpr std::uintptr_t kSteamPauseCloseRva = 0x7885B0;
constexpr unsigned char kSteamPauseDevGuiCallbackBytes[16] = {
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x49, 0x08,
    0xBA, 0x01, 0x00, 0x00, 0x00, 0xE8, 0x5E, 0x94,
};
constexpr std::uintptr_t kSteamPauseDevGuiCallbackRva = 0x78F140;
using PauseShowFn = std::uint64_t(__fastcall*)(void*, void*, void*, void*);
using PauseCloseFn = void(__fastcall*)(void*, int);
PauseShowFn g_originalPauseShow = nullptr;
std::atomic<void*> g_pauseState{nullptr};
std::atomic<std::uint64_t> g_pauseShownCounter{0};
std::atomic<std::uint64_t> g_lastSimulationAdvanceCounter{0};
double g_lastSimulationTime = 0.0;

void NoteSimulationTime(double simulationTime) {
    if (simulationTime != g_lastSimulationTime) {
        g_lastSimulationTime = simulationTime;
        g_lastSimulationAdvanceCounter.store(ReadPerformanceCounter(),
                                             std::memory_order_relaxed);
    }
}

extern "C" std::uint64_t __fastcall HookPauseShow(void* state, void* second, void* third,
                                                  void* fourth) {
    g_pauseState.store(state, std::memory_order_relaxed);
    g_pauseShownCounter.store(ReadPerformanceCounter(), std::memory_order_relaxed);
    return g_originalPauseShow(state, second, third, fourth);
}

bool PauseMenuIsOpen() {
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    const std::uint64_t now = ReadPerformanceCounter();
    const std::uint64_t lastTick = g_lastSimulationAdvanceCounter.load(std::memory_order_relaxed);
    return g_originalPauseShow != nullptr &&
           g_pauseState.load(std::memory_order_relaxed) != nullptr &&
           g_pauseShownCounter.load(std::memory_order_relaxed) > lastTick &&
           now - lastTick > static_cast<std::uint64_t>(frequency.QuadPart / 5);
}

bool ClosePauseMenu() {
    if (!PauseMenuIsOpen()) {
        return false;
    }
    auto* state = static_cast<unsigned char*>(g_pauseState.load(std::memory_order_relaxed));
    void* owner = nullptr;
    if (!IsReadableMemory(state + 8, sizeof(owner))) {
        return false;
    }
    memcpy(&owner, state + 8, sizeof(owner));
    if (owner == nullptr) {
        return false;
    }
    reinterpret_cast<PauseCloseFn>(g_executableBase + kSteamPauseCloseRva)(owner, 1);
    g_pauseShownCounter.store(0, std::memory_order_relaxed);
    return true;
}

bool InstallPauseMenuHook() {
    if (memcmp(reinterpret_cast<const void*>(g_executableBase + kSteamPauseDevGuiCallbackRva),
               kSteamPauseDevGuiCallbackBytes, sizeof(kSteamPauseDevGuiCallbackBytes)) != 0) {
        Log("Pause menu: DevGUI callback bytes do not match; Ctrl+F10 will not close it.");
        return false;
    }
    g_originalPauseShow = reinterpret_cast<PauseShowFn>(g_executableBase + kSteamPauseShowRva);
    if (!ReplaceVtableSlot(g_executableBase + kSteamPauseShowSlotRva,
                           g_executableBase + kSteamPauseShowRva,
                           reinterpret_cast<const void*>(&HookPauseShow))) {
        g_originalPauseShow = nullptr;
        Log("Pause menu: unable to replace the show slot; Ctrl+F10 will not close it.");
        return false;
    }
    Log("Pause menu: Ctrl+F10 in the pause menu closes it and opens DevGUI.");
    return true;
}

// Camera blood (Diagnostics/ForceBloodEffect, Alt+F10). The player FX
// manager's arkPlayerFXCameraBlood (vtable 0x1C3A6D8) plays m_bloodLightFx
// (decl +0x298) on ARK_MSG_DAMAGING when the player hurts a valid target, and
// m_bloodHeavyFx (decl +0x2A0) on ARK_MSG_ASSASSINATION_TARGET_KILLED. Both are
// "screen particle" FX whose emitter is placed each tick at the game camera
// plus pm_screenParticleOffset (3.2) along its forward axis. The toggle keeps
// the heavy effect playing by starting it again (same play call, 0x8120B0)
// whenever it is no longer alive (0x878C30); the instance is captured from the
// class's init slot and dropped by its shutdown slot.
constexpr std::uintptr_t kSteamCameraBloodVtableRva = 0x1C3A6D8;
constexpr std::uintptr_t kSteamCameraBloodInitRva = 0x680800;
constexpr std::uintptr_t kSteamCameraBloodShutdownRva = 0x6808B0;
constexpr std::uintptr_t kSteamFxPlayRva = 0x8120B0;
constexpr std::uintptr_t kSteamFxAliveRva = 0x878C30;
constexpr unsigned char kSteamFxPlayBytes[16] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C,
    0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57,
};
constexpr unsigned char kSteamFxAliveBytes[8] = {
    0x89, 0x54, 0x24, 0x10, 0x48, 0x83, 0xEC, 0x28,
};
constexpr std::size_t kCameraBloodFxComponentOffset = 0x10;
constexpr std::size_t kCameraBloodDeclOffset = 0x18;
constexpr std::size_t kCameraBloodHeavyIdOffset = 0x24;
constexpr std::size_t kCameraBloodHeavyDeclFieldOffset = 0x2A0;
using CameraBloodLifecycleFn = void(__fastcall*)(void*);
using FxPlayFn = std::int32_t*(__fastcall*)(void*, std::int32_t*, const void*);
using FxAliveFn = bool(__fastcall*)(void*, std::int32_t);
CameraBloodLifecycleFn g_originalCameraBloodInit = nullptr;
CameraBloodLifecycleFn g_originalCameraBloodShutdown = nullptr;
std::atomic<void*> g_cameraBlood{nullptr};
std::uint64_t g_lastForcedBloodCounter = 0;

extern "C" void __fastcall HookCameraBloodInit(void* self) {
    g_cameraBlood.store(self, std::memory_order_relaxed);
    g_originalCameraBloodInit(self);
}

extern "C" void __fastcall HookCameraBloodShutdown(void* self) {
    void* expected = self;
    g_cameraBlood.compare_exchange_strong(expected, nullptr, std::memory_order_relaxed);
    g_originalCameraBloodShutdown(self);
}

bool InstallCameraBloodHooks() {
    if (g_layout != &kSteamLayout ||
        memcmp(reinterpret_cast<const void*>(g_executableBase + kSteamFxPlayRva),
               kSteamFxPlayBytes, sizeof(kSteamFxPlayBytes)) != 0 ||
        memcmp(reinterpret_cast<const void*>(g_executableBase + kSteamFxAliveRva),
               kSteamFxAliveBytes, sizeof(kSteamFxAliveBytes)) != 0) {
        return false;
    }
    const std::uintptr_t vtable = g_executableBase + kSteamCameraBloodVtableRva;
    g_originalCameraBloodInit = reinterpret_cast<CameraBloodLifecycleFn>(
        g_executableBase + kSteamCameraBloodInitRva);
    g_originalCameraBloodShutdown = reinterpret_cast<CameraBloodLifecycleFn>(
        g_executableBase + kSteamCameraBloodShutdownRva);
    if (!ReplaceVtableSlot(vtable + 1 * sizeof(void*), g_executableBase + kSteamCameraBloodInitRva,
                           reinterpret_cast<const void*>(&HookCameraBloodInit))) {
        Log("Camera blood: init slot mismatch; ForceBloodEffect unavailable.");
        return false;
    }
    if (!ReplaceVtableSlot(vtable + 2 * sizeof(void*),
                           g_executableBase + kSteamCameraBloodShutdownRva,
                           reinterpret_cast<const void*>(&HookCameraBloodShutdown))) {
        ReplaceVtableSlot(vtable + 1 * sizeof(void*),
                          reinterpret_cast<std::uintptr_t>(&HookCameraBloodInit),
                          reinterpret_cast<const void*>(g_executableBase +
                                                        kSteamCameraBloodInitRva));
        Log("Camera blood: shutdown slot mismatch; ForceBloodEffect unavailable.");
        return false;
    }
    Log("Camera blood: hooked arkPlayerFXCameraBlood init/shutdown; Alt+F10 toggles "
        "ForceBloodEffect (now %s).",
        g_forceBloodEffect.load(std::memory_order_relaxed) ? "on" : "off");
    return true;
}

void ToggleForcedBloodEffect() {
    if (g_originalCameraBloodInit == nullptr) {
        PlayToggleCue(ToggleCue::Unavailable);
        return;
    }
    const bool now = !g_forceBloodEffect.load(std::memory_order_relaxed);
    g_forceBloodEffect.store(now, std::memory_order_relaxed);
    PlayToggleCue(now ? ToggleCue::On : ToggleCue::Off);
    Log("Alt+F10: ForceBloodEffect %s.", now ? "on" : "off");
}

// Runs on the game thread (camera hook). Restarts the heavy camera blood at
// most every 250 ms while it is not alive.
void UpdateForcedBloodEffect() {
    if (!g_forceBloodEffect.load(std::memory_order_relaxed) ||
        g_originalCameraBloodInit == nullptr) {
        return;
    }
    auto* blood = static_cast<unsigned char*>(g_cameraBlood.load(std::memory_order_relaxed));
    if (blood == nullptr || !IsReadableMemory(blood, kCameraBloodHeavyIdOffset + 4)) {
        return;
    }
    const std::uint64_t now = ReadPerformanceCounter();
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    if (now - g_lastForcedBloodCounter < static_cast<std::uint64_t>(frequency.QuadPart / 4)) {
        return;
    }
    g_lastForcedBloodCounter = now;
    void* fxComponent = nullptr;
    unsigned char* decl = nullptr;
    memcpy(&fxComponent, blood + kCameraBloodFxComponentOffset, sizeof(fxComponent));
    memcpy(&decl, blood + kCameraBloodDeclOffset, sizeof(decl));
    if (fxComponent == nullptr || decl == nullptr ||
        !IsReadableMemory(decl + kCameraBloodHeavyDeclFieldOffset, sizeof(void*))) {
        return;
    }
    void* heavyFx = nullptr;
    memcpy(&heavyFx, decl + kCameraBloodHeavyDeclFieldOffset, sizeof(heavyFx));
    if (heavyFx == nullptr) {
        return;
    }
    std::int32_t id = -1;
    memcpy(&id, blood + kCameraBloodHeavyIdOffset, sizeof(id));
    if (id != -1 && reinterpret_cast<FxAliveFn>(g_executableBase + kSteamFxAliveRva)(
                        nullptr, id)) {
        return;
    }
    std::int32_t started = -1;
    reinterpret_cast<FxPlayFn>(g_executableBase + kSteamFxPlayRva)(fxComponent, &started,
                                                                    heavyFx);
    memcpy(blood + kCameraBloodHeavyIdOffset, &started, sizeof(started));
}

// Diagnostics: Iggy callback registration (0x2CD20: context, name, function,
// user data). The pause menu's "DevGUI" and "ResumeGame" callbacks are wrapped
// to log when the menu's script actually sends them.
constexpr std::uintptr_t kSteamIggyRegisterCallbackRva = 0x2CD20;
constexpr unsigned char kSteamIggyRegisterCallbackBytes[15] = {
    0x40, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0xC7, 0x44, 0x24, 0x30, 0xFE, 0xFF, 0xFF, 0xFF,
};
using IggyCallbackFn = std::uint64_t(__fastcall*)(void*, void*, void*, void*);
using IggyRegisterCallbackFn = std::uint64_t(__fastcall*)(void*, const char*, void*, void*);
IggyRegisterCallbackFn g_originalIggyRegisterCallback = nullptr;
std::atomic<IggyCallbackFn> g_originalDevGuiCallback{nullptr};
std::atomic<IggyCallbackFn> g_originalResumeCallback{nullptr};

extern "C" std::uint64_t __fastcall HookDevGuiCallback(void* a, void* b, void* c, void* d) {
    Log("Pause menu: the \"DevGUI\" callback was called by the menu script.");
    return g_originalDevGuiCallback.load()(a, b, c, d);
}

extern "C" std::uint64_t __fastcall HookResumeCallback(void* a, void* b, void* c, void* d) {
    Log("Pause menu: the \"ResumeGame\" callback was called by the menu script.");
    return g_originalResumeCallback.load()(a, b, c, d);
}

extern "C" std::uint64_t __fastcall HookIggyRegisterCallback(void* context, const char* name,
                                                             void* function, void* user) {
    if (name != nullptr && IsReadableMemory(name, 11)) {
        if (strcmp(name, "DevGUI") == 0) {
            g_originalDevGuiCallback.store(reinterpret_cast<IggyCallbackFn>(function));
            function = reinterpret_cast<void*>(&HookDevGuiCallback);
            Log("Pause menu: \"DevGUI\" callback registered (handler RVA 0x%llX).",
                static_cast<unsigned long long>(
                    reinterpret_cast<std::uintptr_t>(g_originalDevGuiCallback.load()) -
                    g_executableBase));
        } else if (strcmp(name, "ResumeGame") == 0) {
            g_originalResumeCallback.store(reinterpret_cast<IggyCallbackFn>(function));
            function = reinterpret_cast<void*>(&HookResumeCallback);
        }
    }
    return g_originalIggyRegisterCallback(context, name, function, user);
}

bool InstallIggyCallbackLogHook() {
    void* original = nullptr;
    if (g_layout != &kSteamLayout ||
        !InstallInlineHook(kSteamIggyRegisterCallbackRva, kSteamIggyRegisterCallbackBytes,
                           sizeof(kSteamIggyRegisterCallbackBytes),
                           reinterpret_cast<const void*>(&HookIggyRegisterCallback), &original,
                           "Iggy callback registration (log)")) {
        return false;
    }
    g_originalIggyRegisterCallback = reinterpret_cast<IggyRegisterCallbackFn>(original);
    return true;
}

// The exe's "DevGUI" pause callback (0x78F140): it closes the pause state and
// buffers the console command "devgui 1", which the retail command system
// does not apply (the cvar stays 0). After it runs, the plugin sets devgui to
// 2 itself. Its 4th instruction is a rel32 call, so the trampoline replays it
// as an absolute call.
constexpr std::uintptr_t kSteamPauseDevGuiCallbackEntryRva = 0x78F140;
constexpr unsigned char kSteamPauseDevGuiCallbackEntryBytes[18] = {
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x49, 0x08, 0xBA, 0x01, 0x00, 0x00, 0x00,
    0xE8, 0x5E, 0x94, 0xFF, 0xFF,
};
using PauseCallbackFn = std::uint64_t(__fastcall*)(void*, void*, void*, void*);
PauseCallbackFn g_originalPauseDevGuiCallback = nullptr;

extern "C" std::uint64_t __fastcall HookPauseDevGuiCallback(void* a, void* b, void* c, void* d) {
    const std::uint64_t result = g_originalPauseDevGuiCallback(a, b, c, d);
    unsigned char* cvar = FindDevGuiCvar();
    if (cvar != nullptr) {
        SetDevGuiCvar(cvar, 2);
        PlayToggleCue(ToggleCue::On);
        Log("Pause menu: Dev GUI chosen; opened DevGUI (devgui 2).");
    } else {
        Log("Pause menu: Dev GUI chosen, but the devgui cvar was not found.");
    }
    return result;
}

bool InstallPauseDevGuiCallbackHook() {
    if (g_layout != &kSteamLayout) {
        return false;
    }
    auto* entry = reinterpret_cast<unsigned char*>(g_executableBase +
                                                   kSteamPauseDevGuiCallbackEntryRva);
    if (memcmp(entry, kSteamPauseDevGuiCallbackEntryBytes,
               sizeof(kSteamPauseDevGuiCallbackEntryBytes)) != 0) {
        return false;
    }
    auto* trampoline = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (trampoline == nullptr) {
        return false;
    }
    std::int32_t relative = 0;
    memcpy(&relative, entry + 14, sizeof(relative));
    const std::uintptr_t callTarget = reinterpret_cast<std::uintptr_t>(entry) + 18 + relative;
    unsigned char* cursor = trampoline;
    memcpy(cursor, entry, 13);
    cursor += 13;
    // call qword ptr [rip+2]; jmp +8; dq target
    const unsigned char callAbsolute[] = {0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08};
    memcpy(cursor, callAbsolute, sizeof(callAbsolute));
    cursor += sizeof(callAbsolute);
    memcpy(cursor, &callTarget, sizeof(callTarget));
    cursor += sizeof(callTarget);
    WriteAbsoluteIndirectJump(cursor, entry + 18);
    FlushInstructionCache(GetCurrentProcess(), trampoline, 0x40);
    unsigned char patch[18];
    memset(patch, 0x90, sizeof(patch));
    WriteAbsoluteIndirectJump(patch, reinterpret_cast<const void*>(&HookPauseDevGuiCallback));
    DWORD oldProtection = 0;
    if (!VirtualProtect(entry, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtection)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return false;
    }
    g_originalPauseDevGuiCallback = reinterpret_cast<PauseCallbackFn>(trampoline);
    memcpy(entry, patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), entry, sizeof(patch));
    DWORD ignored = 0;
    VirtualProtect(entry, sizeof(patch), oldProtection, &ignored);
    Log("Installed the pause-menu DevGUI callback log hook at RVA 0x78F140.");
    return true;
}

bool InstallDevGuiTextLogHook() {
    if (g_layout != &kSteamLayout) {
        return false;
    }
    void* original = nullptr;
    if (!InstallInlineHook(kSteamDevGuiTextRva, kSteamDevGuiTextBytes,
                           kSteamDevGuiTextHookLength,
                           reinterpret_cast<const void*>(&HookDevGuiText), &original,
                           "DevGUI text")) {
        return false;
    }
    g_originalDevGuiText = reinterpret_cast<DevGuiTextFn>(original);
    if (InstallInlineHook(kSteamDevGuiPassRva, kSteamDevGuiPassBytes,
                          kSteamDevGuiPassHookLength,
                          reinterpret_cast<const void*>(&HookDevGuiPass), &original,
                          "DevGUI pass")) {
        g_originalDevGuiPass = reinterpret_cast<DevGuiPassFn>(original);
        Log("DevGUI: Ctrl+F10 opens/closes it; it is drawn by the D3D11 overlay.");
        InstallPauseMenuHook();
    }
    return true;
}


// Diagnostics/CrashLog: a first-chance vectored handler that logs fatal-looking
// exceptions (access violations and similar) with the faulting module offset,
// the argument registers, and return addresses found on the stack. It never
// handles the exception; the game's own handling continues unchanged.
std::atomic<int> g_crashLogCount{0};

void DescribeCodeAddress(std::uintptr_t address, char* output, std::size_t capacity) {
    HMODULE module = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(address), &module) &&
        module != nullptr) {
        char path[MAX_PATH]{};
        GetModuleFileNameA(module, path, MAX_PATH);
        const char* name = strrchr(path, '\\');
        name = name != nullptr ? name + 1 : path;
        sprintf_s(output, capacity, "%s+0x%llX", name,
                  static_cast<unsigned long long>(
                      address - reinterpret_cast<std::uintptr_t>(module)));
        return;
    }
    sprintf_s(output, capacity, "0x%llX", static_cast<unsigned long long>(address));
}

bool IsInLoadedImage(std::uintptr_t address) {
    HMODULE module = nullptr;
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                  GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              reinterpret_cast<LPCWSTR>(address), &module) &&
           (module == reinterpret_cast<HMODULE>(g_executableBase) ||
            module == g_pluginModule);
}

LONG CALLBACK CrashLogHandler(EXCEPTION_POINTERS* info) {
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_PRIV_INSTRUCTION && code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
        code != EXCEPTION_STACK_OVERFLOW && code != EXCEPTION_IN_PAGE_ERROR &&
        code != 0xC0000409 && code != 0xE06D7363 && code != 0x80000003 &&
        code != 0xC0000374 && code != 0xC000041D) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (g_crashLogCount.fetch_add(1, std::memory_order_relaxed) >= 12) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const CONTEXT& context = *info->ContextRecord;
    char where[MAX_PATH + 32]{};
    DescribeCodeAddress(reinterpret_cast<std::uintptr_t>(
                            info->ExceptionRecord->ExceptionAddress), where, sizeof(where));
    char access[96]{};
    if (code == EXCEPTION_ACCESS_VIOLATION &&
        info->ExceptionRecord->NumberParameters >= 2) {
        const ULONG_PTR kind = info->ExceptionRecord->ExceptionInformation[0];
        sprintf_s(access, " (%s 0x%llX)",
                  kind == 0 ? "read" : kind == 1 ? "write" : "execute",
                  static_cast<unsigned long long>(
                      info->ExceptionRecord->ExceptionInformation[1]));
    }
    Log("CrashLog: exception 0x%08lX at %s%s on thread %lu.", code, where, access,
        GetCurrentThreadId());
    Log("CrashLog:   rax=%llX rbx=%llX rcx=%llX rdx=%llX rsi=%llX rdi=%llX",
        context.Rax, context.Rbx, context.Rcx, context.Rdx, context.Rsi, context.Rdi);
    Log("CrashLog:   r8=%llX r9=%llX r10=%llX r11=%llX rsp=%llX rbp=%llX",
        context.R8, context.R9, context.R10, context.R11, context.Rsp, context.Rbp);
    if (code == EXCEPTION_STACK_OVERFLOW) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const auto* stack = reinterpret_cast<const std::uintptr_t*>(context.Rsp);
    int found = 0;
    for (int slot = 0; slot < 256 && found < 16; ++slot) {
        if (!IsReadableMemory(stack + slot, sizeof(std::uintptr_t))) {
            break;
        }
        const std::uintptr_t value = stack[slot];
        if (value < 0x10000 || !IsInLoadedImage(value)) {
            continue;
        }
        char frame[MAX_PATH + 32]{};
        DescribeCodeAddress(value, frame, sizeof(frame));
        Log("CrashLog:   stack[+0x%X] %s", slot * 8, frame);
        ++found;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

DWORD WINAPI InstallThread(void*) {
    g_executableBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    if (!ValidateWorldTransformInterpolationMath()) {
        Log("World-transform interpolation self-test failed; hooks were not installed.");
        return 0;
    }
    if (g_executableBase == 0) {
        return 0;
    }
    LoadConfiguration();
    if (g_crashLog && AddVectoredExceptionHandler(1, CrashLogHandler) != nullptr) {
        Log("CrashLog: first-chance exception logging is on.");
    }
    if (!VerifyExecutableLayout()) {
        return 0;
    }
    if (g_enableTelemetry) {
        InitializeTelemetry();
    }
    if (InstallHook()) {
        InstallSourceLevelHooks();
        if (g_sourceLevelInstalled) {
            InstallScreenParticleHook();
        }
        // In source mode both the world and first-person layers run after the
        // flush; the per-draw hook is kept only for the A/B comparison.
        const bool perDrawNeeded =
            !(g_sourceLevelInstalled && g_sourceLevelWrites &&
              (g_sourceLevelHands || !g_stabilizeFirstPersonHands)) ||
            g_enableInterpolationAbProbe;
        if (perDrawNeeded) {
            InstallRenderModelGpuCopyHook();
        } else {
            g_renderModelGpuCopyHookSkipped = true;
            Log("Renderer model GPU-copy hook not installed: source-level world and "
                "first-person transforms run after the render-world flush.");
        }
        InstallSkinnedPoseUploadHook();
        InstallShadowCasterBuildHooks();
        if (g_overlay) {
            InstallDevGuiTextLogHook();
            InstallIggyCallbackLogHook();
            InstallPauseDevGuiCallbackHook();
        }
        InstallCameraBloodHooks();
    }
    return 0;
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_pluginModule = module;
        DisableThreadLibraryCalls(module);
        if (!g_initializationStarted.exchange(true, std::memory_order_acq_rel)) {
            HANDLE thread = CreateThread(nullptr, 0, InstallThread, nullptr, 0, nullptr);
            if (thread != nullptr) {
                CloseHandle(thread);
            }
        }
    }
    return TRUE;
}
