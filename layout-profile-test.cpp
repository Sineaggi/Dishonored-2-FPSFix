// Offline layout-profile test. Maps a real Dishonored2.exe image into this
// process without running any of its code, then runs the plugin's own profile
// selection, strict validation, and hook installation against that private
// mapping. The executable file on disk is never modified.
#include "d2_high_fps_fix.cpp"

namespace {

int Fail(const char* message) {
    std::fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

bool IsAbsoluteJumpTo(const unsigned char* code, const void* target) {
    std::uintptr_t address = 0;
    memcpy(&address, code + 6, sizeof(address));
    return code[0] == 0xFF && code[1] == 0x25 && code[2] == 0 && code[3] == 0 &&
           code[4] == 0 && code[5] == 0 &&
           address == reinterpret_cast<std::uintptr_t>(target);
}

bool IsNopPadded(const unsigned char* code, std::size_t length) {
    for (std::size_t index = kAbsoluteJumpLength; index < length; ++index) {
        if (code[index] != 0x90) {
            return false;
        }
    }
    return true;
}

// The entry must jump to the hook, and the trampoline must replay the
// profile's original bytes before resuming just after the patched entry.
bool HookIsInstalled(std::uintptr_t rva, const unsigned char* originalBytes,
                     std::size_t length, const void* hook, const void* trampoline) {
    const auto* entry = reinterpret_cast<const unsigned char*>(g_executableBase + rva);
    const auto* replay = static_cast<const unsigned char*>(trampoline);
    return trampoline != nullptr && IsAbsoluteJumpTo(entry, hook) &&
           IsNopPadded(entry, length) && memcmp(replay, originalBytes, length) == 0 &&
           IsAbsoluteJumpTo(replay + length, entry + length);
}

bool NameMatches(const char* name, const wchar_t* expected) {
    for (; *name != '\0' && *expected != L'\0'; ++name, ++expected) {
        if (static_cast<wchar_t>(static_cast<unsigned char>(*name)) != *expected) {
            return false;
        }
    }
    return *name == '\0' && *expected == L'\0';
}

}  // namespace

int wmain(int argumentCount, wchar_t** arguments) {
    if (argumentCount != 3) {
        std::fwprintf(stderr,
                      L"Usage: layout-profile-test.exe <path-to-Dishonored2.exe> "
                      L"<expected-profile-name>\n");
        return 2;
    }

    HMODULE image = LoadLibraryExW(arguments[1], nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (image == nullptr) {
        std::fwprintf(stderr, L"Unable to map %ls: %lu\n", arguments[1], GetLastError());
        return 3;
    }
    g_executableBase = reinterpret_cast<std::uintptr_t>(image);

    // Enable every correction path so every location in the profile is checked.
    g_unlockAbove120 = true;
    g_stabilizeMouseSensitivity = true;
    g_stabilizeFirstPersonHands = true;
    g_interpolateWorldTransforms = true;
    g_interpolateCinematicTransforms = true;
    g_interpolateShadowTransforms = true;
    g_interpolateFirstPersonSkeletons = true;
    g_interpolateWorldSkeletons = true;
    g_interpolateCinematicSkeletons = true;
    g_enableAdaptiveInterpolation = true;
    g_fullInterpolationInCutscenes = true;

    LogExecutableHash(arguments[1]);
    if (!ValidateExecutableImageLayout()) {
        return Fail("strict layout validation rejected the executable");
    }
    if (!NameMatches(g_layout->name, arguments[2])) {
        std::fprintf(stderr, "FAIL: selected profile '%s'\n", g_layout->name);
        return 1;
    }

    ExecutableImageLayout layout{};
    if (!ReadExecutableImageLayout(layout)) {
        return Fail("unable to re-read the image layout");
    }
    int anchorMatches = 0;
    for (const LayoutProfile& profile : kLayoutProfiles) {
        anchorMatches += ViewCopyAnchorMatches(layout, profile) ? 1 : 0;
    }
    if (anchorMatches != 1) {
        return Fail("profile anchors are not mutually exclusive");
    }
    if (g_interpolateShadowTransforms != g_layout->hasShadowCasterBuild) {
        return Fail("shadow-layer availability does not follow the profile");
    }

    if (!InstallHook()) {
        return Fail("view-copy call-site hook was not installed");
    }
    const auto* callsite = reinterpret_cast<const unsigned char*>(
        g_executableBase + g_layout->copyCallsiteRva);
    std::int32_t displacement = 0;
    memcpy(&displacement, callsite + 1, sizeof(displacement));
    const auto* relay = static_cast<const unsigned char*>(g_relay);
    std::uintptr_t relayTarget = 0;
    memcpy(&relayTarget, relay + 2, sizeof(relayTarget));
    if (callsite[0] != 0xE8 ||
        reinterpret_cast<std::uintptr_t>(callsite) + 5 + displacement !=
            reinterpret_cast<std::uintptr_t>(g_relay) ||
        relay[0] != 0x48 || relay[1] != 0xB8 || relay[10] != 0xFF || relay[11] != 0xE0 ||
        relayTarget != reinterpret_cast<std::uintptr_t>(&HookCopyView) ||
        reinterpret_cast<std::uintptr_t>(g_originalCopyView) !=
            g_executableBase + g_layout->copyViewRva) {
        return Fail("view-copy call site does not reach HookCopyView");
    }

    // Expect `lea rax,[rcx+clock+0xC8]; nop` between the unchanged neighbours.
    if (!InstallMouseLookDeltaPatch()) {
        return Fail("mouse-look delta patch was not installed");
    }
    const auto* look = reinterpret_cast<const unsigned char*>(
        g_executableBase + g_layout->mouseLookDeltaSiteRva);
    const unsigned char* lookPatch = look + kMouseLookDeltaPatchOffset;
    const std::size_t lookTail = kMouseLookDeltaPatchOffset + kMouseLookDeltaPatchLength;
    std::uint32_t lookDisplacement = 0;
    memcpy(&lookDisplacement, lookPatch + 3, sizeof(lookDisplacement));
    if (memcmp(look, kExpectedMouseLookDeltaSite, kMouseLookDeltaPatchOffset) != 0 ||
        lookPatch[0] != 0x48 || lookPatch[1] != 0x8D || lookPatch[2] != 0x81 ||
        lookDisplacement != kClockOffset + kSimulationTimerDeltaOffset ||
        lookPatch[7] != 0x66 || lookPatch[8] != 0x90 ||
        memcmp(look + lookTail, kExpectedMouseLookDeltaSite + lookTail,
               sizeof(kExpectedMouseLookDeltaSite) - lookTail) != 0) {
        return Fail("mouse-look delta read was not patched to the simulation timer");
    }

    if (!InstallRenderModelGpuCopyHook() ||
        !HookIsInstalled(g_layout->renderModelGpuCopyRva,
                         g_layout->renderModelGpuCopyBytes.data(),
                         g_layout->renderModelGpuCopyHookLength,
                         reinterpret_cast<const void*>(&HookRenderModelGpuCopy),
                         g_renderModelGpuCopyTrampoline)) {
        return Fail("renderer GPU-copy hook or trampoline is wrong");
    }

    if (!InstallSkinnedPoseUploadHook() ||
        !HookIsInstalled(g_layout->skinnedPoseUploadRva,
                         g_layout->skinnedPoseUploadBytes.data(),
                         g_layout->skinnedPoseUploadHookLength,
                         reinterpret_cast<const void*>(&HookSkinnedPoseUpload),
                         g_skinnedPoseUploadTrampoline)) {
        return Fail("skinned-pose upload hook or trampoline is wrong");
    }

    if (g_layout->hasShadowCasterBuild) {
        const std::array<const void*, 2> hooks = {
            reinterpret_cast<const void*>(&HookShadowCasterBuildA),
            reinterpret_cast<const void*>(&HookShadowCasterBuildB),
        };
        if (!InstallShadowCasterBuildHooks()) {
            return Fail("shadow caster-build hooks were not installed");
        }
        for (std::size_t index = 0; index < hooks.size(); ++index) {
            if (!HookIsInstalled(g_layout->shadowCasterBuildRvas[index],
                                 kExpectedShadowCasterBuildBytes[index],
                                 kShadowCasterBuildHookLength, hooks[index],
                                 g_shadowCasterBuildTrampolines[index])) {
                return Fail("shadow caster-build hook or trampoline is wrong");
            }
        }
    } else if (InstallShadowCasterBuildHooks()) {
        return Fail("shadow hooks were installed for a profile without them");
    }

    // Do not FreeLibrary: hooks in the mapping point into this process.
    std::printf("PASS: %s profile validated; camera, mouse-look, GPU-copy, skeletal%s hooks "
                "installed and verified on a private mapping.\n",
                g_layout->name, g_layout->hasShadowCasterBuild ? ", shadow" : "");
    return 0;
}
