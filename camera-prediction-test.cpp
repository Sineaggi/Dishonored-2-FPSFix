// Offline camera-prediction and slow-motion test. Drives the plugin's own
// camera predictor and slow-motion detector with synthetic frame cadences
// built from the engine's clock rules; no game files are needed.
#include "d2_high_fps_fix.cpp"

namespace {

int g_failures = 0;

void Check(bool condition, const char* format, ...) {
    if (condition) {
        return;
    }
    ++g_failures;
    va_list arguments;
    va_start(arguments, format);
    std::fprintf(stderr, "FAIL: ");
    std::vfprintf(stderr, format, arguments);
    std::fprintf(stderr, "\n");
    va_end(arguments);
}

// The camera predictor as shipped before RealTimeTurnPrediction. Without the
// real-time rule, PredictCamera must reproduce it bit for bit.
struct ReferencePredictionState {
    bool initialized = false;
    const void* sourceView = nullptr;
    double previousTime = 0.0;
    double currentTime = 0.0;
    Transform previous{};
    Transform current{};
};

void ReferenceReset(ReferencePredictionState& state, const void* source,
                    double simulationTime, const Transform& transform) {
    state.initialized = true;
    state.sourceView = source;
    state.previousTime = simulationTime;
    state.currentTime = simulationTime;
    state.previous = transform;
    state.current = transform;
}

bool ReferencePredict(ReferencePredictionState& state, const void* source,
                      double scaledTime, double simulationTime, const Transform& raw,
                      Transform& predicted, double& alpha) {
    if (!state.initialized || state.sourceView != source ||
        simulationTime < state.currentTime - kTimeEpsilon) {
        ReferenceReset(state, source, simulationTime, raw);
        return false;
    }
    if (simulationTime > state.currentTime + kTimeEpsilon) {
        const double interval = simulationTime - state.currentTime;
        if (interval > kMaximumStateInterval ||
            PositionDistance(state.current, raw) > kMaximumPositionJump ||
            RotationDistanceDegrees(state.current, raw) > kMaximumRotationJumpDegrees) {
            ReferenceReset(state, source, simulationTime, raw);
            return false;
        }
        state.previousTime = state.currentTime;
        state.previous = state.current;
        state.currentTime = simulationTime;
        state.current = raw;
    }
    const double interval = state.currentTime - state.previousTime;
    if (!(interval > kTimeEpsilon) || interval > kMaximumStateInterval) {
        return false;
    }
    alpha = Clamp((scaledTime - state.previousTime) / interval,
                  kMinimumAlpha, kMaximumAlpha);
    predicted.origin = {
        state.previous.origin.x + alpha * (state.current.origin.x - state.previous.origin.x),
        state.previous.origin.y + alpha * (state.current.origin.y - state.previous.origin.y),
        state.previous.origin.z + alpha * (state.current.origin.z - state.previous.origin.z),
    };
    const Quaternion previousRotation = MatrixToQuaternion(state.previous.axis);
    const Quaternion currentRotation = MatrixToQuaternion(state.current.axis);
    QuaternionToMatrix(SlerpUnclamped(previousRotation, currentRotation, alpha),
                       predicted.axis);
    return true;
}

// Deterministic frame-time jitter in [0, 1).
struct Random {
    std::uint64_t state;

    double Next() {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        return static_cast<double>(state >> 11) * (1.0 / 9007199254740992.0);
    }
};

// The engine's clock update: scaled time advances by real time times the
// global scale; a frame runs floor(lag * tickScale / step + rounding) ticks,
// 0..12, and simulation time advances by ticks * step / tickScale.
struct ClockModel {
    double scaled = 0.0;
    double simulation = 0.0;
    double rounding = 0.5;

    std::int32_t Advance(double frameSeconds, double globalScale, double tickScale) {
        scaled += frameSeconds * globalScale;
        const double ticks = std::floor(
            (scaled - simulation) * tickScale / kNativeSimulationStep + rounding);
        const std::int32_t count = static_cast<std::int32_t>(Clamp(ticks, 0.0, 12.0));
        simulation += count * kNativeSimulationStep / tickScale;
        return count;
    }
};

enum class TurnSource {
    Mouse,
    Simulation,
};

struct CadenceResult {
    double turnRms = 0.0;
    double positionRms = 0.0;
    bool matchesReference = true;
};

Transform MakeCamera(double position, double yaw) {
    Transform camera{};
    camera.origin = {position, 16.0, 64.0};
    const float c = static_cast<float>(std::cos(yaw));
    const float s = static_cast<float>(std::sin(yaw));
    const float axis[9] = {c, s, 0.0f, -s, c, 0.0f, 0.0f, 0.0f, 1.0f};
    memcpy(camera.axis, axis, sizeof(axis));
    return camera;
}

double Yaw(const Transform& camera) {
    return std::atan2(static_cast<double>(camera.axis[1]),
                      static_cast<double>(camera.axis[0]));
}

double WrapAngle(double angle) {
    while (angle > kPi) {
        angle -= 2.0 * kPi;
    }
    while (angle <= -kPi) {
        angle += 2.0 * kPi;
    }
    return angle;
}

bool SamePrediction(bool applied, const Transform& predicted, double alpha,
                    bool expectedApplied, const Transform& expected, double expectedAlpha) {
    if (applied != expectedApplied) {
        return false;
    }
    return !applied ||
           (memcmp(&predicted.origin, &expected.origin, sizeof(predicted.origin)) == 0 &&
            memcmp(predicted.axis, expected.axis, sizeof(predicted.axis)) == 0 &&
            memcmp(&alpha, &expectedAlpha, sizeof(alpha)) == 0);
}

// Walks forward while turning at a constant rate. Mouse turning follows the
// v1.4.0 look scaling: each frame that runs a tick turns by the input gathered
// in real time since the previous such frame. Simulation turning advances with
// simulation time, like a scripted camera. A tick scale below 1 is slow motion:
// ticks become rarer and longer while game motion slows by the same factor.
// Errors compare each presented frame's increment with the ideal one, in
// frames of motion.
CadenceResult RunCadence(double fps, double jitter, double rounding, TurnSource source,
                         bool realTimeTurn, std::uint64_t seed, double tickScale = 1.0,
                         double intervalScale = 1.0) {
    constexpr double kTurnRate = 1.5;
    // Slow enough that even a 50 ms sample stays inside the predictor's
    // 5-unit jump guard, which would otherwise reset the history.
    constexpr double kWalkSpeed = 80.0;
    constexpr int kFrames = 4000;
    constexpr int kWarmupFrames = 200;
    static const int sourceTag = 0;
    const void* sourceView = &sourceTag;
    Random random{seed};
    ClockModel clock{};
    clock.rounding = rounding;
    PredictionState state{};
    ReferencePredictionState reference{};
    CadenceResult result{};
    const double frameBase = 1.0 / fps;
    const double turnRate = source == TurnSource::Mouse ? kTurnRate : kTurnRate * tickScale;
    const double walkSpeed = kWalkSpeed * tickScale;
    const bool compareReference = !realTimeTurn && intervalScale == 1.0;
    double realTime = 0.0;
    double mouseYaw = 0.0;
    double previousYaw = 0.0;
    double previousIdealYaw = 0.0;
    double previousPosition = 0.0;
    double previousIdealPosition = 0.0;
    double turnSquares = 0.0;
    double positionSquares = 0.0;
    int samples = 0;
    for (int frame = 0; frame < kFrames; ++frame) {
        const double frameSeconds = frame == 0
            ? 0.0
            : frameBase * (1.0 + jitter * (2.0 * random.Next() - 1.0));
        realTime += frameSeconds;
        const std::int32_t ticks = clock.Advance(frameSeconds, 1.0, tickScale);
        if (ticks > 0) {
            mouseYaw = kTurnRate * realTime;
        }
        const double rawYaw = source == TurnSource::Mouse
            ? mouseYaw
            : turnRate * clock.simulation;
        const Transform raw = MakeCamera(walkSpeed * clock.simulation, rawYaw);

        Transform predicted{};
        double alpha = 0.0;
        const bool applied = PredictCamera(
            state, sourceView, clock.scaled, clock.simulation, raw, realTimeTurn,
            kMaximumStateInterval * intervalScale, predicted, alpha);
        if (compareReference) {
            Transform expected{};
            double expectedAlpha = 0.0;
            const bool expectedApplied = ReferencePredict(
                reference, sourceView, clock.scaled, clock.simulation, raw, expected,
                expectedAlpha);
            result.matchesReference = result.matchesReference &&
                SamePrediction(applied, predicted, alpha, expectedApplied, expected,
                               expectedAlpha);
        }

        const Transform& shown = applied ? predicted : raw;
        const double shownYaw = Yaw(shown);
        const double idealYaw = source == TurnSource::Mouse
            ? kTurnRate * realTime
            : turnRate * clock.scaled;
        const double idealPosition = walkSpeed * clock.scaled;
        if (frame > kWarmupFrames) {
            const double turnError =
                (WrapAngle(shownYaw - previousYaw) - (idealYaw - previousIdealYaw)) /
                (turnRate * frameBase);
            const double positionError =
                ((shown.origin.x - previousPosition) - (idealPosition - previousIdealPosition)) /
                (walkSpeed * frameBase);
            turnSquares += turnError * turnError;
            positionSquares += positionError * positionError;
            ++samples;
        }
        previousYaw = shownYaw;
        previousIdealYaw = idealYaw;
        previousPosition = shown.origin.x;
        previousIdealPosition = idealPosition;
    }
    result.turnRms = std::sqrt(turnSquares / samples);
    result.positionRms = std::sqrt(positionSquares / samples);
    return result;
}

void TestCameraPrediction() {
    const double rates[] = {60.0, 75.0, 90.0, 100.0, 105.0, 120.0, 144.0, 165.0, 240.0, 360.0};
    const double roundings[] = {0.5, 0.0};
    const double jitters[] = {0.0, 0.03};
    for (double fps : rates) {
        for (double rounding : roundings) {
            for (double jitter : jitters) {
                for (std::uint64_t seed = 1; seed <= 3; ++seed) {
                    const CadenceResult mouse = RunCadence(
                        fps, jitter, rounding, TurnSource::Mouse, true, seed);
                    const CadenceResult mouseOld = RunCadence(
                        fps, jitter, rounding, TurnSource::Mouse, false, seed);
                    const CadenceResult scriptedOld = RunCadence(
                        fps, jitter, rounding, TurnSource::Simulation, false, seed);
                    const double turnLimit = jitter > 0.0 ? 0.10 : 0.02;
                    Check(mouse.turnRms <= turnLimit,
                          "real-time rule: mouse turn error %.3f at %.0f FPS "
                          "(jitter %.2f, rounding %.1f, seed %llu)",
                          mouse.turnRms, fps, jitter, rounding,
                          static_cast<unsigned long long>(seed));
                    Check(mouse.positionRms <= 0.02 && mouseOld.positionRms <= 0.02,
                          "walking error %.3f/%.3f at %.0f FPS (jitter %.2f, rounding %.1f)",
                          mouse.positionRms, mouseOld.positionRms, fps, jitter, rounding);
                    Check(mouseOld.matchesReference && scriptedOld.matchesReference,
                          "simulation-time rule differs from the previous predictor at "
                          "%.0f FPS (jitter %.2f, rounding %.1f, seed %llu)",
                          fps, jitter, rounding, static_cast<unsigned long long>(seed));
                    Check(scriptedOld.turnRms <= 0.02,
                          "simulation-time rule: scripted turn error %.3f at %.0f FPS "
                          "(jitter %.2f, rounding %.1f)",
                          scriptedOld.turnRms, fps, jitter, rounding);
                }
            }
        }
    }

    // The defect the real-time rule removes.
    const CadenceResult judder = RunCadence(90.0, 0.0, 0.5, TurnSource::Mouse, false, 1);
    const CadenceResult fixed = RunCadence(90.0, 0.0, 0.5, TurnSource::Mouse, true, 1);
    Check(judder.turnRms >= 0.3,
          "simulation-time rule no longer shows the 90 FPS mouse-turn judder (%.3f)",
          judder.turnRms);
    std::printf("90 FPS mouse turn error: simulation-time rule %.3f, real-time rule %.3f "
                "frames RMS.\n", judder.turnRms, fixed.turnRms);
}

// Slow motion stretches each tick to step / tickScale of simulation time. With
// the interval limit scaled to match, walking and turning stay smooth; with
// the native 50 ms limit, ticks longer than that reset the history on every
// sample and the camera shows the stepped raw view.
void TestSlowMotionCamera() {
    const double rates[] = {60.0, 90.0, 120.0, 144.0, 240.0};
    const double tickScales[] = {0.3, 0.172, 0.1, 0.05};
    const double jitters[] = {0.0, 0.03};
    for (double fps : rates) {
        for (double tickScale : tickScales) {
            for (double jitter : jitters) {
                const CadenceResult scaled = RunCadence(
                    fps, jitter, 0.5, TurnSource::Mouse, true, 5, tickScale,
                    1.0 / tickScale);
                const double turnLimit = jitter > 0.0 ? 0.10 : 0.02;
                Check(scaled.turnRms <= turnLimit && scaled.positionRms <= 0.02,
                      "slow motion %.3f at %.0f FPS (jitter %.2f): turn %.3f, walking %.3f",
                      tickScale, fps, jitter, scaled.turnRms, scaled.positionRms);
                const CadenceResult scripted = RunCadence(
                    fps, jitter, 0.5, TurnSource::Simulation, false, 5, tickScale,
                    1.0 / tickScale);
                Check(scripted.turnRms <= 0.02 && scripted.positionRms <= 0.02,
                      "slow motion %.3f at %.0f FPS (jitter %.2f): scripted turn %.3f, "
                      "walking %.3f", tickScale, fps, jitter, scripted.turnRms,
                      scripted.positionRms);
            }
        }
    }
    const CadenceResult unscaled = RunCadence(90.0, 0.0, 0.5, TurnSource::Mouse, true, 5,
                                              0.1, 1.0);
    Check(unscaled.positionRms >= 0.3,
          "a 0.1 tick scale no longer exceeds the native interval limit (walking %.3f)",
          unscaled.positionRms);
    const CadenceResult scaled = RunCadence(90.0, 0.0, 0.5, TurnSource::Mouse, true, 5,
                                            0.1, 10.0);
    std::printf("90 FPS walking error at a 0.1 tick scale: native interval limit %.3f, "
                "scaled limit %.3f frames RMS.\n", unscaled.positionRms, scaled.positionRms);
}

bool Near(double value, double expected) {
    return std::abs(value - expected) <= 1.0e-6;
}

void TestClockTickScale() {
    ClockTimeScales scales{};
    scales.valid = true;
    scales.scaled = 1.0f;
    scales.timer3 = 0.25f;
    scales.timer4 = 0.25f;
    ClockTickScale tick = ComputeClockTickScale(scales);
    Check(tick.valid && Near(tick.tickScale, 0.25) && Near(tick.tickRate, 0.25),
          "timers at 0.25 gave tick scale %.3f, rate %.3f", tick.tickScale, tick.tickRate);
    scales.timer4 = 1.0f;
    tick = ComputeClockTickScale(scales);
    Check(tick.valid && Near(tick.tickScale, 1.0) && Near(tick.tickRate, 1.0),
          "the larger timer does not set the tick scale (%.3f)", tick.tickScale);
    scales.scaled = 0.5f;
    tick = ComputeClockTickScale(scales);
    Check(tick.valid && Near(tick.tickScale, 1.0) && Near(tick.tickRate, 0.5),
          "the global scale changed the tick length or kept the rate (%.3f, %.3f)",
          tick.tickScale, tick.tickRate);

    ClockTimeScales invalid = scales;
    invalid.timer3 = std::numeric_limits<float>::quiet_NaN();
    Check(!ComputeClockTickScale(invalid).valid, "a NaN timer scale was accepted");
    invalid = scales;
    invalid.scaled = 5.0f;
    Check(!ComputeClockTickScale(invalid).valid, "an out-of-range global scale was accepted");
    invalid = scales;
    invalid.valid = false;
    Check(!ComputeClockTickScale(invalid).valid, "an unreadable clock was accepted");
}

void TestSlowMotionState() {
    bool active = false;
    Check(UpdateSlowMotionState(active, 1.0) == SlowMotionTransition::None && !active,
          "normal time started slow motion");
    Check(UpdateSlowMotionState(active, 0.8) == SlowMotionTransition::None && !active,
          "a 0.8 tick rate started slow motion");
    Check(UpdateSlowMotionState(active, 0.7) == SlowMotionTransition::Started && active,
          "a 0.7 tick rate did not start slow motion");
    Check(UpdateSlowMotionState(active, 0.172) == SlowMotionTransition::None && active,
          "deep slow motion changed the state");
    Check(UpdateSlowMotionState(active, 0.0) == SlowMotionTransition::None && active,
          "stopped timers ended slow motion");
    Check(UpdateSlowMotionState(active, 0.85) == SlowMotionTransition::None && active,
          "slow motion ended inside the hysteresis band");
    Check(UpdateSlowMotionState(active, 0.9) == SlowMotionTransition::Ended && !active,
          "a 0.9 tick rate did not end slow motion");
    Check(UpdateSlowMotionState(active, 0.0) == SlowMotionTransition::None && !active,
          "stopped timers started slow motion");
}

void TestIntervalScale() {
    IntervalScaleState state{};
    Check(Near(UpdateIntervalScale(state, 1.0, 10.0), 1.0), "normal time stretched the limit");
    Check(Near(UpdateIntervalScale(state, 0.1, 10.1), 10.0),
          "a 0.1 tick scale did not stretch the limit tenfold");
    Check(Near(UpdateIntervalScale(state, 0.5, 10.4), 10.0),
          "the deepest scale was not held while the timers ramp up");
    Check(Near(UpdateIntervalScale(state, 1.0, 10.7), 1.0),
          "the deepest scale was held beyond its hold time");
    Check(Near(UpdateIntervalScale(state, 0.01, 11.0), 1.0 / kMinimumIntervalTickScale),
          "the interval scale is not bounded");
    Check(Near(UpdateIntervalScale(state, 1.0, 5.0), 1.0),
          "a clock that went backwards kept the old scale");
}

void TestSlowMotionOverride() {
    g_fullInterpolationInSlowMotion = true;
    AdaptiveInterpolationGateState gate{};
    gate.initialized = true;
    gate.mode = AdaptiveInterpolationMode::Off;
    ApplyAdaptiveInterpolationModeFlags(gate.mode);
    PresentationContext context{};
    context.valid = true;
    context.scaledTime = 10.0;
    context.simulationTime = 10.0;
    const auto layersOn = [] {
        return g_transformInterpolationRuntimeEnabled.load() &&
               g_skeletalInterpolationRuntimeEnabled.load();
    };
    const auto layersOff = [] {
        return !g_transformInterpolationRuntimeEnabled.load() &&
               !g_skeletalInterpolationRuntimeEnabled.load();
    };

    g_slowMotionActive.store(true);
    Check(UpdateSlowMotionInterpolationOverride(gate, context) && layersOn(),
          "slow motion did not enable every layer over an off gate");
    Check(OwnerlessSkinnedJointLimit() == kMaximumJointCount,
          "slow motion did not admit ownerless characters");
    gate.cutsceneOverride = true;
    g_slowMotionActive.store(false);
    Check(!UpdateSlowMotionInterpolationOverride(gate, context) && layersOn(),
          "the end of slow motion dropped layers during a cutscene");
    Check(OwnerlessSkinnedJointLimit() == kMaximumCinematicJointCount,
          "ownerless characters stayed admitted after slow motion");
    gate.cutsceneOverride = false;
    ApplyAdaptiveInterpolationRuntimeFlags(gate);
    Check(layersOff(), "the gate's off mode did not return after both overrides");

    g_fullInterpolationInSlowMotion = false;
    g_slowMotionActive.store(true);
    Check(!UpdateSlowMotionInterpolationOverride(gate, context) && layersOff(),
          "FullInterpolationInSlowMotion=0 still enabled layers");
    g_slowMotionActive.store(false);
}

}  // namespace

int main() {
    TestCameraPrediction();
    TestSlowMotionCamera();
    TestClockTickScale();
    TestSlowMotionState();
    TestIntervalScale();
    TestSlowMotionOverride();
    if (g_failures != 0) {
        std::fprintf(stderr, "%d camera-prediction/slow-motion checks failed.\n", g_failures);
        return 1;
    }
    std::printf("Camera-prediction and slow-motion tests passed.\n");
    return 0;
}
