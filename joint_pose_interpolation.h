#pragma once

#include <cmath>
#include <cstddef>

namespace d2_pose {

// idJointMat is a row-major 3x4 affine matrix in this build (0x30 bytes).
// Keep this representation byte-compatible so a validated presentation-only
// palette can be supplied directly to the renderer upload path later.
struct JointMatrix {
    float values[12];
};

static_assert(sizeof(JointMatrix) == 0x30, "Unexpected idJointMat size");

struct Quaternion {
    double w;
    double x;
    double y;
    double z;
};

inline double Clamp(double value, double minimum, double maximum) {
    return value < minimum ? minimum : value > maximum ? maximum : value;
}

inline bool IsFinite(const JointMatrix& matrix) {
    for (float value : matrix.values) {
        if (!std::isfinite(value)) {
            return false;
        }
    }
    return true;
}

inline bool IsRigid(const JointMatrix& matrix) {
    if (!IsFinite(matrix)) {
        return false;
    }
    const auto dotRows = [&](int left, int right) {
        return static_cast<double>(matrix.values[left * 4]) *
                   matrix.values[right * 4] +
               static_cast<double>(matrix.values[left * 4 + 1]) *
                   matrix.values[right * 4 + 1] +
               static_cast<double>(matrix.values[left * 4 + 2]) *
                   matrix.values[right * 4 + 2];
    };
    for (int row = 0; row < 3; ++row) {
        if (std::abs(dotRows(row, row) - 1.0) > 1.0e-2) {
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
    return std::abs(determinant - 1.0) <= 2.0e-2;
}

inline Quaternion Normalize(Quaternion value) {
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

inline Quaternion RotationToQuaternion(const JointMatrix& matrix) {
    Quaternion result{};
    const double m00 = matrix.values[0];
    const double m01 = matrix.values[1];
    const double m02 = matrix.values[2];
    const double m10 = matrix.values[4];
    const double m11 = matrix.values[5];
    const double m12 = matrix.values[6];
    const double m20 = matrix.values[8];
    const double m21 = matrix.values[9];
    const double m22 = matrix.values[10];
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

inline Quaternion SlerpUnclamped(Quaternion from, Quaternion to, double alpha) {
    from = Normalize(from);
    to = Normalize(to);
    double dot = from.w * to.w + from.x * to.x + from.y * to.y + from.z * to.z;
    if (dot < 0.0) {
        dot = -dot;
        to = {-to.w, -to.x, -to.y, -to.z};
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
    const double angle = std::acos(dot);
    const double sine = std::sin(angle);
    const double fromWeight = std::sin((1.0 - alpha) * angle) / sine;
    const double toWeight = std::sin(alpha * angle) / sine;
    return Normalize({
        from.w * fromWeight + to.w * toWeight,
        from.x * fromWeight + to.x * toWeight,
        from.y * fromWeight + to.y * toWeight,
        from.z * fromWeight + to.z * toWeight,
    });
}

inline void WriteRotation(const Quaternion& quaternion, JointMatrix& matrix) {
    const Quaternion q = Normalize(quaternion);
    const double xx = q.x * q.x;
    const double yy = q.y * q.y;
    const double zz = q.z * q.z;
    const double xy = q.x * q.y;
    const double xz = q.x * q.z;
    const double yz = q.y * q.z;
    const double wx = q.w * q.x;
    const double wy = q.w * q.y;
    const double wz = q.w * q.z;
    matrix.values[0] = static_cast<float>(1.0 - 2.0 * (yy + zz));
    matrix.values[1] = static_cast<float>(2.0 * (xy - wz));
    matrix.values[2] = static_cast<float>(2.0 * (xz + wy));
    matrix.values[4] = static_cast<float>(2.0 * (xy + wz));
    matrix.values[5] = static_cast<float>(1.0 - 2.0 * (xx + zz));
    matrix.values[6] = static_cast<float>(2.0 * (yz - wx));
    matrix.values[8] = static_cast<float>(2.0 * (xz - wy));
    matrix.values[9] = static_cast<float>(2.0 * (yz + wx));
    matrix.values[10] = static_cast<float>(1.0 - 2.0 * (xx + yy));
}

inline bool InterpolateJointPalettes(const JointMatrix* previous,
                                     const JointMatrix* current,
                                     std::size_t jointCount, double alpha,
                                     JointMatrix* output,
                                     bool validateRigidity = true) {
    if (previous == nullptr || current == nullptr || output == nullptr ||
        jointCount == 0 || jointCount > 256 || !std::isfinite(alpha)) {
        return false;
    }
    // Callers that only store palettes already accepted as rigid may skip
    // the per-joint re-validation.
    for (std::size_t index = 0; validateRigidity && index < jointCount; ++index) {
        if (!IsRigid(previous[index]) || !IsRigid(current[index])) {
            return false;
        }
    }
    for (std::size_t index = 0; index < jointCount; ++index) {
        JointMatrix result{};
        WriteRotation(SlerpUnclamped(RotationToQuaternion(previous[index]),
                                     RotationToQuaternion(current[index]), alpha),
                      result);
        result.values[3] = static_cast<float>(
            previous[index].values[3] +
            alpha * (current[index].values[3] - previous[index].values[3]));
        result.values[7] = static_cast<float>(
            previous[index].values[7] +
            alpha * (current[index].values[7] - previous[index].values[7]));
        result.values[11] = static_cast<float>(
            previous[index].values[11] +
            alpha * (current[index].values[11] - previous[index].values[11]));
        output[index] = result;
    }
    return true;
}

}  // namespace d2_pose
