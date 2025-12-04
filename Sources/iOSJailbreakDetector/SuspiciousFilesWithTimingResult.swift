//
//  File.swift
//  iOSJailbreakDetector

/// Result from suspicious file detection with timing analysis.
///
/// Measures file existence check duration to detect runtime hooking.
/// Quick access to non-existent jailbreak files indicates sandbox bypass.
///
/// **Usage Example:**
/// ```swift
/// let result = detector.checkSuspiciousFilesWithTiming(
///     path: "/Applications/Cydia.app",
///     suspiciousJailbreakHookTimingInSeconds: 0.05
/// )
/// switch result {
/// case .jailbroken(let time, let path):
///     Logger.error("Cydia detected at $$path) in $$time*1000)ms")
/// case .suspicious(let delay, let path):
///     Logger.warning("Hooking detected on $$path): $$delay*1000)ms delay")
/// case .clean: break
/// }
/// ```
///
/// **Usage Example Timing Thresholds:**
/// - `< 50ms` + file exists = `.jailbroken` (direct access)
/// - `> 50ms` on non-existent = `.suspicious` (hooking delay)
/// - Normal timing = `.clean`
public enum SuspiciousFilesWithTimingResult {
    case clean
    case jailbroken(accessTime: Double, path: String)
    case suspicious(delay: Double, path: String)
}
