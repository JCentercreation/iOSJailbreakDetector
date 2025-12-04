//
//  File.swift
//  iOSJailbreakDetector

/// Detailed result from DYLD injection detection with timing analysis.
///
/// Analyzes dynamic library loading behavior to detect Substrate/libhooker injection.
/// Includes timing measurements to identify runtime hooking delays.
///
/// **Detection Logic:**
/// - `.clean`: Library not present, normal load time
/// - `.suspicious`: Unexpected delay (hooking indicator)
/// - `.injected`: Jailbreak library successfully loaded into process
///
/// **Usage Example:**
/// ```swift
/// let result = detector.checkDYLDInjectionWithTiming(library: "MobileSubstrate.dylib", timeoutSeconds: 0.1)
/// switch result {
/// case .injected(_, let time, let lib): Logger.error("DYLD INJECTION: $$lib)")
/// case .suspicious(let delay, _): Logger.warning("Suspicious DYLD delay: $$delay*1000)ms")
/// case .clean: break
/// }
/// ```
public enum DYLDInjectionResult {
    case clean(loadTime: Double, library: String)
    case suspicious(delay: Double, library: String)
    case injected(handle: UnsafeMutableRawPointer?, loadTime: Double, library: String)
}
