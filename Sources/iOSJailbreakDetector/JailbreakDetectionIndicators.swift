//
//  JailbreakDetectionIndicators.swift
//  JailbreakDetector

public enum JailbreakDetectionIndicators: CaseIterable {
    case jailbreakURLSchemesDetected
    case suspiciousFilesDetected
    case systemPathsViolationDetected
    case dynamicLinkerInjectionDetected
    case sandboxCompromisedIntegrityDetected
    case suspiciousSymbolicLinksDetected
    case forkBehaviourAnomalyDetected
    case suspiciousEnvironmentVariablesDetected
}
