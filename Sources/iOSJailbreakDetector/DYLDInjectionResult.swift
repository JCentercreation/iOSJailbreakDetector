//
//  File.swift
//  DYLDInjectionResult

public enum DYLDInjectionResult {
    case clean(loadTime: Double, library: String)
    case suspicious(delay: Double, library: String)
    case injected(handle: UnsafeMutableRawPointer?, loadTime: Double, library: String)
}
