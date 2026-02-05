import Foundation

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
    /// Enable a mock keychain backend for local development.
    //
    /// Alias for `enableKeyringMock()` on Apple platforms.
    public func enableKeychainMock() {
        enableKeyringMock()
    }
#endif
