import Foundation

/// A convenience wrapper around the v11 sign-in flow.
///
/// The Rust client now drives the whole ceremony itself: it discovers the
/// identity provider's non-browser sign-in route, binds a loopback callback,
/// opens the system browser, receives the delegation and validates it. There is
/// therefore no bridge URL, no redirect URI and no callback payload to hand back
/// — one blocking `login` call carries the flow from start to finish.
///
/// The flow needs a `127.0.0.1` HTTP callback, which is a desktop capability
/// today (macOS, Linux, Windows). On iOS the Rust side returns
/// `AuthError.Unsupported`; a platform-hosted equivalent is still pending.
@MainActor
public final class AuthSession {
    private let client: AuthClient

    public init(client: AuthClient) {
        self.client = client
    }

    /// Signs in, calling `completion` on the main actor with the identity.
    ///
    /// The work happens off the main actor because `login` blocks until the user
    /// finishes in the browser; the callback hops back so callers can touch UI
    /// directly.
    public func login(
        options: LoginOptions = LoginOptions(),
        completion: @escaping (Result<AuthIdentity, Error>) -> Void
    ) {
        let client = self.client
        DispatchQueue.global(qos: .userInitiated).async {
            let result: Result<AuthIdentity, Error>
            do {
                result = .success(try client.login(options: options))
            } catch {
                result = .failure(error)
            }
            Task { @MainActor in
                completion(result)
            }
        }
    }

    /// Signs out, clearing the stored credentials and ending the session at the
    /// identity provider where it can.
    public func logout(completion: @escaping (Result<Void, Error>) -> Void) {
        let client = self.client
        DispatchQueue.global(qos: .userInitiated).async {
            let result: Result<Void, Error>
            do {
                try client.logout()
                result = .success(())
            } catch {
                result = .failure(error)
            }
            Task { @MainActor in
                completion(result)
            }
        }
    }
}
