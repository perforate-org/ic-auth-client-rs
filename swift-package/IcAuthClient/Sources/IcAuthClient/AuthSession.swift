import Foundation

#if os(iOS)
    import UIKit
#elseif os(macOS)
    import AppKit
#endif

@MainActor
public final class AuthSession: NSObject {
    private let client: AuthClient
    private var pendingCompletion: ((Result<Void, Error>) -> Void)?
    private var pendingRedirectScheme: String?

    public init(client: AuthClient) {
        self.client = client
    }

    #if os(iOS)
        public func login(
            authBridgeUrl: String,
            redirectUri: String,
            options: LoginOptions,
            completion: @escaping (Result<Void, Error>) -> Void
        ) {
            startSession(
                authBridgeUrl: authBridgeUrl,
                redirectUri: redirectUri,
                options: options,
                completion: completion
            )
        }
    #endif

    #if os(macOS)
        public func login(
            authBridgeUrl: String,
            redirectUri: String,
            options: LoginOptions,
            completion: @escaping (Result<Void, Error>) -> Void
        ) {
            startSession(
                authBridgeUrl: authBridgeUrl,
                redirectUri: redirectUri,
                options: options,
                completion: completion
            )
        }
    #endif

    private func startSession(
        authBridgeUrl: String,
        redirectUri: String,
        options: LoginOptions,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        do {
            let loginUrl = try client.buildLoginUrl(
                authBridgeUrl: authBridgeUrl,
                redirectUri: redirectUri,
                options: options
            )

            guard let url = URL(string: loginUrl) else {
                completion(.failure(NSError(domain: "AuthSession", code: 1)))
                return
            }

            let redirectScheme = URL(string: redirectUri)?.scheme
            pendingRedirectScheme = redirectScheme

            pendingCompletion = completion
            openExternalBrowser(url: url) { [weak self] success in
                guard let self else { return }
                if !success {
                    self.pendingCompletion = nil
                    self.pendingRedirectScheme = nil
                    completion(.failure(NSError(domain: "AuthSession", code: 3)))
                }
            }
        } catch {
            completion(.failure(error))
        }
    }

    @discardableResult
    public func handleCallbackUrl(_ url: URL) -> Bool {
        return handleCallbackUrl(url, completion: pendingCompletion)
    }

    private func handleCallbackUrl(_ url: URL, completion: ((Result<Void, Error>) -> Void)?) -> Bool
    {
        if let expectedScheme = pendingRedirectScheme, url.scheme != expectedScheme {
            return false
        }

        guard
            let payload = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?
                .first(where: { $0.name == "payload" })?.value
        else {
            completion?(.failure(NSError(domain: "AuthSession", code: 2)))
            pendingCompletion = nil
            pendingRedirectScheme = nil
            return false
        }

        do {
            try client.finishLoginFromPayload(payload: payload)
            completion?(.success(()))
            pendingCompletion = nil
            pendingRedirectScheme = nil
            return true
        } catch {
            completion?(.failure(error))
            pendingCompletion = nil
            pendingRedirectScheme = nil
            return false
        }
    }

    private func openExternalBrowser(url: URL, completion: @escaping (Bool) -> Void) {
        #if os(iOS)
            UIApplication.shared.open(url, options: [:]) { success in
                completion(success)
            }
        #elseif os(macOS)
            completion(NSWorkspace.shared.open(url))
        #else
            completion(false)
        #endif
    }
}
