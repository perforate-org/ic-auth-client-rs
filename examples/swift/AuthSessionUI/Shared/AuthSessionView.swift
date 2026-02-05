import Foundation
import IcAuthClient
import IcpKit
import SwiftUI

@MainActor
final class AuthSessionViewModel: ObservableObject {
    @Published var iiBridgeCanisterId = Env.canisterIdIiBridge
    @Published var backendCanisterId = Env.canisterIdBackend
    @Published var redirectScheme: String
    @Published var statusMessage = ""
    @Published var principalText = ""
    @Published var errorMessage = ""
    @Published var isAuthenticated = false

    private let client: AuthClient
    private let session: AuthSession
    private let basePrincipalText: String?
    private let localReplicaBaseURL = URL(string: "http://localhost:4943")!
    private let localReplicaHost = "localhost"

    private var isLocalNetwork: Bool {
        Env.dfxNetwork == "local"
    }

    var networkLabel: String {
        isLocalNetwork ? "Local" : "Mainnet"
    }

    init() {
        self.redirectScheme = Self.defaultRedirectScheme()
        do {
            let serviceName = "ic-auth-client-auth-session-ui"
            if Env.dfxNetwork == "local" {
                enableKeychainMock()
            }
            self.client = try AuthClient(serviceName: serviceName)
            self.basePrincipalText = try? client.principalText()
            self.session = AuthSession(client: self.client)
        } catch {
            fatalError("Failed to initialize AuthClient: \(error)")
        }
    }

    private static func defaultRedirectScheme() -> String {
        let fallback = "authsessionui"
        guard
            let urlTypes = Bundle.main.object(
                forInfoDictionaryKey: "CFBundleURLTypes"
            ) as? [[String: Any]]
        else {
            return fallback
        }
        for entry in urlTypes {
            if let schemes = entry["CFBundleURLSchemes"] as? [String],
                let scheme = schemes.first,
                !scheme.isEmpty
            {
                return scheme
            }
        }
        return fallback
    }

    func login() {
        let authBridgeUrl = buildAuthBridgeUrl()
        let redirectUri = "\(redirectScheme)://auth"
        let options = LoginOptions(
            identityProvider: nil,
            maxTimeToLive: nil,
            allowPinAuthentication: nil,
            derivationOrigin: nil,
            windowOpenerFeatures: nil,
            timeoutMillis: nil,
            customValuesJson: nil
        )

        errorMessage = ""
        statusMessage = "Opening authentication session..."
        session.login(
            authBridgeUrl: authBridgeUrl,
            redirectUri: redirectUri,
            options: options,
        ) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success:
                self.refreshStatus()
                self.statusMessage = "Login complete."
            case .failure(let error):
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Login failed."
            }
        }
    }

    func handleOpenUrl(_ url: URL) {
        _ = session.handleCallbackUrl(url)
    }

    func logout() {
        client.logout()
        refreshStatus()
        statusMessage = "Logged out."
    }

    func refreshStatus() {
        do {
            principalText = try client.principalText()
        } catch {
            principalText = ""
        }
        isAuthenticated = client.isAuthenticated()
    }

    func callBackend() async {
        guard !backendCanisterId.isEmpty else {
            errorMessage = "Missing backend canister id."
            return
        }
        do {
            let requestClient = try await makeRequestClient()
            let callerQuery = try ICPQueryNoArgs<ICPPrincipal>(backendCanisterId, "whoami")
            let sender: ICPSigningPrincipal
            if client.isAuthenticated() {
                sender = try client.icpDelegatedIdentity()
            } else {
                let publicKey = try client.secp256k1UncompressedPublicKey()
                let principal = try ICPCryptography.selfAuthenticatingPrincipal(
                    uncompressedPublicKey: publicKey
                )
                sender = KeyringSigningPrincipal(
                    client: client,
                    principal: principal,
                    rawPublicKey: publicKey
                )
            }
            let result = try await callerQuery.callMethod(requestClient, sender: sender)
            statusMessage = "whoami -> \(result.string)"
        } catch {
            errorMessage = formatError(error)
        }
    }

    private func buildAuthBridgeUrl() -> String {
        let trimmedId = iiBridgeCanisterId.trimmingCharacters(in: .whitespacesAndNewlines)
        if isLocalNetwork {
            let localId = trimmedId.isEmpty ? Env.canisterIdIiBridge : trimmedId
            if localId.isEmpty {
                return localReplicaBaseURL.absoluteString
            }
            return "http://\(localId).\(localReplicaHost):4943/"
        }
        if trimmedId.isEmpty {
            return "https://identity.ic0.app"
        }
        return "https://\(trimmedId).ic0.app"
    }

    private func makeRequestClient() async throws -> ICPRequestClient {
        if isLocalNetwork {
            let local = ICPNetwork.local(baseURL: localReplicaBaseURL, verifyCertificates: false)
            let client = ICPRequestClient(network: local)
            let rootKey = try await client.fetchRootKey()
            return client.withRootKey(rootKey)
        }
        return ICPRequestClient()
    }

    private func formatError(_ error: Error) -> String {
        let nsError = error as NSError
        var details = [String]()
        details.append(String(reflecting: error))
        details.append("domain=\(nsError.domain)")
        details.append("code=\(nsError.code)")
        if !nsError.userInfo.isEmpty {
            details.append("userInfo=\(nsError.userInfo)")
        }
        return details.joined(separator: " | ")
    }
}

struct AuthSessionView: View {
    @ObservedObject var model: AuthSessionViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            GroupBox("Internet Identity / \(model.networkLabel)") {
                VStack(alignment: .leading, spacing: 8) {
                    LabeledField(
                        title: "II Bridge Canister Id", text: $model.iiBridgeCanisterId)
                    LabeledField(
                        title: "Backend Canister Id", text: $model.backendCanisterId)
                    LabeledField(title: "Redirect Scheme", text: $model.redirectScheme)
                }
            }

            HStack(spacing: 12) {
                Button("Login") {
                    model.login()
                }
                Button("Logout") {
                    model.logout()
                }
                Button("Refresh") {
                    model.refreshStatus()
                }
                Button("Call Backend") {
                    Task { await model.callBackend() }
                }
            }

            GroupBox("Status") {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Authenticated: \(model.isAuthenticated ? "yes" : "no")")
                    Text("Principal: \(model.principalText)")
                    if !model.statusMessage.isEmpty {
                        Text("Status: \(model.statusMessage)")
                    }
                    if !model.errorMessage.isEmpty {
                        Text("Error: \(model.errorMessage)")
                            .foregroundColor(.red)
                    }
                }
            }

            Spacer()
        }
        .padding()
        .onAppear { model.refreshStatus() }
        .onOpenURL { model.handleOpenUrl($0) }
    }
}

private struct LabeledField: View {
    let title: String
    @Binding var text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption)
            TextField(title, text: $text)
                .textFieldStyle(.roundedBorder)
        }
    }
}

private struct KeyringSigningPrincipal: ICPSigningPrincipal {
    let client: AuthClient
    let principal: ICPPrincipal
    let rawPublicKey: Data

    func sign(_ message: Data, domain: ICPDomainSeparator) async throws -> Data {
        try client.signIcRequest(message: message, domain: domain.domain)
    }
}
