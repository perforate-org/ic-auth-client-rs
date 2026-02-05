import SwiftUI

#if os(macOS)
    final class AuthSessionAppDelegate: NSObject, NSApplicationDelegate {
        var onOpenURL: ((URL) -> Void)?

        func application(_ application: NSApplication, open urls: [URL]) {
            for url in urls {
                onOpenURL?(url)
            }
        }
    }
#endif

@main
struct AuthSessionUIApp: App {
    @StateObject private var model: AuthSessionViewModel

    #if os(macOS)
        @NSApplicationDelegateAdaptor(AuthSessionAppDelegate.self)
        private var appDelegate
    #endif

    init() {
        let model = AuthSessionViewModel()
        _model = StateObject(wrappedValue: model)

        #if os(macOS)
            appDelegate.onOpenURL = { url in
                model.handleOpenUrl(url)
            }
        #endif
    }

    var body: some Scene {
        WindowGroup {
            AuthSessionView(model: model)
        }
        .handlesExternalEvents(matching: Set())
    }
}
