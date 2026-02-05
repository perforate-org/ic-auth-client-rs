import SwiftUI

#if os(iOS)
import UIKit

struct WindowAccessor: UIViewRepresentable {
    let onResolve: (UIWindow) -> Void

    func makeUIView(context: Context) -> UIView {
        let view = UIView(frame: .zero)
        DispatchQueue.main.async {
            if let window = view.window ?? UIApplication.shared.connectedScenes
                .compactMap({ $0 as? UIWindowScene })
                .flatMap({ $0.windows })
                .first(where: { $0.isKeyWindow }) {
                onResolve(window)
            }
        }
        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        DispatchQueue.main.async {
            if let window = uiView.window {
                onResolve(window)
            }
        }
    }
}

typealias PlatformWindow = UIWindow
#elseif os(macOS)
import AppKit

struct WindowAccessor: NSViewRepresentable {
    let onResolve: (NSWindow) -> Void

    func makeNSView(context: Context) -> NSView {
        let view = NSView(frame: .zero)
        DispatchQueue.main.async {
            if let window = view.window ?? NSApplication.shared.keyWindow {
                onResolve(window)
            }
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async {
            if let window = nsView.window {
                onResolve(window)
            }
        }
    }
}

typealias PlatformWindow = NSWindow
#endif
