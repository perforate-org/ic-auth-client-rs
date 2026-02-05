import { defineConfig } from "vite";
import environment from "vite-plugin-environment";
import { viteStaticCopy } from "vite-plugin-static-copy";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    environment("all", { prefix: "CANISTER_", defineOn: `import.meta.env` }),
    viteStaticCopy({
      targets: [{ src: ".ic-assets.json5", dest: "." }],
    }),
  ],
});
