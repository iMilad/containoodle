// Build-process-only containment for the unpatched image-size advisories.
// Resolve from the linter, not this script: this must configure the SAME CJS
// module instance that Mozilla's linter uses. Never ship this in the XPI.
const { createRequire } = require("node:module");
const linterRequire = createRequire(require.resolve("addons-linter"));
const imageSize = linterRequire("image-size");
if (!Array.isArray(imageSize.types) || !imageSize.types.includes("png") ||
    typeof imageSize.disableTypes !== "function") {
  throw new Error("Image-parser containment is incompatible with this linter");
}
imageSize.disableTypes(imageSize.types.filter(type => type !== "png"));
