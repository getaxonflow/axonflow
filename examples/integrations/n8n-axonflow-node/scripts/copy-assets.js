// Copy node SVG icons + node.json descriptors from src into dist after tsc.
// n8n loads icons relative to the compiled node file at runtime.
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');

// Explicit allowlist — guards against stray editor-tmp files ending up in
// the published tarball.
const assets = [
  { src: 'nodes/AxonFlow/AxonFlow.node.json', dest: 'dist/nodes/AxonFlow/AxonFlow.node.json' },
  { src: 'nodes/AxonFlow/axonflow.svg', dest: 'dist/nodes/AxonFlow/axonflow.svg' },
];

for (const { src, dest } of assets) {
  fs.mkdirSync(path.dirname(path.join(root, dest)), { recursive: true });
  fs.copyFileSync(path.join(root, src), path.join(root, dest));
}
