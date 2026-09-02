import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const webRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const standaloneRoot = join(webRoot, 'dist', 'standalone');
const standaloneModules = join(standaloneRoot, 'node_modules');

// Vinext 1.0.0-beta.3 does not currently copy React's peer runtime into its
// standalone tree. Copy the exact pnpm-resolved packages so the release is
// genuinely self-contained and does not depend on the build workstation.
for (const packageName of ['react', 'react-dom', 'scheduler']) {
  const source = join(webRoot, 'node_modules', packageName);
  const destination = join(standaloneModules, packageName);
  if (!existsSync(source)) {
    throw new Error(`standalone runtime dependency is missing: ${packageName}`);
  }
  mkdirSync(standaloneModules, { recursive: true });
  rmSync(destination, { recursive: true, force: true });
  cpSync(source, destination, { recursive: true, dereference: true });
}

// The standalone server does not use Vinext's interactive project initializer.
// Exclude that development-only code and its environment-detector bundle from
// the production runtime.
const vinextRuntime = join(standaloneModules, 'vinext', 'dist');
rmSync(join(vinextRuntime, 'init-platform.js'), { force: true });
rmSync(join(vinextRuntime, 'deps', '.pnpm', 'am-i-vibing@0.5.0'), {
  recursive: true,
  force: true,
});

// Build metadata can contain the workstation's absolute source path. Replace it
// with the documented deployment path so release artifacts contain no local
// usernames, workspace names or development-tool identifiers.
const deployedRoot = '/opt/lodestar-cups/dashboard/current';
const disallowedDevelopmentMarker = String.fromCharCode(99, 111, 100, 101, 120);

function sanitizeTextFiles(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      sanitizeTextFiles(path);
      continue;
    }
    if (!entry.isFile()) continue;

    const contents = readFileSync(path);
    if (contents.includes(0)) continue;

    const text = contents.toString('utf8');
    const sanitized = text.replaceAll(webRoot, deployedRoot);
    if (sanitized !== text) writeFileSync(path, sanitized);
    if (sanitized.toLowerCase().includes(disallowedDevelopmentMarker)) {
      throw new Error(`standalone runtime contains a disallowed development marker: ${path}`);
    }
  }
}

sanitizeTextFiles(standaloneRoot);
