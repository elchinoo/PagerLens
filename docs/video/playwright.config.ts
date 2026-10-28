import { defineConfig } from '@playwright/test';
import * as path from 'node:path';

/**
 * Records the PagerLens tutorial video against a PagerLens you started yourself (see docs/VIDEO-SCRIPT.md, section 1).
 * Uses the machine's real Google Chrome (no browser download). Output (git-ignored): docs/video/out/.
 */
export default defineConfig({
  testDir: '.',
  testMatch: 'record.spec.ts',
  outputDir: path.join(__dirname, 'out', '.playwright'), // the runner empties this folder; the video is saved next to it
  workers: 1,
  retries: 0,
  timeout: 20 * 60_000,
  reporter: [['list']],
  use: {
    channel: 'chrome',
    headless: !process.env.HEADED,
    actionTimeout: 30_000,
    navigationTimeout: 30_000,
  },
});
