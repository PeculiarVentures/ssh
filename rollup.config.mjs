import { readFileSync } from 'node:fs';
import path from 'node:path';
import * as url from 'node:url';

import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';
import dts from 'rollup-plugin-dts';

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'));
const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const startYear = 2025;
const currentYear = new Date().getFullYear();

const year = startYear === currentYear
  ? `${startYear}`
  : `${startYear}-${currentYear}`;

const banner = [
  '/**',
  ` * Copyright (c) ${year}, Peculiar Ventures`,
  ' * SPDX-License-Identifier: MIT',
  ' */',
  '',
].join('\n');

const externalDeps = new Set([
  ...Object.keys(pkg.dependencies || {}),
]);

const external = id => {
  return [...externalDeps].some(dep => {
    return id === dep || id.startsWith(`${dep}/`);
  });
};

export default [
  {
    input: path.join(__dirname, 'src/index.ts'),
    external,
    output: [
      {
        file: pkg.main,
        format: 'cjs',
        sourcemap: false,
        preserveModules: false,
        banner
      },
      {
        file: pkg.module,
        format: 'esm',
        sourcemap: false,
        preserveModules: false,
        banner
      }
    ],
    plugins: [
      resolve(),
      commonjs(),
      typescript({
        compilerOptions: {
          module: 'esnext',
          moduleResolution: 'bundler',
          target: 'es2022',
          removeComments: true,
          declaration: false
        }
      })
    ]
  },
  {
    input: path.join(__dirname, 'src/index.ts'),
    external,
    output: {
      file: './dist/index.d.ts',
      format: 'esm',
      banner
    },
    plugins: [dts()]
  }
];
