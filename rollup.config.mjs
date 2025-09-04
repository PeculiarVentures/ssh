import { readFileSync } from 'node:fs';

import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';
import dts from 'rollup-plugin-dts';

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'));

export default [
  {
    input: 'src/index.ts',
    output: [
      {
        file: pkg.main,
        format: 'cjs',
        sourcemap: false,
        preserveModules: false
      },
      {
        file: pkg.module,
        format: 'esm',
        sourcemap: false,
        preserveModules: false
      }
    ],
    external: Object.keys(pkg.dependencies || {}),
    plugins: [
      resolve(),
      commonjs(),
      typescript({
        compilerOptions: {
          module: 'esnext',
          moduleResolution: 'node',
          target: 'es2022',
          removeComments: true,
          declaration: false
        }
      })
    ]
  },
  {
    input: 'src/index.ts',
    output: {
      file: './dist/index.d.ts',
      format: 'esm'
    },
    plugins: [dts()]
  }
];
