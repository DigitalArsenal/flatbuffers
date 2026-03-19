# Copyright 2022 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import tempfile

from flatc_test import *


class TsTests:

  def Aligned(self):
    schema = make_absolute("aligned_mode.fbs")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      flatc(["--ts", "--aligned", "-o", tmpdir, schema], cwd=tmpdir)
      assert_file_contains(
          assert_file_exists("aligned_mode_aligned.ts", tmp_path),
          [
              "export class Root {",
              "static readonly SIZE =",
              "__decodeString",
              "setName(value: string)",
          ],
      )

  def Base(self):
    schema = make_absolute("foo.fbs")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      flatc(["--ts", "-o", tmpdir, schema], cwd=tmpdir)
      assert_file_contains(
          assert_file_exists("foo.ts", tmp_path),
          [
              "export { Bar } from './bar.js';",
              "export { Foo } from './foo.js';",
          ],
      )
      assert_file_contains(
          assert_file_exists("bar.ts", tmp_path),
          "export { Bar } from './bar/bar.js';",
      )
      assert_file_contains(
          assert_file_exists("baz.ts", tmp_path),
          "export { Baz } from './baz/baz.js';",
      )

  def BaseMultipleFiles(self):
    foo_schema = make_absolute("foo.fbs")
    bar_schema = make_absolute("bar/bar.fbs")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      flatc(["--ts", "-o", tmpdir, foo_schema, bar_schema], cwd=tmpdir)
      assert_file_contains(
          assert_file_exists("foo.ts", tmp_path),
          [
              "export { Bar } from './bar.js';",
              "export { Foo } from './foo.js';",
          ],
      )
      assert_file_contains(
          assert_file_exists("bar.ts", tmp_path),
          [
              "export { Bar } from './bar.js';",
              "export { Baz } from './baz.js';",
          ],
      )

  def BaseWithNamespace(self):
    schema = make_absolute("foo_with_ns.fbs")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      flatc(["--ts", "-o", tmpdir, schema], cwd=tmpdir)
      assert_file_contains(
          assert_file_exists("foo_with_ns.ts", tmp_path),
          [
              "export { Baz } from './baz.js';",
              "export * as something from './something.js';",
          ],
      )
      assert_file_contains(
          assert_file_exists("something.ts", tmp_path),
          "export { Foo } from './something/foo.js';",
      )
      assert_file_contains(
          assert_file_exists("something/foo.ts", tmp_path),
          [
              "import { Bar } from '../bar/bar.js';",
              "export class Foo {",
          ],
      )

  def GenAll(self):
    schema = make_absolute("foo.fbs")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      flatc(["--ts", "--gen-all", "-o", tmpdir, schema], cwd=tmpdir)
      assert_file_contains(
          assert_file_exists("foo.ts", tmp_path),
          [
              "export { Bar } from './bar.js';",
              "export { Baz } from './baz.js';",
              "export { Foo } from './foo.js';",
          ],
      )
      assert_file_contains(
          assert_file_exists("bar/bar.ts", tmp_path),
          [
              "import { Baz as Baz } from '../baz.js';",
              "export class Bar {",
          ],
      )
      assert_file_contains(
          assert_file_exists("baz/baz.ts", tmp_path),
          "export enum Baz {",
      )

  def FlatFiles(self):
    schema = make_absolute("foo.fbs")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      flatc(["--ts", "--ts-flat-files", "-o", tmpdir, schema], cwd=tmpdir)
      assert_file_contains(
          assert_file_exists("foo.ts", tmp_path),
          "export { Foo } from './foo.js';",
      )
      assert_file_contains(
          assert_file_exists("bar/bar.ts", tmp_path),
          "export class Bar {",
      )
      assert_file_contains(
          assert_file_exists("bar/foo.ts", tmp_path),
          "export class Foo {",
      )

  def FlatFilesWithNamespace(self):
    schema = make_absolute("foo_with_ns.fbs")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      flatc(["--ts", "--ts-flat-files", "-o", tmpdir, schema], cwd=tmpdir)
      assert_file_contains(
          assert_file_exists("foo_with_ns.ts", tmp_path),
          "export * as something from './something.js';",
      )
      assert_file_contains(
          assert_file_exists("something/foo.ts", tmp_path),
          [
              "import { Bar } from '../bar/bar.js';",
              "export class Foo {",
          ],
      )

  def FlatFilesMultipleFiles(self):
    foo_schema = make_absolute("foo.fbs")
    bar_schema = make_absolute("bar/bar.fbs")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      flatc(
          ["--ts", "--ts-flat-files", "-o", tmpdir, foo_schema, bar_schema],
          cwd=tmpdir,
      )
      assert_file_contains(
          assert_file_exists("foo.ts", tmp_path),
          "export { Foo } from './foo.js';",
      )
      assert_file_contains(
          assert_file_exists("bar.ts", tmp_path),
          [
              "export { Bar } from './bar.js';",
              "export { Baz } from './baz.js';",
          ],
      )
      assert_file_contains(
          assert_file_exists("bar/bar.ts", tmp_path),
          "export class Bar {",
      )

  def FlatFilesGenAll(self):
    schema = make_absolute("foo.fbs")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      flatc(["--ts", "--ts-flat-files", "--gen-all", "-o", tmpdir, schema],
            cwd=tmpdir)
      assert_file_contains(
          assert_file_exists("foo.ts", tmp_path),
          [
              "export { Bar } from './bar.js';",
              "export { Baz } from './baz.js';",
              "export { Foo } from './foo.js';",
          ],
      )
      assert_file_contains(
          assert_file_exists("bar/bar.ts", tmp_path),
          "export class Bar {",
      )
      assert_file_contains(
          assert_file_exists("baz/baz.ts", tmp_path),
          "export enum Baz {",
      )

  def ZFlatFilesGenAllWithNamespacing(self):
    schema = make_absolute("foo_with_ns.fbs")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      flatc(
          ["--ts", "--ts-flat-files", "--gen-all", "-o", tmpdir, schema],
          cwd=tmpdir,
      )
      assert_file_contains(
          assert_file_exists("foo_with_ns.ts", tmp_path),
          [
              "export { Baz } from './baz.js';",
              "export * as something from './something.js';",
          ],
      )
      assert_file_contains(
          assert_file_exists("something.ts", tmp_path),
          "export { Foo } from './something/foo.js';",
      )
      assert_file_contains(
          assert_file_exists("something/foo.ts", tmp_path),
          [
              "import { Bar } from '../bar/bar.js';",
              "export class Foo {",
          ],
      )
