/**
 * Executes the FlatBuffers compiler (`flatc`) with the given command-line arguments.
 *
 * Resets the internal stdout and stderr buffers before execution. Captures the
 * standard output and error streams produced by the WebAssembly module. Returns the
 * exit code along with the trimmed output strings.
 *
 * @param {string[]} args - The arguments to pass to the `flatc` compiler.
 * @returns {{ code: number, stdout: string, stderr: string }} The result object containing:
 *  - `code`: The exit code of the command (0 for success).
 *  - `stdout`: Captured standard output.
 *  - `stderr`: Captured standard error.
 *
 * @throws {any} Re-throws non-integer exceptions thrown by the WebAssembly module.
 *
 * @this {FlatcRunner} The FlatcRunner instance executing the command.
 */
export function runCommand(args) {
  this._stdout = "";
  this._stderr = "";
  let code = 0;
  try {
    this.Module.callMain(args);
  } catch (e) {
    if (typeof e === "number") code = e;
    else throw e;
  }
  return {
    code,
    stdout: this._stdout.trim(),
    stderr: this._stderr.trim(),
  };
}
