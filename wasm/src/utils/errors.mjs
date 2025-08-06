/**
 * Logs an error with contextual metadata including method name, message, stack trace, and timestamp.
 *
 * Appends the error to the internal `errors` array of the current FlatcRunner instance.
 *
 * @param {string} method - The name of the method where the error occurred.
 * @param {Error} error - The error object to log.
 *
 * @this {FlatcRunner} The FlatcRunner instance where the error occurred.
 */
export function logError(method, error) {
  this.errors.push({
    timestamp: new Date().toISOString(),
    method,
    message: error?.message,
    stack: error?.stack,
  });
}
