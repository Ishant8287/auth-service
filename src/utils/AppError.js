/*
AppError is a custom error class used to create structured errors.

isOperational:
→ Indicates this is a known/expected error (like invalid input, user not found)
→ Helps global error middleware decide how to respond

captureStackTrace:
→ Helps in debugging by showing the exact location and call flow where error occurred
→ Removes unnecessary constructor calls from stack trace

FLOW:
Controller → throw new AppError()
        ↓
asyncHandler catches error
        ↓
next(error)
        ↓
Global error middleware
        ↓
Send response to client
*/

class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = statusCode >= 400 && statusCode < 500 ? "fail" : "error";
    this.isOperational = true;
    Error.captureStackTrace(this, this.Constructor);
  }
}

module.exports = AppError;
