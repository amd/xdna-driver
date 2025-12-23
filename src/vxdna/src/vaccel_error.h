// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef VACCEL_ERROR_H
#define VACCEL_ERROR_H

#include <exception>
#include <string>
#include <cstdarg>
#include <cerrno>

#include "../util/vxdna_debug.h"

/**
 * @brief Custom exception class for vxdna errors
 *
 * This exception class carries both an error code (errno-style) and
 * a descriptive error message. It allows C++ internal code to use
 * exception-based error handling while still providing compatibility
 * with C-style error codes at the API boundary.
 *
 * Example usage:
 * @code
 * // Throwing an exception
 * throw vaccel_error(-EINVAL, "Invalid parameter: res_id=%u", res_id);
 *
 * // Catching and checking error code
 * try {
 *     some_function();
 * } catch (const vaccel_error& e) {
 *     if (e.code() == -ENODEV) {
 *         // Handle device not found
 *     }
 *     vxdna_err("Operation failed: %s", e.what());
 * }
 * @endcode
 */
class vaccel_error : public std::exception {
private:
    int error_code;          /**< Error code (negative errno value) */
    std::string error_msg;   /**< Error message */

public:
    /**
     * @brief Construct exception with error code and message
     *
     * @param code Error code (typically negative errno like -EINVAL, -ENOMEM)
     * @param message Error message describing the failure
     */
    vaccel_error(int code, const std::string& message)
        : error_code(code)
        , error_msg(message)
    {
    }

    /**
     * @brief Construct exception with error code and formatted message
     *
     * @param code Error code (typically negative errno like -EINVAL, -ENOMEM)
     * @param format Printf-style format string
     * @param ... Variable arguments for format string
     */
    vaccel_error(int code, const char* format, ...) __attribute__((format(printf, 3, 4)))
        : error_code(code)
    {
        va_list args;
        va_start(args, format);
        
        // Determine required buffer size
        va_list args_copy;
        va_copy(args_copy, args);
        int size = vsnprintf(nullptr, 0, format, args_copy);
        va_end(args_copy);
        
        if (size > 0) {
            // Allocate buffer and format message
            std::string buffer(size + 1, '\0');
            vsnprintf(&buffer[0], buffer.size(), format, args);
            error_msg = buffer.c_str(); // Copy without null terminator
        } else {
            error_msg = "Error formatting message";
        }
        
        va_end(args);
    }

    /**
     * @brief Get error code
     *
     * @return Error code (negative errno value)
     */
    int code() const noexcept {
        return error_code;
    }

    /**
     * @brief Get error message
     *
     * @return Error message as C string
     */
    const char* what() const noexcept override {
        return error_msg.c_str();
    }

    /**
     * @brief Get full error description including code
     *
     * @return Full error description with code and message
     */
    std::string full_message() const {
        return "Error " + std::to_string(error_code) + ": " + error_msg;
    }

    // Virtual destructor for proper cleanup
    virtual ~vaccel_error() = default;
};

/**
 * @brief Helper macro to throw vaccel_error with file/line information
 *
 * Example:
 * @code
 * VACCEL_THROW(-EINVAL, "Invalid resource ID: %u", res_id);
 * @endcode
 */
#define VACCEL_THROW(code, ...) \
    throw vaccel_error(code, "[%s:%d] " __VA_ARGS__, __FILE__, __LINE__)

/**
 * @brief Helper macro to throw vaccel_error with simple message
 */
#define VACCEL_THROW_MSG(code, fmt, ...) \
    throw vaccel_error(code, "[%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

/**
 * @brief Exception-to-error-code wrapper for public API functions
 *
 * Wraps a function that may throw exceptions, catches any exceptions,
 * logs an error message, and returns an appropriate error code.
 * This is used at the public C API boundary to convert C++ exceptions
 * to C-style error codes.
 *
 * Usage:
 * @code
 * int vaccel_create(void *cookie, uint32_t capset_id, ...) {
 *     return vaccel_error_wrap("vaccel_create", [&]() {
 *         _vaccel_device_create(cookie, capset_id, ...);
 *     });
 * }
 * @endcode
 *
 * Error handling:
 * - vaccel_error: Returns e.code(), logs message
 * - std::exception: Returns -EIO, logs e.what()
 * - Unknown: Returns -EIO, logs generic message
 * - No exception: Returns 0
 *
 * @tparam F Callable type (lambda, function, etc.)
 * @param func Function name for error logging
 * @param f Function to execute
 * @return 0 on success, negative errno on failure
 */
template<typename F> int
vaccel_error_wrap(const char *func, F &&f)
{
    try {
        f();
    } catch (const vaccel_error& e) {
        vxdna_err("Function %s failed: %s", func, e.what());
        return e.code();
    } catch (const std::exception& e) {
        vxdna_err("Function %s failed: %s", func, e.what());
        return -EIO;
    } catch (...) {
        vxdna_err("Function %s failed: unknown exception", func);
        return -EIO;
    }
    return 0;
}

#endif /* VACCEL_ERROR_H */

