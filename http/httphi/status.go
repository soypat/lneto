package httphi

// StatusText returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
func StatusText(code int) string {
	switch status(code) {
	case StatusContinue:
		return "Continue"
	case StatusSwitchingProtocols:
		return "Switching Protocols"
	case StatusProcessing:
		return "Processing"
	case StatusEarlyHints:
		return "Early Hints"
	case StatusOK:
		return "OK"
	case StatusCreated:
		return "Created"
	case StatusAccepted:
		return "Accepted"
	case StatusNonAuthoritativeInfo:
		return "Non-Authoritative Information"
	case StatusNoContent:
		return "No Content"
	case StatusResetContent:
		return "Reset Content"
	case StatusPartialContent:
		return "Partial Content"
	case StatusMultiStatus:
		return "Multi-Status"
	case StatusAlreadyReported:
		return "Already Reported"
	case StatusIMUsed:
		return "IM Used"
	case StatusMultipleChoices:
		return "Multiple Choices"
	case StatusMovedPermanently:
		return "Moved Permanently"
	case StatusFound:
		return "Found"
	case StatusSeeOther:
		return "See Other"
	case StatusNotModified:
		return "Not Modified"
	case StatusUseProxy:
		return "Use Proxy"
	case StatusTemporaryRedirect:
		return "Temporary Redirect"
	case StatusPermanentRedirect:
		return "Permanent Redirect"
	case StatusBadRequest:
		return "Bad Request"
	case StatusUnauthorized:
		return "Unauthorized"
	case StatusPaymentRequired:
		return "Payment Required"
	case StatusForbidden:
		return "Forbidden"
	case StatusNotFound:
		return "Not Found"
	case StatusMethodNotAllowed:
		return "Method Not Allowed"
	case StatusNotAcceptable:
		return "Not Acceptable"
	case StatusProxyAuthRequired:
		return "Proxy Authentication Required"
	case StatusRequestTimeout:
		return "Request Timeout"
	case StatusConflict:
		return "Conflict"
	case StatusGone:
		return "Gone"
	case StatusLengthRequired:
		return "Length Required"
	case StatusPreconditionFailed:
		return "Precondition Failed"
	case StatusRequestEntityTooLarge:
		return "Request Entity Too Large"
	case StatusRequestURITooLong:
		return "Request URI Too Long"
	case StatusUnsupportedMediaType:
		return "Unsupported Media Type"
	case StatusRequestedRangeNotSatisfiable:
		return "Requested Range Not Satisfiable"
	case StatusExpectationFailed:
		return "Expectation Failed"
	case StatusTeapot:
		return "I'm a teapot"
	case StatusMisdirectedRequest:
		return "Misdirected Request"
	case StatusUnprocessableEntity:
		return "Unprocessable Entity"
	case StatusLocked:
		return "Locked"
	case StatusFailedDependency:
		return "Failed Dependency"
	case StatusTooEarly:
		return "Too Early"
	case StatusUpgradeRequired:
		return "Upgrade Required"
	case StatusPreconditionRequired:
		return "Precondition Required"
	case StatusTooManyRequests:
		return "Too Many Requests"
	case StatusRequestHeaderFieldsTooLarge:
		return "Request Header Fields Too Large"
	case StatusUnavailableForLegalReasons:
		return "Unavailable For Legal Reasons"
	case StatusInternalServerError:
		return "Internal Server Error"
	case StatusNotImplemented:
		return "Not Implemented"
	case StatusBadGateway:
		return "Bad Gateway"
	case StatusServiceUnavailable:
		return "Service Unavailable"
	case StatusGatewayTimeout:
		return "Gateway Timeout"
	case StatusHTTPVersionNotSupported:
		return "HTTP Version Not Supported"
	case StatusVariantAlsoNegotiates:
		return "Variant Also Negotiates"
	case StatusInsufficientStorage:
		return "Insufficient Storage"
	case StatusLoopDetected:
		return "Loop Detected"
	case StatusNotExtended:
		return "Not Extended"
	case StatusNetworkAuthenticationRequired:
		return "Network Authentication Required"
	default:
		return ""
	}
}

const ()

type status int

// HTTP status codes as registered with IANA.
// See: https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
const (
	// RFC 9110, 15.2.1
	StatusContinue = 100 // Continue
	// RFC 9110, 15.2.2
	StatusSwitchingProtocols = 101 // Switching Protocols
	// RFC 2518, 10.1
	StatusProcessing = 102 // Processing
	// RFC 8297
	StatusEarlyHints = 103 // Early Hints

	// RFC 9110, 15.3.1
	StatusOK = 200 // OK
	// RFC 9110, 15.3.2
	StatusCreated = 201 // Created
	// RFC 9110, 15.3.3
	StatusAccepted = 202 // Accepted
	// RFC 9110, 15.3.4
	StatusNonAuthoritativeInfo = 203 // Non-Authoritative Information
	// RFC 9110, 15.3.5
	StatusNoContent = 204 // No Content
	// RFC 9110, 15.3.6
	StatusResetContent = 205 // Reset Content
	// RFC 9110, 15.3.7
	StatusPartialContent = 206 // Partial Content
	// RFC 4918, 11.1
	StatusMultiStatus = 207 // Multi-Status
	// RFC 5842, 7.1
	StatusAlreadyReported = 208 // Already Reported
	// RFC 3229, 10.4.1
	StatusIMUsed = 226 // IM Used

	// RFC 9110, 15.4.1
	StatusMultipleChoices = 300 // Multiple Choices
	// RFC 9110, 15.4.2
	StatusMovedPermanently = 301 // Moved Permanently
	// RFC 9110, 15.4.3
	StatusFound = 302 // Found
	// RFC 9110, 15.4.4
	StatusSeeOther = 303 // See Other
	// RFC 9110, 15.4.5
	StatusNotModified = 304 // Not Modified
	// RFC 9110, 15.4.6
	StatusUseProxy = 305 // Use Proxy
	// RFC 9110, 15.4.7 (Unused)
	_ = 306
	// RFC 9110, 15.4.8
	StatusTemporaryRedirect = 307 // Temporary Redirect
	// RFC 9110, 15.4.9
	StatusPermanentRedirect = 308 // Permanent Redirect

	// RFC 9110, 15.5.1
	StatusBadRequest = 400 // Bad Request
	// RFC 9110, 15.5.2
	StatusUnauthorized = 401 // Unauthorized
	// RFC 9110, 15.5.3
	StatusPaymentRequired = 402 // Payment Required
	// RFC 9110, 15.5.4
	StatusForbidden = 403 // Forbidden
	// RFC 9110, 15.5.5
	StatusNotFound = 404 // Not Found
	// RFC 9110, 15.5.6
	StatusMethodNotAllowed = 405 // Method Not Allowed
	// RFC 9110, 15.5.7
	StatusNotAcceptable = 406 // Not Acceptable
	// RFC 9110, 15.5.8
	StatusProxyAuthRequired = 407 // Proxy Authentication Required
	// RFC 9110, 15.5.9
	StatusRequestTimeout = 408 // Request Timeout
	// RFC 9110, 15.5.10
	StatusConflict = 409 // Conflict
	// RFC 9110, 15.5.11
	StatusGone = 410 // Gone
	// RFC 9110, 15.5.12
	StatusLengthRequired = 411 // Length Required
	// RFC 9110, 15.5.13
	StatusPreconditionFailed = 412 // Precondition Failed
	// RFC 9110, 15.5.14
	StatusRequestEntityTooLarge = 413 // Request Entity Too Large
	// RFC 9110, 15.5.15
	StatusRequestURITooLong = 414 // Request URI Too Long
	// RFC 9110, 15.5.16
	StatusUnsupportedMediaType = 415 // Unsupported Media Type
	// RFC 9110, 15.5.17
	StatusRequestedRangeNotSatisfiable = 416 // Requested Range Not Satisfiable
	// RFC 9110, 15.5.18
	StatusExpectationFailed = 417 // Expectation Failed
	// RFC 9110, 15.5.19 (Unused)
	StatusTeapot = 418 // I'm a teapot
	// RFC 9110, 15.5.20
	StatusMisdirectedRequest = 421 // Misdirected Request
	// RFC 9110, 15.5.21
	StatusUnprocessableEntity = 422 // Unprocessable Entity
	// RFC 4918, 11.3
	StatusLocked = 423 // Locked
	// RFC 4918, 11.4
	StatusFailedDependency = 424 // Failed Dependency
	// RFC 8470, 5.2.
	StatusTooEarly = 425 // Too Early
	// RFC 9110, 15.5.22
	StatusUpgradeRequired = 426 // Upgrade Required
	// RFC 6585, 3
	StatusPreconditionRequired = 428 // Precondition Required
	// RFC 6585, 4
	StatusTooManyRequests = 429 // Too Many Requests
	// RFC 6585, 5
	StatusRequestHeaderFieldsTooLarge = 431 // Request Header Fields Too Large
	// RFC 7725, 3
	StatusUnavailableForLegalReasons = 451 // Unavailable For Legal Reasons

	// RFC 9110, 15.6.1
	StatusInternalServerError = 500 // Internal Server Error
	// RFC 9110, 15.6.2
	StatusNotImplemented = 501 // Not Implemented
	// RFC 9110, 15.6.3
	StatusBadGateway = 502 // Bad Gateway
	// RFC 9110, 15.6.4
	StatusServiceUnavailable = 503 // Service Unavailable
	// RFC 9110, 15.6.5
	StatusGatewayTimeout = 504 // Gateway Timeout
	// RFC 9110, 15.6.6
	StatusHTTPVersionNotSupported = 505 // HTTP Version Not Supported
	// RFC 2295, 8.1
	StatusVariantAlsoNegotiates = 506 // Variant Also Negotiates
	// RFC 4918, 11.5
	StatusInsufficientStorage = 507 // Insufficient Storage
	// RFC 5842, 7.2
	StatusLoopDetected = 508 // Loop Detected
	// RFC 2774, 7
	StatusNotExtended = 510 // Not Extended
	// RFC 6585, 6
	StatusNetworkAuthenticationRequired = 511 // Network Authentication Required
)
