package acme

import (
	"fmt"
	"net/http"
)

type ProblemDetails struct {
	Type       string `json:"type,omitempty"`
	Detail     string `json:"detail,omitempty"`
	HTTPStatus int    `json:"status,omitempty"`
}

func (pd *ProblemDetails) Error() string {
	return fmt.Sprintf("%s :: %s", pd.Type, pd.Detail)
}

// TODO(@cpu): Make constants for the Type strings

func InternalErrorProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       "urn:acme:error:serverInternal",
		Detail:     detail,
		HTTPStatus: http.StatusInternalServerError,
	}
}

func MalformedProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       "urn:acme:error:malformedRequest",
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func MethodNotAllowed() *ProblemDetails {
	return &ProblemDetails{
		Type:       "urn:acme:error:malformedRequest",
		Detail:     "Method not allowed",
		HTTPStatus: http.StatusMethodNotAllowed,
	}
}

func BadNonceProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       "urn:acme:error:badNonce",
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}
