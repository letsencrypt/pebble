package acme

import (
	"fmt"
	"net/http"
)

const (
	errNS             = "urn:ietf:params:acme:error:"
	serverInternalErr = errNS + "serverInternal"
	malformedErr      = errNS + "malformedRequest"
	badNonceErr       = errNS + "badNonce"
	agreementReqErr   = errNS + "agreementRequired"
)

type ProblemDetails struct {
	Type       string `json:"type,omitempty"`
	Detail     string `json:"detail,omitempty"`
	HTTPStatus int    `json:"status,omitempty"`
}

func (pd *ProblemDetails) Error() string {
	return fmt.Sprintf("%s :: %s", pd.Type, pd.Detail)
}

func InternalErrorProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       serverInternalErr,
		Detail:     detail,
		HTTPStatus: http.StatusInternalServerError,
	}
}

func MalformedProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       malformedErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func MethodNotAllowed() *ProblemDetails {
	return &ProblemDetails{
		Type:       malformedErr,
		Detail:     "Method not allowed",
		HTTPStatus: http.StatusMethodNotAllowed,
	}
}

func BadNonceProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       badNonceErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func Conflict(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       malformedErr,
		Detail:     detail,
		HTTPStatus: http.StatusConflict,
	}
}

func AgreementRequiredProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       agreementReqErr,
		Detail:     detail,
		HTTPStatus: http.StatusForbidden,
	}
}
