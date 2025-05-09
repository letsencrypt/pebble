package acme

import (
	"fmt"
	"net/http"
)

const (
	errNS                    = "urn:ietf:params:acme:error:"
	serverInternalErr        = errNS + "serverInternal"
	malformedErr             = errNS + "malformed"
	badNonceErr              = errNS + "badNonce"
	badCSRErr                = errNS + "badCSR"
	agreementReqErr          = errNS + "agreementRequired"
	externalAccountReqErr    = errNS + "externalAccountRequired"
	connectionErr            = errNS + "connection"
	unauthorizedErr          = errNS + "unauthorized"
	invalidContactErr        = errNS + "invalidContact"
	unsupportedContactErr    = errNS + "unsupportedContact"
	accountDoesNotExistErr   = errNS + "accountDoesNotExist"
	badRevocationReasonErr   = errNS + "badRevocationReason"
	alreadyRevokedErr        = errNS + "alreadyRevoked"
	orderNotReadyErr         = errNS + "orderNotReady"
	badPublicKeyErr          = errNS + "badPublicKey"
	badSignatureAlgorithmErr = errNS + "badSignatureAlgorithm"
	rejectedIdentifierErr    = errNS + "rejectedIdentifier"
)

type ProblemDetails struct {
	Type        string           `json:"type,omitempty"`
	Detail      string           `json:"detail,omitempty"`
	HTTPStatus  int              `json:"status,omitempty"`
	Identifier  *Identifier      `json:"identifier,omitempty"`
	Subproblems []ProblemDetails `json:"subproblems,omitempty"`
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

func NotFoundProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       malformedErr,
		Detail:     detail,
		HTTPStatus: http.StatusNotFound,
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

func BadCSRProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       badCSRErr,
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

func ExternalAccountRequiredProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       externalAccountReqErr,
		Detail:     detail,
		HTTPStatus: http.StatusForbidden,
	}
}

func ConnectionProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       connectionErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func UnauthorizedProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       unauthorizedErr,
		Detail:     detail,
		HTTPStatus: http.StatusForbidden,
	}
}

func InvalidContactProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       invalidContactErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func UnsupportedContactProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       unsupportedContactErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func AccountDoesNotExistProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       accountDoesNotExistErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func UnsupportedMediaTypeProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       malformedErr,
		Detail:     detail,
		HTTPStatus: http.StatusUnsupportedMediaType,
	}
}

func BadRevocationReasonProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       badRevocationReasonErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func AlreadyRevokedProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       alreadyRevokedErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func OrderNotReadyProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       orderNotReadyErr,
		Detail:     detail,
		HTTPStatus: http.StatusForbidden,
	}
}

func BadPublicKeyProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       badPublicKeyErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func BadSignatureAlgorithmProblem(detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       badSignatureAlgorithmErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
	}
}

func RejectedIdentifierProblem(ident Identifier, detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:       rejectedIdentifierErr,
		Detail:     detail,
		HTTPStatus: http.StatusBadRequest,
		Subproblems: []ProblemDetails{
			{
				Type:       rejectedIdentifierErr,
				Identifier: &ident,
				Detail:     fmt.Sprintf("%s is a forbidden domain", ident.Value),
			},
		},
	}
}
