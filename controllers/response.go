package controllers

import (
	"errors"

	"gitlab.devprezum.ru/prezentarium/errcodes"
)

type response struct {
	Result interface{}  `json:"result,omitempty"`
	Error  *errorStruct `json:"error,omitempty"`
}

type DummyResponse struct {
	Val string `json:"val"`
}

type errorStruct struct {
	ErrorMessage string             `json:"message"`
	ErrorCode    errcodes.CodeError `json:"code"`
}

// func ErrorResponse(err error, codeArg ...int) response {
//  code := -1
//  if len(codeArg) > 0 {
//   code = codeArg[0]
//  }
//  return response{Error: &errorStruct{ErrorMessage: err.Error(), ErrorCode: code}}
// }

func Response(data interface{}) response {
	return response{Result: data}
}

func ErrorResponse(err error) (int, response) {
	var errCode errcodes.CodeError
	if errors.As(err, &errCode) {
		return errCode.GetHTTPCode(), response{
			Error: &errorStruct{ErrorMessage: errCode.Error(), ErrorCode: errCode},
		}
	}

	return errcodes.ErrUnknown.GetHTTPCode(), response{
		Error: &errorStruct{ErrorMessage: err.Error(), ErrorCode: errcodes.ErrUnknown},
	}
}
