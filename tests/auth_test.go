package tests

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.devprezum.ru/prezentarium/errcodes"
	"gitlab.devprezum.ru/prezentarium/mw"
	"gitlab.devprezum.ru/prezentarium/mw/controllers"
)

func generateValidJWTToken(user *mw.JWTUser, secret []byte) (string, error) {
	claims := mw.JWTCustomClaims{
		User: *user,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func generateExpiredJWTToken(user *mw.JWTUser, secret []byte) (string, error) {
	claims := mw.JWTCustomClaims{
		User: *user,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func TestJWTMiddleware(t *testing.T) {
	e := echo.New()
	log := slog.New(slog.NewTextHandler(nil, nil))

	jwtMiddleWare := mw.NewAuthMiddleware(log, nil)

	user := &mw.JWTUser{ID: 123, Email: "test@example.com"}

	validJWTToken, _ := generateValidJWTToken(user, nil)
	expiredJWTToken, _ := generateExpiredJWTToken(user, nil)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectedError  error
	}{
		{
			name:           "No Authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  errcodes.ErrNoAuthorizationHeader,
		},
		{
			name:           "Invalid Authorization header",
			authHeader:     "InvalidHeader",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  errcodes.ErrInvalidAuthorizationHeader,
		},
		{
			name:           "Empty token",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  errcodes.ErrInvalidToken,
		},
		{
			name:           "Valid token",
			authHeader:     "Bearer " + validJWTToken,
			expectedStatus: http.StatusOK,
			expectedError:  nil,
		},
		{
			name:           "Expired token",
			authHeader:     "Bearer " + expiredJWTToken,
			expectedStatus: http.StatusOK,
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", tt.authHeader)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := jwtMiddleWare(func(c echo.Context) error {
				jwtContext := c.(*mw.JWTContext)
				if jwtContext.JWTError() != nil {
					return jwtContext.JWTError()
				}
				return c.String(http.StatusOK, "Success")
			})

			err := handler(c)
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, rec.Code)
			}
		})
	}
}

func TestIsRealMiddleware(t *testing.T) {
	e := echo.New()
	log := slog.New(slog.NewTextHandler(nil, nil))

	middlewareFunc := mw.NewIsRealMW(log)

	_, expectedErrorNotRealUnmarshal := controllers.ErrorResponse(errcodes.ErrUserIsNotReal)
	expectedErrorNotReal, _ := json.Marshal(expectedErrorNotRealUnmarshal)

	tests := []struct {
		name           string
		user           *mw.JWTUser
		expectedStatus int
		expectedError  string
	}{
		{
			name: "User is real",
			user: &mw.JWTUser{
				ID:     123,
				Email:  "test@example.com",
				IsReal: true,
			},
			expectedStatus: http.StatusOK,
			expectedError:  "",
		},
		{
			name: "User is not real",
			user: &mw.JWTUser{
				ID:     123,
				Email:  "test@example.com",
				IsReal: false,
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  string(expectedErrorNotReal),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			jwtCtx := &mw.JWTContext{
				Context: c,
			}
			jwtCtx.SetJWTUser(tt.user)

			handler := middlewareFunc(func(c *mw.JWTContext) error {
				return c.String(http.StatusOK, "Success")
			})

			err := handler(jwtCtx)
			if tt.expectedError != "" {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, rec.Code)
				assert.Contains(t, rec.Body.String(), tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, rec.Code)
			}
		})
	}
}
