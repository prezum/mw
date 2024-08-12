package middleware

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"gitlab.devprezum.ru/prezentarium/errcodes"
	"gitlab.devprezum.ru/prezentarium/mw/controllers"
)

type JWTUser struct {
	Name   string `json:"name"`
	Email  string `json:"email"`
	Avatar string `json:"avatar"`
	ID     int    `json:"id"`
	IsReal bool   `json:"is_real"`
}

type JWTCustomClaims struct {
	User JWTUser `json:"user"`
	jwt.RegisteredClaims
}

type JWTContext struct {
	token string
	err   error
	user  *JWTUser
	echo.Context
}

func (c *JWTContext) GetJWTToken() string {
	return c.token
}

func (c *JWTContext) GetJWTUser() *JWTUser {
	return c.user
}

func (c *JWTContext) IsJWTExpired() bool {
	return c.err != nil && errors.Is(c.err, errcodes.ErrTokenExpired)
}

func (c *JWTContext) IsUnaothorized() bool {
	return c.err != nil && errors.Is(c.err, errcodes.ErrNoAuthorizationHeader)
}

func (c *JWTContext) IsError() bool {
	return c.err != nil
}

func (c *JWTContext) JWTError() error {
	return c.err
}

func NewAuthMiddleware(
	log *slog.Logger,
	jwtPublic interface{},
) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			val := c.Request().Header.Get("Authorization")
			if val == "" {
				return next(&JWTContext{err: errcodes.ErrNoAuthorizationHeader, Context: c})
			}

			authSplitted := strings.Split(val, "Bearer ")
			if len(authSplitted) != 2 {
				return next(&JWTContext{err: errcodes.ErrInvalidAuthorizationHeader, Context: c})
			}

			token := authSplitted[1]
			if token == "" {
				return next(&JWTContext{err: errcodes.ErrInvalidToken, Context: c})
			}

			user, err := ParseJWTToken(token, jwtPublic)
			return next(&JWTContext{token: token, user: user, err: err, Context: c})
		}
	}
}

func NewIsRealMW(log *slog.Logger) func(jwtHandlerFunc) echo.HandlerFunc {
	wrapper := NewJWTContextMW(log)

	return func(next jwtHandlerFunc) echo.HandlerFunc {
		return wrapper(func(c *JWTContext) error {
			if !c.user.IsReal {
				return c.JSON(controllers.ErrorResponse(errcodes.ErrUserIsNotReal))
			}

			return next(c)
		})
	}
}

type jwtHandlerFunc func(*JWTContext) error

func NewJWTContextMW(log *slog.Logger) func(jwtHandlerFunc) echo.HandlerFunc {
	return func(next jwtHandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			jwtCtx, ok := c.(*JWTContext)
			if !ok {
				log.Error("cast echo ctx to jwtCtx failed")
				return c.JSON(controllers.ErrorResponse(errcodes.ErrInternal))
			}

			if err := jwtCtx.JWTError(); err != nil {
				return c.JSON(controllers.ErrorResponse(err))
			}

			return next(jwtCtx)
		}
	}
}

func ParseJWTToken(token string, jwtPublic interface{}) (*JWTUser, error) {
	if token == "" {
		return nil, errcodes.ErrInvalidToken
	}

	var claims JWTCustomClaims
	_, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		return jwtPublic, nil
	})

	if errors.Is(err, jwt.ErrTokenExpired) {
		return &claims.User, errcodes.ErrTokenExpired
	} else if err != nil {
		return &claims.User, errcodes.ErrInvalidToken
	}

	return &claims.User, nil
}
