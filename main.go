package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"os"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/urfave/cli/v2"
)

var (
	appName, appVer string
)

func main() {
	app := cli.NewApp()
	app.Name = appName
	app.HelpName = appName
	app.Usage = "Used for quick testing auth on Cognito Auth Pool"
	app.Version = appVer
	app.Copyright = ""

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "profile,p",
			Value:   "default",
			Usage:   "aws profile",
			EnvVars: []string{"AWS_PROFILE"},
		},
	}

	app.Commands = []*cli.Command{
		{
			Name:  "auth",
			Usage: "Authenticates user",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "username",
					Usage: "username used in Cognito User Pool",
				},
				&cli.StringFlag{
					Name:  "password",
					Usage: "Password for the username",
				},
				&cli.StringFlag{
					Name:  "clientID",
					Usage: "App clientID from Cognito User Pool",
				},
				&cli.StringFlag{
					Name:  "hash",
					Usage: "secret hash of the client",
				},
			},
			Action: cmdAuthenticateUser,
		},
		{
			Name:  "admin",
			Usage: "Admin actions",
			Subcommands: []*cli.Command{
				{
					Name:  "reset-pass",
					Usage: "Administratively resets password",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:  "username",
							Usage: "username used in Cognito User Pool",
						},
						&cli.StringFlag{
							Name:  "pass-new",
							Usage: "New password for the username",
						},
						&cli.StringFlag{
							Name:  "clientID",
							Value: "IP",
							Usage: "App clientID from Cognito User Pool",
						},
						&cli.StringFlag{
							Name:  "userPoolID",
							Value: "IP",
							Usage: "Cognito User Pool id",
						},
						&cli.StringFlag{
							Name:  "session",
							Value: "IP",
							Usage: "Session param from auth action",
						},
						&cli.StringFlag{
							Name:  "hash",
							Usage: "Client Application secret",
						},
					},
					Action: cmdAdminResetPassword,
				},
			},
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}

func cmdAdminResetPassword(c *cli.Context) error {
	username := c.String("username")
	passNew := c.String("pass-new")
	clientID := c.String("clientID")
	userPoolID := c.String("userPoolID")
	session := c.String("session")

	fmt.Println(c.String("profile"))
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithSharedConfigProfile(c.String("profile")))
	if err != nil {
		return err
	}

	cip := cognitoidentityprovider.NewFromConfig(cfg)
	mac := hmac.New(sha256.New, []byte(c.String("hash")))
	mac.Write([]byte(c.String("username") + c.String("clientID")))

	secretHash := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	params := &cognitoidentityprovider.AdminRespondToAuthChallengeInput{
		ChallengeName: types.ChallengeNameTypeNewPasswordRequired,
		ChallengeResponses: map[string]string{
			"NEW_PASSWORD": passNew,
			"USERNAME":     username,
			"SECRET_HASH":  secretHash,
		},
		ClientId:   aws.String(clientID),
		UserPoolId: aws.String(userPoolID),
		Session:    aws.String(session),
	}

	adminChallengeResp, adminChallengeErr := cip.AdminRespondToAuthChallenge(context.Background(), params)
	if adminChallengeErr != nil {
		return adminChallengeErr
	}

	jsonAuthResponse, _ := json.MarshalIndent(adminChallengeResp, "", "    ")
	fmt.Println(string(jsonAuthResponse))
	return nil
}

//func cmdChangePassword(c *cli.Context) error {
//
//	accessToken := c.String("token")
//	passOld := c.String("pass-old")
//	passNew := c.String("pass-new")
//
//	params := &cognitoidentityprovider.ChangePasswordInput{
//		AccessToken:      aws.String(accessToken),
//		PreviousPassword: aws.String(passOld),
//		ProposedPassword: aws.String(passNew),
//	}
//
//	newPassResponse, newPassErr := cip.ChangePassword(params)
//
//	if newPassErr != nil {
//		return newPassErr
//	}
//
//	fmt.Println(newPassResponse)
//
//	return nil
//}

// cmdAuthenticateUser invokes auth method with given params
// to get auth tokens.
//
func cmdAuthenticateUser(c *cli.Context) error {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return err
	}
	cip := cognitoidentityprovider.NewFromConfig(cfg)
	mac := hmac.New(sha256.New, []byte(c.String("hash")))
	mac.Write([]byte(c.String("username") + c.String("clientID")))

	secretHash := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	params := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeUserPasswordAuth,
		AuthParameters: map[string]string{
			"USERNAME":    c.String("username"),
			"PASSWORD":    c.String("password"),
			"SECRET_HASH": secretHash,
		},
		ClientId: aws.String(c.String("clientID")),
	}

	authResponse, authError := cip.InitiateAuth(context.Background(), params)
	if authError != nil {
		return authError
	}

	jsonAuthResponse, _ := json.MarshalIndent(authResponse, "", "    ")
	fmt.Println(string(jsonAuthResponse))
	return nil
}
