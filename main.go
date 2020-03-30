package main

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"log"
	"os"
)

type AuthHandler struct {
	IdentityProvider *cognito.CognitoIdentityProvider
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResult struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func HandleRequest(ctx context.Context, credentials Credentials) (string, error) {
	log.Printf("Username: %s; Password: %s", credentials.Username, credentials.Password)
	authHandler := AuthHandler {
		IdentityProvider: getCognitoClient(),
	}

	loginResult, err := authHandler.Login(credentials)
	if err != nil {
		return "", err
	}

	if loginResult.ChallengeName != nil && *loginResult.ChallengeName == cognito.ChallengeNameTypeNewPasswordRequired {
		authHandler.SetNewPassword(credentials.Username, credentials.Password)
		loginResult, err = authHandler.Login(credentials)
		if err != nil {
			panic(err)
		}
	}

	resultJson := getResultJson(loginResult)

	return resultJson, nil
}

func (authHandler *AuthHandler) Login(credentials Credentials) (*cognito.InitiateAuthOutput, error){
	authInput := getAuthInput(credentials)

	res, err := authHandler.IdentityProvider.InitiateAuth(authInput)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (authHandler *AuthHandler) SetNewPassword(username string, password string) {
	newPasswordInput := &cognito.AdminSetUserPasswordInput{
		Password: aws.String(password),
		Username: aws.String(username),
		Permanent: aws.Bool(true),
		UserPoolId: aws.String(os.Getenv("COGNITO_USER_POOL_ID")),
	}

	_, err := authHandler.IdentityProvider.AdminSetUserPassword(newPasswordInput)
	if err != nil {
		panic(err)
	}
}

func getResultJson(res *cognito.InitiateAuthOutput) string {
	authResult := AuthResult{
		AccessToken:  aws.StringValue(res.AuthenticationResult.AccessToken),
		RefreshToken: aws.StringValue(res.AuthenticationResult.RefreshToken),
	}
	buff, err := json.Marshal(authResult)
	if err != nil {
		panic(err)
	}
	resultJson := string(buff)
	return resultJson
}

func getAuthInput(credentials Credentials) *cognito.InitiateAuthInput {
	params := map[string]*string{
		"USERNAME": aws.String(credentials.Username),
		"PASSWORD": aws.String(credentials.Password),
	}
	authInput := &cognito.InitiateAuthInput{
		AuthFlow:       aws.String(cognito.AuthFlowTypeUserPasswordAuth),
		AuthParameters: params,
		ClientId:       aws.String(os.Getenv("COGNITO_APP_CLIENT_ID")),
	}
	return authInput
}

func getCognitoClient() *cognito.CognitoIdentityProvider {
	conf := &aws.Config{
		Region: aws.String("eu-west-1"),
	}

	s, err := session.NewSession(conf)
	if err != nil {
		panic(err)
	}

	identityProvider := cognito.New(s)

	return identityProvider
}

func main() {
	lambda.Start(HandleRequest)
}
