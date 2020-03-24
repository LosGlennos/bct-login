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

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResult struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func HandleRequest(ctx context.Context, credentials Credentials) (string, error) {
	authInput := getAuthInput(credentials)

	identityProvider := getCognitoClient()

	res, err := identityProvider.InitiateAuth(authInput)
	if err != nil {
		return "", err
	}

	resultJson := getResultJson(res)

	return resultJson, nil
}

func getResultJson(res *cognito.InitiateAuthOutput) string {
	log.Print(res.AuthenticationResult.AccessToken)
	log.Print(*res.AuthenticationResult.AccessToken)
	
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
		AuthFlow:       aws.String("USER_PASSWORD_AUTH"),
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
