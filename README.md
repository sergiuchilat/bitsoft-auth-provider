# Project Installation
```bash
npm install
```

# Running the app
```bash
 development(v1)
$ npm run start

# development(v2)
$ nest start

# watch mode(v1)
$ npm run start:dev

# watch mode(v2)
$ nest start --watch

# production mode
$ npm run start:prod
```

# Usage
## Generate JWT token pair of public and private keys
```bash
ssh-keygen -t rsa -b 4096 -m PEM -f jwt/jwt.key
openssl rsa -in jwt/jwt.key -pubout -outform PEM -out jwt/jwt.key.pub
```
Private key will be used to sign the JWT token by the Auth Microservice.
Public key must be used in the Backend CORE api(or any system component that use the Auth Microservice) to verify the user token.

## Classic Auth
### User registration
URL: `http://localhost:3000/api/v1/auth/classic/register`

METHOD: `POST`

```json
{
  "email": "mail@domain.com",
  "password": "strong_password",
  "name": "John Doe"
}
```

### User activation
User activation link will be sent to the user email address. To activate the user account the user must click on the activation link.

URL: `http://localhost:3000/api/v1/auth/classic/activate{TOKEN}`

### User login
URL: `http://localhost:3000/api/v1/auth/classic/login`

METHOD: `POST`

```json
{
  "email": "mail@domain.com",
  "password": "strong_password"
}
```
If user successfully logged in then the response will contain the user data encoded in a JWT token.

## Google Auth
- When user select Google auth method then Frontend must redirect the user to Google login page of Auth Microservice ``http://localhost:3000/api/v1/auth/google/login``
- After successful login, Google will redirect the user back to the Auth Microservice address ``http://localhost:3000/api/v1/auth/google/complete``
- Frontend must send a request to receive the user data ``http://localhost:3000/api/v1/auth/google/status``
  - If user successfully logged in then the response will contain the user data encoded in a JWT token
  - If user is not authenticated then the response will contain an error message with status code 401
- Frontend will use the received JWT token to authenticate the user in the Backend CORE api(or any system component that use the Auth Microservice)
- Backend CORE api(or any system component that use the Auth Microservice) must use JWT public key to verify the user token on any request send by frontend.

## VK Auth
- When user select VK auth method then Frontend must redirect the user to Google login page of Auth Microservice ``http://localhost:3000/api/v1/auth/vk/login``
- After successful login, VK will redirect the user back to the Auth Microservice address ``http://localhost:3000/api/v1/auth/vk/complete``
- Frontend must send a request to receive the user data ``http://localhost:3000/api/v1/auth/vk/status``
    - If user successfully logged in then the response will contain the user data encoded in a JWT token
    - If user is not authenticated then the response will contain an error message with status code 401
- Frontend will use the received JWT token to authenticate the user in the Backend CORE api(or any system component that use the Auth Microservice)
- Backend CORE api(or any system component that use the Auth Microservice) must use JWT public key to verify the user token on any request send by frontend.

## Token structure
```json
{
  "props": {
    "authMethod": "vk-oauth|google-oauth|classic",
    "email": "user.email@domain.com",
    "name": "Name or null"
  },
  "sub": "83db08ca-7e44-4c56-bd21-5cabe3881612",
  "iat": 1713564282,
  "exp": 1713567882
}
```
`"sub": "83db08ca-7e44-4c56-bd21-5cabe3881612"` - user UUID generated by the Auth Microservice

`"iat": 1713564282` - token creation timestamp

`"exp": 1713567882` - token expiration timestamp


# Author
- Sergiu Chilat
- Personal website: [Sergiu Chilat](https://sergiu.live)
- GitHub Profile [https://github.com/sergiuchilat](https://github.com/sergiuchilat)

