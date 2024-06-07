import {Request, Response} from 'express';
import {Body, Controller, Get, HttpStatus, Param, ParseUUIDPipe, Patch, Post, Req, Res} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { ClassicAuthService } from './classic-auth.service';
import ClassicAuthRegisterPayloadDto from './dto/classic-auth-register.payload.dto';
import ClassicAuthLoginPayloadDto from './dto/classic-auth-login.payload.dto';
import {
  ClassicAuthRefreshTokenPayloadDto
} from '@/app/modules/auth/classic-auth/dto/classic-auth-refresh-token.payload.dto';

@ApiTags ('Auth: Classic')
@Controller ({
  version: '1',
  path: 'auth',

})
export class ClassicAuthController {
  constructor (
    private readonly classicAuthService: ClassicAuthService,
  ) {
  }

  @ApiOperation ({summary: 'User login with email and password'})
  @Post ('login')
  async login (
    @Body() classicAuthLoginPayloadDto: ClassicAuthLoginPayloadDto,
    @Res () response: Response,
    @Req () request: Request
  ) {
    response
      .status (HttpStatus.OK)
      .send (await this.classicAuthService.login (classicAuthLoginPayloadDto, request));
  }

  @Post ('/refresh-token')
  @ApiOperation ({summary: 'Refresh token'})
  async refreshToken (
    @Body() classicAuthRefreshTokenPayloadDto: ClassicAuthRefreshTokenPayloadDto,
    @Res () response: Response,
    @Req () request: Request,
  ) {
    response
      .status (HttpStatus.OK)
      .send (await this.classicAuthService.refreshToken (classicAuthRefreshTokenPayloadDto, request));
  }

  @ApiOperation ({summary: 'User registration with email and password'})
  @Post ('register')
  async register (
    @Body() classicAuthRegisterPayloadDto: ClassicAuthRegisterPayloadDto,
    @Res () response: Response,
  ) {
    response
      .status (HttpStatus.CREATED)
      .send (await this.classicAuthService.register (classicAuthRegisterPayloadDto));
  }

  @ApiOperation ({summary: 'Activate user account'})
  @Patch ('activate/:token')
  async activate (
    @Res () response: Response,
    @Param ('token', ParseUUIDPipe) token: string,
  ) {
    response
      .status (HttpStatus.OK)
      .send (await this.classicAuthService.activate (token));
  }

  @ApiOperation ({summary: 'Resend activation email(---! needs to be implemented)'})
  @Post ('activate/resend')
  resendActivationEmail () {
    // Resend activation email.
    // Payload should contain email address
    // {
    //   "email": "email@domain.com"
    // }
    // after sending email, return success message
    // if email not found, return also success message to prevent email enumeration attack.
    // The message "If the email is registered, an activation email will be sent" should be returned
    return 'resendActivationEmail';
  }

  @ApiOperation ({summary: 'Request password reset(---! needs to be implemented)'})
  @Post ('password/reset/request')
  resetPasswordStart () {
    // Request password reset.
    // Payload should contain email address
    // after sending email, return success message
    // if email not found, return also success message to prevent email enumeration attack.
    // The message "If the email is registered, a password reset email will be sent" should be returned
    // Generate a token and send it to the user email
    // The token should be valid for 1 hour
    // The token should be unique
    // The token should be stored in the database
    // The token should be hashed
    // The token should be sent to the user email
    // The token should be used to reset the password
    // The token should be deleted after the password is reset
    // Generated link = {FRONTEND_URL}/password/reset/{TOKEN}
    // Frontend will send a GET request to {AUTH_MICROSERVICE}/password/reset/{TOKEN}
    // The token should be verified
    // If token is not valid, return an error
    // If token is valid then
    // Frontend will send a PATCH request to {AUTH_MICROSERVICE}/password/reset/confirm with the token and the new password
    // The password should be hashed

    return 'resetPassword';
  }

  @ApiOperation ({summary: 'Verify password reset token(---! needs to be implemented)'})
  @Get ('password/reset/:token')
  verifyResetPasswordToken () {
    // Verify password reset token.
    // Token should be valid
    // Token should be unique
    // Token should be hashed
    // Token should be stored in the database
    // If token is not valid, return an error
    // If token is valid, return success message with the token in response body
    return 'verifyResetPasswordToken';
  }

  @ApiOperation ({summary: 'Confirm password reset(---! needs to be implemented)'})
  @Patch ('password/reset/confirm')
  resetPasswordConfirm () {
    // Confirm password reset.
    // Payload should contain token and new password
    // Token should be valid
    // Token should be unique
    // Token should be hashed
    // Token should be stored in the database
    // If token is not valid, return an error
    // If token is valid, return success message
    // The password should be hashed
    // The password should be stored in the database
    // The token should be deleted
    return 'resetPassword';
  }

  @ApiOperation ({summary: 'Change password(---! needs to be implemented)'})
  @Patch ('password/change')
  changePassword () {
    // Change password.
    // Payload should contain old password and new password
    // Old password should be valid
    // Request must contain a valid JWT token
    // User uuid should be parsed from the JWT token
    // Check if the old password is correct for the user extracted from the JWT token
    // If old password is not correct, return an error
    // If old password is correct, change the password to the new password
    // The new password should be hashed
    return 'changePassword';
  }

  @ApiOperation ({summary: 'Update email(---! needs to be implemented)'})
  @Patch ('email/update')
  updateEmail() {
    return 'updateEmail';
  }

}
