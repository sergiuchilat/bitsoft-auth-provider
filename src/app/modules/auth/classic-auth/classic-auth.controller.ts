import { Request, Response } from 'express';
import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { ClassicAuthService } from './classic-auth.service';
import ClassicAuthRegisterPayloadDto from './dto/classic-auth-register.payload.dto';
import ClassicAuthLoginPayloadDto from './dto/classic-auth-login.payload.dto';
import ClassicAuthActivateResendPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-activate-resend.payload.dto';
import ClassicAuthResetPasswordPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-reset-password.payload.dto';
import ClassicAuthResetPasswordConfirmPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-reset-password-confirm.payload.dto';

@ApiTags('Auth: Classic')
@Controller({
  version: '1',
  path: 'auth',
})
export class ClassicAuthController {
  constructor(private readonly classicAuthService: ClassicAuthService) {}

  @ApiOperation({ summary: 'User login with email and password' })
  @Post('login')
  async login(
    @Body() classicAuthLoginPayloadDto: ClassicAuthLoginPayloadDto,
    @Res() response: Response,
    @Req() request: Request,
  ) {
    response
      .status(HttpStatus.OK)
      .send(await this.classicAuthService.login(classicAuthLoginPayloadDto, request.localization));
  }

  @ApiOperation({ summary: 'User registration with email and password' })
  @Post('register')
  async register(
    @Body() classicAuthRegisterPayloadDto: ClassicAuthRegisterPayloadDto,
    @Res() response: Response,
    @Req() request: Request,
  ) {
    response
      .status(HttpStatus.CREATED)
      .send(await this.classicAuthService.register(classicAuthRegisterPayloadDto, request.localization));
  }

  @ApiOperation({ summary: 'Activate user account' })
  @Patch('activate/:token')
  async activate(
    @Res() response: Response,
    @Param('token', ParseUUIDPipe) token: string,
    @Req() request: Request,
  ) {
    response.status(HttpStatus.OK).send(await this.classicAuthService.activate(token, request.localization));
  }

  @ApiOperation({ summary: 'Resend activation email' })
  @Post('activate/resend')
  resendActivationEmail(
    @Res() response: Response,
    @Body() classicAuthActivateResendPayloadDto: ClassicAuthActivateResendPayloadDto,
    @Req() request: Request,
  ) {
    return response
      .status(HttpStatus.OK)
      .send(
        this.classicAuthService.resendActivationEmail(
          classicAuthActivateResendPayloadDto,
          request.localization,
        ),
      );
  }

  @ApiOperation({ summary: 'Request password reset' })
  @Post('password/reset/request')
  async resetPasswordStart(
    @Res() response: Response,
    @Body() classicAuthResetPasswordPayloadDto: ClassicAuthResetPasswordPayloadDto,
    @Req() req: Request,
  ) {
    return response
      .status(HttpStatus.OK)
      .send(
        await this.classicAuthService.startResetPassword(
          classicAuthResetPasswordPayloadDto,
          req.localization,
        ),
      );
  }

  @ApiOperation({ summary: 'Verify password reset token' })
  @Get('password/reset/:token')
  async verifyResetPasswordToken(@Res() response: Response, @Param('token', ParseUUIDPipe) token: string) {
    return response.status(HttpStatus.OK).send(await this.classicAuthService.verifyResetPassword(token));
  }

  @ApiOperation({ summary: 'Confirm password reset' })
  @Patch('password/reset/confirm')
  async resetPasswordConfirm(
    @Res() response: Response,
    @Body() classicAuthResetPasswordConfirmPayloadDto: ClassicAuthResetPasswordConfirmPayloadDto,
  ) {
    return response
      .status(HttpStatus.OK)
      .send(await this.classicAuthService.resetPasswordConfirm(classicAuthResetPasswordConfirmPayloadDto));
  }

  @ApiOperation({ summary: 'Change password(---! needs to be implemented)' })
  @Patch('password/change')
  changePassword() {
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

  @ApiOperation({ summary: 'Update email(---! needs to be implemented)' })
  @Patch('email/update')
  updateEmail() {
    return 'updateEmail';
  }
}
