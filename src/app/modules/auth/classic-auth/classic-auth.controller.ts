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
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { ClassicAuthService } from './classic-auth.service';
import ClassicAuthRegisterPayloadDto from './dto/classic-auth-register.payload.dto';
import ClassicAuthLoginPayloadDto from './dto/classic-auth-login.payload.dto';
import ClassicAuthActivateResendPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-activate-resend.payload.dto';
import ClassicAuthResetPasswordPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-reset-password.payload.dto';
import ClassicAuthResetPasswordConfirmPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-reset-password-confirm.payload.dto';
import ClassicAuthChangePasswordPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-change-password.payload.dto';
import { AuthGuard } from '@/app/middleware/guards/auth.guard';
import ClassicAuthUpdateEmailPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-update-email.payload.dto';
import { ClassicAuthRefreshTokenPayloadDto } from '@/app/modules/auth/classic-auth/dto/classic-auth-refresh-token.payload.dto';
import ClassicAuthVerifyQrPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-verify-qr.payload.dto';
import { RequestUser } from '@/app/request/decorators/request-user.decorator';
import RequestUserInterface from '@/app/request/interfaces/request-user.Interface';
import ClassicAuthRegisterWithoutPasswordPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-register-without-password.payload.dto';

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
    const clientIp = request.headers['x-client-ip'] as string;

    response
      .status(HttpStatus.OK)
      .send(
        await this.classicAuthService.login(
          classicAuthLoginPayloadDto,
          request.localization,
          clientIp,
          request.hostname,
        ),
      );
  }

  @Post('/refresh-token')
  @ApiOperation({ summary: 'Refresh token' })
  async refreshToken(
    @Body() classicAuthRefreshTokenPayloadDto: ClassicAuthRefreshTokenPayloadDto,
    @Res() response: Response,
    @Req() request: Request,
  ) {
    response
      .status(HttpStatus.OK)
      .send(
        await this.classicAuthService.refreshToken(
          classicAuthRefreshTokenPayloadDto,
          request.hostname,
          request.localization,
        ),
      );
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

  @ApiOperation({ summary: 'User registration with email' })
  @Post('register-v2')
  async registerV2(
    @Body() classicAuthRegisterWithoutPasswordPayloadDto: ClassicAuthRegisterWithoutPasswordPayloadDto,
    @Res() response: Response,
    @Req() request: Request,
  ) {
    response
      .status(HttpStatus.CREATED)
      .send(
        await this.classicAuthService.registerV2(
          classicAuthRegisterWithoutPasswordPayloadDto,
          request.localization,
        ),
      );
  }

  @ApiOperation({ summary: 'Connect two factor' })
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @Post('connect-two-factor')
  async generateQR(
    @Res() response: Response,
    @RequestUser() user: RequestUserInterface,
    @Req() req: Request,
  ) {
    response
      .status(HttpStatus.CREATED)
      .send(await this.classicAuthService.toggleTwoFactor(user, req.localization));
  }

  @ApiOperation({ summary: 'Verify two factor' })
  @ApiBearerAuth()
  @Post('2fa')
  async verifyQr(
    @Res() response: Response,
    @Body() classicAuthVerifyQrPayloadDto: ClassicAuthVerifyQrPayloadDto,
    @RequestUser() user: RequestUserInterface,
    @Req() req: Request,
  ) {
    response
      .status(HttpStatus.CREATED)
      .send(
        await this.classicAuthService.verifyQr(
          classicAuthVerifyQrPayloadDto,
          user,
          req.hostname,
          req.localization,
        ),
      );
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
    response
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
    response
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
    response.status(HttpStatus.OK).send(await this.classicAuthService.verifyResetPassword(token));
  }

  @ApiOperation({ summary: 'Confirm password reset' })
  @Patch('password/reset/confirm')
  async resetPasswordConfirm(
    @Res() response: Response,
    @Body() classicAuthResetPasswordConfirmPayloadDto: ClassicAuthResetPasswordConfirmPayloadDto,
  ) {
    response
      .status(HttpStatus.OK)
      .send(await this.classicAuthService.resetPasswordConfirm(classicAuthResetPasswordConfirmPayloadDto));
  }

  @ApiOperation({ summary: 'Change password' })
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @Patch('password/change')
  async changePassword(
    @Res() response: Response,
    @Body() classicAuthChangePasswordPayloadDto: ClassicAuthChangePasswordPayloadDto,
    @Req() req: Request,
  ) {
    response
      .status(HttpStatus.OK)
      .send(await this.classicAuthService.changePassword(classicAuthChangePasswordPayloadDto, req.user));
  }

  @ApiOperation({ summary: 'Update email' })
  @Patch('email/update')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  async updateEmail(
    @Res() response: Response,
    @Body() classicAuthUpdateEmailPayloadDto: ClassicAuthUpdateEmailPayloadDto,
    @Req() req: Request,
  ) {
    response
      .status(HttpStatus.OK)
      .send(await this.classicAuthService.updateEmail(classicAuthUpdateEmailPayloadDto, req.user));
  }
}
