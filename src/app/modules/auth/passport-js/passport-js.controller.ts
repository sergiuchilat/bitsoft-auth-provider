import { Body, Controller, Get, HttpStatus, Param, Post, Req, Res, UseGuards } from '@nestjs/common';
import { ApiExcludeEndpoint, ApiTags } from '@nestjs/swagger';
import { GoogleGuard } from '@/app/modules/auth/passport-js/guards/google.guard';
import { VkGuard } from '@/app/modules/auth/passport-js/guards/vk.guard';
import { FbGuard } from '@/app/modules/auth/passport-js/guards/fb.guard';
import { PassportJsService } from '@/app/modules/auth/passport-js/passport-js.service';
import { OauthProvider } from '@/app/modules/common/enums/provider.enum';
import { Response, Request } from 'express';
import PassportGoogleMobileLoginPayloadDto from '@/app/modules/auth/passport-js/dto/passport-google-mobile-login.payload.dto';

@Controller({
  version: '1',
  path: '/oauth',
})
@ApiTags('Auth: PassportJs')
export class PassportJsController {
  constructor(private readonly passportJsService: PassportJsService) {}

  @Get('google')
  @UseGuards(GoogleGuard)
  handleGoogleLogin() {
    return 'Google login';
  }

  @Get('google/complete')
  @UseGuards(GoogleGuard)
  @ApiExcludeEndpoint()
  async handleGoogleComplete(@Req() req: Request, @Res() res: Response) {
    const clientIp = req.headers['x-client-ip'] as string;
    const response = await this.passportJsService.login(req, OauthProvider.GOOGLE, clientIp);
    res.redirect(`${process.env.REDIRECT_AFTER_LOGIN}?code=${response.token_code}`);
  }

  @Post('google/complete/mobile')
  // @ApiExcludeEndpoint()
  async handleGoogleCompleteMobile(
    @Body() passportGoogleMobileLoginPayloadDto: PassportGoogleMobileLoginPayloadDto,
    @Res() response: Response,
    @Req() request: Request,
  ) {
    response
      .status(HttpStatus.OK)
      .send(
        await this.passportJsService.loginMobile(
          passportGoogleMobileLoginPayloadDto,
          OauthProvider.GOOGLE,
          request.hostname,
          request.localization,
        ),
      );
  }

  @Get('vk')
  @UseGuards(VkGuard)
  handleVkLogin() {
    return 'VK login';
  }

  @Get('vk/complete')
  @UseGuards(VkGuard)
  @ApiExcludeEndpoint()
  async handleVkComplete(@Req() req: Request, @Res() res: Response) {
    const clientIp = req.headers['x-client-ip'] as string;
    const response = await this.passportJsService.login(req, OauthProvider.VK, clientIp);
    res.redirect(`${process.env.REDIRECT_AFTER_LOGIN}?code=${response.token_code}`);
  }

  @Get('fb')
  @UseGuards(FbGuard)
  handleFbLogin() {
    return 'FB login';
  }

  @Get('fb/complete')
  @UseGuards(FbGuard)
  @ApiExcludeEndpoint()
  async handleFbComplete(@Req() req: Request, @Res() res: Response) {
    const clientIp = req.headers['x-client-ip'] as string;
    const response = await this.passportJsService.login(req, OauthProvider.FACEBOOK, clientIp);
    res.redirect(`${process.env.REDIRECT_AFTER_LOGIN}?code=${response.token_code}`);
  }

  @Get('token/:code')
  async getToken(@Param('code') code: string, @Res() response: Response, @Req() request: Request) {
    response
      .status(HttpStatus.OK)
      .send(await this.passportJsService.getTokenByCode(code, request.hostname, request.localization));
  }
}
