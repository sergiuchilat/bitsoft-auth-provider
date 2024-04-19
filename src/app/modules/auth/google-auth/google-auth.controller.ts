import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { GoogleAuthGuard } from '@/app/modules/auth/google-auth/google-auth.guard';
import { Request } from 'express';

@ApiTags('Google Authentication')
@Controller({
  version: '1',
  path: '/auth/google'
})
export class GoogleAuthController {

  @Get('login')
  @UseGuards(GoogleAuthGuard)
  handleLogin() {
    return 'Google login';
  }

  @Get('redirect')
  @UseGuards(GoogleAuthGuard)
  handleRedirect() {
    return 'Google redirect';
  }

  @Get('status')
  handleStatus(@Req() request: Request){

    console.log(request.user);
    if (request.user) {
      return {
        user: request.user,
        message: 'User is logged in'
      };
    }
    return {
      message: 'User is not logged in'
    };
  }
}