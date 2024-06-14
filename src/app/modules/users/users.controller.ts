import { Controller, Delete, Get, HttpStatus, Param, Patch, Post, Query, Req, Res } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { UsersService } from '@/app/modules/users/users.service';
import { Response, Request } from 'express';
import { UserPaginatorDto } from '@/app/modules/users/dto/user-paginator.dto';

@ApiTags('Users')
@Controller({
  version: '1',
  path: 'users',
})
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @ApiOperation({ summary: 'Get all users' })
  @Get()
  async getAll(@Res() response: Response, @Query() userPaginatorDto: UserPaginatorDto) {
    response.status(HttpStatus.OK).send(await this.usersService.getList(userPaginatorDto));
  }

  @ApiOperation({ summary: 'Get a user by uuid' })
  @Get('/:uuid')
  async get(@Res() response: Response, @Param('uuid') uuid: string, @Req() request: Request) {
    response.status(HttpStatus.OK).send(await this.usersService.getByUUID(uuid, request.localization));
  }

  @ApiOperation({ summary: 'Block user' })
  @Patch('block/:uuid')
  async block(@Res() response: Response, @Param('uuid') uuid: string) {
    response.status(HttpStatus.OK).send(await this.usersService.block(uuid));
  }

  @ApiOperation({ summary: 'Unblock user' })
  @Patch('unblock/:uuid')
  unblock(@Res() response: Response, @Param('uuid') uuid: string) {
    // Unblock a user by uuid. Just system admin can unblock a user
    // when user is unblocked he can use any of the auth methods
    response.status(HttpStatus.OK).send(this.usersService.unblock(uuid));
  }

  @ApiOperation({ summary: 'Delete user' })
  @Delete('/:uuid')
  async delete(@Res() response: Response, @Param('uuid') uuid: string): Promise<any> {
    response.status(HttpStatus.OK).send(await this.usersService.delete(uuid));
  }

  @ApiOperation({ summary: 'Attach an auth method to a user(---! needs to be implemented)' })
  @Post('auth-method')
  async attachAuthMethod(): Promise<any> {
    // Attach an auth method to a user. Just user can attach auth method to himself. Parse uuid from token
    // System admin can't attach auth method to any user
    return 'Attach an auth method to a user';
  }

  @ApiOperation({ summary: 'Detach an auth method from a user(---! needs to be implemented)' })
  @Delete('auth-method')
  async detachAuthMethod(): Promise<any> {
    // Detach an auth method from a user. Just user can detach auth method from himself. Parse uuid from token
    // System admin can also detach auth method from any user
    return 'Detach an auth method from a user';
  }

  @ApiOperation({ summary: 'Logout(---! needs to be implemented)' })
  @Delete('logout')
  async logout() {
    // Just user can execute logout for himself
    // Parse uuid from token
    // Logout should be done by deleting the token from the database for all auth methods

    // System admin can also execute logout for any user
    return 'Logout';
  }

  @ApiOperation({ summary: 'Check token status(---! needs to be implemented)' })
  @Get('/token/:uuid/status')
  async checkTokenStatus() {
    // Check token status. Just user can check their own token status. Parse uuid from token
    return 'Check token status';
  }
}
