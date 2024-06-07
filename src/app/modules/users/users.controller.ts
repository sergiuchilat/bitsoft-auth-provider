import { Controller, Delete, Get, Patch, Post, UseGuards } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { UsersService } from '@/app/modules/users/users.service';
import { AuthGuard } from '@/app/middleware/guards/auth.guard';

@ApiTags('Users')
@Controller({
  version: '1',
  path: 'users',
})
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @ApiOperation({ summary: 'Get all users(---! ---! needs to be implemented)' })
  @Get()
  @UseGuards(AuthGuard)
  getAll() {
    // Paginated list of users. Just system admin can get all users
    return 'Get all users';
  }

  @ApiOperation({ summary: 'Get a user(---! needs to be implemented)' })
  @Get('/:uuid')
  get(uuid: string) {
    // Get a user by uuid. Just system admin can get a user
    return 'Get a user ' + uuid;
  }

  @ApiOperation({ summary: 'Block user(---! needs to be implemented)' })
  @Patch('block/:uuid')
  async block() {
    // Block a user by uuid. Just system admin can block a user
    // when user is blocked he can't use any of the auth methods
    return 'BLock a user';
  }

  @ApiOperation({ summary: 'Unblock user(---! needs to be implemented)' })
  @Patch('unblock/:uuid')
  async unblock() {
    // Unblock a user by uuid. Just system admin can unblock a user
    // when user is unblocked he can use any of the auth methods
    return 'Unblock a user';
  }

  @ApiOperation({ summary: 'Delete user(---! needs to be implemented)' })
  @Delete('/:uuid')
  async delete(id: number): Promise<any> {
    // Delete a user by uuid. Just system admin can delete a user
    // also delete all auth methods attached to the user
    return await this.usersService.delete(id);
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
