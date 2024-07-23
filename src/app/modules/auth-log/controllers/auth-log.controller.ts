import { Controller, Get, Query } from '@nestjs/common';
import { AuthLogService } from '@/app/modules/auth-log/services/auth-log.service';
import { AuthLogPaginatorDto } from '@/app/modules/auth-log/dto/auth-log-paginator.dto';
import { ApiTags } from '@nestjs/swagger';
import { plainToInstance } from 'class-transformer';

@ApiTags('Auth Logs')
@Controller({
  version: '1',
  path: 'auth-logs',
})
export class AuthLogController {
  constructor(private readonly authLogService: AuthLogService) {}

  @Get()
  findAll(@Query() paginator: AuthLogPaginatorDto) {
    return this.authLogService.findAll(plainToInstance(AuthLogPaginatorDto, paginator));
  }
}
