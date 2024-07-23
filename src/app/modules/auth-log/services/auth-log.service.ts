import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { AuthLogEntity } from '@/app/modules/auth-log/entities/auth-log.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthLogPaginatorDto } from '@/app/modules/auth-log/dto/auth-log-paginator.dto';
import { PaginateResponseDto } from '@/app/response/dto/paginate-response.dto';

@Injectable()
export class AuthLogService {
  constructor(
    @InjectRepository(AuthLogEntity)
    readonly authLogRepository: Repository<AuthLogEntity>,
  ) {}

  async findAll(paginator: AuthLogPaginatorDto) {
    const response = await this.authLogRepository.findAndCount({
      take: paginator.take,
      skip: paginator.skip,
    });

    return new PaginateResponseDto(paginator, response);
  }
}
