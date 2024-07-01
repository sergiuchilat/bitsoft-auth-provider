import PaginatorConfigInterface from '@/database/interfaces/paginator-config.interface';
import { IsPositive } from 'class-validator';
import { Transform } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UserPaginatorDto implements PaginatorConfigInterface {
  @IsPositive()
  @ApiPropertyOptional({ example: 10, type: 'number' })
  @Transform(({ value }) => parseInt(value))
  limit = 10;

  @IsPositive()
  @ApiPropertyOptional({ example: 1, type: 'number' })
  @Transform(({ value }) => parseInt(value))
  page = 1;
}
