import { IsInt, IsOptional, Max, Min } from 'class-validator';
import { Type } from 'class-transformer';
import PaginatorConfigInterface from '@/database/interfaces/paginator-config.interface';

export abstract class AbstractPaginatorDto implements PaginatorConfigInterface {
  @IsInt()
  @Min(1)
  @Max(100)
  @Type(() => Number)
  @IsOptional()
  limit = 10;

  @IsInt()
  @Min(1)
  @Type(() => Number)
  @IsOptional()
  page = 1;

  get skip() {
    return (this.page - 1) * this.limit;
  }

  get take() {
    return this.limit;
  }
}
