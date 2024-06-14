import PaginatorConfigInterface from '@/database/interfaces/paginator-config.interface';
import {IsPositive} from 'class-validator';
import {Transform} from 'class-transformer';

export class UserPaginatorDto implements PaginatorConfigInterface {
    @IsPositive()
    @Transform(({ value }) => parseInt(value))
      limit = 10;

    @IsPositive()
    @Transform(({ value }) => parseInt(value))
      page = 1;
}
