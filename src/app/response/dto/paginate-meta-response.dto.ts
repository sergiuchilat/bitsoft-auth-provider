import { ApiProperty } from '@nestjs/swagger';
import PaginatorConfigInterface from '@/database/interfaces/paginator-config.interface';

export default class PaginateMetaResponseDto {
  @ApiProperty({
    example: 10,
    description: 'Total items count in database',
    type: Number,
  })
  totalItems: number;

  @ApiProperty({
    example: 2,
    description: 'Total available items count on selected page',
    type: Number,
  })
  itemCount: number;

  @ApiProperty({
    example: 5,
    description: 'Items per page',
    type: Number,
  })
  itemsPerPage: number;

  @ApiProperty({
    example: 2,
    description: 'Total pages count',
    type: Number,
  })
  totalPages: number;

  @ApiProperty({
    example: 1,
    description: 'Current page',
    type: Number,
  })
  currentPage: number;

  constructor(paginator: PaginatorConfigInterface, [entities, totalItems]: [unknown[], number]) {
    this.itemsPerPage = paginator.limit;
    this.totalItems = totalItems;
    this.itemCount = entities.length;
    this.currentPage = paginator.page;
    this.totalPages = Math.ceil(totalItems / paginator.limit);
  }
}
