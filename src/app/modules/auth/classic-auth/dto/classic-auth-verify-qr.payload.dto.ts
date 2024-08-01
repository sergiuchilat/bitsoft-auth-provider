import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export default class ClassicAuthVerifyQrPayloadDto {
  @ApiProperty({ example: 123, description: 'Code' })
  @IsString()
  code: string;
}
