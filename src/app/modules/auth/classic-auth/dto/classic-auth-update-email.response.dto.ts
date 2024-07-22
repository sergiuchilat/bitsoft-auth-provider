import { IsString } from 'class-validator';
import { Expose } from 'class-transformer';

export default class ClassicAuthUpdateEmailResponseDto {
  @IsString()
  @Expose()
  message: string;
}
