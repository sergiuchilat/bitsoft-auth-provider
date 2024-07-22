import { IsString } from 'class-validator';
import { Expose } from 'class-transformer';

export default class ClassicAuthVerifyResetPasswordResponseDto {
  @IsString()
  @Expose()
  token: string;
}
