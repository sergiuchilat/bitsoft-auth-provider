import { ApiProperty } from '@nestjs/swagger';
import { IsUUID, Length, Matches } from 'class-validator';

export default class ClassicAuthResetPasswordConfirmPayloadDto {
  @ApiProperty({ example: 'd43d4adb-f99c-45da-9d85-4212fed1b402', description: 'Token' })
  @IsUUID()
  token: string;

  @ApiProperty({ example: 'Asdasd12!', description: 'Password' })
  @Length(8, 255, {
    message: 'Password must contain from $constraint1 to $constraint2 characters',
  })
  password: string;
}
