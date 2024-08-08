import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsOptional, Length } from 'class-validator';

export default class ClassicAuthRegisterPayloadDto {
  @ApiProperty({ example: 'mail@domain.com', description: 'Email' })
  @Length(6, 255, {
    message: 'Email must contain from $constraint1 to $constraint2 characters',
  })
  email: string;

  @ApiProperty({ example: 'strong_password', description: 'Password' })
  @Length(8, 255, {
    message: 'Password must contain from $constraint1 to $constraint2 characters',
  })
  password: string;

  @ApiProperty({ example: 'John Doe', description: 'Name' })
  @Length(1, 255, {
    message: 'Name must contain from $constraint1 to $constraint2 characters',
  })
  @IsOptional()
  name?: string;

  @ApiProperty({ example: false, description: 'Send password on email', default: false })
  @IsBoolean()
  @IsOptional()
  send_password_on_email?: boolean;
}
