import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, Length } from 'class-validator';

export default class ClassicAuthUpdateEmailPayloadDto {
  @ApiProperty({ example: 'mail@domain.com', description: 'Email' })
  @Length(5, 255, {
    message: 'Email must contain from $constraint1 to $constraint2 characters',
  })
  @IsEmail()
  email: string;
}
