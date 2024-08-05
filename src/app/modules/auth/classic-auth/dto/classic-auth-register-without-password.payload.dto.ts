import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, Length } from 'class-validator';

export default class ClassicAuthRegisterWithoutPasswordPayloadDto {
  @ApiProperty({ example: 'mail@domain.com', description: 'Email' })
  @Length(6, 255, {
    message: 'Email must contain from $constraint1 to $constraint2 characters',
  })
  email: string;

  @ApiProperty({ example: 'John Doe', description: 'Name' })
  @Length(1, 255, {
    message: 'Name must contain from $constraint1 to $constraint2 characters',
  })
  @IsOptional()
  name?: string;
}
