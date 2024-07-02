import { ApiProperty } from '@nestjs/swagger';
import { Length, Matches } from 'class-validator';

export default class ClassicAuthChangePasswordPayloadDto {
  @ApiProperty({ example: 'Asdasd12!', description: 'Password' })
  @Length(8, 255, {
    message: 'Old password must contain from $constraint1 to $constraint2 characters',
  })
  old_password: string;

  @ApiProperty({ example: 'Asdasd12!', description: 'Password' })
  @Length(8, 255, {
    message: 'New password must contain from $constraint1 to $constraint2 characters',
  })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/, {
    message: 'New password must contain at least one lowercase letter, one uppercase letter, and one digit',
  })
  new_password: string;
}
