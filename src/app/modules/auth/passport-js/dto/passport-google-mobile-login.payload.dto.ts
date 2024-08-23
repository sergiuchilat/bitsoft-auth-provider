import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export default class PassportGoogleMobileLoginPayloadDto {
  @ApiProperty({ example: 'Some string', description: 'Access token' })
  @IsString()
  access_token: string;
}
