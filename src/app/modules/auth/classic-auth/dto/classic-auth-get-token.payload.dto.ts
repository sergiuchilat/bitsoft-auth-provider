import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, Length } from 'class-validator';
import { OauthProvider } from '@/app/modules/common/enums/provider.enum';

export default class ClassicAuthGetTokenPayloadDto {
  @ApiProperty({ example: 'mail@domain.com', description: 'Email' })
  @Length(6, 255, {
    message: 'Email must contain from $constraint1 to $constraint2 characters',
  })
  email: string;

  @ApiProperty({ example: OauthProvider.CLASSIC, description: 'Provider' })
  @IsEnum(OauthProvider)
  authProvider: OauthProvider;
}
