import { ApiProperty } from '@nestjs/swagger';
import { Expose } from 'class-transformer';

export default class PassportGoogleMobileUserResponseDto {
  @ApiProperty({ example: '123123123', description: 'Id' })
  @Expose()
  id: string;

  @ApiProperty({ example: 'user@gmail.com', description: 'Email' })
  @Expose()
  email: string;

  @ApiProperty({
    example: 'https://lh3.googleusercontent.com/a/ACg8ocI0ADiSAx_11TT0STERNHOxChY',
    description: 'Picture',
  })
  @Expose()
  picture: string;
}
