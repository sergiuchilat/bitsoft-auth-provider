import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';
export class ClassicAuthRefreshTokenPayloadDto {
  @ApiProperty({
    example:
      'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJwcm9wcyI6eyJhdXRoUHJvdmlkZXIiOiJDTEFTU0lDIiwiZW1haWwiOiJ2aWN1Z2FpZGVpY0BnbWFpbC5jb20iLCJuYW1lIjoiVmljdSIsImlzQWN0aXZlIjp0cnVlLCJkb21haW4iOiJsb2NhbGhvc3QifSwic3ViIjoiZjJhYWRkMGMtNWVhZC00ZjZjLWJmYjMtMDlhYzM3MWE5NTZmIiwiaWF0IjoxNzE2ODk1NTE4LCJleHAiOjE3MTY4OTkxMTh9.HKBbKfQ5iAlRuUkXYTGpfauXc_NIEYkQMVMMQUIiHZgTmJyu7vtTce5d9vjHAjmzBLmsoLxWQuMcYOMeSsYL4OuQeN1sIdpBlmGF7ljLwmLv1zAZfn2q00ZpPV--AxWoA6KbtHKC6UdQLUC9hG6U1pluAEhERz0DEgJyaxQF8j3YRn4Kga0Xzj2ImySYV3-Ec7lOU8Pk9IhkDRzxgF11i6DKzAshtG6H0oQO6ltL6-o-Un6XGY5RXlMR-9dB9uF7T7',
    description: 'Refresh token',
  })
  @IsString()
  refreshToken: string;
}
