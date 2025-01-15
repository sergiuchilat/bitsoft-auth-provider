import { ApiPropertyOptional } from '@nestjs/swagger';
import { UserRoleEnum } from '@/app/modules/users/enums/user-role.enum';
import { IsString } from 'class-validator';

export class UserChangeRolePayloadDto {
  @ApiPropertyOptional({ example: UserRoleEnum.PUBLIC_USER, type: 'string', title: 'Role' })
  @IsString()
  role: UserRoleEnum;
}
