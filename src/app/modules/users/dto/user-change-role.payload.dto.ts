import { ApiPropertyOptional } from '@nestjs/swagger';
import { UserRoleEnum } from '@/app/modules/users/enums/user-role.enum';
import { IsEnum } from 'class-validator';

export class UserChangeRolePayloadDto {
  @ApiPropertyOptional({ example: UserRoleEnum.PUBLIC_USER, type: 'enum', enum: UserRoleEnum, title: 'Role' })
  @IsEnum(UserRoleEnum)
  role: UserRoleEnum;
}
