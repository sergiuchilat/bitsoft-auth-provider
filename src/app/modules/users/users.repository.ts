import { DataSource, Repository, UpdateResult } from 'typeorm';
import { UserEntity } from '@/app/modules/users/user.entity';
import { Injectable, NotFoundException } from '@nestjs/common';
import { UserStatusEnum } from '@/app/modules/common/enums/user-status.enum';
import { I18nService } from 'nestjs-i18n';
import UsersListResponseDto from '@/app/modules/users/dto/user-item.response.dto';
import { PaginateResponseDto } from '@/app/response/dto/paginate-response.dto';
import PaginatorConfigInterface from '@/database/interfaces/paginator-config.interface';
import { UserPaginatorDto } from '@/app/modules/users/dto/user-paginator.dto';
import { Language } from '@/app/enum/language.enum';

export interface UserRepository {
  findAllAndCount(pageOptionsDto: PaginatorConfigInterface): Promise<[UserEntity[], number]>;
  findByUUID(uuid: string, language: Language): Promise<UserEntity>;
  findByUUIDWithAuthMethods(uuid: string): Promise<UserEntity>;
  block(uuid: string): Promise<UpdateResult>;
  unblock(uuid: string): Promise<UpdateResult>;
  this: Repository<UserEntity>;
}

@Injectable()
export class UsersRepository extends Repository<UserEntity> {
  constructor(
    private readonly dataSource: DataSource,
    private readonly i18nService: I18nService,
  ) {
    super(UserEntity, dataSource.createEntityManager());
  }
  async findByEmail(email: string): Promise<UserEntity> {
    return await this.findOne({
      where: {
        email: email,
      },
    });
  }

  async findAllAndCount(
    userPaginatorDto: UserPaginatorDto,
  ): Promise<PaginateResponseDto<UsersListResponseDto>> {
    const response = await this.findAndCount({
      take: userPaginatorDto.limit,
      skip: (userPaginatorDto.page - 1) * userPaginatorDto.limit,
    });

    return new PaginateResponseDto(userPaginatorDto, response);
  }

  async findByUUID(uuid: string, language: Language) {
    const user = await this.findOne({ where: { uuid } });

    if (!user) {
      const message = {
        message: this.i18nService.t('auth.errors.user_not_found', {
          lang: language,
          args: { uuid },
        }),
      };
      throw new NotFoundException(message);
    }

    return user;
  }

  block(uuid: string) {
    return this.update({ uuid }, { status: UserStatusEnum.BLOCKED });
  }

  unblock(uuid: string) {
    return this.update({ uuid }, { status: UserStatusEnum.ACTIVE });
  }
}
