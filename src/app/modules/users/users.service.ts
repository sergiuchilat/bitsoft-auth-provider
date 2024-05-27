import {HttpException, HttpStatus, Injectable} from '@nestjs/common';
import { v4 } from 'uuid';
import { UserEntity } from '@/app/modules/users/user.entity';
import { OauthProvider } from '@/app/modules/common/enums/provider.enum';
import {PageDto, PageOptionsDto} from '@/app/response/dto/paginate-meta-response.dto';
import UsersListResponseDto from '@/app/modules/users/dto/user-item.response.dto';
import {UsersRepository} from '@/app/modules/users/users.repository';
import {UserStatusEnum} from '@/app/modules/common/enums/user-status.enum';
import {EntityManager} from 'typeorm';

@Injectable ()
export class UsersService {
  constructor (
      private readonly usersRepository: UsersRepository,
      private readonly entityManager: EntityManager
  ) {
  }

  async getList (pageOptionsDto: PageOptionsDto): Promise<PageDto<UsersListResponseDto>> {
    return await this.usersRepository.findAllAndCount(pageOptionsDto);
  }

  async getByUUID (uuid: string, request: Request) {
    return this.usersRepository.findByUUID(uuid, request);
  }

  async block (uuid: string) {
    const result = await this.usersRepository.block(uuid);

    if(!result.affected) {
      throw new HttpException(`User with uuid: ${uuid} not found`, HttpStatus.NOT_FOUND);
    }

    return result;
  }

  async activate(id: number) {
    return this.usersRepository.update(id, {
      status: UserStatusEnum.ACTIVE,
    });
  }

  async unblock (uuid: string) {
    const result = await this.usersRepository.unblock(uuid);

    if(!result.affected) {
      throw new HttpException(`User with uuid: ${uuid} not found`, HttpStatus.NOT_FOUND);
    }

    return result;
  }

  async create (
    email: string = null,
    name: string = null,
    provider: OauthProvider = null
  ): Promise<UserEntity> {

    const existingUser = await this.findExistingUser (email, provider);
    console.log ('existingUser', existingUser);

    if (existingUser) {
      return existingUser;
    }

    return await this.usersRepository.save ({
      uuid: v4(),
      email: email || null,
      name: name || null
    });
  }

  async findExistingUser (
    email: string,
    requestProvider: OauthProvider = null
  ): Promise<UserEntity> {

    if (requestProvider === OauthProvider.CLASSIC) {
      return this.usersRepository.findOne ({
        where: {
          oAuth: {
            email
          }
        },
        relations: ['oAuth']
      });
    }

    if (requestProvider === OauthProvider.GOOGLE) {
      return this.usersRepository.findOne ({
        where: {
          classicAuth: {
            email
          }
        },
        relations: ['classicAuth']
      });
    }

    return null;
  }

  async delete (uuid: string): Promise<void> {
    await this.entityManager.transaction(async manager => {
      const user = await manager.findOne(UserEntity, {where:{uuid}});

      if (!user) {
        throw new Error('User not found.');
      }

      await manager.remove(user);
    });
  }
}

