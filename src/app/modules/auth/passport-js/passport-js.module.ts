import { Module } from '@nestjs/common';
import { PassportJsController } from '@/app/modules/auth/passport-js/passport-js.controller';
import { GoogleStrategy } from '@/app/modules/auth/passport-js/strategies/google.strategy';
import { VkStrategy } from '@/app/modules/auth/passport-js/strategies/vk.strategy';
import { FbStrategy } from '@/app/modules/auth/passport-js/strategies/fb.strategy';
import { PassportJsService } from '@/app/modules/auth/passport-js/passport-js.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { OauthCredentialEntity } from '@/app/modules/auth/passport-js/entities/oauth-credential.entity';
import { UsersService } from '@/app/modules/users/users.service';
import { UserEntity } from '@/app/modules/users/user.entity';
import { JwtService } from '@nestjs/jwt';
import {UsersRepository} from '@/app/modules/users/users.repository';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      OauthCredentialEntity, UserEntity
    ]),
  ],
  controllers: [
    PassportJsController
  ],
  providers: [
    PassportJsService,
    UsersService,
    UsersRepository,
    GoogleStrategy,
    VkStrategy,
    FbStrategy,
    JwtService
  ]
})
export class PassportJsModule {}
