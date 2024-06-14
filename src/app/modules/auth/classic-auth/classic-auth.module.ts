import { Module } from '@nestjs/common';
import { ClassicAuthService } from './classic-auth.service';
import { ClassicAuthController } from './classic-auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ClassicAuthEntity } from './classic-auth.entity';
import { JwtService } from '@nestjs/jwt';
import { HttpModule } from '@nestjs/axios';
import { MailerService } from '@/app/modules/auth/classic-auth/mailer.service';
import { UserEntity } from '@/app/modules/users/user.entity';
import { UsersService } from '@/app/modules/users/users.service';
import { UsersModule } from '@/app/modules/users/users.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([ClassicAuthEntity, UserEntity]),
    HttpModule.register({
      timeout: 5000,
      maxRedirects: 5,
    }),
    UsersModule,
  ],
  providers: [ClassicAuthService, UsersService, JwtService, MailerService],
  controllers: [ClassicAuthController],
})
export class ClassicAuthModule {}
