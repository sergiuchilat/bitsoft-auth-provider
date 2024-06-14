import { v4 } from 'uuid';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { compare, hash } from 'bcrypt';
import { DataSource, IsNull, MoreThan, Not } from 'typeorm';
import { ClassicAuthEntity } from '@/app/modules/auth/classic-auth/classic-auth.entity';
import { ClassicAuthRepository } from '@/app/modules/auth/classic-auth/classic-auth.repository';
import ClassicAuthLoginPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-login.payload.dto';
import ClassicAuthRegisterPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-register.payload.dto';
import ClassicAuthRegisterResponseDto from '@/app/modules/auth/classic-auth/dto/classic-auth-register.response.dto';
import AppConfig from '@/config/app-config';
import { JwtService } from '@nestjs/jwt';
import { TokenGeneratorService } from '@/app/modules/common/token-generator.service';
import { MailerService } from '@/app/modules/auth/classic-auth/mailer.service';
import { UsersService } from '@/app/modules/users/users.service';
import { plainToInstance } from 'class-transformer';
import AuthLoginResponseDto from '@/app/modules/common/dto/auth-login.response.dto';
import { OauthProvider } from '@/app/modules/common/enums/provider.enum';
import { AuthMethodStatus } from '@/app/modules/common/enums/auth-method.status';
import { UserEntity } from '@/app/modules/users/user.entity';
import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import { TokenType } from '@/app/modules/common/enums/token-type.enum';
import { Language } from '@/app/enum/language.enum';
import { I18nService } from 'nestjs-i18n';

dayjs.extend(utc);

@Injectable()
export class ClassicAuthService {
  private readonly codeExpiresIn: number;

  constructor(
    @InjectRepository(ClassicAuthEntity)
    private readonly classicAuthRepository: ClassicAuthRepository,
    private readonly usersService: UsersService,
    private readonly dataSource: DataSource,
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerService,
    private readonly i18n: I18nService,
  ) {
    this.codeExpiresIn = AppConfig.authProviders.classic.code_expires_in;
  }

  async login(
    classicAuthLoginPayloadDto: ClassicAuthLoginPayloadDto,
    language: Language,
  ): Promise<AuthLoginResponseDto> {
    const existingUser = await this.classicAuthRepository.findOne({
      where: {
        email: classicAuthLoginPayloadDto.email,
        user_id: Not(IsNull()),
      },
      relations: ['user'],
    });
    const passwordMatch = await compare(classicAuthLoginPayloadDto.password, existingUser?.password || '');

    if (existingUser && passwordMatch) {
      return {
        token: this.jwtService.sign (
        TokenGeneratorService.generatePayload (
          TokenType.ACCESS,
          existingUser.user.uuid,
          OauthProvider.CLASSIC,
          {
            email: existingUser.email,
            name: existingUser.user.name,
            isActive: existingUser.status === AuthMethodStatus.ACTIVE,
          }),
          {
            secret: AppConfig.jwt.privateKey,
            expiresIn: AppConfig.jwt.expiresIn,
            algorithm: 'RS256',
          },
        ),
        refresh_token: null,
      };
    }

    throw new HttpException(
      this.i18n.t('auth.errors.invalid_credentials', {
        lang: language,
      }),
      HttpStatus.UNAUTHORIZED,
    );
  }

  async register(classicAuthRegisterPayloadDto: ClassicAuthRegisterPayloadDto, language: Language) {
    const activationCode = v4();
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();
    console.log('classicAuthRegisterPayloadDto', classicAuthRegisterPayloadDto);
    try {
      let existingUser = await this.usersService.findExistingUser(
        classicAuthRegisterPayloadDto.email,
        OauthProvider.CLASSIC,
      );

      if (!existingUser) {
        existingUser = await queryRunner.manager.save(UserEntity, {
          email: classicAuthRegisterPayloadDto.email,
          name: classicAuthRegisterPayloadDto.name,
          uuid: v4(),
        });
      }

      const registeredClassicCredentials = await queryRunner.manager.save(ClassicAuthEntity, {
        ...classicAuthRegisterPayloadDto,
        activation_code: activationCode,
        status: AuthMethodStatus.NEW,
        name: classicAuthRegisterPayloadDto.name,
        password: await hash(classicAuthRegisterPayloadDto.password, 10),
        user_id: existingUser.id,
      });

      await this.mailerService.sendActivationEmail(
        classicAuthRegisterPayloadDto.email,
        this.generateActivationLink(activationCode),
        classicAuthRegisterPayloadDto.name,
      );
      await queryRunner.commitTransaction();
      console.log('registeredClassicCredentials', registeredClassicCredentials);

      return plainToInstance(ClassicAuthRegisterResponseDto, registeredClassicCredentials);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      console.log('Error registering user', error);

      throw new HttpException(
        this.i18n.t('auth.errors.error_registering', {
          lang: language,
        }),
        HttpStatus.CONFLICT,
      );
    } finally {
      await queryRunner.release();
    }
  }

  async activate(token: string) {
    // await this.classicAuthRepository.delete ({
    //   status: AuthMethodStatusEnum.NEW,
    //   created_at: LessThan (new Date (new Date ().getTime () - AppConfig.authProviders.classic.code_expires_in *
    // 1000)) });

    // const test = await this.classicAuthRepository.find({
    //   where: {
    //     status: AuthMethodStatusEnum.NEW,
    //     created_at: LessThan (new Date (new Date ().getTime () - AppConfig.authProviders.classic.code_expires_in *
    //       1000))
    //   }});
    //
    // console.log('test', test);

    const existingClassicCredentials = await this.classicAuthRepository.findOne({
      where: {
        activation_code: token,
        status: AuthMethodStatus.NEW,
      },
      relations: ['user'],
    });

    if (!existingClassicCredentials) {
      throw new HttpException('Invalid token', HttpStatus.NOT_FOUND);
    }

    const result = await this.classicAuthRepository.update(
      {
        activation_code: token,
        status: AuthMethodStatus.NEW,
        created_at: MoreThan(this.calculateCreationDateOfTokenToBeExpired()),
      },
      {
        status: AuthMethodStatus.ACTIVE,
        user_id: existingClassicCredentials.user_id,
        activation_code: null,
        name: existingClassicCredentials.name,
      },
    );

    if (!result?.affected) {
      throw new HttpException('Invalid token', HttpStatus.NOT_FOUND);
    }

    const activationToken = this.jwtService.sign (TokenGeneratorService.generatePayload (
      TokenType.ACTIVATION,
      existingClassicCredentials.user.uuid,
      OauthProvider.CLASSIC,
      {
        email: existingClassicCredentials.user.email,
        name: existingClassicCredentials.user.name,
        isActive: existingClassicCredentials.status === AuthMethodStatus.ACTIVE,
      }),
      {
        secret: AppConfig.jwt.privateKey,
        expiresIn: AppConfig.jwt.expiresIn,
        algorithm: 'RS256',
      },
    );

    return {
      token: token,
      activation_token: activationToken,
      status: AuthMethodStatus.ACTIVE,
    };
  }

  private calculateCreationDateOfTokenToBeExpired() {
    return dayjs().utc().subtract(this.codeExpiresIn, 'seconds').toDate();
  }

  async startResetPassword(email: string) {
    const credentials = await this.classicAuthRepository.findOne({
      where: {
        email: email,
      },
      relations: ['user'],
    });

    if (!credentials) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    const resetCode = v4();

    await this.classicAuthRepository.update(
      {
        email: email,
      },
      {
        reset_password_code: resetCode,
      },
    );

    await this.mailerService.sendResetPasswordEmail(
      email,
      `${credentials.user.name}`,
      this.generateResetPasswordLink(resetCode),
    );

    return {
      email: email,
      status: AuthMethodStatus.NEW,
    };
  }

  private generateActivationLink(token: string) {
    return process.env.CLASSIC_AUTH_ACTIVATION_LINK.replace('{token}', token);
  }

  private generateResetPasswordLink(token: string) {
    return process.env.CLASSIC_AUTH_RESET_PASSWORD_LINK.replace('{token}', token);
  }
}
