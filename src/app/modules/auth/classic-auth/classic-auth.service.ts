import { v4 } from 'uuid';
import { BadRequestException, HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { compare, hash } from 'bcrypt';
import { DataSource, IsNull, MoreThan, Not, Repository } from 'typeorm';
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
import ClassicAuthActivateResendPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-activate-resend.payload.dto';
import ClassicAuthResetPasswordPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-reset-password.payload.dto';
import ClassicAuthResetPasswordConfirmPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-reset-password-confirm.payload.dto';
import ClassicAuthChangePasswordPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-change-password.payload.dto';
import ClassicAuthUpdateEmailPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-update-email.payload.dto';
import ClassicAuthUpdateEmailResponseDto from '@/app/modules/auth/classic-auth/dto/classic-auth-update-email.response.dto';
import ClassicAuthVerifyResetPasswordResponseDto from '@/app/modules/auth/classic-auth/dto/classic-auth-verify-reset-password.response.dto';
import { AuthLogEntity } from '@/app/modules/common/entities/auth.log.entity';
import { PassportJsService } from '@/app/modules/auth/passport-js/passport-js.service';
import { ClassicAuthRefreshTokenPayloadDto } from '@/app/modules/auth/classic-auth/dto/classic-auth-refresh-token.payload.dto';
import { Request } from 'express';

dayjs.extend(utc);

@Injectable()
export class ClassicAuthService {
  private readonly codeExpiresIn: number;

  constructor(
    @InjectRepository(ClassicAuthEntity)
    private readonly classicAuthRepository: ClassicAuthRepository,
    @InjectRepository(AuthLogEntity)
    private readonly authLogRepository: Repository<AuthLogEntity>,
    private readonly usersService: UsersService,
    private readonly dataSource: DataSource,
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerService,
    private readonly i18nService: I18nService,
    private readonly passportJsService: PassportJsService,
  ) {
    this.codeExpiresIn = AppConfig.authProviders.classic.code_expires_in;
  }

  async login(
    classicAuthLoginPayloadDto: ClassicAuthLoginPayloadDto,
    language: Language,
    clientIp: string,
  ): Promise<AuthLoginResponseDto> {

    await this.authLogRepository.save({
      email: classicAuthLoginPayloadDto.email,
      ip: clientIp
    });

    const existingUser = await this.classicAuthRepository.findOne({
      where: {
        email: classicAuthLoginPayloadDto.email,
        user_id: Not(IsNull()),
      },
      relations: ['user'],
    });
    const passwordMatch = await compare(classicAuthLoginPayloadDto.password, existingUser?.password || '');

    if (existingUser && passwordMatch && existingUser.status !== AuthMethodStatus.BLOCKED) {
      return {
        token: this.jwtService.sign(
          TokenGeneratorService.generatePayload(
            TokenType.ACCESS,
            existingUser.user.uuid,
            OauthProvider.CLASSIC,
            {
              email: existingUser.email,
              name: existingUser.user.name,
              isActive: existingUser.status === AuthMethodStatus.ACTIVE,
            },
          ),
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
      this.i18nService.t('auth.errors.invalid_credentials', {
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
        language,
      );
      await queryRunner.commitTransaction();
      console.log('registeredClassicCredentials', registeredClassicCredentials);

      return plainToInstance(ClassicAuthRegisterResponseDto, registeredClassicCredentials);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      console.log('Error registering user', error);

      throw new HttpException(
        this.i18nService.t('auth.errors.error_registering', {
          lang: language,
        }),
        HttpStatus.CONFLICT,
      );
    } finally {
      await queryRunner.release();
    }
  }

    async refreshToken(classicAuthRefreshTokenPayloadDto: ClassicAuthRefreshTokenPayloadDto, request: Request) {
        try {
            const payload = this.jwtService.verify(classicAuthRefreshTokenPayloadDto.refreshToken, {
                algorithms: ['RS256'],
                publicKey: AppConfig.jwt.publicKey,
            });
            if (!payload.provider) {
                const existingUser = await this.classicAuthRepository.findOneByEmail(payload.email);

                return this.generateToken(existingUser, request);
            }

            return this.passportJsService.getNewToken(payload, request);
        } catch (e) {
            throw new UnauthorizedException('Invalid refresh token');
        }
    }

  async resendActivationEmail(
    classicAuthActivateResendPayloadDto: ClassicAuthActivateResendPayloadDto,
    language: Language,
  ) {
    const message = {
      message: this.i18nService.t('auth.mail.activation', {
        lang: language,
      }),
    };
    try {
      const user = await this.classicAuthRepository.findOne({
        where: { email: classicAuthActivateResendPayloadDto.email },
      });

      if (!user) {
        return message;
      }

      const activationCode = v4();
      await this.classicAuthRepository.update(
        { email: user.email },
        {
          activation_code: activationCode,
        },
      );

      await this.mailerService.sendActivationEmail(
        classicAuthActivateResendPayloadDto.email,
        this.generateActivationLink(activationCode),
        user.name,
        language,
      );

      return message;
    } catch (e) {
      throw new HttpException('Error sending activation message', HttpStatus.BAD_REQUEST);
    }
  }

  async activate(token: string, language: Language) {
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
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();
    try {
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
        const message = {
          message: this.i18nService.t('auth.errors.invalid_token', {
            lang: language,
          }),
        };
        throw new HttpException(message, HttpStatus.NOT_FOUND);
      }

      await this.usersService.activate(existingClassicCredentials.user_id);

      await queryRunner.commitTransaction();

      const activationToken = this.jwtService.sign(
        TokenGeneratorService.generatePayload(
          TokenType.ACTIVATION,
          existingClassicCredentials.user.uuid,
          OauthProvider.CLASSIC,
          {
            email: existingClassicCredentials.user.email,
            name: existingClassicCredentials.user.name,
            isActive: existingClassicCredentials.status === AuthMethodStatus.ACTIVE,
          },
        ),
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
    } catch (error) {
      await queryRunner.rollbackTransaction();
      console.log('Error activate user', error);
      const message = {
        message: this.i18nService.t('auth.errors.activate_user', {
          lang: language,
        }),
      };
      throw new HttpException(message, HttpStatus.CONFLICT);
    } finally {
      await queryRunner.release();
    }
  }

  private calculateCreationDateOfTokenToBeExpired() {
    return dayjs().utc().subtract(this.codeExpiresIn, 'seconds').toDate();
  }

  async startResetPassword(
    classicAuthResetPasswordPayloadDto: ClassicAuthResetPasswordPayloadDto,
    language: Language,
  ) {
    const message = {
      message: this.i18nService.t('auth.mail.activation', {
        lang: language,
      }),
    };
    const credentials = await this.classicAuthRepository.findOneByEmail(
      classicAuthResetPasswordPayloadDto.email,
    );

    if (!credentials) {
      return message;
    }

    const resetCode = v4();

    this.classicAuthRepository.updateResetPasswordCode(classicAuthResetPasswordPayloadDto.email, resetCode);

    await this.mailerService.sendResetPasswordEmail(
      classicAuthResetPasswordPayloadDto.email,
      `${credentials.user.name}`,
      this.generateResetPasswordLink(resetCode),
    );

    return message;
  }

  public async verifyResetPassword(token: string): Promise<ClassicAuthVerifyResetPasswordResponseDto> {
    const credentials = await this.classicAuthRepository.findOne({
      where: {
        reset_password_code: token,
        reset_password_code_expired_at: MoreThan(this.calculateCreationDateOfTokenToBeExpired()),
      },
    });

    if (!credentials) {
      throw new BadRequestException('Invalid reset password token');
    }

    return { token };
  }

  public async resetPasswordConfirm(
    classicAuthResetPasswordConfirmPayloadDto: ClassicAuthResetPasswordConfirmPayloadDto,
  ) {
    await this.verifyResetPassword(classicAuthResetPasswordConfirmPayloadDto.token);

    await this.classicAuthRepository.update(
      {
        reset_password_code: classicAuthResetPasswordConfirmPayloadDto.token,
      },
      {
        password: await hash(classicAuthResetPasswordConfirmPayloadDto.password, 10),
        reset_password_code: null,
        reset_password_code_expired_at: null,
      },
    );

    return 'Password reset successfully';
  }

  public async changePassword(
    classicAuthChangePasswordPayloadDto: ClassicAuthChangePasswordPayloadDto,
    user,
  ): Promise<ClassicAuthUpdateEmailResponseDto> {
    const existingUser = await this.usersService.findByUUID(user.uuid);
    const credentials = await this.classicAuthRepository.findOne({ where: { user_id: existingUser.id } });
    const matchPassword = await compare(
      classicAuthChangePasswordPayloadDto.old_password,
      credentials.password,
    );

    if (!matchPassword) {
      throw new BadRequestException('Invalid old password');
    }

    await this.classicAuthRepository.update(credentials.id, {
      password: await hash(classicAuthChangePasswordPayloadDto.new_password, 10),
    });

    return {
      message: 'Password changed successfully',
    };
  }

  public async updateEmail(
    classicAuthUpdateEmailPayloadDto: ClassicAuthUpdateEmailPayloadDto,
    user,
  ): Promise<ClassicAuthUpdateEmailResponseDto> {
    const existingUser = await this.usersService.findByUUID(user.uuid);
    await this.classicAuthRepository.update(
      { email: existingUser.email },
      {
        email: classicAuthUpdateEmailPayloadDto.email,
      },
    );

    await this.usersService.updateEmail(user.uuid, classicAuthUpdateEmailPayloadDto.email);

    return {
      message: 'Email updated successfully',
    };
  }

  private generateActivationLink(token: string) {
    return process.env.CLASSIC_AUTH_ACTIVATION_LINK.replace('{token}', token);
  }

  private generateResetPasswordLink(token: string) {
    return process.env.CLASSIC_AUTH_RESET_PASSWORD_LINK.replace('{token}', token);
  }

    private generateToken(existingUser: ClassicAuthEntity, request: Request) {
        const refreshToken = this.jwtService.sign(
            { email: existingUser.user.email },
            {
                secret: AppConfig.jwt.privateKey,
                expiresIn: AppConfig.jwt.refreshTokenExpiresIn,
                algorithm: 'RS256',
            },
        );

        return {
            token: this.jwtService.sign(
                TokenGeneratorService.generatePayload(existingUser.user.uuid, OauthProvider.CLASSIC, {
                    email: existingUser.email,
                    name: existingUser.user.name,
                    isActive: existingUser.status === AuthMethodStatus.ACTIVE,
                    domain: request.hostname,
                }),
                {
                    secret: AppConfig.jwt.privateKey,
                    expiresIn: AppConfig.jwt.expiresIn,
                    algorithm: 'RS256',
                },
            ),
            refresh_token: refreshToken,
        };
    }
}
