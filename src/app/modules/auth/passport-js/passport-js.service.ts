import { HttpException, Injectable, UnauthorizedException } from '@nestjs/common';
import { OauthCredentialEntity } from '@/app/modules/auth/passport-js/entities/oauth-credential.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UsersService } from '@/app/modules/users/users.service';
import { v4 } from 'uuid';
import { TokenGeneratorService } from '@/app/modules/common/token-generator.service';
import AppConfig from '@/config/app-config';
import { JwtService } from '@nestjs/jwt';
import { OauthProvider } from '@/app/modules/common/enums/provider.enum';
import { TokenType } from '@/app/modules/common/enums/token-type.enum';
import { UserStatusEnum } from '@/app/modules/common/enums/user-status.enum';
import { AuthLogEntity } from '@/app/modules/auth-log/entities/auth-log.entity';
import ClassicAuthGetTokenPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-get-token.payload.dto';
import { Language } from '@/app/enum/language.enum';
import { I18nService } from 'nestjs-i18n';
import { UsersRepository } from '@/app/modules/users/users.repository';

@Injectable()
export class PassportJsService {
  constructor(
    @InjectRepository(OauthCredentialEntity)
    private readonly oauthCredentialRepository: Repository<OauthCredentialEntity>,
    @InjectRepository(AuthLogEntity)
    private readonly authLogRepository: Repository<AuthLogEntity>,
    private readonly usersService: UsersService,
    private readonly usersRepository: UsersRepository,
    private readonly jwtService: JwtService,
    private readonly i18nService: I18nService,
  ) {}

  async login(req: any, provider: OauthProvider, clientIp: string): Promise<any> {
    await this.authLogRepository.save({
      email: req?.user?.email,
      ip: clientIp,
    });

    if (!req?.user) {
      throw new HttpException('Not found', 401);
    }

    const tokenCode = v4();
    const existingCredentials = await this.findExistingCredentials(provider, req.user.id);

    if (existingCredentials?.id) {
      await this.updateTokenCode(existingCredentials.id, tokenCode);
      await this.usersRepository.update(
        { uuid: existingCredentials.user.uuid },
        { is_two_factor_confirmed: false },
      );

      return {
        token_code: tokenCode,
      };
    }

    const existingUser = await this.getUser(req.user, provider);

    if (existingUser.status === UserStatusEnum.BLOCKED) {
      throw new UnauthorizedException('Your account is blocked');
    }

    const createdOauthCredentials = await this.oauthCredentialRepository.save({
      user_id: existingUser.id,
      email: req.user.email,
      provider: provider,
      provider_user_id: req.user.id,
      token_activation_code: tokenCode,
      photo: req.user.photo,
    });

    return {
      token_code: createdOauthCredentials.token_activation_code,
    };
  }

  private async findExistingCredentials(provider: OauthProvider, providerUserId: string) {
    return await this.oauthCredentialRepository.findOne({
      where: {
        provider: provider,
        provider_user_id: providerUserId,
      },
      relations: ['user'],
    });
  }
  findExistingCredentialsByEmailAndProvider(provider: OauthProvider, email: string) {
    return this.oauthCredentialRepository.findOne({
      where: {
        provider: provider,
        email: email,
      },
      relations: ['user'],
    });
  }

  private async updateTokenCode(id: string, tokenCode: string) {
    await this.oauthCredentialRepository.update(id, {
      token_activation_code: tokenCode,
    });
  }

  private async getUser(user: any, provider: OauthProvider) {
    let existingUser = await this.usersService.findExistingUser(user.email, provider);

    if (!existingUser) {
      existingUser = await this.usersService.create(user.email, `${user.firstName} ${user.lastName}`);
    }

    return existingUser;
  }

  async getTokenByCode(code: string, hostname: string, language: Language) {
    const existingCredentials = await this.oauthCredentialRepository.findOne({
      where: { token_activation_code: code },
      relations: ['user'],
    });

    return this.generateToken(existingCredentials, hostname, language);
  }

  async generateToken(existingCredentials: OauthCredentialEntity, hostname: string, language: Language) {
    if (!existingCredentials) {
      throw new HttpException(
        this.i18nService.t('auth.errors.not_found', {
          lang: language,
        }),
        404,
      );
    }

    const token = this.jwtService.sign(
      TokenGeneratorService.generatePayload(
        TokenType.ACCESS,
        existingCredentials.user.uuid,
        existingCredentials.provider,
        {
          email: existingCredentials.email,
          name: existingCredentials.user.name,
          photo: existingCredentials.photo,
          domain: hostname,
          isTwoFactorConfirmed: existingCredentials.user.is_two_factor_confirmed,
          isTwoFactorEnable: existingCredentials.user.is_two_factor_enable,
        },
      ),
      {
        secret: AppConfig.jwt.privateKey,
        expiresIn: AppConfig.jwt.expiresIn,
        algorithm: 'RS256',
      },
    );

    const refreshToken = this.jwtService.sign(
      {
        email: existingCredentials.email,
        provider: existingCredentials.provider,
      },
      {
        secret: AppConfig.jwt.privateKey,
        expiresIn: AppConfig.jwt.refreshTokenExpiresIn,
        algorithm: 'RS256',
      },
    );

    await this.oauthCredentialRepository.update(existingCredentials.id, {
      token_activation_code: null,
      token: token,
    });

    return {
      token,
      refresh_token: refreshToken,
    };
  }

  async getNewToken(payload: ClassicAuthGetTokenPayloadDto, hostname: string, language: Language) {
    const existingCredentials = await this.oauthCredentialRepository.findOne({
      where: { email: payload.email, provider: payload.authProvider },
      relations: ['user'],
    });
    return this.generateToken(existingCredentials, hostname, language);
  }
}
