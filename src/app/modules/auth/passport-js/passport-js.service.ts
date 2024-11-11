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
import PassportGoogleMobileLoginPayloadDto from '@/app/modules/auth/passport-js/dto/passport-google-mobile-login.payload.dto';
import { HttpService } from '@nestjs/axios';
import PassportGoogleMobileUserResponseDto from '@/app/modules/auth/passport-js/dto/passport-google-mobile-user.response.dto';

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
    private readonly httpService: HttpService,
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

  async getUserFromGoogle(access_token: string) {
    try {
      const response = await this.httpService.axiosRef.get<PassportGoogleMobileUserResponseDto>(
        AppConfig.authProviders.google.userInfoUrl,
        {
          headers: {
            Authorization: `Bearer ${access_token}`,
          },
        },
      );

      return response.data;
    } catch (e) {
      throw new UnauthorizedException(e);
    }
  }

  async loginMobile(
    passportGoogleMobileLoginPayloadDto: PassportGoogleMobileLoginPayloadDto,
    provider: OauthProvider,
    hostname: string,
    language: Language,
  ) {
    const user = await this.getUserFromGoogle(passportGoogleMobileLoginPayloadDto.access_token);

    if (!user) {
      throw new HttpException('Not found', 401);
    }

    const tokenCode = v4();
    const existingCredentials = await this.findExistingCredentials(provider, user.id);

    if (existingCredentials?.id) {
      await this.updateTokenCode(existingCredentials.id, tokenCode);
      await this.usersRepository.update(
        { uuid: existingCredentials.user.uuid },
        { is_two_factor_confirmed: false },
      );

      return await this.getTokenByCode(tokenCode, hostname, language);
    }

    const existingUser = await this.getUser(user, provider);

    if (existingUser.status === UserStatusEnum.BLOCKED) {
      throw new UnauthorizedException('Your account is blocked');
    }

    const createdOauthCredentials = await this.oauthCredentialRepository.save({
      user_id: existingUser.id,
      email: user.email,
      provider: provider,
      provider_user_id: user.id,
      token_activation_code: tokenCode,
      photo: user.picture,
    });

    return await this.getTokenByCode(createdOauthCredentials.token_activation_code, hostname, language);
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
      const name = user.name ? user.name : `${user.firstName} ${user.lastName}`;
      existingUser = await this.usersService.create(user.email, name);
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
          role: existingCredentials.user.role,
        },
      ),
      {
        secret: AppConfig.jwt.privateKey,
        expiresIn: AppConfig.jwt.expiresIn,
        algorithm: 'RS256',
      },
    );

    const refreshToken = this.jwtService.sign(
      TokenGeneratorService.generatePayload(
        TokenType.REFRESH,
        existingCredentials.user.uuid,
        existingCredentials.provider,
        {
          email: existingCredentials.email,
          uuid: existingCredentials.user.uuid,
          provider: existingCredentials.provider,
        },
      ),
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
