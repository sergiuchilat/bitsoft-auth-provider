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
import { AuthLogEntity } from '@/app/modules/common/entities/auth.log.entity';

@Injectable()
export class PassportJsService {
  constructor(
    @InjectRepository(OauthCredentialEntity)
    private readonly oauthCredentialRepository: Repository<OauthCredentialEntity>,
    @InjectRepository(AuthLogEntity)
    private readonly authLogRepository: Repository<AuthLogEntity>,
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async login(req: any, provider: OauthProvider, clientIp: string): Promise<any> {

    await this.authLogRepository.save({
      email: req?.user?.email,
      ip: clientIp
    });

    if (!req?.user) {
      throw new HttpException('Not found', 401);
    }

    const tokenCode = v4();
    const existingCredentials = await this.findExistingCredentials(provider, req.user.id);

    if (existingCredentials?.id) {
      await this.updateTokenCode(existingCredentials.id, tokenCode);

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

  async getTokenByCode(code: string) {
    const existingCredentials = await this.oauthCredentialRepository.findOne({
      where: { token_activation_code: code },
      relations: ['user'],
    });

    if (!existingCredentials) {
      throw new HttpException('Not found', 404);
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
        },
      ),
      {
        secret: AppConfig.jwt.privateKey,
        expiresIn: AppConfig.jwt.expiresIn,
        algorithm: 'RS256',
      },
    );

    await this.oauthCredentialRepository.update(existingCredentials.id, {
      token_activation_code: null,
      token: token,
    });

    return {
      token,
      refresh_token: null,
    };
  }
}
