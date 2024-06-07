import { HttpException, Injectable } from '@nestjs/common';
import { OauthCredentialEntity } from '@/app/modules/auth/passport-js/entities/oauth-credential.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UsersService } from '@/app/modules/users/users.service';
import { v4 } from 'uuid';
import { TokenGeneratorService } from '@/app/modules/common/token-generator.service';
import AppConfig from '@/config/app-config';
import { JwtService } from '@nestjs/jwt';
import { OauthProvider } from '@/app/modules/common/enums/provider.enum';
import {Request} from 'express';
import ClassicAuthGetTokenPayloadDto from '@/app/modules/auth/classic-auth/dto/classic-auth-get-token.payload.dto';

@Injectable ()
export class PassportJsService {
  constructor (
    @InjectRepository (OauthCredentialEntity) private readonly oauthCredentialRepository: Repository<OauthCredentialEntity>,
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {
  }

  async login (
    req: any,
    provider: OauthProvider,
  ): Promise<any> {

    if (!req?.user) {
      throw new HttpException ('Not found', 401);
    }

    const tokenCode = v4 ();
    const existingCredentials = await this.findExistingCredentials(provider, req.user.id);

    if (existingCredentials?.id) {
      await this.updateTokenCode(existingCredentials.id, tokenCode);

      return {
        token_code: tokenCode
      };
    }

    const existingUser = await this.getUser(req.user, provider);

    const createdOauthCredentials = await this.oauthCredentialRepository.save ({
      user_id: existingUser.id,
      email: req.user.email,
      provider: provider,
      provider_user_id: req.user.id,
      token_activation_code: tokenCode,
      photo: req.user.photo
    });

    return {
      token_code: createdOauthCredentials.token_activation_code
    };
  }

  private async findExistingCredentials (provider: OauthProvider, providerUserId: string) {
    return await this.oauthCredentialRepository.findOne ({
      where: {
        provider: provider,
        provider_user_id: providerUserId,
      },
      relations: ['user']
    });
  }

  private async updateTokenCode (id: string, tokenCode: string) {
    await this.oauthCredentialRepository.update (id, {
      token_activation_code: tokenCode
    });
  }

  private async getUser(user: any, provider: OauthProvider){
    let existingUser = await this.usersService.findExistingUser (
      user.email,
      provider
    );

    if (!existingUser) {
      existingUser = await this.usersService.create (user.email, `${user.firstName} ${user.lastName}`);
    }

    return existingUser;
  }

  async getTokenByCode (code: string, request: Request) {
    const existingCredentials = await this.oauthCredentialRepository.findOne ({
      where: { token_activation_code: code },
      relations: ['user']
    });

    return await this.generateToken(existingCredentials, request);
  }

  async generateToken (existingCredentials: OauthCredentialEntity, request: Request) {
    if (!existingCredentials) {
      throw new HttpException ('Not found', 404);
    }

    const token = this.jwtService.sign (TokenGeneratorService.generatePayload (
      existingCredentials.user.uuid,
      existingCredentials.provider,
      {
        email: existingCredentials.email,
        name: existingCredentials.user.name,
        photo: existingCredentials.photo,
        domain: request.hostname
      }
    ), {
      secret: AppConfig.jwt.privateKey,
      expiresIn: AppConfig.jwt.expiresIn,
      algorithm: 'RS256'
    });

    const refreshToken = this.jwtService.sign({
      email: existingCredentials.email,
      provider: existingCredentials.provider
    }, {
      secret: AppConfig.jwt.privateKey,
      expiresIn: AppConfig.jwt.refreshTokenExpiresIn,
      algorithm: 'RS256'
    });

    await this.oauthCredentialRepository.update (existingCredentials.id, {
      token_activation_code: null,
      token: token
    });

    return {
      token,
      refresh_token: refreshToken
    };
  }

  async getNewToken (payload: ClassicAuthGetTokenPayloadDto, request: Request) {
    const existingCredentials = await this.oauthCredentialRepository.findOne ({
      where: { email: payload.email, provider: payload.provider },
      relations: ['user']
    });

    return this.generateToken(existingCredentials, request);
  }
}
