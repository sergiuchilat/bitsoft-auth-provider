import { BadRequestException, Injectable, NestMiddleware } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { NextFunction, Request, Response } from 'express';
import AppConfig from '@/config/app-config';
import { UserEntity } from '@/app/modules/users/user.entity';
import requestIp from 'request-ip';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UsersRepository } from '@/app/modules/users/users.repository';
import { AuthLogEntity } from '@/app/modules/auth-log/entities/auth-log.entity';
import { ValidatedRequest } from '@/app/request/interfaces/validated-request';

@Injectable()
export class ParseTokenMiddleware implements NestMiddleware {
  constructor(
    @InjectRepository(AuthLogEntity)
    private readonly authLogRepository: Repository<AuthLogEntity>,
    @InjectRepository(UserEntity)
    private readonly userRepository: UsersRepository,
    private readonly jwtService: JwtService,
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    try {
      const token = this.extractTokenFromHeader(req);

      if (!token) {
        next();
        return;
      }
      const parsedToken = await this.jwtService.verify(token, {
        algorithms: ['RS256'],
        publicKey: AppConfig.jwt.publicKey,
      });

      req.user = {
        uuid: parsedToken.sub,
        domain: parsedToken.props?.domain,
        email: parsedToken.props?.email,
        isTwoFactorConfirmed: parsedToken.props?.isTwoFactorConfirmed,
        isTwoFactorEnable: parsedToken.props?.isTwoFactorEnable,
      };

      next();
    } catch (e) {
      throw new BadRequestException('Invalid token');
    } finally {
      await this.logAuthAttempt(req as ValidatedRequest);
    }
  }

  private async logAuthAttempt(request: ValidatedRequest) {
    const storedUser = await this.userRepository.findOneBy({ uuid: request.user?.uuid });
    const clientIp = requestIp.getClientIp(request);

    const authLogPayload: Partial<AuthLogEntity> = {
      ip: clientIp,
      user_agent: request.headers['user-agent'],
      referer: request.headers.referer,
      user_id: storedUser?.id ?? null,
    };

    request.headers['x-client-ip'] = clientIp;

    return this.authLogRepository.insert(authLogPayload);
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];

    return type === 'Bearer' ? token : undefined;
  }
}
