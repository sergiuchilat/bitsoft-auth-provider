import { BadRequestException, Injectable, NestMiddleware } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { NextFunction, Request, Response } from 'express';
import AppConfig from '@/config/app-config';

@Injectable()
export class ParseTokenMiddleware implements NestMiddleware {
  constructor(private readonly jwtService: JwtService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    //console.log('ParseTokenMiddleware')
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
        roles: parsedToken.roles,
        domain: parsedToken.props?.domain
      };
      next();
    } catch (e) {
      throw new BadRequestException('Invalid token');
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
