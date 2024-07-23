import { ForbiddenException, Injectable, NestMiddleware } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UsersRepository } from '@/app/modules/users/users.repository';
import { BlockedIpEntity } from '@/app/modules/blocked-ip/entities/blocked-ip.entity';
import { BlockedIpRepository } from '@/app/modules/blocked-ip/repositories/blocked-ip.repository';

@Injectable()
export class IpFilterMiddleware implements NestMiddleware {
  constructor(
    private readonly userRepository: UsersRepository,
    @InjectRepository(BlockedIpEntity)
    private readonly blockedIpRepository: BlockedIpRepository,
  ) {}

  async use(request: any, res: any, next: (error?: any) => void): Promise<void> {
    const ip = request.headers['x-forwarded-for'] ?? request.connection.remoteAddress;
    const ipIsBlocked = await this.blockedIpRepository.exist({ where: { ip } });

    if (ipIsBlocked) {
      throw new ForbiddenException();
    }

    const userUuid = request.user?.uuid;

    if (userUuid) {
      await this.userRepository.update({ uuid: userUuid }, { last_login_ip: ip });
    }

    next();
  }
}
