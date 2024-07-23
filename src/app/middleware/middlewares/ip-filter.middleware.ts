import { ForbiddenException, Injectable, NestMiddleware } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UsersRepository } from '@/app/modules/users/users.repository';
import { BlockedIpEntity } from '@/app/modules/blocked-ip/entities/blocked-ip.entity';
import requestIp from 'request-ip';
import { Repository } from 'typeorm';
import { UserEntity } from '@/app/modules/users/user.entity';

@Injectable()
export class IpFilterMiddleware implements NestMiddleware {
  constructor(
    @InjectRepository(BlockedIpEntity)
    private readonly blockedIpRepository: Repository<BlockedIpEntity>,
    @InjectRepository(UserEntity)
    private readonly userRepository: UsersRepository,
  ) {}

  async use(request: any, res: any, next: (error?: any) => void): Promise<void> {
    const clientIp = requestIp.getClientIp(request);
    const ipIsBlocked = await this.blockedIpRepository.exist({ where: { ip: clientIp } });

    if (ipIsBlocked) {
      throw new ForbiddenException();
    }

    const userUuid = request.user?.uuid;

    if (userUuid) {
      await this.userRepository.update({ uuid: userUuid }, { last_login_ip: clientIp });
    }

    next();
  }
}
