import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import AppModules from './modules';
import EventEmitterConfig from '@/app/services/events-gateway/event-emitter.config';
import { SeedService } from '@/database/seeds/seed.service';
import i18nConfig from '@/app/services/i18n-config';
import TypeormConnector from '@/database/connectors/typeorm.connector';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '@/app/modules/users/user.entity';
import { BlockedIpEntity } from '@/app/modules/blocked-ip/entities/blocked-ip.entity';
import { ParseTokenMiddleware } from '@/app/middleware/middlewares/parse-token.middleware';
import { ParseLocalizationMiddleware } from '@/app/middleware/middlewares/parse-localization.middleware';
import { IpFilterMiddleware } from '@/app/middleware/middlewares/ip-filter.middleware';

@Module({
  imports: [
    ...TypeormConnector,
    i18nConfig,
    ...AppModules,
    EventEmitterConfig,
    JwtModule,
    PassportModule.register({ session: true }),
    TypeOrmModule.forFeature([UserEntity, BlockedIpEntity]),
  ],
  providers: [SeedService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(ParseTokenMiddleware)
      .exclude('(.*)login(.*)', '(.*)register(.*)', '(.*)oauth(.*)')
      .forRoutes('*');
    consumer.apply(ParseLocalizationMiddleware).forRoutes('*');
    consumer.apply(IpFilterMiddleware).forRoutes('*');
  }
}
