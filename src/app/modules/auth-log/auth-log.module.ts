import { Module } from '@nestjs/common';
import { AuthLogController } from '@/app/modules/auth-log/controllers/auth-log.controller';
import { AuthLogService } from '@/app/modules/auth-log/services/auth-log.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthLogEntity } from '@/app/modules/auth-log/entities/auth-log.entity';

@Module({
  imports: [TypeOrmModule.forFeature([AuthLogEntity])],
  controllers: [AuthLogController],
  providers: [AuthLogService],
  exports: [AuthLogService],
})
export class AuthLogModule {}
