import { DataSource, IsNull, Not, Repository } from 'typeorm';
import { ClassicAuthEntity } from './classic-auth.entity';
import { Injectable } from '@nestjs/common';
import { I18nService } from 'nestjs-i18n';

export interface ClassicAuthRepository {
  updateResetPasswordCode(email: string, resetCode: string): void;
  findOneByEmail(email: string): Promise<ClassicAuthEntity>;
  this: Repository<ClassicAuthEntity>;
}


@Injectable()
export class ClassicAuthRepository extends Repository<ClassicAuthEntity> {
  constructor(
    private readonly dataSource: DataSource,
    private readonly i18nService: I18nService,
  ) {
    super(ClassicAuthEntity, dataSource.createEntityManager());
  }

  findOneByEmail(email: string) {
    return this.findOne({
      where: {
        email,
        user_id: Not(IsNull()),
      },
      relations: ['user'],
    });
  }
  updateResetPasswordCode(email: string, resetCode: string) {
    this.update(
      {
        email,
      },
      {
        reset_password_code: resetCode,
        reset_password_code_expired_at: new Date(),
      },
    );
  }
}
