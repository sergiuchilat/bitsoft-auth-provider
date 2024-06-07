import { DataSource, IsNull, Not, Repository } from 'typeorm';
import { ClassicAuthEntity } from './classic-auth.entity';
import { Injectable } from '@nestjs/common';

export interface ClassicAuthRepository {
  this: Repository<ClassicAuthEntity>;
  findOneByEmail(email: string): Promise<ClassicAuthEntity>;
}

@Injectable()
export class ClassicAuthRepository extends Repository<ClassicAuthEntity> {
  constructor(private readonly dataSource: DataSource) {
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
}
