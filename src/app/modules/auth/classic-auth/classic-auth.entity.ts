import { Column, CreateDateColumn, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn } from 'typeorm';

import { UserEntity } from '@/app/modules/users/user.entity';
import { AuthMethodStatus } from '@/app/modules/common/enums/auth-method.status';

@Entity('credentials_classic')
export class ClassicAuthEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({
    length: 255,
    unique: true,
    nullable: false,
  })
  email: string;

  @Column({
    length: 60,
    nullable: false,
  })
  password: string;

  @Column({
    length: 255,
    nullable: true,
  })
  name: string;

  @Column({
    nullable: false,
    default: AuthMethodStatus.NEW,
  })
  status: AuthMethodStatus;

  @Column({
    nullable: true,
    length: 36,
  })
  activation_code: string;

  @Column({
    nullable: true,
    length: 36,
  })
  reset_password_code: string;

  @Column({
    nullable: true,
    type: 'timestamptz',
  })
  expired_at_reset_password_code: Date;

  @Column({
    nullable: true,
  })
  user_id: number;

  @OneToOne(() => UserEntity, (user) => user.id)
  @JoinColumn({
    name: 'user_id',
    referencedColumnName: 'id',
  })
  user: UserEntity;

  @CreateDateColumn({
    type: 'timestamptz',
    default: () => 'CURRENT_TIMESTAMP(6)',
  })
  public created_at: Date;
}
