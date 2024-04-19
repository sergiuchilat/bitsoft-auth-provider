import { Column, CreateDateColumn, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn } from 'typeorm';
import { UserEntity } from '@/app/modules/users/entities/user.entity';
import { AuthMethodStatusEnum } from '@/app/modules/common/auth-method-status.enum';

@Entity('auth_credentials_classic')
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
    nullable: false,
    default: AuthMethodStatusEnum.NEW
  })
    status: AuthMethodStatusEnum;

  @Column({
    nullable: true,
    length: 36
  })
    activation_code: string;

  @Column({
    nullable: false,
  })
    user_id: number;

  @OneToOne(() => UserEntity, (user) => user.id)
  @JoinColumn({
    name: 'user_id',
    referencedColumnName: 'id'
  })
    user: UserEntity;

  @CreateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
  })
  public created_at: Date;
}