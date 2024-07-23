import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { UserEntity } from '@/app/modules/users/user.entity';

@Entity({ name: 'auth_log' })
export class AuthLogEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({
    length: 255,
    nullable: true,
  })
  ip: string;

  @Column({
    type: 'timestamptz',
    default: () => 'CURRENT_TIMESTAMP(6)',
  })
  created_at: Date;

  @Column({
    length: 255,
    nullable: true,
  })
  user_agent: string;

  @Column({
    length: 255,
    nullable: true,
  })
  referer: string;

  @Column({
    length: 255,
    nullable: true,
  })
  origin: string;

  @Column({
    type: 'int',
    nullable: true,
  })
  user_id: number;

  @ManyToOne(() => UserEntity, (user) => user.id)
  @JoinColumn({ name: 'user_id' })
  user: UserEntity;
}
