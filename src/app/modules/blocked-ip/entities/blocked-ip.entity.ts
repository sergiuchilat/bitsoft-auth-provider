import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity({ name: 'blocked_ips' })
export class BlockedIpEntity {
  @PrimaryGeneratedColumn()
  id?: number;

  @Column({
    type: 'varchar',
    length: 39,
  })
  ip: string;

  @Column({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
  })
  created_at?: Date;

  @Column({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
  })
  updated_at?: Date;
}
