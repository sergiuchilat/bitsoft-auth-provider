import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
@Entity('auth_log')
export class AuthLogEntity {
  @PrimaryGeneratedColumn ()
  id: number;

  @Column ({
    length: 255,
    nullable: true,
  })
  email: string;

  @Column ({
    length: 255,
    nullable: true,
  })
  ip: string;

  @Column ({
    type: 'timestamptz',
    default: () => 'CURRENT_TIMESTAMP(6)',
  })
  created_at: Date;

  @Column ({
    length: 255,
    nullable: true,
  })
  user_agent: string;

  @Column ({
    length: 255,
    nullable: true,
  })
  referer: string;

  @Column ({
    length: 255,
    nullable: true,
  })
  origin: string;
}
