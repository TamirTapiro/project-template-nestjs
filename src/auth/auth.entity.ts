// user.entity.ts
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('auth')
export class AuthEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  token: string;

  @Column({ default: false })
  tokenFor: 'email_verify' | 'forgot_password';

  @UpdateDateColumn()
  updatedAt: Date;
}
