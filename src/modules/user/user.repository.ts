// user.repository.ts
import { DataSource, FindOptionsSelect, Repository } from 'typeorm';
import { Injectable, NotFoundException } from '@nestjs/common';
import { User } from './user.entity';

@Injectable()
export class UserRepository extends Repository<User> {
  constructor(private dataSource: DataSource) {
    super(User, dataSource.createEntityManager());
  }

  async findById(id: number, select?: FindOptionsSelect<User>): Promise<User> {
    const user = await this.findOne({
      where: { id },
      select,
    });
    if (!user) {
      throw new NotFoundException({ msg: `User with id ${id} not found` });
    }
    return user;
  }
}
